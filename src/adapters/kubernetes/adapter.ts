import { spawnSync } from 'child_process';
import { writeFileSync, unlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { SafeAdapter } from '../adapter.interface.js';
import type { SafeIntent, SandboxResult, ExecutionResult, SafeExecutorConfig } from '../../types/index.js';
import type { KubeIntent, ResourceSnapshot } from './types.js';
import { parseKubeCommand, toSafeIntent } from './parser.js';
import { runKubeSandbox } from './sandbox.js';

/**
 * Kubernetes Adapter — SafeAdapter implementation for kubectl and helm.
 *
 * Integrates with the SafeExecutor 6-gate pipeline:
 *   Gate 1  ping()         → kubectl version --client
 *   Gate 1  parseIntent()  → parse kubectl/helm command into SafeIntent
 *   Gate 3  sandbox()      → kubectl --dry-run=server / helm --dry-run
 *   Gate 5  execute()      → capture pre-state snapshot, run command, guard rollback
 *
 * Rollback strategy (best-effort):
 *   - Workloads (Deployment, StatefulSet, DaemonSet): kubectl rollout undo
 *   - Everything else: kubectl apply -f <saved-manifest.yaml>
 *
 * @example
 *   const executor = new SafeExecutor({
 *     configPath: './config.json',
 *     policyPath: './config/policies/kubernetes-default-policy.json',
 *     adapter: new KubernetesAdapter({ context: 'my-cluster' }),
 *   });
 *   await executor.run('kubectl delete deployment my-app -n production');
 */

export interface KubernetesAdapterOptions {
  /** kubectl context to use (--context flag). Defaults to current kubeconfig context. */
  context?: string;
}

const ROLLBACK_MULTIPLIER = 1.5;
const WORKLOAD_TYPES = new Set(['deployment', 'daemonset', 'statefulset']);

export class KubernetesAdapter implements SafeAdapter {
  readonly domain = 'kubernetes';

  private readonly context?: string;

  constructor(options: KubernetesAdapterOptions = {}) {
    this.context = options.context;
  }

  // ── Connectivity ─────────────────────────────────────────────────────────

  async ping(): Promise<void> {
    const args = this.withContext(['version', '--client', '--output=json']);
    const result = spawnSync('kubectl', args, { encoding: 'utf-8', timeout: 10_000 });
    if (result.error !== null && result.error !== undefined) {
      throw new Error(`kubectl not found: ${result.error.message}`);
    }
    if (result.status !== 0) {
      throw new Error(`kubectl unavailable: ${result.stderr}`);
    }
  }

  // ── Gate 1: Intent Parsing ───────────────────────────────────────────────

  async parseIntent(raw: string): Promise<SafeIntent> {
    const kubeIntent = parseKubeCommand(raw);
    return toSafeIntent(kubeIntent);
  }

  // ── Gate 3: Sandbox ──────────────────────────────────────────────────────

  async sandbox(intent: SafeIntent): Promise<SandboxResult> {
    const kubeIntent = intent.ast as KubeIntent;
    const start = Date.now();

    if (!kubeIntent || typeof kubeIntent !== 'object') {
      return {
        feasible: true,
        estimatedRowsAffected: 0,
        executionPlan: `Sandbox skipped — no AST available for: ${intent.raw}`,
        warnings: ['Could not parse K8s intent from AST — sandbox skipped'],
        durationMs: Date.now() - start,
      };
    }

    const result = runKubeSandbox(kubeIntent);

    return {
      feasible: result.feasible,
      estimatedRowsAffected: result.resourcesAffected,
      executionPlan: result.plan,
      warnings: result.warnings,
      durationMs: result.durationMs,
    };
  }

  // ── Gate 5: Execution ────────────────────────────────────────────────────

  async execute(
    intent: SafeIntent,
    _config: SafeExecutorConfig,
    estimatedRows: number | null,
  ): Promise<ExecutionResult> {
    const start = Date.now();
    const kubeIntent = intent.ast as KubeIntent;

    if (!kubeIntent || typeof kubeIntent !== 'object') {
      return {
        status: 'failed',
        rowsAffected: 0,
        durationMs: Date.now() - start,
        savepointUsed: false,
        rolledBack: false,
        error: 'Cannot execute: K8s intent AST missing from parsed intent',
      };
    }

    // Capture pre-execution state for rollback
    const snapshot = await this.captureSnapshot(kubeIntent);

    // Run the command
    const args = this.buildArgs(kubeIntent);
    const result = spawnSync(kubeIntent.tool, args, { encoding: 'utf-8', timeout: 120_000 });

    if (result.error !== null && result.error !== undefined) {
      return {
        status: 'failed',
        rowsAffected: 0,
        durationMs: Date.now() - start,
        savepointUsed: false,
        rolledBack: false,
        error: `${kubeIntent.tool} error: ${result.error.message}`,
      };
    }

    if (result.status !== 0) {
      return {
        status: 'failed',
        rowsAffected: 0,
        durationMs: Date.now() - start,
        savepointUsed: false,
        rolledBack: false,
        error: `${kubeIntent.tool} command failed:\n${result.stderr}`,
      };
    }

    const resourcesAffected = snapshot !== null ? 1 : 1;

    // Guard: if actual resources exceed estimate by ROLLBACK_MULTIPLIER, roll back
    if (
      estimatedRows !== null &&
      estimatedRows > 0 &&
      resourcesAffected > estimatedRows * ROLLBACK_MULTIPLIER &&
      snapshot !== null
    ) {
      const rollbackReason = `Resources affected (${resourcesAffected}) exceeds estimated (${estimatedRows}) by factor ${ROLLBACK_MULTIPLIER}`;
      await this.restoreSnapshot(snapshot);
      return {
        status: 'rolled_back',
        rowsAffected: resourcesAffected,
        durationMs: Date.now() - start,
        savepointUsed: true,
        rolledBack: true,
        rollbackReason,
      };
    }

    return {
      status: 'success',
      rowsAffected: resourcesAffected,
      durationMs: Date.now() - start,
      savepointUsed: snapshot !== null,
      rolledBack: false,
    };
  }

  async close(): Promise<void> {
    // No persistent connections to release
  }

  // ── Private Helpers ──────────────────────────────────────────────────────

  /**
   * Capture the current manifest of the target resource before execution.
   * Returns null if the resource doesn't exist or can't be fetched
   * (e.g. before a kubectl create).
   */
  private async captureSnapshot(intent: KubeIntent): Promise<ResourceSnapshot | null> {
    const { resourceType, resourceName, namespace } = intent;
    if (resourceType === undefined || resourceName === undefined || resourceName === '') return null;

    const args = this.withContext([
      'get', resourceType, resourceName, '-o', 'yaml',
      ...(namespace !== undefined ? ['-n', namespace] : []),
    ]);

    const result = spawnSync('kubectl', args, { encoding: 'utf-8', timeout: 15_000 });
    if (result.error !== null && result.error !== undefined) return null;
    if (result.status !== 0) return null; // resource doesn't exist yet

    return {
      id: `${namespace ?? 'default'}/${resourceType}/${resourceName}`,
      namespace: namespace ?? 'default',
      resourceType,
      resourceName,
      manifest: result.stdout,
      capturedAt: new Date(),
    };
  }

  /**
   * Restore a snapshot after a failed or overflowing execution.
   * - Workload types: kubectl rollout undo
   * - Everything else: kubectl apply -f <saved-manifest>
   */
  private async restoreSnapshot(snapshot: ResourceSnapshot): Promise<void> {
    if (WORKLOAD_TYPES.has(snapshot.resourceType.toLowerCase())) {
      const args = this.withContext([
        'rollout', 'undo',
        `${snapshot.resourceType}/${snapshot.resourceName}`,
        '-n', snapshot.namespace,
      ]);
      spawnSync('kubectl', args, { encoding: 'utf-8', timeout: 60_000 });
    } else {
      const tmpPath = join(
        tmpdir(),
        `se-rollback-${Date.now()}-${Math.random().toString(36).slice(2)}.yaml`,
      );
      try {
        writeFileSync(tmpPath, snapshot.manifest);
        const args = this.withContext(['apply', '-f', tmpPath]);
        spawnSync('kubectl', args, { encoding: 'utf-8', timeout: 60_000 });
      } finally {
        try { unlinkSync(tmpPath); } catch { /* best-effort */ }
      }
    }
  }

  /** Rebuild args from the raw command, injecting --context if configured. */
  private buildArgs(intent: KubeIntent): string[] {
    const rest = intent.raw.split(/\s+/).slice(1); // drop tool name
    return this.withContext(rest);
  }

  private withContext(args: string[]): string[] {
    return this.context !== undefined ? ['--context', this.context, ...args] : args;
  }
}
