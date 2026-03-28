import { spawnSync } from 'child_process';
import type { KubeIntent } from './types.js';

export interface KubeSandboxResult {
  feasible: boolean;
  plan: string;
  resourcesAffected: number;
  warnings: string[];
  durationMs: number;
}

const READ_VERBS = new Set(['get', 'describe', 'logs', 'top', 'list']);

/**
 * Dry-run a kubectl or helm command without side effects.
 *
 * Strategy:
 *   kubectl apply       → --dry-run=server -o yaml
 *   kubectl diff        → kubectl diff (shows diff vs current state)
 *   resource write ops  → kubectl get to count affected resources
 *   helm install/upgrade→ helm --dry-run
 *   read ops            → no sandbox needed
 */
export function runKubeSandbox(intent: KubeIntent): KubeSandboxResult {
  const start = Date.now();
  const warnings: string[] = [];

  return intent.tool === 'kubectl'
    ? runKubectlSandbox(intent, start, warnings)
    : runHelmSandbox(intent, start, warnings);
}

// ─── kubectl ─────────────────────────────────────────────────────────────────

function runKubectlSandbox(
  intent: KubeIntent,
  start: number,
  warnings: string[],
): KubeSandboxResult {
  const { verb } = intent;

  if (READ_VERBS.has(verb)) {
    return {
      feasible: true,
      plan: `Read-only operation — no sandbox needed: ${intent.raw}`,
      resourcesAffected: 0,
      warnings,
      durationMs: Date.now() - start,
    };
  }

  if (verb === 'apply') return applyDryRun(intent, start, warnings);

  if (['delete', 'scale', 'patch', 'label', 'annotate', 'edit'].includes(verb)) {
    return resourceStateSandbox(intent, start, warnings);
  }

  // exec, port-forward, rollout, drain, cordon — no dry-run available
  warnings.push(`Dry-run not supported for 'kubectl ${verb}' — manual verification required`);
  return {
    feasible: true,
    plan: `Planned: ${intent.raw}\n(Dry-run not available for this verb)`,
    resourcesAffected: 1,
    warnings,
    durationMs: Date.now() - start,
  };
}

/**
 * kubectl apply --dry-run=server -o yaml
 * Shows exactly what the cluster would create/update.
 */
function applyDryRun(
  intent: KubeIntent,
  start: number,
  warnings: string[],
): KubeSandboxResult {
  // Rebuild args from the raw command, injecting --dry-run=server
  const parts = intent.raw.split(/\s+/).slice(1); // drop 'kubectl'
  const hasDryRun = parts.some((p) => p.startsWith('--dry-run'));
  if (!hasDryRun) {
    parts.push('--dry-run=server', '-o', 'yaml');
  }

  const result = spawnSync('kubectl', parts, { encoding: 'utf-8', timeout: 30_000 });

  if (result.error !== null && result.error !== undefined) {
    return failure(result.error.message, start, warnings);
  }
  if (result.status !== 0) {
    return failure(result.stderr || 'kubectl apply --dry-run failed', start, warnings);
  }

  const output = result.stdout;
  const resourcesAffected = Math.max((output.match(/^---/gm) ?? []).length, 1);

  return { feasible: true, plan: output, resourcesAffected, warnings, durationMs: Date.now() - start };
}

/**
 * For delete / scale / patch: query current state so the operator can see
 * what resources would be affected before approving.
 */
function resourceStateSandbox(
  intent: KubeIntent,
  start: number,
  warnings: string[],
): KubeSandboxResult {
  const { resourceType, resourceName, namespace } = intent;

  if (resourceType === undefined) {
    warnings.push('No resource type specified — sandbox skipped');
    return {
      feasible: true,
      plan: `Planned: ${intent.raw}\n(No resource type; state lookup skipped)`,
      resourcesAffected: 0,
      warnings,
      durationMs: Date.now() - start,
    };
  }

  const args: string[] = ['get', resourceType];
  if (resourceName !== undefined && resourceName !== '') args.push(resourceName);
  if (namespace !== undefined) args.push('-n', namespace);
  args.push('--no-headers');

  const result = spawnSync('kubectl', args, { encoding: 'utf-8', timeout: 15_000 });

  if (result.error !== null && result.error !== undefined) {
    return failure(result.error.message, start, warnings);
  }
  if (result.status !== 0) {
    return failure(result.stderr || 'kubectl get failed', start, warnings);
  }

  const lines = result.stdout.trim().split('\n').filter(Boolean);
  const resourcesAffected = lines.length;

  return {
    feasible: true,
    plan: `Planned: ${intent.raw}\n\nCurrent state (${resourcesAffected} resource(s) would be affected):\n${result.stdout}`,
    resourcesAffected,
    warnings,
    durationMs: Date.now() - start,
  };
}

// ─── Helm ─────────────────────────────────────────────────────────────────────

function runHelmSandbox(
  intent: KubeIntent,
  start: number,
  warnings: string[],
): KubeSandboxResult {
  const { verb } = intent;

  if (['list', 'status', 'history', 'get', 'template', 'lint', 'search', 'show'].includes(verb)) {
    return {
      feasible: true,
      plan: `Read/template operation — no sandbox needed: ${intent.raw}`,
      resourcesAffected: 0,
      warnings,
      durationMs: Date.now() - start,
    };
  }

  if (verb === 'install' || verb === 'upgrade') {
    return helmDryRun(intent, start, warnings);
  }

  warnings.push(`Dry-run not supported for 'helm ${verb}' — manual verification required`);
  return {
    feasible: true,
    plan: `Helm operation planned: ${intent.raw}\n(Dry-run not available for this verb)`,
    resourcesAffected: 1,
    warnings,
    durationMs: Date.now() - start,
  };
}

/** helm install/upgrade --dry-run */
function helmDryRun(
  intent: KubeIntent,
  start: number,
  warnings: string[],
): KubeSandboxResult {
  const parts = intent.raw.split(/\s+/).slice(1); // drop 'helm'
  if (!parts.includes('--dry-run')) parts.push('--dry-run');

  const result = spawnSync('helm', parts, { encoding: 'utf-8', timeout: 60_000 });

  if (result.error !== null && result.error !== undefined) {
    return failure(result.error.message, start, warnings);
  }
  if (result.status !== 0) {
    return failure(result.stderr || 'helm dry-run failed', start, warnings);
  }

  const output = result.stdout;
  const resourcesAffected = Math.max((output.match(/^---/gm) ?? []).length, 1);

  return { feasible: true, plan: output, resourcesAffected, warnings, durationMs: Date.now() - start };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function failure(
  reason: string,
  start: number,
  warnings: string[],
): KubeSandboxResult {
  return {
    feasible: false,
    plan: reason,
    resourcesAffected: 0,
    warnings,
    durationMs: Date.now() - start,
  };
}
