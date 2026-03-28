/**
 * SafeExecutor — Public API
 *
 * Entry point for programmatic use.
 *
 * Usage:
 *   import { SafeExecutor } from 'safe-executor';
 *
 *   const executor = new SafeExecutor({
 *     configPath: './config/my-config.json',
 *   });
 *
 *   const result = await executor.run('DELETE FROM users WHERE id = $1');
 */

import { SafeExecutorPipeline } from './core/pipeline.js';
import { loadConfig, loadPolicy } from './config/loader.js';
import { SQLAdapter, PostgresAdapter } from './adapters/sql/index.js';
import type { SafeAdapter } from './adapters/adapter.interface.js';
import type { PipelineResult, SafeExecutorConfig, Policy } from './types/index.js';

export interface SafeExecutorOptions {
  configPath: string;
  policyPath?: string;
  /** Provide a custom SafeAdapter to override the default SQL adapter */
  adapter?: SafeAdapter;
}

export class SafeExecutor {
  private readonly config: SafeExecutorConfig;
  private readonly policy: Policy;
  private readonly adapter: SafeAdapter;
  private readonly pipeline: SafeExecutorPipeline;

  constructor(options: SafeExecutorOptions) {
    this.config = loadConfig(options.configPath);

    const policyPath = options.policyPath ?? this.config.policy.file;
    this.policy = loadPolicy(policyPath);

    this.adapter = options.adapter ?? this.createDefaultAdapter();

    this.pipeline = new SafeExecutorPipeline(this.config, this.policy, this.adapter);
  }

  async run(raw: string, requestedBy?: string): Promise<PipelineResult> {
    await this.adapter.ping();
    return this.pipeline.run(raw, requestedBy);
  }

  async close(): Promise<void> {
    await this.adapter.close();
  }

  private createDefaultAdapter(): SafeAdapter {
    const { adapter, connectionString } = this.config.database;
    if (adapter === 'postgres') {
      return new SQLAdapter(new PostgresAdapter(connectionString));
    }
    throw new Error(
      `No built-in adapter for '${adapter}'. Pass a custom adapter via options.adapter.`,
    );
  }
}

// ─── Re-exports for library users ───────────────────────────────────────────

export { SafeExecutorPipeline } from './core/pipeline.js';
export { SQLAdapter, PostgresAdapter } from './adapters/sql/index.js';
export { loadConfig, loadPolicy } from './config/loader.js';
export { registerAdapter, getAdapter, listDomains } from './plugins/registry.js';

export type { SafeAdapter, DatabaseAdapter } from './adapters/adapter.interface.js';
export type {
  PipelineResult,
  SafeExecutorConfig,
  Policy,
  PolicyRule,
  SafeIntent,
  ParsedIntent,
  AuditEntry,
  ExecutionResult,
  RiskFactor,
  Target,
  Scope,
} from './types/index.js';

// ── Cloud Infrastructure Adapter ──────────────────────────────────────────────
export { CloudAdapter } from './adapters/cloud/index.js';

// ── Kubernetes Adapter ────────────────────────────────────────────────────────
export { KubernetesAdapter } from './adapters/kubernetes/index.js';
export type { KubernetesAdapterOptions } from './adapters/kubernetes/index.js';
export type {
  CloudIntent,
  CloudCommand,
  CloudSnapshot,
  CloudProvider,
  CloudRiskLevel,
  CloudActionType,
} from './adapters/cloud/index.js';
export type {
  SimulationResult,
  AdapterExecutionResult,
} from './core/types.js';

// ── Filesystem / Shell Adapter ────────────────────────────────────────────────
export { FilesystemAdapter } from './adapters/filesystem/index.js';
export { parseIntent as parseFilesystemIntent } from './adapters/filesystem/index.js';
export type {
  FilesystemIntent,
  FilesystemSnapshot,
  FsCommandType,
  FsOperationCategory,
  PathRiskInfo,
} from './adapters/filesystem/index.js';
