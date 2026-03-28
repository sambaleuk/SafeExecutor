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
 *   const result = await executor.run('DELETE FROM users WHERE id = $1', { params: [42] });
 */

import { SafeExecutorPipeline } from './core/pipeline.js';
import { loadConfig, loadPolicy } from './config/loader.js';
import { PostgresAdapter } from './adapters/postgres.js';
import type { DatabaseAdapter } from './adapters/adapter.interface.js';
import type { PipelineResult, SafeExecutorConfig, Policy } from './types/index.js';

export interface SafeExecutorOptions {
  configPath: string;
  policyPath?: string;
  adapter?: DatabaseAdapter;
}

export class SafeExecutor {
  private readonly config: SafeExecutorConfig;
  private readonly policy: Policy;
  private readonly adapter: DatabaseAdapter;
  private readonly pipeline: SafeExecutorPipeline;

  constructor(options: SafeExecutorOptions) {
    this.config = loadConfig(options.configPath);

    const policyPath = options.policyPath ?? this.config.policy.file;
    this.policy = loadPolicy(policyPath);

    this.adapter =
      options.adapter ??
      this.createDefaultAdapter();

    this.pipeline = new SafeExecutorPipeline(this.config, this.policy, this.adapter);
  }

  async run(sql: string, requestedBy?: string): Promise<PipelineResult> {
    await this.adapter.ping();
    return this.pipeline.run(sql, requestedBy);
  }

  async close(): Promise<void> {
    await this.adapter.close();
  }

  private createDefaultAdapter(): DatabaseAdapter {
    const { adapter, connectionString } = this.config.database;
    if (adapter === 'postgres') {
      return new PostgresAdapter(connectionString);
    }
    throw new Error(
      `No built-in adapter for '${adapter}'. Pass a custom adapter via options.adapter.`,
    );
  }
}

// Re-exports for library users
export { SafeExecutorPipeline } from './core/pipeline.js';
export { PostgresAdapter } from './adapters/postgres.js';
export { SecretsAdapter } from './adapters/secrets/index.js';
export { loadConfig, loadPolicy } from './config/loader.js';
export type { DatabaseAdapter } from './adapters/adapter.interface.js';
export type {
  PipelineResult,
  SafeExecutorConfig,
  Policy,
  PolicyRule,
  ParsedIntent,
  AuditEntry,
  ExecutionResult,
} from './types/index.js';
export type {
  ParsedSecretCommand,
  LeakDetectionResult,
  SecretsAdapterOptions,
  SecretTool,
  SecretAction,
  SecretEnvironment,
} from './adapters/secrets/index.js';
