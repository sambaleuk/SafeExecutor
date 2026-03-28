import { parseIntent } from './parser.js';
import { runSQLSandbox } from './sandbox.js';
import { executeSQLWithRollback } from './executor.js';
import { PostgresAdapter } from './postgres.js';
import type { SafeAdapter } from '../adapter.interface.js';
import type { SafeIntent, SandboxResult, ExecutionResult, SafeExecutorConfig } from '../../types/index.js';

/**
 * SQL Adapter — SafeAdapter implementation for SQL databases.
 *
 * Composes the AST-based parser, sandbox, and executor into a single
 * domain adapter that the pipeline can invoke without SQL knowledge.
 *
 * Usage:
 *   const adapter = new SQLAdapter(new PostgresAdapter(connectionString));
 *   const pipeline = new SafeExecutorPipeline(config, policy, adapter);
 */
export class SQLAdapter implements SafeAdapter {
  readonly domain = 'sql';

  constructor(private readonly db: PostgresAdapter) {}

  async ping(): Promise<void> {
    return this.db.ping();
  }

  async parseIntent(raw: string): Promise<SafeIntent> {
    return parseIntent(raw);
  }

  async sandbox(intent: SafeIntent): Promise<SandboxResult> {
    return runSQLSandbox(intent, this.db);
  }

  async execute(
    intent: SafeIntent,
    config: SafeExecutorConfig,
    estimatedRows: number | null,
  ): Promise<ExecutionResult> {
    return executeSQLWithRollback(intent, this.db, config, estimatedRows);
  }

  async close(): Promise<void> {
    return this.db.close();
  }
}

// Re-exports for convenience
export { PostgresAdapter } from './postgres.js';
export { parseIntent as parseSQLIntent } from './parser.js';
