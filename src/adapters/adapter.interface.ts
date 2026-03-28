import type {
  SafeIntent,
  SandboxResult,
  ExecutionResult,
  SafeExecutorConfig,
} from '../types/index.js';

// ─── Low-Level Database Adapter ──────────────────────────────────────────────

/**
 * Low-level database connection interface.
 * Used internally by SQL adapters to manage connections, transactions, and
 * dry-run execution. Not exposed to the pipeline directly.
 */

export interface DryRunResult {
  feasible: boolean;
  rowsAffected: number;
  plan: string;
}

export interface ExecuteResult {
  rowsAffected: number;
}

export interface DatabaseAdapter {
  /** Adapter identifier (e.g. 'postgres', 'mysql') */
  readonly name: string;

  /** Check connectivity and permissions before pipeline starts */
  ping(): Promise<void>;

  /** Run EXPLAIN on a query (without execution) */
  explainQuery(sql: string): Promise<string>;

  /**
   * Run EXPLAIN ANALYZE — actually executes but does not commit.
   * Used for SELECT queries where row estimates are needed.
   */
  explainAnalyzeQuery(sql: string): Promise<string>;

  /**
   * Execute a DML query inside a transaction, capture stats, then ROLLBACK.
   * Used by the sandbox layer for realistic simulation.
   */
  runInDryRunTransaction(sql: string): Promise<DryRunResult>;

  /** Begin a new transaction */
  beginTransaction(): Promise<void>;

  /** Create a named savepoint within the current transaction */
  setSavepoint(name: string): Promise<void>;

  /** Roll back to a named savepoint (partial rollback) */
  rollbackToSavepoint(name: string): Promise<void>;

  /** Commit the current transaction */
  commitTransaction(): Promise<void>;

  /** Roll back the entire current transaction */
  rollbackTransaction(): Promise<void>;

  /**
   * Execute SQL and return affected row count.
   * Called only from Executor after all gates have passed.
   */
  execute(sql: string): Promise<ExecuteResult>;

  /** Close the connection/pool */
  close(): Promise<void>;
}

// ─── SafeAdapter (v2 Universal Interface) ────────────────────────────────────

/**
 * Universal adapter interface for all SafeExecutor domains.
 *
 * Every domain (SQL, cloud, filesystem, API, CI/CD) implements this interface.
 * The pipeline exclusively calls SafeAdapter methods — it has no knowledge of
 * the underlying technology.
 *
 * Contract:
 *   - parseIntent() MUST be deterministic for the same input
 *   - sandbox() MUST never commit side effects
 *   - execute() is called ONLY after all pipeline gates have passed
 *   - rollback() MUST be a best-effort operation (not all domains support it)
 */
export interface SafeAdapter {
  /** Domain identifier matching SafeIntent.domain: 'sql', 'cloud', 'filesystem', … */
  readonly domain: string;

  /** Verify the adapter is connected and ready to process operations */
  ping(): Promise<void>;

  /**
   * Parse a raw operation string into a normalized SafeIntent.
   * This is Gate 1 of the pipeline.
   *
   * @param raw - Raw input (SQL string, terraform plan path, shell command, HTTP request, …)
   */
  parseIntent(raw: string): Promise<SafeIntent>;

  /**
   * Simulate the operation without committing side effects.
   * This is Gate 3 (conditional — only called if policy requires dry-run).
   *
   * Must populate intent.estimatedRowsAffected if applicable.
   */
  sandbox(intent: SafeIntent): Promise<SandboxResult>;

  /**
   * Execute the operation with rollback protection.
   * Called only from Gate 5, after policy + approval have passed.
   */
  execute(
    intent: SafeIntent,
    config: SafeExecutorConfig,
    estimatedRows: number | null,
  ): Promise<ExecutionResult>;

  /** Release all resources (connections, file handles, etc.) */
  close(): Promise<void>;
}

// ─── Plugin Registration ──────────────────────────────────────────────────────

/**
 * Metadata for a SafeAdapter plugin (used by the plugin registry).
 * Published adapters follow @safe-executor/<domain> naming convention.
 */
export interface SafeAdapterPlugin {
  /** Package name, e.g. '@safe-executor/sql' */
  name: string;
  version: string;
  adapter: SafeAdapter;
}
