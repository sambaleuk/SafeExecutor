/**
 * Database Adapter Interface
 *
 * All database adapters must implement this interface.
 * This allows SafeExecutor to be extended to MySQL, SQLite, CockroachDB, etc.
 * without modifying the core pipeline.
 *
 * Adapter contract:
 *   - Adapters are responsible for connection management
 *   - Adapters MUST implement dry-run via actual transaction + rollback
 *   - Adapters MUST expose EXPLAIN/EXPLAIN ANALYZE for planning
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
  /**
   * Adapter identifier (e.g. 'postgres', 'mysql')
   */
  readonly name: string;

  /**
   * Check connectivity and permissions before pipeline starts
   */
  ping(): Promise<void>;

  /**
   * Run EXPLAIN on a query (without execution)
   */
  explainQuery(sql: string): Promise<string>;

  /**
   * Run EXPLAIN ANALYZE — actually executes but does not commit
   * Used for SELECT queries where row estimates are needed
   */
  explainAnalyzeQuery(sql: string): Promise<string>;

  /**
   * Execute a DML query inside a transaction, capture stats, then ROLLBACK
   * Used by the sandbox layer for realistic simulation
   */
  runInDryRunTransaction(sql: string): Promise<DryRunResult>;

  /**
   * Begin a new transaction
   */
  beginTransaction(): Promise<void>;

  /**
   * Create a named savepoint within the current transaction
   */
  setSavepoint(name: string): Promise<void>;

  /**
   * Roll back to a named savepoint (partial rollback)
   */
  rollbackToSavepoint(name: string): Promise<void>;

  /**
   * Commit the current transaction
   */
  commitTransaction(): Promise<void>;

  /**
   * Roll back the entire current transaction
   */
  rollbackTransaction(): Promise<void>;

  /**
   * Execute SQL and return affected row count
   * Called only from Executor after all gates have passed
   */
  execute(sql: string): Promise<ExecuteResult>;

  /**
   * Close the connection/pool
   */
  close(): Promise<void>;
}
