import type { DatabaseAdapter, DryRunResult, ExecuteResult } from '../adapter.interface.js';

/**
 * PostgreSQL Adapter
 *
 * Uses the `pg` (node-postgres) driver.
 * Connection is configured via the SafeExecutorConfig database.connectionString.
 *
 * Install: npm install pg @types/pg
 *
 * Key PostgreSQL-specific behaviors:
 *   - EXPLAIN ANALYZE wraps SELECT in BEGIN/ROLLBACK to avoid side effects
 *   - Dry-run uses BEGIN → EXECUTE → pg_stat_user_tables delta → ROLLBACK
 *   - Savepoints use PostgreSQL SAVEPOINT syntax
 */

// Lazy-loaded to avoid requiring pg if another adapter is used
let pgPool: import('pg').Pool | null = null;
let pgClient: import('pg').PoolClient | null = null;

async function getPool(connectionString: string): Promise<import('pg').Pool> {
  if (!pgPool) {
    const { Pool } = await import('pg');
    pgPool = new Pool({ connectionString, max: 5 });
  }
  return pgPool;
}

export class PostgresAdapter implements DatabaseAdapter {
  readonly name = 'postgres';

  constructor(private readonly connectionString: string) {}

  async ping(): Promise<void> {
    const pool = await getPool(this.connectionString);
    const client = await pool.connect();
    try {
      await client.query('SELECT 1');
    } finally {
      client.release();
    }
  }

  async explainQuery(sql: string): Promise<string> {
    const pool = await getPool(this.connectionString);
    const client = await pool.connect();
    try {
      const result = await client.query(`EXPLAIN ${sql}`);
      return result.rows.map((r) => Object.values(r)[0]).join('\n');
    } finally {
      client.release();
    }
  }

  async explainAnalyzeQuery(sql: string): Promise<string> {
    const pool = await getPool(this.connectionString);
    const client = await pool.connect();
    try {
      // Wrap in transaction so EXPLAIN ANALYZE on DML doesn't commit
      await client.query('BEGIN');
      const result = await client.query(`EXPLAIN ANALYZE ${sql}`);
      await client.query('ROLLBACK');
      return result.rows.map((r) => Object.values(r)[0]).join('\n');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  async runInDryRunTransaction(sql: string): Promise<DryRunResult> {
    const pool = await getPool(this.connectionString);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Get EXPLAIN plan first
      let plan = '';
      try {
        const explainResult = await client.query(`EXPLAIN ${sql}`);
        plan = explainResult.rows.map((r) => Object.values(r)[0]).join('\n');
      } catch {
        plan = 'EXPLAIN failed';
      }

      // Execute and capture actual result
      const execResult = await client.query(sql);
      const rowsAffected = execResult.rowCount ?? 0;

      // Always rollback — this is a dry-run
      await client.query('ROLLBACK');

      return {
        feasible: true,
        rowsAffected,
        plan,
      };
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      const message = err instanceof Error ? err.message : String(err);
      return {
        feasible: false,
        rowsAffected: 0,
        plan: `Dry-run failed: ${message}`,
      };
    } finally {
      client.release();
    }
  }

  async beginTransaction(): Promise<void> {
    const pool = await getPool(this.connectionString);
    pgClient = await pool.connect();
    await pgClient.query('BEGIN');
  }

  async setSavepoint(name: string): Promise<void> {
    if (!pgClient) throw new Error('No active transaction');
    await pgClient.query(`SAVEPOINT ${name}`);
  }

  async rollbackToSavepoint(name: string): Promise<void> {
    if (!pgClient) throw new Error('No active transaction');
    await pgClient.query(`ROLLBACK TO SAVEPOINT ${name}`);
  }

  async commitTransaction(): Promise<void> {
    if (!pgClient) throw new Error('No active transaction');
    await pgClient.query('COMMIT');
    pgClient.release();
    pgClient = null;
  }

  async rollbackTransaction(): Promise<void> {
    if (!pgClient) return;
    await pgClient.query('ROLLBACK').catch(() => {});
    pgClient.release();
    pgClient = null;
  }

  async execute(sql: string): Promise<ExecuteResult> {
    if (!pgClient) throw new Error('No active transaction — call beginTransaction() first');
    const result = await pgClient.query(sql);
    return { rowsAffected: result.rowCount ?? 0 };
  }

  async close(): Promise<void> {
    if (pgClient) {
      pgClient.release();
      pgClient = null;
    }
    if (pgPool) {
      await pgPool.end();
      pgPool = null;
    }
  }
}
