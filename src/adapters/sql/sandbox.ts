import type { SafeIntent, SandboxResult } from '../../types/index.js';
import type { DatabaseAdapter } from '../adapter.interface.js';

/**
 * SQL Sandbox — Dry-Run Simulation
 *
 * Simulates execution before committing anything to the database.
 * Strategy depends on operation type:
 *   - SELECT → EXPLAIN ANALYZE (no data change)
 *   - DML (INSERT/UPDATE/DELETE) → BEGIN → EXECUTE → capture stats → ROLLBACK
 *   - DDL (ALTER/DROP/CREATE/TRUNCATE) → EXPLAIN only (DDL cannot be rolled back cleanly)
 */

const DDL_TYPES = new Set(['ALTER', 'DROP', 'CREATE', 'TRUNCATE']);
const DML_TYPES = new Set(['INSERT', 'UPDATE', 'DELETE']);

export async function runSQLSandbox(
  intent: SafeIntent,
  db: DatabaseAdapter,
): Promise<SandboxResult> {
  const start = Date.now();
  const warnings: string[] = [];

  if (DDL_TYPES.has(intent.type)) {
    warnings.push('DDL operations cannot be fully simulated — dry-run provides schema inspection only');
    const plan = await db.explainQuery(intent.raw);
    return {
      feasible: true,
      estimatedRowsAffected: -1,
      executionPlan: plan,
      warnings,
      durationMs: Date.now() - start,
    };
  }

  if (intent.type === 'SELECT') {
    const plan = await db.explainAnalyzeQuery(intent.raw);
    const rowEstimate = extractRowEstimate(plan);
    return {
      feasible: true,
      estimatedRowsAffected: rowEstimate,
      executionPlan: plan,
      warnings,
      durationMs: Date.now() - start,
    };
  }

  if (DML_TYPES.has(intent.type)) {
    const result = await db.runInDryRunTransaction(intent.raw);

    if (!intent.hasWhereClause && result.rowsAffected > 0) {
      warnings.push(
        `Operation has no WHERE clause and would affect ${result.rowsAffected} rows`,
      );
    }

    if (result.rowsAffected > 10_000) {
      warnings.push(`Large operation: ${result.rowsAffected} rows would be affected`);
    }

    return {
      feasible: result.feasible,
      estimatedRowsAffected: result.rowsAffected,
      executionPlan: result.plan,
      warnings,
      durationMs: Date.now() - start,
    };
  }

  warnings.push('Unknown operation type — cannot simulate');
  return {
    feasible: false,
    estimatedRowsAffected: -1,
    executionPlan: '',
    warnings,
    durationMs: Date.now() - start,
  };
}

function extractRowEstimate(explainOutput: string): number {
  // PostgreSQL EXPLAIN ANALYZE: "rows=NNN" in the first line
  const match = explainOutput.match(/rows=(\d+)/);
  return match ? parseInt(match[1], 10) : 0;
}
