import type { SafeIntent, SandboxResult } from '../../types/index.js';
import type { DatabaseAdapter } from '../adapter.interface.js';

/**
 * SQL Sandbox — Dry-Run Simulation
 *
 * Simulates execution before committing anything to the database.
 * Strategy depends on operation type:
 *   - SELECT → EXPLAIN ANALYZE (no data change)
 *   - DML (INSERT/UPDATE/DELETE) → BEGIN → EXECUTE → capture stats → ROLLBACK
 *   - DDL explainable (ALTER, CREATE) → EXPLAIN only (schema inspection)
 *   - DDL non-explainable (TRUNCATE, DROP) → skip dry-run, pass to approval gate
 *     (PostgreSQL does not support EXPLAIN for TRUNCATE/DROP)
 */

// PostgreSQL supports EXPLAIN for these DDL statements
const DDL_EXPLAINABLE = new Set(['ALTER', 'CREATE']);
// PostgreSQL does NOT support EXPLAIN for these — skip dry-run entirely
const DDL_NON_EXPLAINABLE = new Set(['DROP', 'TRUNCATE']);
const DML_TYPES = new Set(['INSERT', 'UPDATE', 'DELETE']);

export async function runSQLSandbox(
  intent: SafeIntent,
  db: DatabaseAdapter,
): Promise<SandboxResult> {
  const start = Date.now();
  const warnings: string[] = [];

  if (DDL_NON_EXPLAINABLE.has(intent.type)) {
    // TRUNCATE / DROP: PostgreSQL does not support EXPLAIN for these statements.
    // Return feasible=true so the pipeline advances to Gate 4 (Approval), which
    // will block them cleanly (CRITICAL risk → auto-mode rejects).
    warnings.push(
      `${intent.type} cannot be dry-run — EXPLAIN is not supported for this operation. ` +
        'Proceeding to approval gate.',
    );
    return {
      feasible: true,
      estimatedRowsAffected: -1,
      executionPlan: 'N/A — EXPLAIN not supported for this DDL operation',
      warnings,
      durationMs: Date.now() - start,
    };
  }

  if (DDL_EXPLAINABLE.has(intent.type)) {
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
  const match = explainOutput.match(/rows=(\d+)/);
  return match ? parseInt(match[1], 10) : 0;
}
