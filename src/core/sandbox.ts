import type { ParsedIntent, SandboxResult } from '../types/index.js';
import type { DatabaseAdapter } from '../adapters/adapter.interface.js';

/**
 * Sandbox / Dry-Run Layer — Layer 3
 *
 * Simulates execution before committing anything to the database.
 * Strategy depends on operation type:
 *   - SELECT → EXPLAIN ANALYZE (no data change)
 *   - DML (INSERT/UPDATE/DELETE) → BEGIN → EXECUTE → capture stats → ROLLBACK
 *   - DDL explainable (ALTER, CREATE) → EXPLAIN only (schema inspection)
 *   - DDL non-explainable (TRUNCATE, DROP) → skip EXPLAIN, pass straight to Gate 4
 *     so the approval gate can block them with a clear message
 *
 * Returns row estimates, warnings, and the query execution plan.
 */

// PostgreSQL supports EXPLAIN for these DDL statements
const DDL_EXPLAINABLE = new Set(['ALTER', 'CREATE']);
// PostgreSQL does NOT support EXPLAIN for these — skip dry-run entirely
const DDL_NON_EXPLAINABLE = new Set(['DROP', 'TRUNCATE']);
const DML_TYPES = new Set(['INSERT', 'UPDATE', 'DELETE']);

export async function runSandbox(
  intent: ParsedIntent,
  adapter: DatabaseAdapter,
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
    // ALTER / CREATE: schema inspection via EXPLAIN
    warnings.push('DDL operations cannot be fully simulated — dry-run provides schema inspection only');
    const plan = await adapter.explainQuery(intent.raw);
    return {
      feasible: true,
      estimatedRowsAffected: -1, // unknown for DDL
      executionPlan: plan,
      warnings,
      durationMs: Date.now() - start,
    };
  }

  if (intent.type === 'SELECT') {
    const plan = await adapter.explainAnalyzeQuery(intent.raw);
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
    // Wrap in transaction, execute, capture stats, rollback
    const result = await adapter.runInDryRunTransaction(intent.raw);

    if (!intent.hasWhereClause && result.rowsAffected > 0) {
      warnings.push(
        `Operation has no WHERE clause and would affect ${result.rowsAffected} rows`,
      );
    }

    if (result.rowsAffected > 10_000) {
      warnings.push(
        `Large operation: ${result.rowsAffected} rows would be affected`,
      );
    }

    return {
      feasible: result.feasible,
      estimatedRowsAffected: result.rowsAffected,
      executionPlan: result.plan,
      warnings,
      durationMs: Date.now() - start,
    };
  }

  // UNKNOWN type
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
