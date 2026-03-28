import type { ParsedIntent, SandboxResult } from '../types/index.js';
import type { DatabaseAdapter } from '../adapters/adapter.interface.js';

/**
 * Sandbox / Dry-Run Layer — Layer 3
 *
 * Simulates execution before committing anything to the database.
 * Strategy depends on operation type:
 *   - SELECT → EXPLAIN ANALYZE (no data change)
 *   - DML (INSERT/UPDATE/DELETE) → BEGIN → EXECUTE → capture stats → ROLLBACK
 *   - DDL (ALTER/DROP/CREATE) → EXPLAIN only (some DDL cannot be rolled back cleanly)
 *
 * Returns row estimates, warnings, and the query execution plan.
 */

const DDL_TYPES = new Set(['ALTER', 'DROP', 'CREATE', 'TRUNCATE']);
const DML_TYPES = new Set(['INSERT', 'UPDATE', 'DELETE']);

export async function runSandbox(
  intent: ParsedIntent,
  adapter: DatabaseAdapter,
): Promise<SandboxResult> {
  const start = Date.now();
  const warnings: string[] = [];

  if (DDL_TYPES.has(intent.type)) {
    // DDL: we can only explain, not simulate
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

  // UNKNOWN type — delegate to the adapter's own dry-run implementation.
  // This enables non-SQL adapters (e.g. SecretsAdapter) to provide their own
  // feasibility check via runInDryRunTransaction().
  const result = await adapter.runInDryRunTransaction(intent.raw);
  return {
    feasible: result.feasible,
    estimatedRowsAffected: result.rowsAffected,
    executionPlan: result.plan,
    warnings,
    durationMs: Date.now() - start,
  };
}

function extractRowEstimate(explainOutput: string): number {
  // PostgreSQL EXPLAIN ANALYZE: "rows=NNN" in the first line
  const match = explainOutput.match(/rows=(\d+)/);
  return match ? parseInt(match[1], 10) : 0;
}
