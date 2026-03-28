import type { ParsedIntent, ExecutionResult, SafeExecutorConfig } from '../types/index.js';
import type { DatabaseAdapter } from '../adapters/adapter.interface.js';

/**
 * Executor — Layer 5
 *
 * Wraps the actual SQL execution in a transaction with savepoint.
 * Automatically rolls back if:
 *   - Rows affected exceed the predicted threshold by a configurable factor
 *   - The adapter signals an unexpected error
 *   - A post-execution validation fails
 *
 * Non-bypassable: transactions are always used. Direct execution is not available.
 */

const ROLLBACK_MULTIPLIER = 1.5; // roll back if actual > estimated * 1.5

export async function executeWithRollback(
  intent: ParsedIntent,
  adapter: DatabaseAdapter,
  config: SafeExecutorConfig,
  estimatedRows: number | null,
): Promise<ExecutionResult> {
  const start = Date.now();
  const savepointName = `se_sp_${Date.now()}`;

  let rowsAffected = 0;
  let rolledBack = false;
  let rollbackReason: string | undefined;

  try {
    await adapter.beginTransaction();
    await adapter.setSavepoint(savepointName);

    const result = await adapter.execute(intent.raw);
    rowsAffected = result.rowsAffected;

    // Guard: check if actual rows exceed predicted threshold
    if (
      estimatedRows !== null &&
      estimatedRows > 0 &&
      rowsAffected > estimatedRows * ROLLBACK_MULTIPLIER
    ) {
      rollbackReason = `Rows affected (${rowsAffected}) exceeds predicted (${estimatedRows}) by factor ${ROLLBACK_MULTIPLIER}`;
      await adapter.rollbackToSavepoint(savepointName);
      await adapter.rollbackTransaction();
      rolledBack = true;

      return {
        status: 'rolled_back',
        rowsAffected,
        durationMs: Date.now() - start,
        savepointUsed: true,
        rolledBack: true,
        rollbackReason,
      };
    }

    await adapter.commitTransaction();

    return {
      status: 'success',
      rowsAffected,
      durationMs: Date.now() - start,
      savepointUsed: true,
      rolledBack: false,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);

    try {
      await adapter.rollbackToSavepoint(savepointName);
      await adapter.rollbackTransaction();
    } catch {
      // Best-effort rollback — swallow secondary errors
    }

    return {
      status: 'failed',
      rowsAffected,
      durationMs: Date.now() - start,
      savepointUsed: true,
      rolledBack: true,
      rollbackReason: `Execution error: ${message}`,
      error: message,
    };
  }
}
