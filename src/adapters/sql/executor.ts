import type { SafeIntent, ExecutionResult, SafeExecutorConfig } from '../../types/index.js';
import type { DatabaseAdapter } from '../adapter.interface.js';

/**
 * SQL Executor — Safe Execution with Savepoint Protection
 *
 * Wraps the actual SQL execution in a transaction with savepoint.
 * Automatically rolls back if:
 *   - Rows affected exceed the predicted threshold by a configurable factor
 *   - The adapter signals an unexpected error
 *
 * Non-bypassable: transactions are always used. Direct execution is not available.
 */

const ROLLBACK_MULTIPLIER = 1.5; // roll back if actual > estimated * 1.5

export async function executeSQLWithRollback(
  intent: SafeIntent,
  db: DatabaseAdapter,
  config: SafeExecutorConfig,
  estimatedRows: number | null,
): Promise<ExecutionResult> {
  const start = Date.now();
  const savepointName = `se_sp_${Date.now()}`;

  let rowsAffected = 0;

  try {
    await db.beginTransaction();
    await db.setSavepoint(savepointName);

    const result = await db.execute(intent.raw);
    rowsAffected = result.rowsAffected;

    // Guard: check if actual rows exceed predicted threshold
    if (
      estimatedRows !== null &&
      estimatedRows > 0 &&
      rowsAffected > estimatedRows * ROLLBACK_MULTIPLIER
    ) {
      const rollbackReason = `Rows affected (${rowsAffected}) exceeds predicted (${estimatedRows}) by factor ${ROLLBACK_MULTIPLIER}`;
      await db.rollbackToSavepoint(savepointName);
      await db.rollbackTransaction();

      return {
        status: 'rolled_back',
        rowsAffected,
        durationMs: Date.now() - start,
        savepointUsed: true,
        rolledBack: true,
        rollbackReason,
      };
    }

    // Guard: absolute row threshold from config
    if (rowsAffected > config.database.maxRowsThreshold) {
      const rollbackReason = `Rows affected (${rowsAffected}) exceeds config.database.maxRowsThreshold (${config.database.maxRowsThreshold})`;
      await db.rollbackToSavepoint(savepointName);
      await db.rollbackTransaction();

      return {
        status: 'rolled_back',
        rowsAffected,
        durationMs: Date.now() - start,
        savepointUsed: true,
        rolledBack: true,
        rollbackReason,
      };
    }

    await db.commitTransaction();

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
      await db.rollbackToSavepoint(savepointName);
      await db.rollbackTransaction();
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
