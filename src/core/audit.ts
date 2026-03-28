import * as fs from 'fs';
import * as path from 'path';
import type { AuditEntry, SafeExecutorConfig } from '../types/index.js';

/**
 * Audit Trail — Layer 6
 *
 * Records the complete lifecycle of every operation:
 * who, what, when, why, before/after state, execution plan, duration.
 *
 * Outputs: console | file | database
 * Every entry is immutable once written.
 */

let entryCounter = 0;

export function generateAuditId(): string {
  return `audit-${Date.now()}-${++entryCounter}`;
}

export async function writeAuditEntry(
  entry: AuditEntry,
  config: SafeExecutorConfig,
): Promise<void> {
  if (!config.audit.enabled) return;

  const serialized = serializeEntry(entry);

  switch (config.audit.output) {
    case 'console':
      writeToConsole(entry, serialized);
      break;
    case 'file':
      await writeToFile(serialized, config);
      break;
    case 'database':
      // TODO Phase 6: write to audit_log table
      writeToConsole(entry, serialized);
      break;
  }
}

function serializeEntry(entry: AuditEntry): string {
  return JSON.stringify(
    {
      ...entry,
      timestamp: entry.timestamp.toISOString(),
      operation: {
        ...entry.operation,
        metadata: entry.operation.metadata,
      },
      approvalResponse: entry.approvalResponse
        ? {
            ...entry.approvalResponse,
            approvedAt: entry.approvalResponse.approvedAt?.toISOString(),
          }
        : null,
    },
    null,
    2,
  );
}

function writeToConsole(entry: AuditEntry, serialized: string): void {
  const icon = entry.executionResult?.status === 'success' ? '✓' : '✗';
  const risk = entry.policyDecision.riskLevel;
  const status = entry.executionResult?.status ?? 'aborted';

  console.log(`\n[SafeExecutor Audit] ${icon} ${status.toUpperCase()} | ${risk} | ${entry.id}`);
  console.log(`  Operation  : ${entry.operation.type} on [${entry.operation.tables.join(', ')}]`);
  console.log(`  Executor   : ${entry.executor}`);
  console.log(`  Duration   : ${entry.totalDurationMs}ms`);

  if (entry.executionResult?.rolledBack) {
    console.log(`  Rollback   : ${entry.executionResult.rollbackReason}`);
  }

  if (process.env['SAFE_EXECUTOR_VERBOSE'] === 'true') {
    console.log(serialized);
  }
}

async function writeToFile(serialized: string, config: SafeExecutorConfig): Promise<void> {
  const filePath = config.audit.filePath ?? './safe-executor-audit.log';
  const dir = path.dirname(filePath);

  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.appendFileSync(filePath, serialized + '\n---\n', 'utf-8');
}
