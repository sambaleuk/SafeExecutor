import { spawnSync } from 'child_process';
import type { SimulationResult } from '../../core/types.js';
import type { ParsedQueueCommand } from './types.js';

// ─── Describe helpers ─────────────────────────────────────────────────────────

/**
 * Attempt to describe a Kafka topic before deletion.
 * Returns a summary string, or null if the CLI is unavailable.
 */
function describeKafkaTopic(
  bootstrapServer: string,
  topic: string,
): string | null {
  const result = spawnSync(
    'kafka-topics',
    ['--describe', '--topic', topic, '--bootstrap-server', bootstrapServer],
    { timeout: 10_000, encoding: 'utf8' },
  );

  if (result.error || result.status !== 0) return null;
  return result.stdout?.trim() ?? null;
}

/**
 * Attempt to list consumer groups for a Kafka topic.
 * Returns true if at least one group is found, null if CLI unavailable.
 */
function listKafkaConsumers(
  bootstrapServer: string,
  topic: string,
): boolean | null {
  const result = spawnSync(
    'kafka-consumer-groups',
    ['--list', '--bootstrap-server', bootstrapServer, '--topic', topic],
    { timeout: 10_000, encoding: 'utf8' },
  );

  if (result.error || result.status !== 0) return null;
  const lines = (result.stdout ?? '').trim().split('\n').filter(Boolean);
  return lines.length > 0;
}

/**
 * Attempt to get the approximate message count from an SQS queue.
 * Returns a number, or null if unavailable.
 */
function getSqsMessageCount(queueUrl: string): number | null {
  const result = spawnSync(
    'aws',
    [
      'sqs', 'get-queue-attributes',
      '--queue-url', queueUrl,
      '--attribute-names', 'ApproximateNumberOfMessages',
      '--output', 'json',
    ],
    { timeout: 15_000, encoding: 'utf8' },
  );

  if (result.error || result.status !== 0) return null;

  try {
    const parsed = JSON.parse(result.stdout ?? '{}') as {
      Attributes?: { ApproximateNumberOfMessages?: string };
    };
    const val = parsed.Attributes?.ApproximateNumberOfMessages;
    return val !== undefined ? parseInt(val, 10) : null;
  } catch {
    return null;
  }
}

// ─── Summary builder ──────────────────────────────────────────────────────────

function buildSummary(
  parsed: ParsedQueueCommand,
  warnings: string[],
  extraLines: string[],
): string {
  const lines: string[] = [
    '[DRY-RUN] Queue Command Preview',
    `Tool    : ${parsed.tool}`,
    `Service : ${parsed.service}`,
    `Action  : ${parsed.action}`,
  ];

  if (parsed.targetName)    lines.push(`Target  : ${parsed.targetName}`);
  if (parsed.consumerGroup) lines.push(`Group   : ${parsed.consumerGroup}`);

  lines.push(`Risk    : ${parsed.riskLevel}`);
  lines.push(`Env     : ${parsed.isProduction ? 'PRODUCTION' : 'non-production'}`);

  if (extraLines.length > 0) {
    lines.push('');
    lines.push(...extraLines);
  }

  if (warnings.length > 0) {
    lines.push('');
    lines.push('Warnings:');
    for (const w of warnings) lines.push(`  ⚠  ${w}`);
  }

  return lines.join('\n');
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Simulate a queue command without executing it.
 *
 * Strategy:
 *  - DENY-severity patterns → feasible: false immediately
 *  - delete topic/queue → attempt describe (Kafka) to surface impact
 *  - purge queue → attempt message count (SQS) to surface data loss scale
 *  - delete Kafka topic → attempt consumer group list to warn about active consumers
 *  - All checks that fail due to missing CLIs surface warnings rather than blocking
 */
export async function simulateQueueCommand(parsed: ParsedQueueCommand): Promise<SimulationResult> {
  const start = Date.now();
  const warnings: string[] = [];
  const extraLines: string[] = [];

  // ── DENY patterns — hard stop ─────────────────────────────────────────────
  for (const dp of parsed.dangerousPatterns) {
    if (dp.severity === 'DENY') {
      return {
        feasible: false,
        resourcesImpacted: 0,
        summary: `DENIED: ${dp.description}`,
        warnings: [`Dangerous pattern '${dp.pattern}': ${dp.description}`],
        durationMs: Date.now() - start,
      };
    }
  }

  // ── Production check ──────────────────────────────────────────────────────
  if (parsed.isProduction) {
    warnings.push('Targeting PRODUCTION queue/topic — elevated risk');
  }

  // ── Destructive action checks ─────────────────────────────────────────────
  if (parsed.action === 'delete') {
    warnings.push(
      `Destructive action 'delete' on '${parsed.targetName ?? 'target'}' — ` +
      'operation is permanent and cannot be automatically reversed',
    );

    // Kafka topic delete: try to describe the topic and list consumers
    if (parsed.tool === 'kafka' && parsed.service === 'topics' && parsed.targetName) {
      const bootstrapServer =
        typeof parsed.flags['bootstrap-server'] === 'string'
          ? parsed.flags['bootstrap-server']
          : 'localhost:9092';

      const describe = describeKafkaTopic(bootstrapServer, parsed.targetName);
      if (describe) {
        extraLines.push('--- Topic description (before delete) ---');
        extraLines.push(describe);
        extraLines.push('---');
      } else {
        warnings.push(
          'Could not describe topic before deletion — verify topic exists and broker is reachable',
        );
      }

      const hasConsumers = listKafkaConsumers(bootstrapServer, parsed.targetName);
      if (hasConsumers === true) {
        warnings.push(
          `ACTIVE consumer groups detected on topic '${parsed.targetName}' — ` +
          'deleting this topic will break active consumers',
        );
      } else if (hasConsumers === null) {
        warnings.push(
          'Could not check consumer groups — verify no active consumers before deleting',
        );
      }
    }
  }

  // ── Purge checks ──────────────────────────────────────────────────────────
  if (parsed.action === 'purge') {
    warnings.push(
      `Purge will permanently delete ALL messages from '${parsed.targetName ?? 'target'}' — ` +
      'this cannot be undone',
    );

    // SQS purge: fetch approximate message count
    if (parsed.tool === 'sqs' && parsed.targetName) {
      const count = getSqsMessageCount(parsed.targetName);
      if (count !== null) {
        warnings.push(`Queue contains approximately ${count.toLocaleString()} message(s) that will be deleted`);
        extraLines.push(`Approximate message count before purge: ${count.toLocaleString()}`);
      } else {
        warnings.push('Could not fetch message count — verify queue URL and AWS credentials');
      }
    }
  }

  // ── Configure/reset-offsets check ─────────────────────────────────────────
  if (parsed.action === 'configure') {
    const isOffsetReset =
      parsed.dangerousPatterns.some((p) => p.pattern.includes('reset-offsets')) ||
      (parsed.tool === 'kafka' &&
        parsed.service === 'consumer-groups' &&
        parsed.flags['reset-offsets'] === true);

    if (isOffsetReset) {
      warnings.push(
        'Consumer offset reset — affected consumers will re-process or skip messages from the new position',
      );
    }
  }

  // ── HIGH/CRITICAL dangerous patterns (non-DENY) ───────────────────────────
  for (const dp of parsed.dangerousPatterns) {
    if (dp.severity !== 'DENY') {
      warnings.push(`${dp.severity} pattern: ${dp.description}`);
    }
  }

  const resourcesImpacted = parsed.targetName ? 1 : -1;
  const summary = buildSummary(parsed, warnings, extraLines);

  return {
    feasible: true,
    resourcesImpacted,
    summary,
    warnings,
    durationMs: Date.now() - start,
  };
}
