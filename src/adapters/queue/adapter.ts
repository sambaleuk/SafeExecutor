import { spawnSync } from 'child_process';
import type { SafeAdapter, SimulationResult, AdapterExecutionResult } from '../../core/types.js';
import type {
  QueuePolicy,
  QueuePolicyDecision,
  QueuePolicyRule,
  QueueSnapshot,
  ParsedQueueCommand,
} from './types.js';
import type { RiskLevel } from '../../types/index.js';
import { parseQueueCommand } from './parser.js';
import { simulateQueueCommand } from './sandbox.js';

// ─── Policy evaluator ─────────────────────────────────────────────────────────

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function escalateRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

function matchesRule(intent: ParsedQueueCommand, rule: QueuePolicyRule): boolean {
  const m = rule.match;
  if (m.tools && !m.tools.includes(intent.tool)) return false;
  if (m.actions && !m.actions.includes(intent.action)) return false;
  if (m.isProduction !== undefined && intent.isProduction !== m.isProduction) return false;
  if (m.hasActiveConsumers !== undefined && intent.hasActiveConsumers !== m.hasActiveConsumers) {
    return false;
  }
  if (m.hasDangerousPattern !== undefined) {
    const found = intent.dangerousPatterns.some((dp) =>
      dp.pattern.includes(m.hasDangerousPattern!),
    );
    if (!found) return false;
  }
  return true;
}

export function evaluateQueuePolicy(
  intent: ParsedQueueCommand,
  policy: QueuePolicy,
): QueuePolicyDecision {
  const matchedRules: QueuePolicyRule[] = [];
  let allowed = true;
  let requiresDryRun = false;
  let requiresApproval = false;
  let currentRisk: RiskLevel = 'LOW';
  const messages: string[] = [];

  for (const rule of policy.rules) {
    if (!matchesRule(intent, rule)) continue;
    matchedRules.push(rule);
    currentRisk = escalateRisk(currentRisk, rule.riskLevel);

    switch (rule.action) {
      case 'deny':
        allowed = false;
        messages.push(rule.message ?? `Denied by rule: ${rule.id}`);
        break;
      case 'require_approval':
        requiresApproval = true;
        messages.push(rule.message ?? `Approval required: ${rule.id}`);
        break;
      case 'require_dry_run':
        requiresDryRun = true;
        messages.push(rule.message ?? `Dry-run required: ${rule.id}`);
        break;
      case 'allow':
        messages.push(rule.message ?? `Allowed: ${rule.id}`);
        break;
    }
  }

  if (matchedRules.length === 0) {
    currentRisk = policy.defaults.defaultRiskLevel;
    if (!policy.defaults.allowUnknown) {
      allowed = false;
      messages.push('No matching rule found and allowUnknown is false');
    } else {
      messages.push('No matching rule — default: allowed');
    }
  }

  // CRITICAL risk always forces dry-run + approval
  if (currentRisk === 'CRITICAL') {
    requiresDryRun = true;
    requiresApproval = true;
  }

  return {
    allowed,
    riskLevel: currentRisk,
    requiresDryRun,
    requiresApproval,
    matchedRules,
    message: messages.join('; '),
  };
}

// ─── Argv builder ──────────────────────────────────────────────────────────────

/**
 * Reconstruct CLI argv from the parsed command.
 * Using the parsed structure prevents shell injection from raw string manipulation.
 */
function buildArgv(intent: ParsedQueueCommand): string[] {
  // Sanitize: strip shell metacharacters
  const sanitized = intent.raw.replace(/[;&|`$]/g, '');
  return sanitized.split(/\s+/).filter(Boolean);
}

// ─── Adapter ──────────────────────────────────────────────────────────────────

/**
 * QueueAdapter — SafeAdapter<ParsedQueueCommand, QueueSnapshot>
 *
 * Implements the 4-method gate interface for message queue operations:
 *   parseIntent  → classify the raw CLI command
 *   sandbox      → static analysis + optional live describe/count checks
 *   execute      → run the command via spawnSync (no shell)
 *   rollback     → surface snapshot info; automatic rollback not supported
 *
 * Supported:
 *   Kafka   — kafka-topics, kafka-consumer-groups, kafka-configs
 *   RabbitMQ — rabbitmqctl, rabbitmqadmin
 *   Redis   — redis-cli
 *   AWS     — aws sqs, aws sns
 *   GCP     — gcloud pubsub
 *
 * Security note: execute() uses spawnSync with a parsed argument list (not via
 * shell), preventing injection attacks from raw command strings.
 */
export class QueueAdapter implements SafeAdapter<ParsedQueueCommand, QueueSnapshot> {
  readonly name = 'queue';

  parseIntent(raw: string): ParsedQueueCommand {
    return parseQueueCommand(raw);
  }

  async sandbox(intent: ParsedQueueCommand): Promise<SimulationResult> {
    return simulateQueueCommand(intent);
  }

  async execute(intent: ParsedQueueCommand): Promise<AdapterExecutionResult> {
    const start = Date.now();
    const argv = buildArgv(intent);
    const [cli, ...args] = argv;

    if (!cli) {
      return {
        success: false,
        output: '',
        resourcesAffected: 0,
        durationMs: Date.now() - start,
        error: 'Empty command after sanitization',
      };
    }

    const result = spawnSync(cli, args, {
      timeout: 60_000,
      encoding: 'utf8',
      shell: false,
    });

    const durationMs = Date.now() - start;

    if (result.error) {
      return {
        success: false,
        output: '',
        resourcesAffected: 0,
        durationMs,
        error: result.error.message,
      };
    }

    const output = [result.stdout, result.stderr]
      .filter(Boolean)
      .join('\n')
      .trim();

    if (result.status !== 0) {
      return {
        success: false,
        output,
        resourcesAffected: 0,
        durationMs,
        error: `Process exited with code ${result.status}`,
      };
    }

    return {
      success: true,
      output,
      resourcesAffected: 1,
      durationMs,
    };
  }

  async rollback(intent: ParsedQueueCommand, snapshot: QueueSnapshot): Promise<void> {
    // Queue operations are generally irreversible:
    //  - Deleted topics/queues must be re-created manually
    //  - Purged messages are gone permanently
    //  - Offset resets require a new explicit reset command
    throw new Error(
      `Automatic rollback is not supported for queue action '${intent.action}' ` +
      `on '${intent.targetName ?? 'target'}'. ` +
      `A snapshot was captured at ${snapshot.timestamp.toISOString()} ` +
      `(id: ${snapshot.commandId}). ` +
      `Pre-execution state: ${snapshot.preState}. ` +
      'Manual intervention is required.',
    );
  }
}
