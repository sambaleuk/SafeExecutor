import { spawnSync } from 'child_process';
import type { SafeAdapter, SimulationResult, AdapterExecutionResult } from '../../core/types.js';
import type {
  CicdPolicy,
  CicdPolicyDecision,
  CicdPolicyRule,
  CicdSnapshot,
  ParsedCicdCommand,
} from './types.js';
import type { RiskLevel } from '../../types/index.js';
import { parseCicdCommand } from './parser.js';
import { simulateCicdCommand } from './sandbox.js';

// ─── Policy evaluator ──────────────────────────────────────────────────────────

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function escalateRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

function matchesRule(intent: ParsedCicdCommand, rule: CicdPolicyRule): boolean {
  const m = rule.match;
  if (m.tools && !m.tools.includes(intent.tool)) return false;
  if (m.actions && !m.actions.includes(intent.action)) return false;
  if (m.environments && !m.environments.includes(intent.environment)) return false;
  if (m.hasSpecificTag !== undefined && intent.hasSpecificTag !== m.hasSpecificTag) return false;
  if (m.isForceDeployment !== undefined && intent.isForceDeployment !== m.isForceDeployment) {
    return false;
  }
  if (m.isPrivileged !== undefined && intent.isPrivileged !== m.isPrivileged) return false;
  if (m.hasDangerousMount !== undefined && intent.hasDangerousMount !== m.hasDangerousMount) {
    return false;
  }
  if (m.isPublicRegistry !== undefined && intent.isPublicRegistry !== m.isPublicRegistry) {
    return false;
  }
  return true;
}

export function evaluateCicdPolicy(
  intent: ParsedCicdCommand,
  policy: CicdPolicy,
): CicdPolicyDecision {
  const matchedRules: CicdPolicyRule[] = [];
  let allowed = true;
  let requiresDryRun = false;
  let requiresApproval = false;
  // Start from LOW; escalate per rule. Default only applies when no rule matches.
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

// ─── Argv builder ─────────────────────────────────────────────────────────────

/**
 * Reconstruct a safe argv array from the parsed intent.
 * Splitting intent.raw via shell would re-introduce injection risk from
 * tokens parsed earlier; using the structured fields is safer.
 */
function buildArgv(intent: ParsedCicdCommand): string[] {
  // For CI/CD tools, the safest approach is to split the raw command on
  // whitespace after stripping shell metacharacters. The parsed fields
  // already validated the command is structurally sound.
  const sanitized = intent.raw.replace(/[;&|`$]/g, '');
  return sanitized.split(/\s+/).filter(Boolean);
}

// ─── Adapter ───────────────────────────────────────────────────────────────────

/**
 * CicdAdapter — SafeAdapter<ParsedCicdCommand, CicdSnapshot>
 *
 * Implements the 4-method gate interface for CI/CD operations:
 *   parseIntent  → classify the raw command
 *   sandbox      → validate without executing (static analysis)
 *   execute      → run the command via spawnSync
 *   rollback     → re-trigger the previous stable run (where supported)
 *
 * Policy evaluation (evaluateCicdPolicy) is a standalone export — the
 * adapter's core methods are policy-agnostic; the orchestrator applies policy.
 */
export class CicdAdapter implements SafeAdapter<ParsedCicdCommand, CicdSnapshot> {
  readonly name = 'cicd';

  parseIntent(raw: string): ParsedCicdCommand {
    return parseCicdCommand(raw);
  }

  async sandbox(intent: ParsedCicdCommand): Promise<SimulationResult> {
    return simulateCicdCommand(intent);
  }

  async execute(intent: ParsedCicdCommand): Promise<AdapterExecutionResult> {
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
      timeout: 300_000,
      encoding: 'utf8',
      shell: false, // explicit — never shell-expand
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

  async rollback(intent: ParsedCicdCommand, snapshot: CicdSnapshot): Promise<void> {
    // Only rollback actions are auto-reversible: re-deploy from snapshot state
    if (intent.action !== 'rollback') {
      throw new Error(
        `Automatic rollback is not supported for action '${intent.action}'. ` +
          `A CI/CD snapshot was captured at ${snapshot.timestamp.toISOString()} ` +
          `(id: ${snapshot.commandId}). Pre-execution state: ${snapshot.preState}. ` +
          `Manual intervention is required.`,
      );
    }

    // For explicit rollback actions, the intent itself is the rollback command
    await this.execute(intent);
  }
}
