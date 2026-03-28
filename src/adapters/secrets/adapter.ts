import { spawnSync } from 'child_process';
import type { SafeAdapter, SimulationResult, AdapterExecutionResult } from '../../core/types.js';
import type {
  SecretPolicy,
  SecretPolicyDecision,
  SecretPolicyRule,
  SecretSnapshot,
  ParsedSecretCommand,
} from './types.js';
import type { RiskLevel } from '../../types/index.js';
import { parseSecretCommand } from './parser.js';
import { simulateSecretCommand } from './sandbox.js';

// ─── Policy evaluator ──────────────────────────────────────────────────────────

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function escalateRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

function matchesRule(intent: ParsedSecretCommand, rule: SecretPolicyRule): boolean {
  const m = rule.match;
  if (m.tools && !m.tools.includes(intent.tool)) return false;
  if (m.actions && !m.actions.includes(intent.action)) return false;
  if (m.scopes && !m.scopes.includes(intent.scope)) return false;
  if (m.exposesValue !== undefined && intent.exposesValue !== m.exposesValue) return false;
  if (m.isOverwrite !== undefined && intent.isOverwrite !== m.isOverwrite) return false;
  if (m.isProduction !== undefined && intent.isProduction !== m.isProduction) return false;
  if (m.isForce !== undefined && intent.isForce !== m.isForce) return false;
  return true;
}

export function evaluateSecretPolicy(
  intent: ParsedSecretCommand,
  policy: SecretPolicy,
): SecretPolicyDecision {
  const matchedRules: SecretPolicyRule[] = [];
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

// ─── Argv builder ─────────────────────────────────────────────────────────────

function buildArgv(intent: ParsedSecretCommand): string[] {
  const sanitized = intent.raw.replace(/[;&|`$]/g, '');
  return sanitized.split(/\s+/).filter(Boolean);
}

// ─── Adapter ───────────────────────────────────────────────────────────────────

/**
 * SecretsAdapter — SafeAdapter<ParsedSecretCommand, SecretSnapshot>
 *
 * Implements the 4-method gate interface for secrets management operations:
 *   parseIntent  → classify the raw command (vault, aws, gcloud, az, kubectl, docker, export)
 *   sandbox      → validate without executing (static analysis + leak detection)
 *   execute      → run the command via spawnSync
 *   rollback     → restore from snapshot (where supported)
 */
export class SecretsAdapter implements SafeAdapter<ParsedSecretCommand, SecretSnapshot> {
  readonly name = 'secrets';

  parseIntent(raw: string): ParsedSecretCommand {
    return parseSecretCommand(raw);
  }

  async sandbox(intent: ParsedSecretCommand): Promise<SimulationResult> {
    return simulateSecretCommand(intent);
  }

  async execute(intent: ParsedSecretCommand): Promise<AdapterExecutionResult> {
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
      timeout: 30_000, // shorter timeout for secrets ops
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

  async rollback(intent: ParsedSecretCommand, snapshot: SecretSnapshot): Promise<void> {
    if (!snapshot.previousVersionId) {
      throw new Error(
        `Automatic rollback is not supported for action '${intent.action}'. ` +
        `A snapshot was captured at ${snapshot.timestamp.toISOString()} ` +
        `(id: ${snapshot.commandId}). Pre-execution state: ${snapshot.preState}. ` +
        `Manual intervention is required.`,
      );
    }

    // For versioned secret stores, we could restore the previous version
    // This is a placeholder — actual implementation depends on the secret store
    throw new Error(
      `Automatic rollback to version '${snapshot.previousVersionId}' ` +
      `requires manual intervention. Snapshot: ${snapshot.preState}`,
    );
  }
}
