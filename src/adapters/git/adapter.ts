import { spawnSync } from 'child_process';
import type { SafeAdapter, SimulationResult, AdapterExecutionResult } from '../../core/types.js';
import type {
  GitPolicy,
  GitPolicyDecision,
  GitPolicyRule,
  GitSnapshot,
  ParsedGitCommand,
} from './types.js';
import type { RiskLevel } from '../../types/index.js';
import { parseGitCommand } from './parser.js';
import { simulateGitCommand } from './sandbox.js';

// ─── Policy evaluator ─────────────────────────────────────────────────────────

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function escalateRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

function matchesRule(intent: ParsedGitCommand, rule: GitPolicyRule): boolean {
  const m = rule.match;
  if (m.actions && !m.actions.includes(intent.action)) return false;
  if (m.isForce !== undefined && intent.isForce !== m.isForce) return false;
  if (m.isProtectedBranch !== undefined && intent.isProtectedBranch !== m.isProtectedBranch) return false;
  if (m.rewritesHistory !== undefined && intent.rewritesHistory !== m.rewritesHistory) return false;
  if (m.isDestructive !== undefined && intent.isDestructive !== m.isDestructive) return false;
  if (m.flags) {
    const hasAll = m.flags.every(f => intent.flags.includes(f));
    if (!hasAll) return false;
  }
  return true;
}

export function evaluateGitPolicy(
  intent: ParsedGitCommand,
  policy: GitPolicy,
): GitPolicyDecision {
  const matchedRules: GitPolicyRule[] = [];
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

function buildArgv(intent: ParsedGitCommand): string[] {
  // Sanitize against shell injection — git commands must not include shell metacharacters
  const sanitized = intent.raw.replace(/[;&|`$(){}[\]<>\\]/g, '');
  const tokens = sanitized.split(/\s+/).filter(Boolean);
  // Strip the leading 'git' binary if present — we call git directly via spawnSync
  if (tokens[0] === 'git') tokens.shift();
  return tokens;
}

// ─── Adapter ──────────────────────────────────────────────────────────────────

/**
 * GitAdapter — SafeAdapter<ParsedGitCommand, GitSnapshot>
 *
 * Gate interface for git operations:
 *   parseIntent  → classify the raw git command
 *   sandbox      → dry-run preview (push --dry-run, clean -n, merge --no-commit)
 *   execute      → run the git command via spawnSync
 *   rollback     → attempt to restore HEAD from snapshot
 */
export class GitAdapter implements SafeAdapter<ParsedGitCommand, GitSnapshot> {
  readonly name = 'git';

  parseIntent(raw: string): ParsedGitCommand {
    return parseGitCommand(raw);
  }

  async sandbox(intent: ParsedGitCommand): Promise<SimulationResult> {
    return simulateGitCommand(intent);
  }

  async execute(intent: ParsedGitCommand): Promise<AdapterExecutionResult> {
    const start = Date.now();
    const args = buildArgv(intent);

    if (args.length === 0) {
      return {
        success: false,
        output: '',
        resourcesAffected: 0,
        durationMs: Date.now() - start,
        error: 'Empty git command after sanitization',
      };
    }

    const result = spawnSync('git', args, {
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
        error: `git exited with code ${result.status}`,
      };
    }

    return {
      success: true,
      output,
      resourcesAffected: 1,
      durationMs,
    };
  }

  async rollback(intent: ParsedGitCommand, snapshot: GitSnapshot): Promise<void> {
    if (!snapshot.headSha) {
      throw new Error(
        `Automatic rollback is not supported for action '${intent.action}'. ` +
        `Snapshot captured at ${snapshot.timestamp.toISOString()} (id: ${snapshot.commandId}). ` +
        `Pre-state: ${snapshot.preState}. Manual intervention required.`,
      );
    }

    // Attempt: git reset --hard <headSha>
    const result = spawnSync('git', ['reset', '--hard', snapshot.headSha], {
      encoding: 'utf8',
      timeout: 15_000,
      shell: false,
    });

    if (result.status !== 0) {
      const output = [result.stdout, result.stderr].filter(Boolean).join('\n');
      throw new Error(
        `Rollback to ${snapshot.headSha} failed: ${output}. ` +
        `Manual recovery: git reset --hard ${snapshot.headSha}`,
      );
    }
  }
}
