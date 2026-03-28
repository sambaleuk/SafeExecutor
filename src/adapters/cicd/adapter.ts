import type { SafeAdapter, SafeAdapterOptions, SafeAdapterResult } from '../../core/types.js';
import type {
  CicdPolicy,
  CicdPolicyDecision,
  CicdPolicyRule,
  ParsedCicdCommand,
} from './types.js';
import type { RiskLevel } from '../../types/index.js';
import { parseCicdCommand } from './parser.js';
import { runCicdSandbox } from './sandbox.js';

// ─── Policy evaluator ──────────────────────────────────────────────────────────

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function escalateRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

function matchesRule(parsed: ParsedCicdCommand, rule: CicdPolicyRule): boolean {
  const m = rule.match;
  if (m.tools && !m.tools.includes(parsed.tool)) return false;
  if (m.actions && !m.actions.includes(parsed.action)) return false;
  if (m.environments && !m.environments.includes(parsed.environment)) return false;
  if (m.hasSpecificTag !== undefined && parsed.hasSpecificTag !== m.hasSpecificTag) return false;
  if (m.isForceDeployment !== undefined && parsed.isForceDeployment !== m.isForceDeployment) {
    return false;
  }
  if (m.isPrivileged !== undefined && parsed.isPrivileged !== m.isPrivileged) return false;
  if (m.hasDangerousMount !== undefined && parsed.hasDangerousMount !== m.hasDangerousMount) {
    return false;
  }
  if (m.isPublicRegistry !== undefined && parsed.isPublicRegistry !== m.isPublicRegistry) {
    return false;
  }
  return true;
}

function evaluateCicdPolicy(
  parsed: ParsedCicdCommand,
  policy: CicdPolicy,
): CicdPolicyDecision {
  const matchedRules: CicdPolicyRule[] = [];
  let allowed = true;
  let requiresDryRun = false;
  let requiresApproval = false;
  // Start from LOW; escalate based on matched rules. Default applies only when no rule matches.
  let currentRisk: RiskLevel = 'LOW';
  const messages: string[] = [];

  for (const rule of policy.rules) {
    if (!matchesRule(parsed, rule)) continue;
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

// ─── Adapter ───────────────────────────────────────────────────────────────────

/**
 * CicdAdapter — SafeAdapter implementation for CI/CD operations.
 *
 * Pipeline:
 *   1. Parse the command (tool, action, environment, flags, dangerous patterns)
 *   2. Evaluate policy rules
 *   3. Run sandbox validation (if required by policy or dryRun option)
 *   4. Return result with full decision trail
 *
 * Actual execution is delegated to the caller after approval — the adapter
 * produces a safe authorization decision, not a shell invocation.
 */
export class CicdAdapter implements SafeAdapter {
  readonly name = 'cicd';

  constructor(private readonly policy: CicdPolicy) {}

  async execute(command: string, options: SafeAdapterOptions = {}): Promise<SafeAdapterResult> {
    const start = Date.now();

    // ── Gate 1: Parse ─────────────────────────────────────────────────────────
    let parsed: ParsedCicdCommand;
    try {
      parsed = parseCicdCommand(command);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        parsed: {
          raw: command,
          riskLevel: 'CRITICAL',
          isDestructive: false,
          metadata: {},
        },
        policyDecision: {
          allowed: false,
          riskLevel: 'CRITICAL',
          requiresDryRun: false,
          requiresApproval: false,
          message: `Parse error: ${message}`,
        },
        sandboxResult: null,
        executionResult: null,
        abortReason: `Parse error: ${message}`,
      };
    }

    // ── Gate 2: Policy ───────────────────────────────────────────────────────
    const policyDecision = evaluateCicdPolicy(parsed, this.policy);

    if (!policyDecision.allowed) {
      return {
        success: false,
        parsed,
        policyDecision,
        sandboxResult: null,
        executionResult: {
          status: 'denied',
          durationMs: Date.now() - start,
          output: '',
          error: policyDecision.message,
        },
        abortReason: `Policy denied: ${policyDecision.message}`,
      };
    }

    // ── Gate 3: Sandbox ──────────────────────────────────────────────────────
    let sandboxResult = null;
    if (policyDecision.requiresDryRun || options.dryRun) {
      sandboxResult = await runCicdSandbox(parsed);

      if (!sandboxResult.feasible) {
        return {
          success: false,
          parsed,
          policyDecision,
          sandboxResult,
          executionResult: {
            status: 'denied',
            durationMs: Date.now() - start,
            output: sandboxResult.preview,
            error: sandboxResult.warnings[0] ?? 'Sandbox validation failed',
          },
          abortReason: `Sandbox failed: ${sandboxResult.warnings.join('; ')}`,
        };
      }
    }

    // ── Dry-run mode — stop here, do not execute ──────────────────────────────
    if (options.dryRun) {
      return {
        success: true,
        parsed,
        policyDecision,
        sandboxResult,
        executionResult: {
          status: 'dry_run',
          durationMs: Date.now() - start,
          output: sandboxResult?.preview ?? '[dry-run] no sandbox result',
        },
      };
    }

    // ── Gate 4: Approval required — surface to caller ─────────────────────────
    if (policyDecision.requiresApproval && !options.skipApproval) {
      return {
        success: false,
        parsed,
        policyDecision,
        sandboxResult,
        executionResult: null,
        abortReason: `Approval required: ${policyDecision.message}`,
      };
    }

    // ── Authorized — command is cleared for execution ─────────────────────────
    return {
      success: true,
      parsed,
      policyDecision,
      sandboxResult,
      executionResult: {
        status: 'success',
        durationMs: Date.now() - start,
        output: `Authorized: ${parsed.raw}`,
      },
    };
  }
}
