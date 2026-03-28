import type {
  ParsedIntent,
  Policy,
  PolicyDecision,
  PolicyRule,
  RiskLevel,
} from '../types/index.js';

/**
 * Policy Engine — Layer 2
 *
 * Evaluates a parsed intent against a loaded policy.
 * Equivalent to Modragor's state machine: rules are evaluated in order,
 * first matching rule wins (unless multiple rules apply and escalate risk).
 *
 * Non-bypassable: DENY rules cannot be overridden at runtime.
 */

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function escalateRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

function matchesRule(intent: ParsedIntent, rule: PolicyRule): boolean {
  const m = rule.match;

  if (m.operationType && !m.operationType.includes(intent.type)) return false;

  if (m.hasWhereClause !== undefined && intent.hasWhereClause !== m.hasWhereClause) return false;

  if (m.tablesPattern && m.tablesPattern.length > 0) {
    const patterns = m.tablesPattern.map((p) => new RegExp(p, 'i'));
    const hasMatch = intent.tables.some((t) => patterns.some((p) => p.test(t)));
    if (!hasMatch) return false;
  }

  if (
    m.minRowsAffected !== undefined &&
    intent.estimatedRowsAffected !== null &&
    intent.estimatedRowsAffected < m.minRowsAffected
  ) {
    return false;
  }

  return true;
}

export function evaluatePolicy(intent: ParsedIntent, policy: Policy): PolicyDecision {
  const matchedRules: PolicyRule[] = [];
  let allowed = true;
  let requiresDryRun = false;
  let requiresApproval = false;
  // Start at the lowest possible risk — each matching rule can only escalate it.
  // defaultRiskLevel is applied below only when no rule matches at all.
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
        messages.push(rule.message ?? `Approval required by rule: ${rule.id}`);
        break;
      case 'require_dry_run':
        requiresDryRun = true;
        messages.push(rule.message ?? `Dry-run required by rule: ${rule.id}`);
        break;
      case 'allow':
        messages.push(rule.message ?? `Allowed by rule: ${rule.id}`);
        break;
    }
  }

  if (matchedRules.length === 0) {
    // No rule matched — fall back to policy defaults
    currentRisk = policy.defaults.defaultRiskLevel;
    if (!policy.defaults.allowUnknown) {
      allowed = false;
      messages.push('No matching rule found and allowUnknown is false');
    } else {
      messages.push('No matching rule — default: allowed');
    }
  }

  // CRITICAL operations always require dry-run + approval
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
