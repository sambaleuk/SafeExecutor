/**
 * MCP Tool handlers for SafeExecutor.
 * These tools parse + classify commands but do NOT execute them.
 */

import { detectDomain } from './auto-detect.js';

// ─── Lazy parser imports ─────────────────────────────────────────────────────

async function parseWithDomain(command: string, domain: string) {
  switch (domain) {
    case 'sql': {
      const { parseIntent } = await import('../adapters/sql/parser.js');
      const intent = await parseIntent(command);
      return {
        domain,
        operation: intent.operationType,
        targets: intent.targets?.map((t) => t.name) ?? [],
        riskLevel: intent.riskLevel,
        blocked: intent.riskLevel === 'critical' || intent.riskLevel === 'high',
        reason: intent.riskFactors?.map((r) => r.description).join('; ') ?? null,
      };
    }
    case 'filesystem': {
      const { parseIntent } = await import('../adapters/filesystem/parser.js');
      const intent = parseIntent(command);
      return {
        domain,
        operation: intent.commandType,
        targets: intent.targets?.map((t) => t.path) ?? [],
        riskLevel: intent.riskLevel,
        blocked: intent.denied,
        reason: intent.denyReason ?? null,
      };
    }
    case 'cloud': {
      const { buildCloudIntent } = await import('../adapters/cloud/parser.js');
      const intent = buildCloudIntent(command);
      return {
        domain,
        operation: intent.operationType,
        targets: intent.targets?.map((t) => t.name) ?? [],
        riskLevel: intent.riskLevel,
        blocked: intent.riskLevel === 'critical' || intent.riskLevel === 'high',
        reason: intent.riskFactors?.map((r: { description: string }) => r.description).join('; ') ?? null,
      };
    }
    case 'kubernetes': {
      const { parseKubeCommand, toSafeIntent } = await import('../adapters/kubernetes/parser.js');
      const kube = parseKubeCommand(command);
      const intent = toSafeIntent(kube);
      return {
        domain,
        operation: intent.operationType,
        targets: intent.targets?.map((t) => t.name) ?? [],
        riskLevel: intent.riskLevel,
        blocked: intent.riskLevel === 'critical' || intent.riskLevel === 'high',
        reason: intent.riskFactors?.map((r) => r.description).join('; ') ?? null,
      };
    }
    case 'cicd': {
      const { parseCicdCommand } = await import('../adapters/cicd/parser.js');
      const intent = parseCicdCommand(command);
      return {
        domain,
        operation: intent.operation,
        targets: intent.targets ?? [],
        riskLevel: intent.riskLevel,
        blocked: intent.riskLevel === 'critical' || intent.riskLevel === 'high',
        reason: intent.riskFactors?.join('; ') ?? null,
      };
    }
    case 'api': {
      const { parseHttpRequest } = await import('../adapters/api/parser.js');
      const intent = parseHttpRequest(command);
      return {
        domain,
        operation: intent.method,
        targets: [intent.url ?? command],
        riskLevel: intent.riskLevel,
        blocked: intent.riskLevel === 'critical' || intent.riskLevel === 'high',
        reason: intent.riskFactors?.map((r: { description: string }) => r.description).join('; ') ?? null,
      };
    }
    case 'secrets': {
      const { parseSecretCommand } = await import('../adapters/secrets/parser.js');
      const intent = parseSecretCommand(command);
      return {
        domain,
        operation: intent.operation,
        targets: intent.secretPaths ?? [],
        riskLevel: intent.riskLevel,
        blocked: intent.riskLevel === 'critical' || intent.riskLevel === 'high',
        reason: intent.riskFactors?.join('; ') ?? null,
      };
    }
    case 'network': {
      const { parseNetworkCommand } = await import('../adapters/network/parser.js');
      const intent = parseNetworkCommand(command);
      return {
        domain,
        operation: intent.commandType,
        targets: intent.targets ?? [],
        riskLevel: intent.riskLevel,
        blocked: intent.riskLevel === 'critical' || intent.riskLevel === 'high',
        reason: intent.riskFactors?.join('; ') ?? null,
      };
    }
    default:
      return {
        domain,
        operation: 'unknown',
        targets: [],
        riskLevel: 'unknown',
        blocked: false,
        reason: 'No parser available for this domain',
      };
  }
}

// ─── Tool Handlers ───────────────────────────────────────────────────────────

export async function safeExecute(command: string, domain?: string) {
  const resolvedDomain = domain ?? detectDomain(command);
  const result = await parseWithDomain(command, resolvedDomain);
  return {
    ...result,
    policy_decision: result.blocked ? 'BLOCKED' : 'ALLOWED',
  };
}

export async function safeAnalyze(command: string, domain?: string) {
  const resolvedDomain = domain ?? detectDomain(command);
  const result = await parseWithDomain(command, resolvedDomain);
  return {
    ...result,
    policy_decision: result.blocked ? 'BLOCKED' : 'ALLOWED',
    note: 'Analysis only — no execution performed',
  };
}

export async function safePolicyCheck(command: string) {
  const domain = detectDomain(command);
  const result = await parseWithDomain(command, domain);
  return {
    allowed: !result.blocked,
    risk: result.riskLevel,
    domain,
    reason: result.reason ?? (result.blocked ? 'High-risk operation blocked by policy' : 'Operation is within safe thresholds'),
  };
}
