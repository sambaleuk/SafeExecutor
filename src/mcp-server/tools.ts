/**
 * MCP Tool handlers for SafeExecutor.
 * These tools parse + classify commands but do NOT execute them.
 */

import { detectDomain } from './auto-detect.js';

// ─── Lazy parser imports ─────────────────────────────────────────────────────

const HIGH_RISK_LEVELS = new Set(['HIGH', 'CRITICAL']);

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
        blocked: HIGH_RISK_LEVELS.has(intent.riskLevel),
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
        operation: intent.actionType,
        targets: intent.resources ?? [],
        riskLevel: intent.riskLevel,
        blocked: HIGH_RISK_LEVELS.has(intent.riskLevel),
        reason: intent.isDestructive ? `Destructive cloud operation: ${intent.actionType}` : null,
      };
    }
    case 'kubernetes': {
      const { parseKubeCommand } = await import('../adapters/kubernetes/parser.js');
      const kube = parseKubeCommand(command);
      return {
        domain,
        operation: kube.verb,
        targets: kube.resourceName ? [kube.resourceName] : kube.namespace ? [kube.namespace] : [],
        riskLevel: kube.riskLevel,
        blocked: HIGH_RISK_LEVELS.has(kube.riskLevel),
        reason: kube.dangerousPatterns?.join('; ') ?? null,
      };
    }
    case 'cicd': {
      const { parseCicdCommand } = await import('../adapters/cicd/parser.js');
      const intent = parseCicdCommand(command);
      return {
        domain,
        operation: intent.action,
        targets: intent.imageTag ? [intent.imageTag] : [],
        riskLevel: intent.riskLevel,
        blocked: HIGH_RISK_LEVELS.has(intent.riskLevel),
        reason: intent.dangerousPatterns?.map((p: { description: string }) => p.description).join('; ') ?? null,
      };
    }
    case 'api': {
      const { parseHttpRequest } = await import('../adapters/api/parser.js');
      const intent = parseHttpRequest(command);
      return {
        domain,
        operation: intent.method,
        targets: intent.host ? [intent.host + intent.path] : [command],
        riskLevel: intent.riskLevel,
        blocked: HIGH_RISK_LEVELS.has(intent.riskLevel),
        reason: intent.isDestructive ? `Destructive HTTP method: ${intent.method}` : null,
      };
    }
    case 'secrets': {
      const { parseSecretCommand } = await import('../adapters/secrets/parser.js');
      const intent = parseSecretCommand(command);
      return {
        domain,
        operation: intent.action,
        targets: intent.secretPath ? [intent.secretPath] : [],
        riskLevel: intent.riskLevel,
        blocked: HIGH_RISK_LEVELS.has(intent.riskLevel),
        reason: intent.dangerousPatterns?.map((p: { description: string }) => p.description).join('; ') ?? null,
      };
    }
    case 'network': {
      const { parseNetworkCommand } = await import('../adapters/network/parser.js');
      const intent = parseNetworkCommand(command);
      return {
        domain,
        operation: intent.action,
        targets: intent.targetHost ? [intent.targetHost] : [],
        riskLevel: intent.riskLevel,
        blocked: HIGH_RISK_LEVELS.has(intent.riskLevel),
        reason: intent.dangerousPatterns?.map((p: { description: string }) => p.description).join('; ') ?? null,
      };
    }
    case 'git': {
      const { parseGitCommand } = await import('../adapters/git/parser.js');
      const intent = parseGitCommand(command);
      return {
        domain,
        operation: intent.action,
        targets: intent.branch ? [intent.branch] : intent.remote ? [intent.remote] : [],
        riskLevel: intent.riskLevel,
        blocked: HIGH_RISK_LEVELS.has(intent.riskLevel),
        reason: intent.dangerousPatterns?.map((p: { description: string }) => p.description).join('; ') ?? null,
      };
    }
    case 'queue': {
      const { parseQueueCommand } = await import('../adapters/queue/parser.js');
      const intent = parseQueueCommand(command);
      return {
        domain,
        operation: intent.action,
        targets: intent.targetName ? [intent.targetName] : [],
        riskLevel: intent.riskLevel,
        blocked: HIGH_RISK_LEVELS.has(intent.riskLevel),
        reason: intent.dangerousPatterns?.map((p: { description: string }) => p.description).join('; ') ?? null,
      };
    }
    default:
      return {
        domain,
        operation: 'unknown',
        targets: [] as string[],
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
