/**
 * MCP Tool handlers for SafeExecutor.
 * These tools parse + classify commands but do NOT execute them.
 */

import { detectDomain } from './auto-detect.js';
import type { RiskLevel, RiskFactor } from '../types/index.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function maxRisk(factors: RiskFactor[]): RiskLevel {
  const order: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  return factors.reduce<RiskLevel>((max, f) => {
    return order.indexOf(f.severity) > order.indexOf(max) ? f.severity : max;
  }, 'LOW');
}

// ─── Lazy parser imports ─────────────────────────────────────────────────────

async function parseWithDomain(command: string, domain: string) {
  switch (domain) {
    case 'sql': {
      const { parseIntent } = await import('../adapters/sql/parser.js');
      const intent = await parseIntent(command);
      const riskLevel = maxRisk(intent.riskFactors);
      return {
        domain,
        operation: intent.type,
        targets: intent.tables,
        riskLevel,
        blocked: riskLevel === 'CRITICAL' || riskLevel === 'HIGH',
        reason: intent.riskFactors.map((r) => r.description).join('; ') || null,
      };
    }
    case 'filesystem': {
      const { parseIntent } = await import('../adapters/filesystem/parser.js');
      const intent = parseIntent(command);
      return {
        domain,
        operation: intent.commandType,
        targets: intent.targetPaths,
        riskLevel: intent.riskLevel,
        blocked: intent.isDenied || intent.riskLevel === 'CRITICAL' || intent.riskLevel === 'HIGH',
        reason: intent.denyReason ?? null,
      };
    }
    case 'cloud': {
      const { buildCloudIntent } = await import('../adapters/cloud/parser.js');
      const intent = buildCloudIntent(command);
      return {
        domain,
        operation: intent.actionType,
        targets: intent.command.resources,
        riskLevel: intent.riskLevel,
        blocked: intent.riskLevel === 'CRITICAL' || intent.riskLevel === 'HIGH',
        reason: intent.isDestructive ? 'Destructive cloud operation' : null,
      };
    }
    case 'kubernetes': {
      const { parseKubeCommand } = await import('../adapters/kubernetes/parser.js');
      const kube = parseKubeCommand(command);
      return {
        domain,
        operation: kube.verb,
        targets: [kube.resourceType, kube.resourceName].filter((v): v is string => v !== undefined),
        riskLevel: kube.riskLevel,
        blocked: kube.riskLevel === 'CRITICAL' || kube.riskLevel === 'HIGH',
        reason: kube.dangerousPatterns.join('; ') || null,
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
        blocked: intent.riskLevel === 'CRITICAL' || intent.riskLevel === 'HIGH',
        reason: intent.dangerousPatterns.map((p) => p.description).join('; ') || null,
      };
    }
    case 'api': {
      const { parseHttpRequest } = await import('../adapters/api/parser.js');
      const intent = parseHttpRequest(command);
      return {
        domain,
        operation: intent.method,
        targets: [`${intent.host}${intent.path}`],
        riskLevel: intent.riskLevel,
        blocked: intent.riskLevel === 'CRITICAL' || intent.riskLevel === 'HIGH',
        reason: intent.sensitiveFields.length > 0 ? intent.sensitiveFields.map((f) => f.field).join(', ') : null,
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
        blocked: intent.riskLevel === 'CRITICAL' || intent.riskLevel === 'HIGH',
        reason: intent.dangerousPatterns.map((p) => p.description).join('; ') || null,
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
        blocked: intent.riskLevel === 'CRITICAL' || intent.riskLevel === 'HIGH',
        reason: intent.dangerousPatterns.map((p) => p.description).join('; ') || null,
      };
    }
    case 'git': {
      const { parseGitCommand } = await import('../adapters/git/parser.js');
      const intent = parseGitCommand(command);
      return {
        domain,
        operation: intent.action,
        targets: intent.refs,
        riskLevel: intent.riskLevel,
        blocked: intent.riskLevel === 'CRITICAL' || intent.riskLevel === 'HIGH',
        reason: intent.isDestructive ? 'Destructive git operation' : null,
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
        blocked: intent.riskLevel === 'CRITICAL' || intent.riskLevel === 'HIGH',
        reason: intent.dangerousPatterns.map((p) => p.description).join('; ') || null,
      };
    }
    default:
      return {
        domain,
        operation: 'unknown' as const,
        targets: [] as string[],
        riskLevel: 'unknown' as RiskLevel,
        blocked: false,
        reason: 'No parser available for this domain' as string | null,
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
