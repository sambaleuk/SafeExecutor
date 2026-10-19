/**
 * MCP Tool handlers for SafeExecutor.
 * These tools parse + classify commands but do NOT execute them.
 *
 * Fail-closed: a command is only ALLOWED when every simple command it would
 * run was recognized by a domain parser and classified below HIGH. Unknown
 * commands, parser errors and unanalyzable shell constructs are BLOCKED.
 */

import { detectDomain } from './auto-detect.js';
import { extractSegments } from './command-segments.js';
import type { CommandSegment } from './command-segments.js';
import type { RiskLevel, RiskFactor } from '../types/index.js';

interface Analysis {
  domain: string;
  operation: string;
  targets: string[];
  riskLevel: RiskLevel;
  blocked: boolean;
  reason: string | null;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function maxRisk(factors: RiskFactor[]): RiskLevel {
  return factors.reduce<RiskLevel>((max, f) => {
    return RISK_ORDER.indexOf(f.severity) > RISK_ORDER.indexOf(max) ? f.severity : max;
  }, 'LOW');
}

function blockedAnalysis(domain: string, reason: string): Analysis {
  return { domain, operation: 'unknown', targets: [], riskLevel: 'HIGH', blocked: true, reason };
}

/** Blocked beats allowed, then higher risk wins; ties keep the earlier entry. */
function riskiest(analyses: Analysis[]): Analysis {
  return analyses.reduce((worst, a) => {
    if (a.blocked !== worst.blocked) return a.blocked ? a : worst;
    return RISK_ORDER.indexOf(a.riskLevel) > RISK_ORDER.indexOf(worst.riskLevel) ? a : worst;
  });
}

// ─── Lazy parser imports ─────────────────────────────────────────────────────

async function parseWithDomain(command: string, domain: string): Promise<Analysis> {
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
      return blockedAnalysis(domain, 'No parser available for this domain: blocked by default (fail-closed)');
  }
}

async function analyzeWithDomain(command: string, domain: string): Promise<Analysis> {
  try {
    return await parseWithDomain(command, domain);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return blockedAnalysis(domain, `The ${domain} parser could not analyze this command: ${message}`);
  }
}

/**
 * The auto-detected domain is always evaluated. A caller-supplied domain is
 * evaluated in addition, so it can add scrutiny but never lower the verdict.
 */
async function analyzeSegment(segment: CommandSegment, domainOverride?: string): Promise<Analysis> {
  if (segment.blockedReason) return blockedAnalysis('unknown', segment.blockedReason);

  const detected = segment.domain ?? detectDomain(segment.command);
  const domains = domainOverride && domainOverride !== detected ? [domainOverride, detected] : [detected];
  return riskiest(await Promise.all(domains.map((d) => analyzeWithDomain(segment.command, d))));
}

async function analyzeCommand(command: string, domainOverride?: string, asShell = false) {
  // SQL text is not a shell command line: `||` is string concatenation and
  // `;` separates statements, which the SQL parser evaluates itself. Input
  // known to be a shell command (asShell) is always segmented.
  const segments: CommandSegment[] =
    !asShell && detectDomain(command) === 'sql'
      ? [{ command: command.trim(), domain: 'sql' }]
      : extractSegments(command ?? '');

  if (segments.length === 0) {
    return { ...blockedAnalysis('unknown', 'Empty command'), segments: [] };
  }

  const analyses = await Promise.all(segments.map((s) => analyzeSegment(s, domainOverride)));
  return {
    ...riskiest(analyses),
    segments: segments.map((s, i) => {
      const { domain, riskLevel, blocked, reason } = analyses[i] as Analysis;
      return { command: s.command, domain, riskLevel, blocked, reason };
    }),
  };
}

/** Analysis of a command line that will be run by a shell (e.g. Claude Code's Bash tool). */
export async function analyzeShellCommand(command: string) {
  return analyzeCommand(command, undefined, true);
}

// ─── Tool Handlers ───────────────────────────────────────────────────────────

export async function safeExecute(command: string, domain?: string) {
  const result = await analyzeCommand(command, domain);
  return {
    ...result,
    policy_decision: result.blocked ? 'BLOCKED' : 'ALLOWED',
  };
}

export async function safeAnalyze(command: string, domain?: string) {
  const result = await analyzeCommand(command, domain);
  return {
    ...result,
    policy_decision: result.blocked ? 'BLOCKED' : 'ALLOWED',
    note: 'Analysis only — no execution performed',
  };
}

export async function safePolicyCheck(command: string) {
  const result = await analyzeCommand(command);
  return {
    allowed: !result.blocked,
    risk: result.riskLevel,
    domain: result.domain,
    reason: result.reason ?? (result.blocked ? 'High-risk operation blocked by policy' : 'Operation is within safe thresholds'),
  };
}
