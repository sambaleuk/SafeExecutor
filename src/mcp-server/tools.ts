/**
 * MCP Tool Definitions & Handlers
 *
 * Exposes SafeExecutor's capabilities as MCP tools:
 *   - safe_execute:     Run the full pipeline (parse → policy → sandbox → execute)
 *   - safe_analyze:     Analyze without executing (parse → policy)
 *   - safe_policy_check: Quick policy lookup (allow/deny/require_approval)
 *   - configure_policy:  Update policy rules at runtime
 */

import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { detectDomain, isValidDomain, type Domain } from './auto-detect.js';
import { evaluatePolicy } from '../core/policy-engine.js';
import type {
  Policy,
  PolicyRule,
  PolicyDecision,
  SafeIntent,
  RiskLevel,
} from '../types/index.js';

// ── Adapter parsers (imported statically to avoid full adapter instantiation) ─

import { buildCloudIntent } from '../adapters/cloud/parser.js';
import { parseIntent as parseFilesystem } from '../adapters/filesystem/parser.js';
import { parseKubeCommand, toSafeIntent as kubeToSafeIntent } from '../adapters/kubernetes/parser.js';
import { parseNetworkCommand } from '../adapters/network/parser.js';
import { parseCicdCommand } from '../adapters/cicd/parser.js';
import { parseSecretCommand } from '../adapters/secrets/parser.js';
import { parseHttpRequest } from '../adapters/api/parser.js';

// ── Tool Schemas ────────────────────────────────────────────────────────────

export const TOOL_DEFINITIONS = [
  {
    name: 'safe_execute',
    description:
      'Execute a command through the SafeExecutor pipeline. ' +
      'Parses intent, evaluates policy, runs sandbox simulation, and returns ' +
      'risk assessment with policy decision. Supports SQL, cloud (terraform/aws/gcloud/az), ' +
      'Kubernetes (kubectl/helm), filesystem (rm/cp/mv), CI/CD, API, secrets, git, network, queue.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        command: {
          type: 'string',
          description: 'The raw command to execute (e.g. "DELETE FROM users WHERE id = 1", "terraform destroy", "kubectl delete pod my-pod")',
        },
        domain: {
          type: 'string',
          description: 'Domain hint: sql, cloud, kubernetes, filesystem, cicd, api, secrets, git, network, queue. Auto-detected if omitted.',
          enum: ['sql', 'cloud', 'kubernetes', 'filesystem', 'cicd', 'api', 'secrets', 'git', 'network', 'queue'],
        },
      },
      required: ['command'],
    },
  },
  {
    name: 'safe_analyze',
    description:
      'Analyze a command WITHOUT executing it. Returns intent classification, ' +
      'risk level, risk factors, and policy decision (allow/deny/require_approval). ' +
      'Use this to pre-check commands before running them.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        command: {
          type: 'string',
          description: 'The raw command to analyze',
        },
        domain: {
          type: 'string',
          description: 'Domain hint. Auto-detected if omitted.',
          enum: ['sql', 'cloud', 'kubernetes', 'filesystem', 'cicd', 'api', 'secrets', 'git', 'network', 'queue'],
        },
      },
      required: ['command'],
    },
  },
  {
    name: 'safe_policy_check',
    description:
      'Quick policy check: will this command be allowed, denied, or require approval? ' +
      'Returns the policy decision without full analysis.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        command: {
          type: 'string',
          description: 'The raw command to check against policy',
        },
        domain: {
          type: 'string',
          description: 'Domain hint. Auto-detected if omitted.',
          enum: ['sql', 'cloud', 'kubernetes', 'filesystem', 'cicd', 'api', 'secrets', 'git', 'network', 'queue'],
        },
      },
      required: ['command'],
    },
  },
  {
    name: 'configure_policy',
    description:
      'Update SafeExecutor policy rules at runtime. Add, remove, or replace policy rules.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        action: {
          type: 'string',
          description: 'What to do: add a rule, remove a rule by id, replace all rules, or reset to defaults.',
          enum: ['add_rule', 'remove_rule', 'replace_all', 'reset'],
        },
        rule: {
          type: 'object',
          description: 'The policy rule to add (required for add_rule action)',
          properties: {
            id: { type: 'string' },
            description: { type: 'string' },
            match: {
              type: 'object',
              properties: {
                operationType: { type: 'array', items: { type: 'string' } },
                hasWhereClause: { type: 'boolean' },
                tablesPattern: { type: 'array', items: { type: 'string' } },
                minRowsAffected: { type: 'number' },
              },
            },
            action: { type: 'string', enum: ['allow', 'deny', 'require_approval', 'require_dry_run'] },
            riskLevel: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
            message: { type: 'string' },
          },
        },
        rule_id: {
          type: 'string',
          description: 'Rule ID to remove (required for remove_rule action)',
        },
        rules: {
          type: 'array',
          description: 'Complete rule set (required for replace_all action)',
        },
      },
      required: ['action'],
    },
  },
] as const;

// ── Runtime Policy State ────────────────────────────────────────────────────

const DEFAULT_POLICY: Policy = {
  version: '1.0.0',
  rules: [
    {
      id: 'deny-drop-table',
      description: 'Block all DROP TABLE operations',
      match: { operationType: ['DROP'] },
      action: 'deny',
      riskLevel: 'CRITICAL',
      message: 'DROP TABLE operations are blocked by default policy',
    },
    {
      id: 'deny-truncate',
      description: 'Block all TRUNCATE operations',
      match: { operationType: ['TRUNCATE'] },
      action: 'deny',
      riskLevel: 'CRITICAL',
      message: 'TRUNCATE operations are blocked by default policy',
    },
    {
      id: 'approval-delete-no-where',
      description: 'Require approval for DELETE without WHERE clause',
      match: { operationType: ['DELETE'], hasWhereClause: false },
      action: 'require_approval',
      riskLevel: 'HIGH',
      message: 'DELETE without WHERE clause requires human approval',
    },
    {
      id: 'dryrun-update-no-where',
      description: 'Require dry-run for UPDATE without WHERE clause',
      match: { operationType: ['UPDATE'], hasWhereClause: false },
      action: 'require_dry_run',
      riskLevel: 'HIGH',
      message: 'UPDATE without WHERE clause — dry-run required',
    },
    {
      id: 'approval-mass-operations',
      description: 'Require approval for operations affecting 1000+ rows',
      match: { minRowsAffected: 1000 },
      action: 'require_approval',
      riskLevel: 'HIGH',
      message: 'Mass operation (1000+ rows) requires human approval',
    },
  ],
  defaults: {
    allowUnknown: true,
    defaultRiskLevel: 'MEDIUM',
  },
};

let activePolicy: Policy = structuredClone(DEFAULT_POLICY);

export function getActivePolicy(): Policy {
  return activePolicy;
}

export function setActivePolicy(policy: Policy): void {
  activePolicy = policy;
}

// ── Intent Parsing ──────────────────────────────────────────────────────────

/**
 * Parse a raw command into a SafeIntent using the appropriate adapter parser.
 * Falls back to a generic intent if no adapter-specific parser is available.
 */
function parseCommandToIntent(command: string, domain: Domain): SafeIntent {
  switch (domain) {
    case 'sql':
      // SQL parsing is handled by node-sql-parser; we build a minimal SafeIntent
      return buildSqlIntent(command);

    case 'cloud':
      return cloudIntentToSafe(command);

    case 'kubernetes':
      return kubeToSafeIntent(parseKubeCommand(command));

    case 'filesystem':
      return filesystemIntentToSafe(command);

    case 'network':
      return networkIntentToSafe(command);

    case 'cicd':
      return cicdIntentToSafe(command);

    case 'secrets':
      return secretsIntentToSafe(command);

    case 'api':
      return apiIntentToSafe(command);

    case 'git':
      return buildGenericIntent(command, 'git');

    case 'queue':
      return buildGenericIntent(command, 'queue');
  }
}

// ── Adapter-to-SafeIntent Converters ────────────────────────────────────────

function buildSqlIntent(raw: string): SafeIntent {
  const upper = raw.trim().toUpperCase();
  const type = (['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'ALTER', 'DROP', 'CREATE'] as const)
    .find((t) => upper.startsWith(t)) ?? 'UNKNOWN';

  const hasWhereClause = /\bWHERE\b/i.test(raw);
  const isDestructive = ['DELETE', 'DROP', 'TRUNCATE'].includes(type);

  // Extract table names (simple heuristic)
  const tableMatches = raw.match(/(?:FROM|INTO|UPDATE|TABLE|JOIN)\s+([`"']?\w+[`"']?)/gi) ?? [];
  const tables = tableMatches.map((m) => m.replace(/^(?:FROM|INTO|UPDATE|TABLE|JOIN)\s+/i, '').replace(/[`"']/g, ''));

  return {
    domain: 'sql',
    type,
    raw,
    target: {
      name: tables[0] ?? 'unknown',
      type: 'table',
      affectedResources: tables,
    },
    scope: hasWhereClause ? 'single' : 'all',
    riskFactors: buildSqlRiskFactors(type, hasWhereClause),
    tables,
    hasWhereClause,
    estimatedRowsAffected: null,
    isDestructive,
    isMassive: !hasWhereClause && isDestructive,
    metadata: {},
  };
}

function buildSqlRiskFactors(type: string, hasWhere: boolean): SafeIntent['riskFactors'] {
  const factors: SafeIntent['riskFactors'] = [];
  if (['DELETE', 'DROP', 'TRUNCATE'].includes(type)) {
    factors.push({ code: 'DESTRUCTIVE_OP', severity: 'HIGH', description: `${type} is a destructive operation` });
  }
  if (['DELETE', 'UPDATE'].includes(type) && !hasWhere) {
    factors.push({ code: 'NO_WHERE_CLAUSE', severity: 'CRITICAL', description: `${type} without WHERE affects all rows` });
  }
  return factors;
}

function cloudIntentToSafe(raw: string): SafeIntent {
  const intent = buildCloudIntent(raw);
  const isDestructive = intent.actionType === 'DESTROY';
  const riskMap: Record<string, RiskLevel> = { LOW: 'LOW', MEDIUM: 'MEDIUM', HIGH: 'HIGH', CRITICAL: 'CRITICAL' };
  const riskLevel = riskMap[intent.riskLevel] ?? 'MEDIUM';

  return {
    domain: 'cloud',
    type: isDestructive ? 'DELETE' : intent.actionType === 'WRITE' ? 'UPDATE' : 'SELECT',
    raw,
    target: {
      name: intent.command.resources[0] ?? intent.command.service ?? 'unknown',
      type: intent.command.provider,
      affectedResources: intent.command.resources,
    },
    scope: intent.affectsAll ? 'all' : 'single',
    riskFactors: [{ code: `CLOUD_${intent.actionType}`, severity: riskLevel, description: `${intent.command.provider} ${intent.command.action}` }],
    ast: intent,
    tables: intent.command.resources,
    hasWhereClause: !intent.affectsAll,
    estimatedRowsAffected: null,
    isDestructive,
    isMassive: intent.affectsAll,
    metadata: { provider: intent.command.provider, service: intent.command.service },
  };
}

function filesystemIntentToSafe(raw: string): SafeIntent {
  const intent = parseFilesystem(raw);
  const destructiveOps = new Set(['rm', 'rmdir', 'unlink']);
  const isDestructive = destructiveOps.has(intent.command);
  const targets = intent.targetPaths;
  const isRecursive = intent.flags.some((f) => f.chars.includes('r') || f.chars.includes('recursive'));

  const riskFactors: SafeIntent['riskFactors'] = [];
  if (intent.isDenied) {
    riskFactors.push({ code: 'FS_DENIED', severity: 'CRITICAL', description: intent.denyReason ?? 'Denied by filesystem adapter' });
  }
  if (intent.hasGlobs) {
    riskFactors.push({ code: 'FS_GLOB_PATTERN', severity: 'HIGH', description: 'Command uses glob patterns' });
  }
  if (intent.hasVarExpansion) {
    riskFactors.push({ code: 'FS_VAR_EXPANSION', severity: 'HIGH', description: 'Command contains variable expansion' });
  }
  if (isDestructive) {
    riskFactors.push({ code: 'FS_DESTRUCTIVE', severity: 'HIGH', description: `${intent.command} is a destructive operation` });
  }

  return {
    domain: 'filesystem',
    type: isDestructive ? 'DELETE' : 'UPDATE',
    raw,
    target: {
      name: targets[0] ?? 'unknown',
      type: 'file',
      affectedResources: targets,
    },
    scope: isRecursive ? 'all' : 'single',
    riskFactors,
    ast: intent,
    tables: targets,
    hasWhereClause: true,
    estimatedRowsAffected: null,
    isDestructive,
    isMassive: intent.isDenied || intent.hasGlobs,
    metadata: { command: intent.command, flags: intent.flags.map((f) => f.raw) },
  };
}

function networkIntentToSafe(raw: string): SafeIntent {
  const intent = parseNetworkCommand(raw);
  const isDestructive = intent.isDestructive;
  const ifaces = intent.interface ? [intent.interface] : [];

  return {
    domain: 'network',
    type: isDestructive ? 'DELETE' : intent.action === 'configure' ? 'UPDATE' : 'SELECT',
    raw,
    target: {
      name: intent.tool,
      type: 'network',
      affectedResources: ifaces,
    },
    scope: intent.isFirewallDisable ? 'all' : 'single',
    riskFactors: intent.dangerousPatterns.map((p) => ({
      code: `NET_${p.pattern.toUpperCase().replace(/\s+/g, '_')}`,
      severity: (p.severity === 'DENY' ? 'CRITICAL' : p.severity) as RiskLevel,
      description: p.description,
    })),
    ast: intent,
    tables: [],
    hasWhereClause: true,
    estimatedRowsAffected: null,
    isDestructive,
    isMassive: intent.isFirewallDisable,
    metadata: { tool: intent.tool, action: intent.action },
  };
}

function cicdIntentToSafe(raw: string): SafeIntent {
  const intent = parseCicdCommand(raw);
  const isDestructive = intent.isDestructive;

  return {
    domain: 'cicd',
    type: isDestructive ? 'DELETE' : (intent.action === 'deploy' || intent.action === 'trigger') ? 'CREATE' : 'SELECT',
    raw,
    target: {
      name: intent.tool,
      type: 'pipeline',
      affectedResources: [],
    },
    scope: 'single',
    riskFactors: intent.dangerousPatterns.map((p) => ({
      code: `CICD_${p.pattern.toUpperCase().replace(/\s+/g, '_')}`,
      severity: (p.severity === 'DENY' ? 'CRITICAL' : p.severity) as RiskLevel,
      description: p.description,
    })),
    ast: intent,
    tables: [],
    hasWhereClause: true,
    estimatedRowsAffected: null,
    isDestructive,
    isMassive: false,
    metadata: { tool: intent.tool, action: intent.action, environment: intent.environment },
  };
}

function secretsIntentToSafe(raw: string): SafeIntent {
  const intent = parseSecretCommand(raw);
  const isDestructive = intent.action === 'delete';

  return {
    domain: 'secrets',
    type: isDestructive ? 'DELETE' : intent.action === 'write' ? 'UPDATE' : 'SELECT',
    raw,
    target: {
      name: intent.secretPath ?? intent.tool,
      type: 'secret',
      affectedResources: intent.secretPath ? [intent.secretPath] : [],
    },
    scope: intent.scope === 'global' ? 'all' : 'single',
    riskFactors: intent.dangerousPatterns.map((p) => ({
      code: `SECRET_${p.pattern.toUpperCase().replace(/\s+/g, '_')}`,
      severity: (p.severity === 'DENY' ? 'CRITICAL' : p.severity) as RiskLevel,
      description: p.description,
    })),
    ast: intent,
    tables: [],
    hasWhereClause: true,
    estimatedRowsAffected: null,
    isDestructive,
    isMassive: false,
    metadata: { tool: intent.tool, action: intent.action, scope: intent.scope },
  };
}

function apiIntentToSafe(raw: string): SafeIntent {
  const intent = parseHttpRequest(raw);
  const destructiveMethods = new Set(['DELETE', 'PUT', 'PATCH']);
  const isDestructive = destructiveMethods.has(intent.method);
  const url = `${intent.host}${intent.path}`;

  return {
    domain: 'api',
    type: intent.method === 'DELETE' ? 'DELETE' : intent.method === 'POST' ? 'INSERT' : 'SELECT',
    raw,
    target: {
      name: url,
      type: 'url',
      affectedResources: [url],
    },
    scope: intent.isBulk ? 'batch' : 'single',
    riskFactors: intent.sensitiveFields.map((s) => ({
      code: `API_SENSITIVE_${s.type.toUpperCase()}`,
      severity: s.sensitivity,
      description: `Sensitive data detected: ${s.type} in field '${s.field}'`,
    })),
    ast: intent,
    tables: [],
    hasWhereClause: true,
    estimatedRowsAffected: null,
    isDestructive,
    isMassive: intent.isBulk,
    metadata: { method: intent.method, url, host: intent.host, path: intent.path },
  };
}

function buildGenericIntent(raw: string, domain: string): SafeIntent {
  return {
    domain,
    type: 'UNKNOWN',
    raw,
    target: { name: 'unknown', type: domain, affectedResources: [] },
    scope: 'single',
    riskFactors: [],
    tables: [],
    hasWhereClause: true,
    estimatedRowsAffected: null,
    isDestructive: false,
    isMassive: false,
    metadata: {},
  };
}

// ── Tool Handlers ───────────────────────────────────────────────────────────

function resolveDomain(command: string, domainHint?: string): Domain {
  if (domainHint && isValidDomain(domainHint)) {
    return domainHint;
  }
  const detected = detectDomain(command);
  if (detected) {
    return detected.domain;
  }
  return 'filesystem'; // fallback to filesystem for unknown shell commands
}

function formatAnalysis(intent: SafeIntent, decision: PolicyDecision, domain: Domain): object {
  return {
    domain,
    operationType: intent.type,
    target: intent.target,
    scope: intent.scope,
    isDestructive: intent.isDestructive,
    isMassive: intent.isMassive,
    riskFactors: intent.riskFactors,
    policy: {
      allowed: decision.allowed,
      riskLevel: decision.riskLevel,
      requiresDryRun: decision.requiresDryRun,
      requiresApproval: decision.requiresApproval,
      matchedRules: decision.matchedRules.map((r) => r.id),
      message: decision.message,
    },
  };
}

export function handleSafeExecute(args: Record<string, unknown>): CallToolResult {
  const command = args.command as string;
  const domainHint = args.domain as string | undefined;
  const domain = resolveDomain(command, domainHint);

  try {
    const intent = parseCommandToIntent(command, domain);
    const decision = evaluatePolicy(intent, activePolicy);

    const analysis = formatAnalysis(intent, decision, domain);

    if (!decision.allowed) {
      return {
        content: [{ type: 'text', text: JSON.stringify({
          status: 'DENIED',
          reason: decision.message,
          ...analysis,
        }, null, 2) }],
        isError: false,
      };
    }

    if (decision.requiresApproval) {
      return {
        content: [{ type: 'text', text: JSON.stringify({
          status: 'REQUIRE_APPROVAL',
          reason: decision.message,
          ...analysis,
        }, null, 2) }],
        isError: false,
      };
    }

    // For the MCP server, we don't actually execute commands — we analyze and gate.
    // Execution would require adapter instantiation with credentials, which is
    // handled by the full SafeExecutor pipeline in the host application.
    return {
      content: [{ type: 'text', text: JSON.stringify({
        status: 'ALLOWED',
        riskLevel: decision.riskLevel,
        requiresDryRun: decision.requiresDryRun,
        ...analysis,
      }, null, 2) }],
      isError: false,
    };
  } catch (err) {
    return {
      content: [{ type: 'text', text: `Error analyzing command: ${err instanceof Error ? err.message : String(err)}` }],
      isError: true,
    };
  }
}

export function handleSafeAnalyze(args: Record<string, unknown>): CallToolResult {
  const command = args.command as string;
  const domainHint = args.domain as string | undefined;
  const domain = resolveDomain(command, domainHint);

  try {
    const intent = parseCommandToIntent(command, domain);
    const decision = evaluatePolicy(intent, activePolicy);

    return {
      content: [{ type: 'text', text: JSON.stringify(formatAnalysis(intent, decision, domain), null, 2) }],
      isError: false,
    };
  } catch (err) {
    return {
      content: [{ type: 'text', text: `Error analyzing command: ${err instanceof Error ? err.message : String(err)}` }],
      isError: true,
    };
  }
}

export function handleSafePolicyCheck(args: Record<string, unknown>): CallToolResult {
  const command = args.command as string;
  const domainHint = args.domain as string | undefined;
  const domain = resolveDomain(command, domainHint);

  try {
    const intent = parseCommandToIntent(command, domain);
    const decision = evaluatePolicy(intent, activePolicy);

    const status = !decision.allowed
      ? 'DENY'
      : decision.requiresApproval
        ? 'REQUIRE_APPROVAL'
        : 'ALLOW';

    return {
      content: [{ type: 'text', text: JSON.stringify({
        status,
        riskLevel: decision.riskLevel,
        message: decision.message,
      }, null, 2) }],
      isError: false,
    };
  } catch (err) {
    return {
      content: [{ type: 'text', text: `Error checking policy: ${err instanceof Error ? err.message : String(err)}` }],
      isError: true,
    };
  }
}

export function handleConfigurePolicy(args: Record<string, unknown>): CallToolResult {
  const action = args.action as string;

  switch (action) {
    case 'add_rule': {
      const rule = args.rule as PolicyRule | undefined;
      if (!rule || !rule.id) {
        return { content: [{ type: 'text', text: 'Error: rule with id is required for add_rule action' }], isError: true };
      }
      activePolicy.rules.push(rule);
      return {
        content: [{ type: 'text', text: JSON.stringify({ status: 'ok', message: `Rule '${rule.id}' added`, totalRules: activePolicy.rules.length }) }],
        isError: false,
      };
    }

    case 'remove_rule': {
      const ruleId = args.rule_id as string | undefined;
      if (!ruleId) {
        return { content: [{ type: 'text', text: 'Error: rule_id is required for remove_rule action' }], isError: true };
      }
      const before = activePolicy.rules.length;
      activePolicy.rules = activePolicy.rules.filter((r) => r.id !== ruleId);
      const removed = before - activePolicy.rules.length;
      return {
        content: [{ type: 'text', text: JSON.stringify({ status: 'ok', message: `Removed ${removed} rule(s) with id '${ruleId}'`, totalRules: activePolicy.rules.length }) }],
        isError: false,
      };
    }

    case 'replace_all': {
      const rules = args.rules as PolicyRule[] | undefined;
      if (!rules) {
        return { content: [{ type: 'text', text: 'Error: rules array is required for replace_all action' }], isError: true };
      }
      activePolicy.rules = rules;
      return {
        content: [{ type: 'text', text: JSON.stringify({ status: 'ok', message: `Policy replaced with ${rules.length} rules` }) }],
        isError: false,
      };
    }

    case 'reset': {
      activePolicy = structuredClone(DEFAULT_POLICY);
      return {
        content: [{ type: 'text', text: JSON.stringify({ status: 'ok', message: 'Policy reset to defaults', totalRules: activePolicy.rules.length }) }],
        isError: false,
      };
    }

    default:
      return { content: [{ type: 'text', text: `Error: unknown action '${action}'` }], isError: true };
  }
}
