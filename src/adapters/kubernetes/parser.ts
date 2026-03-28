import type { SafeIntent, OperationType, RiskLevel, RiskFactor, Target, Scope } from '../../types/index.js';
import type { KubeIntent } from './types.js';
import { escalateRisk, getResourceRisk, getNamespaceEscalation, combineRisk } from './risk-matrix.js';

const KUBE_SYSTEM_NAMESPACES = new Set(['kube-system', 'kube-public', 'kube-node-lease']);
const READ_VERBS = new Set(['get', 'describe', 'logs', 'top', 'list', 'explain', 'version', 'cluster-info']);
const STORAGE_TYPES = new Set(['pv', 'pvc', 'persistentvolume', 'persistentvolumeclaim']);
const NS_ALIASES = new Set(['namespace', 'namespaces', 'ns']);

/**
 * Parse a raw kubectl or helm command into a structured KubeIntent.
 * Extracts tool, verb, resource type, resource name, namespace, flags,
 * and classifies the operation risk.
 */
export function parseKubeCommand(raw: string): KubeIntent {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('K8s Parser: empty command');

  const tokens = tokenize(trimmed);
  const tool = tokens[0];

  if (tool !== 'kubectl' && tool !== 'helm') {
    throw new Error(`K8s Parser: unsupported tool '${tool}'. Expected 'kubectl' or 'helm'.`);
  }

  const { positional, flags } = parseTokens(tokens.slice(1));
  const verb = positional[0] ?? '';

  let resourceType: string | undefined;
  let resourceName: string | undefined;
  const namespace = (flags['namespace'] ?? flags['n']) as string | undefined;

  if (tool === 'kubectl') {
    const resourceArg = positional[1];
    if (resourceArg !== undefined) {
      const slashIdx = resourceArg.indexOf('/');
      if (slashIdx !== -1) {
        // e.g. deployment/myapp
        resourceType = resourceArg.slice(0, slashIdx);
        resourceName = resourceArg.slice(slashIdx + 1);
      } else {
        resourceType = resourceArg;
        resourceName = positional[2];
      }
    }
  } else {
    // helm: positional[1] = release name
    resourceType = 'release';
    resourceName = positional[1];
  }

  const { riskLevel, dangerousPatterns } = classifyRisk(
    tool, verb, resourceType, resourceName, namespace, flags,
  );

  return {
    raw: trimmed,
    tool,
    verb,
    resourceType,
    resourceName,
    namespace,
    flags,
    riskLevel,
    isDangerous: riskLevel === 'HIGH' || riskLevel === 'CRITICAL',
    dangerousPatterns,
  };
}

/**
 * Convert a KubeIntent into a SafeExecutor ParsedIntent.
 *
 * Operation type mapping:
 *   READ (get, describe, logs, top)  → SELECT
 *   exec, port-forward               → SELECT  (HIGH risk via parser)
 *   apply, create                    → INSERT
 *   patch, edit, label, scale(>0)... → UPDATE
 *   scale --replicas=0               → TRUNCATE  (service blackout)
 *   delete (specific resource)       → DELETE
 *   delete namespace/pv, --all, drain→ DROP
 *   helm install                     → INSERT
 *   helm upgrade / rollback          → UPDATE
 *   helm uninstall                   → DROP
 *
 * The `tables` field stores the K8s resource path as `namespace/type/name`
 * so policy tablesPattern rules can match on namespace or resource type.
 */
export function toSafeIntent(intent: KubeIntent): SafeIntent {
  const type = mapToOperationType(intent);
  const resourcePath = buildResourcePath(intent);
  const tables = [resourcePath];
  const hasWhereClause = hasSpecificTarget(intent);
  const isDestructive = ['DELETE', 'DROP', 'TRUNCATE', 'ALTER'].includes(type);
  const isMassive = intent.dangerousPatterns.some((p) =>
    ['delete-all-flag', 'all-namespaces-delete', 'scale-to-zero', 'delete-no-target'].includes(p),
  );

  const target: Target = {
    name: resourcePath,
    type: intent.resourceType ?? 'resource',
    affectedResources: tables,
  };

  const scope: Scope = isMassive ? 'all' : 'single';

  const riskFactors: RiskFactor[] = buildKubeRiskFactors(intent, type, hasWhereClause, isMassive);

  return {
    domain: 'kubernetes',
    type,
    raw: intent.raw,
    target,
    scope,
    riskFactors,
    ast: intent,
    tables,
    hasWhereClause,
    estimatedRowsAffected: null,
    isDestructive,
    isMassive,
    metadata: {
      parsedAt: new Date().toISOString(),
      tool: intent.tool,
      verb: intent.verb,
      resourceType: intent.resourceType,
      resourceName: intent.resourceName,
      namespace: intent.namespace,
      flags: intent.flags,
      riskLevel: intent.riskLevel,
      dangerousPatterns: intent.dangerousPatterns,
    },
  };
}

function buildKubeRiskFactors(
  intent: KubeIntent,
  type: OperationType,
  hasSpecific: boolean,
  isMassive: boolean,
): RiskFactor[] {
  const factors: RiskFactor[] = [];
  const { dangerousPatterns, riskLevel } = intent;

  if (dangerousPatterns.includes('delete-namespace')) {
    factors.push({ code: 'DELETE_NAMESPACE', severity: 'CRITICAL', description: 'Deletes an entire Kubernetes namespace and all resources within it' });
  }
  if (dangerousPatterns.includes('delete-all-flag')) {
    factors.push({ code: 'DELETE_ALL_FLAG', severity: 'CRITICAL', description: '--all flag deletes all resources of the specified type in the namespace' });
  }
  if (dangerousPatterns.includes('all-namespaces-delete')) {
    factors.push({ code: 'ALL_NAMESPACES_DELETE', severity: 'CRITICAL', description: '--all-namespaces delete affects every namespace in the cluster' });
  }
  if (dangerousPatterns.includes('delete-no-target')) {
    factors.push({ code: 'DELETE_NO_TARGET', severity: 'CRITICAL', description: 'Delete without specific resource name, label selector, or field selector' });
  }
  if (dangerousPatterns.includes('scale-to-zero')) {
    factors.push({ code: 'SCALE_TO_ZERO', severity: 'CRITICAL', description: 'Scaling replicas to 0 causes a service outage' });
  }
  if (dangerousPatterns.includes('drain-node')) {
    factors.push({ code: 'DRAIN_NODE', severity: 'HIGH', description: 'Node drain evicts all pods and makes the node unschedulable' });
  }
  if (dangerousPatterns.includes('exec-command')) {
    factors.push({ code: 'EXEC_COMMAND', severity: 'HIGH', description: 'kubectl exec provides direct shell access inside a running container' });
  }
  if (dangerousPatterns.includes('helm-uninstall')) {
    factors.push({ code: 'HELM_UNINSTALL', severity: 'HIGH', description: 'Helm uninstall removes all Kubernetes resources managed by the release' });
  }
  if (dangerousPatterns.includes('kube-system-write')) {
    factors.push({ code: 'KUBE_SYSTEM_WRITE', severity: 'CRITICAL', description: 'Write to kube-system namespace can destabilize the cluster control plane' });
  }
  if (dangerousPatterns.includes('production-namespace') && riskLevel === 'CRITICAL') {
    factors.push({ code: 'PRODUCTION_WRITE', severity: 'CRITICAL', description: 'Destructive write operation targeting a production namespace' });
  } else if (dangerousPatterns.includes('production-namespace')) {
    factors.push({ code: 'PRODUCTION_NAMESPACE', severity: 'HIGH', description: 'Operation targets a production namespace' });
  }
  if (dangerousPatterns.includes('delete-storage')) {
    factors.push({ code: 'DELETE_STORAGE', severity: 'CRITICAL', description: 'Deletes a PersistentVolume or PersistentVolumeClaim — may cause permanent data loss' });
  }

  if (isMassive && factors.length === 0) {
    factors.push({ code: 'MASSIVE_OPERATION', severity: 'HIGH', description: 'Operation affects multiple or all resources of the target type' });
  }

  if (['DROP', 'DELETE'].includes(type) && !hasSpecific && factors.length === 0) {
    factors.push({ code: 'BROAD_DESTRUCTIVE_OP', severity: 'HIGH', description: 'Destructive operation without a specific target' });
  }

  return factors;
}

// ─── Tokenizer ───────────────────────────────────────────────────────────────

function tokenize(raw: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inQuote = false;
  let quoteChar = '';

  for (const ch of raw) {
    if (inQuote) {
      if (ch === quoteChar) {
        inQuote = false;
      } else {
        current += ch;
      }
    } else if (ch === '"' || ch === "'") {
      inQuote = true;
      quoteChar = ch;
    } else if (/\s/.test(ch)) {
      if (current) { tokens.push(current); current = ''; }
    } else {
      current += ch;
    }
  }
  if (current) tokens.push(current);
  return tokens;
}

function parseTokens(tokens: string[]): {
  positional: string[];
  flags: Record<string, string | boolean>;
} {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];

    if (token.startsWith('--')) {
      const eqIdx = token.indexOf('=');
      if (eqIdx !== -1) {
        flags[token.slice(2, eqIdx)] = token.slice(eqIdx + 1);
      } else {
        const next = tokens[i + 1];
        if (next !== undefined && !next.startsWith('-')) {
          flags[token.slice(2)] = next;
          i++;
        } else {
          flags[token.slice(2)] = true;
        }
      }
    } else if (token.startsWith('-') && token.length === 2) {
      const key = token.slice(1);
      const next = tokens[i + 1];
      if (next !== undefined && !next.startsWith('-')) {
        flags[key === 'n' ? 'namespace' : key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(token);
    }
  }

  return { positional, flags };
}

// ─── Risk Classification ─────────────────────────────────────────────────────

function classifyRisk(
  tool: 'kubectl' | 'helm',
  verb: string,
  resourceType: string | undefined,
  resourceName: string | undefined,
  namespace: string | undefined,
  flags: Record<string, string | boolean>,
): { riskLevel: RiskLevel; dangerousPatterns: string[] } {
  const patterns: string[] = [];

  let riskLevel: RiskLevel =
    tool === 'kubectl'
      ? classifyKubectlVerb(verb, resourceType, resourceName, flags, patterns)
      : classifyHelmVerb(verb, patterns);

  // Combine with resource-type base risk (for write operations)
  if (resourceType !== undefined && resourceType !== 'release' && !READ_VERBS.has(verb)) {
    riskLevel = combineRisk(riskLevel, getResourceRisk(resourceType));
  }

  // Namespace escalation
  if (namespace !== undefined) {
    const ns = namespace.toLowerCase();
    if (KUBE_SYSTEM_NAMESPACES.has(ns)) {
      // Reads on kube-system are safe; writes are always CRITICAL
      if (!READ_VERBS.has(verb)) {
        riskLevel = 'CRITICAL';
        patterns.push('kube-system-write');
      }
    } else {
      const escalation = getNamespaceEscalation(ns);
      if (escalation > 0) {
        riskLevel = escalateRisk(riskLevel, escalation);
        patterns.push('production-namespace');
      }
    }
  }

  return { riskLevel, dangerousPatterns: patterns };
}

function classifyKubectlVerb(
  verb: string,
  resourceType: string | undefined,
  resourceName: string | undefined,
  flags: Record<string, string | boolean>,
  patterns: string[],
): RiskLevel {
  if (READ_VERBS.has(verb)) return 'LOW';

  if (verb === 'exec') { patterns.push('exec-command'); return 'HIGH'; }
  if (verb === 'port-forward') return 'HIGH';

  if (verb === 'rollout') return 'MEDIUM';

  if (verb === 'scale') {
    const rep = flags['replicas'];
    if (rep === '0') { patterns.push('scale-to-zero'); return 'CRITICAL'; }
    return 'MEDIUM';
  }

  if (['apply', 'create', 'patch', 'edit', 'label', 'annotate', 'set'].includes(verb)) {
    return 'MEDIUM';
  }

  if (verb === 'delete') {
    return classifyDeleteRisk(resourceType, resourceName, flags, patterns);
  }

  if (verb === 'drain') { patterns.push('drain-node'); return 'HIGH'; }
  if (verb === 'cordon' || verb === 'taint') return 'HIGH';

  return 'MEDIUM';
}

function classifyDeleteRisk(
  resourceType: string | undefined,
  resourceName: string | undefined,
  flags: Record<string, string | boolean>,
  patterns: string[],
): RiskLevel {
  if (flags['all-namespaces'] === true) {
    patterns.push('all-namespaces-delete');
    return 'CRITICAL';
  }

  if (flags['all'] === true) {
    patterns.push('delete-all-flag');
    return 'CRITICAL';
  }

  if (resourceType !== undefined && NS_ALIASES.has(resourceType.toLowerCase())) {
    patterns.push('delete-namespace');
    return 'CRITICAL';
  }

  if (resourceType !== undefined && STORAGE_TYPES.has(resourceType.toLowerCase())) {
    patterns.push('delete-storage');
    return 'CRITICAL';
  }

  // No specific target and no label selector
  if (
    (resourceName === undefined || resourceName === '') &&
    flags['selector'] === undefined &&
    flags['l'] === undefined &&
    flags['field-selector'] === undefined
  ) {
    patterns.push('delete-no-target');
    return 'CRITICAL';
  }

  return 'HIGH';
}

function classifyHelmVerb(verb: string, patterns: string[]): RiskLevel {
  if (['list', 'status', 'get', 'history', 'search', 'show', 'version', 'template', 'lint'].includes(verb)) {
    return 'LOW';
  }
  if (['install', 'repo', 'pull', 'package'].includes(verb)) return 'MEDIUM';
  if (verb === 'upgrade') return 'MEDIUM';
  if (verb === 'rollback') return 'HIGH';
  if (verb === 'uninstall') { patterns.push('helm-uninstall'); return 'HIGH'; }
  return 'MEDIUM';
}

// ─── ParsedIntent Helpers ────────────────────────────────────────────────────

function mapToOperationType(intent: KubeIntent): OperationType {
  const { tool, verb, dangerousPatterns } = intent;

  if (tool === 'helm') {
    switch (verb) {
      case 'install': return 'INSERT';
      case 'upgrade': return 'UPDATE';
      case 'rollback': return 'UPDATE';
      case 'uninstall': return 'DROP';
      case 'list': case 'status': case 'get': case 'history': return 'SELECT';
      default: return 'UNKNOWN';
    }
  }

  // kubectl
  if (READ_VERBS.has(verb) || verb === 'exec' || verb === 'port-forward') return 'SELECT';

  switch (verb) {
    case 'apply': case 'create': return 'INSERT';
    case 'patch': case 'edit': case 'label': case 'annotate': case 'set': case 'rollout': return 'UPDATE';
    case 'scale': {
      const rep = intent.flags['replicas'];
      return rep === '0' ? 'TRUNCATE' : 'UPDATE';
    }
    case 'delete': {
      const isBroadDrop = dangerousPatterns.some((p) =>
        ['delete-namespace', 'delete-storage', 'delete-all-flag', 'all-namespaces-delete', 'delete-no-target'].includes(p),
      );
      return isBroadDrop ? 'DROP' : 'DELETE';
    }
    case 'drain': case 'cordon': case 'taint': return 'DROP';
    default: return 'UNKNOWN';
  }
}

/**
 * Build a resource path string: `namespace/resourceType/resourceName`
 * Wildcards (`*`) fill in unknown segments.
 * Used as the `tables` array in ParsedIntent so policy tablesPattern rules can match.
 */
function buildResourcePath(intent: KubeIntent): string {
  const ns = intent.namespace ?? '*';
  const type = intent.resourceType ?? '*';
  const name = intent.resourceName ?? '*';
  return `${ns}/${type}/${name}`;
}

/**
 * Whether the command targets a specific resource (analogous to SQL WHERE clause).
 * false = dangerously broad (delete --all, no name, etc.)
 */
function hasSpecificTarget(intent: KubeIntent): boolean {
  if (intent.resourceName !== undefined && intent.resourceName !== '') return true;
  if (intent.flags['selector'] !== undefined || intent.flags['l'] !== undefined) return true;
  if (intent.flags['field-selector'] !== undefined) return true;
  return false;
}
