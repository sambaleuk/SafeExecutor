import type { RiskLevel } from '../../types/index.js';

/**
 * Base risk level per Kubernetes resource type.
 * This is the minimum risk for any write/delete operation on that resource.
 */
export const RESOURCE_RISK: Record<string, RiskLevel> = {
  // Cluster-scoped — catastrophic if deleted
  namespace: 'CRITICAL',
  ns: 'CRITICAL',
  pv: 'CRITICAL',
  persistentvolume: 'CRITICAL',
  node: 'HIGH',
  clusterrole: 'HIGH',
  clusterrolebinding: 'HIGH',

  // Namespace-scoped workloads
  deployment: 'HIGH',
  statefulset: 'HIGH',
  daemonset: 'HIGH',
  replicaset: 'MEDIUM',

  // Storage
  pvc: 'CRITICAL',
  persistentvolumeclaim: 'CRITICAL',

  // Networking
  service: 'MEDIUM',
  ingress: 'MEDIUM',
  networkpolicy: 'MEDIUM',

  // Batch
  job: 'MEDIUM',
  cronjob: 'MEDIUM',

  // Config / secrets
  configmap: 'LOW',
  secret: 'MEDIUM',
  serviceaccount: 'LOW',

  // RBAC
  role: 'MEDIUM',
  rolebinding: 'MEDIUM',

  // Pods (direct pod ops are fragile)
  pod: 'MEDIUM',

  // Helm release (treated as a single deployable unit)
  release: 'HIGH',
};

/**
 * How many risk levels to escalate for operations in a given namespace.
 * 99 = force to CRITICAL (kube-system writes are always CRITICAL).
 */
export const NAMESPACE_ESCALATION: Record<string, number> = {
  'kube-system': 99,
  'kube-public': 99,
  'kube-node-lease': 99,
  'production': 2,
  'prod': 2,
  'staging': 1,
  'development': 0,
  'dev': 0,
};

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

/** Return the higher of two risk levels. */
export function combineRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

/** Escalate a risk level by N steps, capped at CRITICAL. */
export function escalateRisk(base: RiskLevel, levels: number): RiskLevel {
  const idx = RISK_ORDER.indexOf(base);
  return RISK_ORDER[Math.min(idx + levels, RISK_ORDER.length - 1)];
}

/** Look up the base risk for a resource type (default: MEDIUM). */
export function getResourceRisk(resourceType: string): RiskLevel {
  return RESOURCE_RISK[resourceType.toLowerCase()] ?? 'MEDIUM';
}

/** Number of risk levels to add for a given namespace (0 if unknown). */
export function getNamespaceEscalation(namespace: string): number {
  return NAMESPACE_ESCALATION[namespace.toLowerCase()] ?? 0;
}
