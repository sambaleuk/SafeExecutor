export { KubernetesAdapter } from './adapter.js';
export type { KubernetesAdapterOptions } from './adapter.js';
export { parseKubeCommand, toSafeIntent } from './parser.js';
export { runKubeSandbox } from './sandbox.js';
export { RESOURCE_RISK, NAMESPACE_ESCALATION, getResourceRisk, getNamespaceEscalation } from './risk-matrix.js';
export type { KubeIntent, ResourceSnapshot } from './types.js';
