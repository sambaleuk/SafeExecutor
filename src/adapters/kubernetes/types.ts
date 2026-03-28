import type { RiskLevel } from '../../types/index.js';

export type KubeTool = 'kubectl' | 'helm';

/**
 * Parsed representation of a kubectl or helm command.
 */
export interface KubeIntent {
  raw: string;
  tool: KubeTool;
  verb: string;
  resourceType?: string;
  resourceName?: string;
  namespace?: string;
  flags: Record<string, string | boolean>;
  riskLevel: RiskLevel;
  isDangerous: boolean;
  dangerousPatterns: string[];
}

/**
 * Snapshot of a Kubernetes resource captured before execution.
 * Used to restore state on rollback.
 */
export interface ResourceSnapshot {
  id: string;
  namespace: string;
  resourceType: string;
  resourceName: string;
  manifest: string;
  capturedAt: Date;
}
