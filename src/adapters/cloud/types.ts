// ─── Cloud Providers ─────────────────────────────────────────────────────────

export type CloudProvider = 'terraform' | 'aws' | 'gcloud' | 'az';

export type CloudRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/**
 * Semantic classification of what a cloud command does:
 *   READ         — describe, list, get, show, plan → no state change
 *   WRITE        — create, update, deploy, scale → adds or modifies resources
 *   DESTROY      — delete, terminate, destroy, rm → permanently removes resources
 *   STATE_MODIFY — terraform state rm/mv, taint → modifies infrastructure state file
 */
export type CloudActionType = 'READ' | 'WRITE' | 'DESTROY' | 'STATE_MODIFY';

// ─── Parsed Command ───────────────────────────────────────────────────────────

export interface CloudCommand {
  provider: CloudProvider;
  /** Provider-specific service or resource group (e.g. 'ec2', 'rds', 'compute:instances') */
  service: string;
  /** The action verb (e.g. 'terminate-instances', 'delete', 'apply') */
  action: string;
  /** Positional resource identifiers extracted from the command */
  resources: string[];
  /** Named flags (--key value or --key=value or --flag) */
  flags: Record<string, string | boolean>;
  raw: string;
}

// ─── Parsed Intent ────────────────────────────────────────────────────────────

export interface CloudIntent {
  raw: string;
  command: CloudCommand;
  riskLevel: CloudRiskLevel;
  actionType: CloudActionType;
  /** True if the command will permanently remove or alter resources */
  isDestructive: boolean;
  /**
   * True when a destructive command has no scope limiter.
   * Example: `terraform destroy` without `-target` destroys ALL resources.
   */
  affectsAll: boolean;
  metadata: Record<string, unknown>;
}

// ─── Snapshot (for rollback) ──────────────────────────────────────────────────

export interface CloudSnapshot {
  /** Unique command execution ID */
  commandId: string;
  timestamp: Date;
  /** Serialized resource state captured before execution (JSON or describe output) */
  resourceState: string;
}
