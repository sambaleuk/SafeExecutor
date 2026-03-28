import type { RiskLevel } from '../../types/index.js';

export type CicdTool =
  | 'github-actions'
  | 'gitlab-ci'
  | 'jenkins'
  | 'docker'
  | 'docker-compose'
  | 'deploy-script'
  | 'unknown';

export type CicdAction =
  | 'build'
  | 'test'
  | 'lint'
  | 'deploy'
  | 'rollback'
  | 'push'
  | 'run'
  | 'compose-up'
  | 'compose-down'
  | 'trigger'
  | 'unknown';

export type TargetEnvironment =
  | 'local'
  | 'development'
  | 'staging'
  | 'preview'
  | 'production'
  | 'unknown';

export interface DangerousPattern {
  pattern: string;
  description: string;
  severity: 'HIGH' | 'CRITICAL' | 'DENY';
}

export interface ValidationResult {
  check: string;
  passed: boolean;
  message: string;
}

/**
 * Parsed CI/CD command intent — the TIntent type for SafeAdapter<ParsedCicdCommand, CicdSnapshot>.
 */
export interface ParsedCicdCommand {
  raw: string;
  tool: CicdTool;
  action: CicdAction;
  environment: TargetEnvironment;
  riskLevel: RiskLevel;
  isDestructive: boolean;
  imageTag?: string;
  registry?: string;
  /** True when the registry is known to be public (docker.io, ghcr.io, quay.io, etc.) */
  isPublicRegistry: boolean;
  /** False when image tag is "latest" or absent — version not pinned */
  hasSpecificTag: boolean;
  /** True when --force, --skip-checks, or similar flags are present */
  isForceDeployment: boolean;
  /** True when docker --privileged flag is present */
  isPrivileged: boolean;
  /** True when a root filesystem mount (-v /:/…) is detected */
  hasDangerousMount: boolean;
  dangerousPatterns: DangerousPattern[];
  parameters: Record<string, string>;
  flags: string[];
  metadata: Record<string, unknown>;
}

/**
 * Snapshot captured before execution — used by rollback().
 */
export interface CicdSnapshot {
  commandId: string;
  timestamp: Date;
  /** Serialized pre-execution state (last deployed version, container IDs, etc.) */
  preState: string;
}

export interface CicdRuleMatch {
  tools?: CicdTool[];
  actions?: CicdAction[];
  environments?: TargetEnvironment[];
  hasSpecificTag?: boolean;
  isForceDeployment?: boolean;
  isPrivileged?: boolean;
  hasDangerousMount?: boolean;
  isPublicRegistry?: boolean;
}

export interface CicdPolicyRule {
  id: string;
  description: string;
  match: CicdRuleMatch;
  action: 'allow' | 'deny' | 'require_approval' | 'require_dry_run';
  riskLevel: RiskLevel;
  message?: string;
}

export interface CicdPolicy {
  version: string;
  rules: CicdPolicyRule[];
  defaults: {
    allowUnknown: boolean;
    defaultRiskLevel: RiskLevel;
  };
}

export interface CicdPolicyDecision {
  allowed: boolean;
  riskLevel: RiskLevel;
  requiresDryRun: boolean;
  requiresApproval: boolean;
  matchedRules: CicdPolicyRule[];
  message: string;
}
