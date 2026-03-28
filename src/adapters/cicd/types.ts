import type { RiskLevel } from '../../types/index.js';
import type { SafeParsedCommand, SafePolicyDecision, SafeSandboxResult, SafeExecutionResult } from '../../core/types.js';

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

/**
 * Parsed representation of a CI/CD command.
 * Extends SafeParsedCommand so it's compatible with SafeAdapterResult.parsed.
 */
export interface ParsedCicdCommand extends SafeParsedCommand {
  tool: CicdTool;
  action: CicdAction;
  environment: TargetEnvironment;
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

export interface ValidationResult {
  check: string;
  passed: boolean;
  message: string;
}

export interface CicdSandboxResult extends SafeSandboxResult {
  validations: ValidationResult[];
}

export type CicdPolicyDecision = SafePolicyDecision & {
  matchedRules: CicdPolicyRule[];
};

export type CicdExecutionResult = SafeExecutionResult;
