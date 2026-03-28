import type { RiskLevel } from '../../types/index.js';

export type SecretTool =
  | 'vault'
  | 'aws-secrets'
  | 'aws-ssm'
  | 'gcloud-secrets'
  | 'az-keyvault'
  | 'kubectl-secrets'
  | 'docker-secrets'
  | 'env-export'
  | 'unknown';

export type SecretAction =
  | 'read'
  | 'write'
  | 'delete'
  | 'list'
  | 'rotate'
  | 'export'
  | 'create'
  | 'unknown';

export type SecretScope =
  | 'single'
  | 'namespace'
  | 'global'
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
 * Parsed secrets command intent — TIntent for SafeAdapter<ParsedSecretCommand, SecretSnapshot>.
 */
export interface ParsedSecretCommand {
  raw: string;
  tool: SecretTool;
  action: SecretAction;
  scope: SecretScope;
  riskLevel: RiskLevel;
  isDestructive: boolean;
  /** Secret path/key being targeted */
  secretPath?: string;
  /** Namespace or project context */
  namespace?: string;
  /** True when the command would expose a secret value in stdout */
  exposesValue: boolean;
  /** True when the command writes/overwrites an existing secret */
  isOverwrite: boolean;
  /** True when the command targets production secrets */
  isProduction: boolean;
  /** True when the command uses --force or equivalent */
  isForce: boolean;
  /** Detected dangerous patterns */
  dangerousPatterns: DangerousPattern[];
  parameters: Record<string, string>;
  flags: string[];
  metadata: Record<string, unknown>;
}

/**
 * Result of scanning a string for leaked secrets.
 */
export interface LeakDetectionResult {
  hasLeaks: boolean;
  leaks: DetectedLeak[];
  maskedValue: string;
}

export interface DetectedLeak {
  type: LeakType;
  value: string;
  masked: string;
  position: { start: number; end: number };
}

export type LeakType =
  | 'aws-access-key'
  | 'aws-secret-key'
  | 'github-pat'
  | 'github-oauth'
  | 'jwt'
  | 'private-key'
  | 'generic-api-key'
  | 'generic-secret';

/**
 * Snapshot captured before execution — used by rollback().
 */
export interface SecretSnapshot {
  commandId: string;
  timestamp: Date;
  /** Previous secret version or value hash (never the actual value) */
  previousVersionId?: string;
  preState: string;
}

export interface SecretRuleMatch {
  tools?: SecretTool[];
  actions?: SecretAction[];
  scopes?: SecretScope[];
  exposesValue?: boolean;
  isOverwrite?: boolean;
  isProduction?: boolean;
  isForce?: boolean;
}

export interface SecretPolicyRule {
  id: string;
  description: string;
  match: SecretRuleMatch;
  action: 'allow' | 'deny' | 'require_approval' | 'require_dry_run';
  riskLevel: RiskLevel;
  message?: string;
}

export interface SecretPolicy {
  version: string;
  rules: SecretPolicyRule[];
  defaults: {
    allowUnknown: boolean;
    defaultRiskLevel: RiskLevel;
  };
}

export interface SecretPolicyDecision {
  allowed: boolean;
  riskLevel: RiskLevel;
  requiresDryRun: boolean;
  requiresApproval: boolean;
  matchedRules: SecretPolicyRule[];
  message: string;
}
