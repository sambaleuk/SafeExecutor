// ─── Secret Tool ─────────────────────────────────────────────────────────────

export type SecretTool =
  | 'vault'
  | 'aws-secrets-manager'
  | 'aws-ssm'
  | 'gcp-secret-manager'
  | 'azure-key-vault'
  | 'kubernetes'
  | 'docker'
  | 'env'
  | 'unknown';

// ─── Secret Action ───────────────────────────────────────────────────────────

export type SecretAction = 'read' | 'write' | 'delete' | 'list' | 'rotate';

// ─── Environment ─────────────────────────────────────────────────────────────

export type SecretEnvironment = 'production' | 'staging' | 'development' | 'unknown';

// ─── Parsed Command ──────────────────────────────────────────────────────────

export interface ParsedSecretCommand {
  raw: string;
  tool: SecretTool;
  action: SecretAction;
  secretPath: string;
  version?: string;
  environment: SecretEnvironment;
  isWildcard: boolean;
  hasPlaintextSecret: boolean;
  isRawOutput: boolean;
  metadata: Record<string, unknown>;
}

// ─── Leak Detection ──────────────────────────────────────────────────────────

export interface LeakPattern {
  name: string;
  pattern: RegExp;
  severity: 'HIGH' | 'CRITICAL';
}

export interface LeakDetectionResult {
  hasLeak: boolean;
  patterns: string[];
  masked: string;
  isExfiltration: boolean;
}

// ─── Sandbox ─────────────────────────────────────────────────────────────────

export interface SecretSandboxOutcome {
  feasible: boolean;
  secretExists: boolean;
  dependentsCount: number;
  validationErrors: string[];
  plan: string;
  durationMs: number;
}

// ─── Adapter Options ─────────────────────────────────────────────────────────

export interface SecretsAdapterOptions {
  /**
   * When true (default), commands are validated and audited but never executed.
   * Set to false only when CLI tools (vault, aws, gcloud, az, kubectl) are available.
   */
  dryRunOnly?: boolean;

  /**
   * Allowlist of secret path prefixes. If set, only paths matching these prefixes are permitted.
   */
  allowedPaths?: string[];

  /**
   * Blocklist of secret path prefixes. Commands targeting these paths are denied.
   */
  blockedPaths?: string[];

  /**
   * Override environment classification for all operations (e.g. force 'production' for extra caution).
   */
  environment?: SecretEnvironment;
}
