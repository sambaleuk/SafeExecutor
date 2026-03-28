// ─── Operation Types ────────────────────────────────────────────────────────

/**
 * SQL-specific operation types (used by current policy rules).
 * Phase 1 will generalize these to domain-agnostic types (read/write/destroy/…).
 */
export type OperationType =
  | 'SELECT'
  | 'INSERT'
  | 'UPDATE'
  | 'DELETE'
  | 'TRUNCATE'
  | 'ALTER'
  | 'DROP'
  | 'CREATE'
  | 'UNKNOWN';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ApprovalStatus = 'auto_approved' | 'pending' | 'approved' | 'rejected';

export type ExecutionStatus = 'success' | 'rolled_back' | 'failed' | 'dry_run';

// ─── SafeIntent v2 Types ─────────────────────────────────────────────────────

/**
 * Scope of the operation — how many resources are targeted.
 */
export type Scope = 'single' | 'batch' | 'all';

/**
 * A structured reference to the primary resource being operated on.
 */
export interface Target {
  /** Primary resource name (table name, file path, bucket, endpoint, etc.) */
  name: string;
  /** Resource type in the domain ('table', 'file', 's3_bucket', 'url', 'pipeline') */
  type: string;
  /** All resources touched, including secondary ones (joins, dependencies) */
  affectedResources: string[];
  /** Row/item count estimate (filled by sandbox layer) */
  estimatedCount?: number;
}

/**
 * An explicit risk signal extracted by the adapter during intent parsing.
 * Risk factors drive policy decisions and approval routing.
 */
export interface RiskFactor {
  /** Machine-readable risk code (e.g. 'NO_WHERE_CLAUSE', 'DESTRUCTIVE_OP') */
  code: string;
  severity: RiskLevel;
  description: string;
}

// ─── SafeIntent ──────────────────────────────────────────────────────────────

/**
 * Universal intent format — the lingua franca between the pipeline and adapters.
 *
 * Every adapter (SQL, cloud, filesystem, API, CI/CD) must produce a SafeIntent.
 * The pipeline core and policy engine only operate on SafeIntent fields.
 *
 * Backward-compat fields (type, tables, hasWhereClause, …) match the old
 * ParsedIntent interface so the policy engine and approval gate work unchanged.
 */
export interface SafeIntent {
  // ── Identity ──────────────────────────────────────────────────────────────
  /** Domain identifier: 'sql', 'cloud', 'filesystem', 'api', 'cicd', … */
  domain: string;
  /** Operation classification (currently SQL-specific; Phase 1 makes this generic) */
  type: OperationType;
  /** Raw, unmodified input string */
  raw: string;

  // ── Target & Scope ────────────────────────────────────────────────────────
  target: Target;
  scope: Scope;

  // ── Risk Signals ──────────────────────────────────────────────────────────
  /** Explicit risk factors extracted by the adapter parser */
  riskFactors: RiskFactor[];

  // ── Domain-Specific AST ───────────────────────────────────────────────────
  /** Domain-specific parsed representation (opaque to the pipeline core) */
  ast?: unknown;

  // ── Backward-Compatible Fields (policy engine + approval gate) ────────────
  /** All table/resource names touched (flattened from target.affectedResources) */
  tables: string[];
  hasWhereClause: boolean;
  /** Filled by the sandbox layer after dry-run simulation */
  estimatedRowsAffected: number | null;
  isDestructive: boolean;
  /** True if the operation could affect a massive number of rows/resources */
  isMassive: boolean;
  metadata: Record<string, unknown>;
}

/**
 * Backward-compatibility alias.
 * @deprecated Use SafeIntent directly. ParsedIntent will be removed in v3.
 */
export type ParsedIntent = SafeIntent;

// ─── Policy ─────────────────────────────────────────────────────────────────

export interface PolicyRule {
  id: string;
  description: string;
  match: {
    operationType?: OperationType[];
    hasWhereClause?: boolean;
    tablesPattern?: string[];
    minRowsAffected?: number;
  };
  action: 'allow' | 'deny' | 'require_approval' | 'require_dry_run';
  riskLevel: RiskLevel;
  message?: string;
}

export interface Policy {
  version: string;
  rules: PolicyRule[];
  defaults: {
    allowUnknown: boolean;
    defaultRiskLevel: RiskLevel;
  };
}

export interface PolicyDecision {
  allowed: boolean;
  riskLevel: RiskLevel;
  requiresDryRun: boolean;
  requiresApproval: boolean;
  matchedRules: PolicyRule[];
  message: string;
}

// ─── Sandbox ─────────────────────────────────────────────────────────────────

export interface SandboxResult {
  feasible: boolean;
  estimatedRowsAffected: number;
  executionPlan: string;
  warnings: string[];
  durationMs: number;
}

// ─── Approval ────────────────────────────────────────────────────────────────

export interface ApprovalRequest {
  id: string;
  operation: SafeIntent;
  riskLevel: RiskLevel;
  sandboxResult: SandboxResult | null;
  requestedAt: Date;
  requestedBy: string;
  reason?: string;
}

export interface ApprovalResponse {
  requestId: string;
  status: ApprovalStatus;
  approvedBy?: string;
  approvedAt?: Date;
  comment?: string;
}

// ─── Execution ───────────────────────────────────────────────────────────────

export interface ExecutionResult {
  status: ExecutionStatus;
  rowsAffected: number;
  durationMs: number;
  savepointUsed: boolean;
  rolledBack: boolean;
  rollbackReason?: string;
  error?: string;
}

// ─── Audit ───────────────────────────────────────────────────────────────────

export interface AuditEntry {
  id: string;
  timestamp: Date;
  executor: string;
  operation: SafeIntent;
  policyDecision: PolicyDecision;
  sandboxResult: SandboxResult | null;
  approvalResponse: ApprovalResponse | null;
  executionResult: ExecutionResult | null;
  totalDurationMs: number;
  environment: string;
  tags: string[];
}

// ─── Config ──────────────────────────────────────────────────────────────────

export interface SafeExecutorConfig {
  version: string;
  environment: string;
  executor: string;
  database: {
    adapter: 'postgres' | 'mysql' | 'sqlite';
    connectionString: string;
    schema?: string;
    allowedTables?: string[];
    blockedTables?: string[];
    maxRowsThreshold: number;
  };
  policy: {
    file: string;
    strictMode: boolean;
  };
  approval: {
    mode: 'cli' | 'webhook' | 'auto';
    webhookUrl?: string;
    timeoutSeconds: number;
  };
  audit: {
    enabled: boolean;
    output: 'console' | 'file' | 'database';
    filePath?: string;
    retentionDays?: number;
  };
}

// ─── Pipeline ────────────────────────────────────────────────────────────────

export interface PipelineContext {
  config: SafeExecutorConfig;
  sql: string;
  intent: SafeIntent | null;
  policyDecision: PolicyDecision | null;
  sandboxResult: SandboxResult | null;
  approvalResponse: ApprovalResponse | null;
  executionResult: ExecutionResult | null;
  auditEntry: Partial<AuditEntry>;
  startedAt: Date;
}

export interface PipelineResult {
  success: boolean;
  executionResult: ExecutionResult | null;
  auditEntry: AuditEntry;
  abortedAt?: string;
  abortReason?: string;
}
