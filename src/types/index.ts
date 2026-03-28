// ─── Operation Types ────────────────────────────────────────────────────────

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

// ─── Parsed Intent ──────────────────────────────────────────────────────────

export interface ParsedIntent {
  raw: string;
  type: OperationType;
  tables: string[];
  hasWhereClause: boolean;
  estimatedRowsAffected: number | null;
  isDestructive: boolean;
  isMassive: boolean;
  metadata: Record<string, unknown>;
}

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
  operation: ParsedIntent;
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
  operation: ParsedIntent;
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
  intent: ParsedIntent | null;
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
