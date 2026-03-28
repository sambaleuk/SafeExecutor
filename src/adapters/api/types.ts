import type { RiskLevel } from '../../types/index.js';

// ─── HTTP Method ─────────────────────────────────────────────────────────────

export type HttpMethod =
  | 'GET'
  | 'HEAD'
  | 'OPTIONS'
  | 'POST'
  | 'PUT'
  | 'PATCH'
  | 'DELETE'
  | 'UNKNOWN';

// ─── Endpoint Classification ─────────────────────────────────────────────────

export type EndpointCategory =
  | 'payment'   // /charges, /payments, /transfers, /invoices, /subscriptions
  | 'auth'      // /tokens, /sessions, /oauth, /login, /auth
  | 'admin'     // /admin, /internal, /management
  | 'bulk'      // /batch, /bulk, /import, /export
  | 'standard'; // everything else

export type SensitiveFieldType = 'credential' | 'pii' | 'financial' | 'token';

// ─── Sensitive Data ───────────────────────────────────────────────────────────

export interface SensitiveDataMatch {
  field: string;
  type: SensitiveFieldType;
  /** Risk level of this sensitive data match */
  sensitivity: RiskLevel;
  /** Value with characters replaced for audit logging */
  maskedValue: string;
}

// ─── Parsed HTTP Request ──────────────────────────────────────────────────────

export interface ParsedHttpRequest {
  /** Original raw input (curl command or URL string) */
  raw: string;
  method: HttpMethod;
  host: string;
  path: string;
  queryParams: Record<string, string>;
  /** Lowercased header names */
  headers: Record<string, string>;
  body: Record<string, unknown> | null;
  endpointCategory: EndpointCategory;
  riskLevel: RiskLevel;
  isDestructive: boolean;
  isBulk: boolean;
  /** Number of items in batch payload, or null if not a batch */
  itemCount: number | null;
  sensitiveFields: SensitiveDataMatch[];
  metadata: Record<string, unknown>;
}

// ─── API Policy ───────────────────────────────────────────────────────────────

export interface ApiPolicyRule {
  id: string;
  description: string;
  match: {
    methods?: HttpMethod[];
    /** Regex pattern matched against the request path */
    pathPattern?: string;
    /** Regex pattern matched against the request host */
    hostPattern?: string;
    endpointCategory?: EndpointCategory[];
    /** Minimum item count for bulk matching */
    minItemCount?: number;
    /** Whether the URL has credentials in query params */
    hasCredentialsInUrl?: boolean;
  };
  action: 'allow' | 'deny' | 'require_approval' | 'require_dry_run';
  riskLevel: RiskLevel;
  message?: string;
}

export interface ApiPolicy {
  version: string;
  rules: ApiPolicyRule[];
  defaults: {
    allowUnknown: boolean;
    defaultRiskLevel: RiskLevel;
    /** If defined, requests to hosts not in this list are denied */
    allowedHosts?: string[];
    /** Financial amounts above this threshold escalate to CRITICAL */
    maxFinancialAmount?: number;
  };
}

// ─── Policy Decision ──────────────────────────────────────────────────────────

export interface ApiPolicyDecision {
  allowed: boolean;
  riskLevel: RiskLevel;
  requiresDryRun: boolean;
  requiresApproval: boolean;
  matchedRules: ApiPolicyRule[];
  message: string;
  blockedByHostWhitelist: boolean;
}

// ─── Rate Limiting ────────────────────────────────────────────────────────────

export interface RateLimitConfig {
  requestsPerMinute: number;
  burstSize: number;
}

export interface RateLimitStatus {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
}

// ─── Sandbox ──────────────────────────────────────────────────────────────────

export interface ApiSandboxResult {
  feasible: boolean;
  /** The request that WOULD be sent (not actually sent) */
  wouldSend: {
    method: HttpMethod;
    url: string;
    headers: Record<string, string>;
    body: Record<string, unknown> | null;
  };
  warnings: string[];
  rateLimitStatus: RateLimitStatus;
  schemaValidation: {
    valid: boolean;
    errors: string[];
  };
  durationMs: number;
}

// ─── Execution ────────────────────────────────────────────────────────────────

export interface ApiExecutionResult {
  status: 'success' | 'dry_run' | 'denied' | 'failed' | 'rate_limited';
  httpStatus?: number;
  responseBody?: unknown;
  durationMs: number;
  error?: string;
  rateLimited: boolean;
}

// ─── Audit ────────────────────────────────────────────────────────────────────

export interface ApiAuditEntry {
  id: string;
  timestamp: Date;
  executor: string;
  request: ParsedHttpRequest;
  policyDecision: ApiPolicyDecision;
  sandboxResult: ApiSandboxResult | null;
  executionResult: ApiExecutionResult | null;
  totalDurationMs: number;
  environment: string;
}

// ─── Pipeline Result ──────────────────────────────────────────────────────────

export interface ApiPipelineResult {
  success: boolean;
  executionResult: ApiExecutionResult | null;
  auditEntry: ApiAuditEntry;
  abortedAt?: string;
  abortReason?: string;
}

// ─── Adapter Config ───────────────────────────────────────────────────────────

export interface ApiAdapterConfig {
  /** Adapter name for audit records */
  name?: string;
  /** Environment label (e.g. staging, production) */
  environment?: string;
  /** Executor identifier for audit records */
  executor?: string;
  /** Whitelist of allowed hosts; unmatched hosts are denied */
  allowedHosts?: string[];
  /** Redirect dry-run requests to this mock server URL */
  mockServerUrl?: string;
  /** Path to an OpenAPI schema file for payload validation */
  openApiSchemaPath?: string;
  /** Per-host rate limit overrides (key = hostname) */
  rateLimits?: Record<string, RateLimitConfig>;
  /** Default rate limit applied to all hosts not explicitly configured */
  defaultRateLimit?: RateLimitConfig;
  /** Financial amounts above this threshold escalate risk to CRITICAL */
  maxFinancialAmount?: number;
  /** Mask sensitive fields in audit logs (default: true) */
  auditSensitiveFields?: boolean;
  /** Force dry-run mode — never actually send requests */
  dryRunMode?: boolean;
}

// ─── HTTP Client Interface ────────────────────────────────────────────────────

export interface HttpRequestInit {
  method: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface HttpResponse {
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

/** Injectable HTTP client — defaults to fetch, can be mocked in tests */
export type HttpClient = (url: string, init: HttpRequestInit) => Promise<HttpResponse>;
