import type {
  ParsedHttpRequest,
  ApiPolicy,
  ApiPolicyRule,
  ApiPolicyDecision,
  ApiAdapterConfig,
  ApiPipelineResult,
  ApiAuditEntry,
  ApiExecutionResult,
  ApiSandboxResult,
  HttpClient,
  HttpRequestInit,
  HttpResponse,
} from './types.js';
import type { RiskLevel } from '../../types/index.js';
import { parseHttpRequest } from './parser.js';
import { RateLimiter } from './rate-limiter.js';
import { runSandbox } from './sandbox.js';

/**
 * ApiAdapter — Orchestrator
 *
 * Implements a 5-gate pipeline for safe HTTP/API execution:
 *
 *   Gate 1 — Intent Parser:  parse raw input into ParsedHttpRequest
 *   Gate 2 — Policy Engine:  evaluate ApiPolicy rules
 *   Gate 3 — Sandbox:        dry-run if required (never sends the request)
 *   Gate 4 — Rate Limiter:   consume token before actual execution
 *   Gate 5 — Executor:       send request (or return dry_run if dryRunMode)
 *   Gate 6 — Audit:          record full lifecycle
 *
 * Non-bypassable: DENY and host-whitelist blocks cannot be overridden.
 */

// ─── Policy engine ────────────────────────────────────────────────────────────

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function escalateRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

function matchesRule(request: ParsedHttpRequest, rule: ApiPolicyRule): boolean {
  const m = rule.match;

  if (m.methods && !m.methods.includes(request.method)) return false;

  if (m.pathPattern) {
    try {
      if (!new RegExp(m.pathPattern, 'i').test(request.path)) return false;
    } catch {
      return false;
    }
  }

  if (m.hostPattern) {
    try {
      if (!new RegExp(m.hostPattern, 'i').test(request.host)) return false;
    } catch {
      return false;
    }
  }

  if (m.endpointCategory && !m.endpointCategory.includes(request.endpointCategory)) return false;

  if (
    m.minItemCount !== undefined &&
    (request.itemCount === null || request.itemCount < m.minItemCount)
  ) {
    return false;
  }

  if (m.hasCredentialsInUrl !== undefined) {
    const actual = request.metadata['hasCredentialsInUrl'] === true;
    if (actual !== m.hasCredentialsInUrl) return false;
  }

  return true;
}

function evaluatePolicy(
  request: ParsedHttpRequest,
  policy: ApiPolicy,
): ApiPolicyDecision {
  const matchedRules: ApiPolicyRule[] = [];
  const messages: string[] = [];
  let allowed = true;
  let requiresDryRun = false;
  let requiresApproval = false;
  let currentRisk: RiskLevel = policy.defaults.defaultRiskLevel;

  // Host whitelist check (non-bypassable)
  const allowedHosts = policy.defaults.allowedHosts;
  if (allowedHosts && allowedHosts.length > 0) {
    const hostAllowed = allowedHosts.some((h) => {
      // Allow exact match or subdomain match
      return request.host === h || request.host.endsWith(`.${h}`);
    });
    if (!hostAllowed) {
      return {
        allowed: false,
        riskLevel: 'CRITICAL',
        requiresDryRun: false,
        requiresApproval: false,
        matchedRules: [],
        message: `Host '${request.host}' is not in the allowed hosts whitelist`,
        blockedByHostWhitelist: true,
      };
    }
  }

  // Evaluate rules in order
  for (const rule of policy.rules) {
    if (!matchesRule(request, rule)) continue;
    matchedRules.push(rule);
    currentRisk = escalateRisk(currentRisk, rule.riskLevel);

    switch (rule.action) {
      case 'deny':
        allowed = false;
        messages.push(rule.message ?? `Denied by rule: ${rule.id}`);
        break;
      case 'require_approval':
        requiresApproval = true;
        messages.push(rule.message ?? `Approval required: ${rule.id}`);
        break;
      case 'require_dry_run':
        requiresDryRun = true;
        messages.push(rule.message ?? `Dry-run required: ${rule.id}`);
        break;
      case 'allow':
        messages.push(rule.message ?? `Allowed by rule: ${rule.id}`);
        break;
    }
  }

  if (matchedRules.length === 0) {
    if (!policy.defaults.allowUnknown) {
      allowed = false;
      messages.push('No matching rule and allowUnknown is false');
    } else {
      messages.push('No matching rule — default: allowed');
    }
  }

  // CRITICAL risk always requires dry-run + approval
  if (currentRisk === 'CRITICAL') {
    requiresDryRun = true;
    requiresApproval = true;
  }

  return {
    allowed,
    riskLevel: currentRisk,
    requiresDryRun,
    requiresApproval,
    matchedRules,
    message: messages.join('; '),
    blockedByHostWhitelist: false,
  };
}

// ─── Default HTTP client ──────────────────────────────────────────────────────

const defaultHttpClient: HttpClient = async (
  url: string,
  init: HttpRequestInit,
): Promise<HttpResponse> => {
  const res = await fetch(url, {
    method: init.method,
    headers: init.headers,
    body: init.body,
  });
  return {
    status: res.status,
    json: () => res.json() as Promise<unknown>,
    text: () => res.text(),
  };
};

// ─── Audit ────────────────────────────────────────────────────────────────────

let auditCounter = 0;

function buildAuditId(): string {
  auditCounter += 1;
  return `api-audit-${Date.now()}-${auditCounter}`;
}

function writeAudit(entry: ApiAuditEntry, config: ApiAdapterConfig): void {
  const label = entry.executionResult?.status === 'success' ? '✓ SUCCESS' : '✗ ABORT';
  console.log(
    `[SafeExecutor/API] ${label} | ${entry.policyDecision.riskLevel} | ${entry.id}`,
  );
  console.log(`  Method     : ${entry.request.method} ${entry.request.host}${entry.request.path}`);
  console.log(`  Executor   : ${config.executor ?? 'unknown'}`);
  console.log(`  Duration   : ${entry.totalDurationMs}ms`);
  if (entry.policyDecision.message) {
    console.log(`  Policy     : ${entry.policyDecision.message}`);
  }
}

// ─── ApiAdapter ───────────────────────────────────────────────────────────────

export class ApiAdapter {
  private readonly policy: ApiPolicy;
  private readonly config: ApiAdapterConfig;
  private readonly rateLimiter: RateLimiter;
  private readonly httpClient: HttpClient;

  constructor(
    policy: ApiPolicy,
    config: ApiAdapterConfig = {},
    httpClient?: HttpClient,
  ) {
    this.policy = policy;
    this.config = config;
    this.rateLimiter = new RateLimiter(
      config.defaultRateLimit ?? { requestsPerMinute: 60, burstSize: 10 },
      config.rateLimits ?? {},
    );
    this.httpClient = httpClient ?? defaultHttpClient;
  }

  /**
   * Run the full pipeline for a raw HTTP request string.
   *
   * Accepts curl commands, "METHOD URL" strings, or plain URLs.
   */
  async run(input: string): Promise<ApiPipelineResult> {
    const startedAt = Date.now();
    const auditId = buildAuditId();

    // ── Gate 1: Intent Parser ──────────────────────────────────────────────
    let request: ParsedHttpRequest;
    try {
      request = parseHttpRequest(input, {
        maxFinancialAmount: this.config.maxFinancialAmount ?? this.policy.defaults.maxFinancialAmount,
      });
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      const stub = this.buildRequestStub(input);
      const stubDecision = this.buildDenyDecision(`Parse error: ${error}`);
      return this.abort(stub, stubDecision, null, `Parse error: ${error}`, startedAt, auditId);
    }

    // ── Gate 2: Policy Engine ──────────────────────────────────────────────
    const decision = evaluatePolicy(request, this.policy);

    if (!decision.allowed) {
      return this.abort(request, decision, null, decision.message, startedAt, auditId);
    }

    // ── Gate 3: Sandbox (if required or dryRunMode) ────────────────────────
    let sandboxResult: ApiSandboxResult | null = null;

    if (decision.requiresDryRun || this.config.dryRunMode) {
      sandboxResult = await runSandbox(request, this.rateLimiter, this.config);

      if (!sandboxResult.feasible) {
        return this.abort(
          request,
          decision,
          sandboxResult,
          'Sandbox: request is not feasible (rate limit exceeded)',
          startedAt,
          auditId,
        );
      }
    }

    // ── Gate 4: Approval check ─────────────────────────────────────────────
    // For operations requiring approval: auto-approve LOW/MEDIUM, auto-deny HIGH/CRITICAL.
    // A full approval webhook/CLI flow would be added in a future gate.
    if (decision.requiresApproval) {
      const autoApproved = RISK_ORDER.indexOf(decision.riskLevel) <= RISK_ORDER.indexOf('MEDIUM');
      if (!autoApproved) {
        return this.abort(
          request,
          decision,
          sandboxResult,
          `Approval required for ${decision.riskLevel} risk operation — no approval mechanism configured`,
          startedAt,
          auditId,
        );
      }
    }

    // ── Gate 5: Execute ────────────────────────────────────────────────────
    if (this.config.dryRunMode) {
      const execResult: ApiExecutionResult = {
        status: 'dry_run',
        durationMs: 0,
        rateLimited: false,
      };
      return this.succeed(request, decision, sandboxResult, execResult, startedAt, auditId);
    }

    // Consume rate limit token before sending
    const tokenConsumed = this.rateLimiter.consume(request.host);
    if (!tokenConsumed) {
      const execResult: ApiExecutionResult = {
        status: 'rate_limited',
        durationMs: 0,
        error: `Rate limit exceeded for host '${request.host}'`,
        rateLimited: true,
      };
      return this.abort(request, decision, sandboxResult, execResult.error ?? '', startedAt, auditId, execResult);
    }

    const execResult = await this.execute(request);
    const success = execResult.status === 'success';

    const auditEntry = this.buildAuditEntry(
      auditId,
      request,
      decision,
      sandboxResult,
      execResult,
      startedAt,
    );
    writeAudit(auditEntry, this.config);

    return {
      success,
      executionResult: execResult,
      auditEntry,
      ...(success ? {} : { abortReason: execResult.error }),
    };
  }

  private async execute(request: ParsedHttpRequest): Promise<ApiExecutionResult> {
    const start = Date.now();
    const queryString = Object.entries(request.queryParams)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join('&');
    const url = `https://${request.host}${request.path}${queryString ? `?${queryString}` : ''}`;

    const init: HttpRequestInit = {
      method: request.method,
      headers: request.headers,
      body: request.body ? JSON.stringify(request.body) : undefined,
    };

    try {
      const response = await this.httpClient(url, init);
      let responseBody: unknown;
      try {
        responseBody = await response.json();
      } catch {
        responseBody = null;
      }
      return {
        status: response.status >= 200 && response.status < 300 ? 'success' : 'failed',
        httpStatus: response.status,
        responseBody,
        durationMs: Date.now() - start,
        rateLimited: false,
      };
    } catch (err) {
      return {
        status: 'failed',
        durationMs: Date.now() - start,
        error: err instanceof Error ? err.message : String(err),
        rateLimited: false,
      };
    }
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────

  private buildAuditEntry(
    id: string,
    request: ParsedHttpRequest,
    decision: ApiPolicyDecision,
    sandboxResult: ApiSandboxResult | null,
    executionResult: ApiExecutionResult | null,
    startedAt: number,
  ): ApiAuditEntry {
    return {
      id,
      timestamp: new Date(),
      executor: this.config.executor ?? 'unknown',
      request,
      policyDecision: decision,
      sandboxResult,
      executionResult,
      totalDurationMs: Date.now() - startedAt,
      environment: this.config.environment ?? 'unknown',
    };
  }

  private abort(
    request: ParsedHttpRequest,
    decision: ApiPolicyDecision,
    sandboxResult: ApiSandboxResult | null,
    reason: string,
    startedAt: number,
    auditId: string,
    execResult?: ApiExecutionResult,
  ): ApiPipelineResult {
    const executionResult: ApiExecutionResult = execResult ?? {
      status: 'denied',
      durationMs: 0,
      error: reason,
      rateLimited: false,
    };
    const auditEntry = this.buildAuditEntry(
      auditId,
      request,
      decision,
      sandboxResult,
      executionResult,
      startedAt,
    );
    writeAudit(auditEntry, this.config);
    return {
      success: false,
      executionResult,
      auditEntry,
      abortedAt: new Date().toISOString(),
      abortReason: reason,
    };
  }

  private succeed(
    request: ParsedHttpRequest,
    decision: ApiPolicyDecision,
    sandboxResult: ApiSandboxResult | null,
    execResult: ApiExecutionResult,
    startedAt: number,
    auditId: string,
  ): ApiPipelineResult {
    const auditEntry = this.buildAuditEntry(
      auditId,
      request,
      decision,
      sandboxResult,
      execResult,
      startedAt,
    );
    writeAudit(auditEntry, this.config);
    return { success: true, executionResult: execResult, auditEntry };
  }

  private buildRequestStub(raw: string): ParsedHttpRequest {
    return {
      raw,
      method: 'UNKNOWN',
      host: '',
      path: '',
      queryParams: {},
      headers: {},
      body: null,
      endpointCategory: 'standard',
      riskLevel: 'HIGH',
      isDestructive: false,
      isBulk: false,
      itemCount: null,
      sensitiveFields: [],
      metadata: {},
    };
  }

  private buildDenyDecision(message: string): ApiPolicyDecision {
    return {
      allowed: false,
      riskLevel: 'HIGH',
      requiresDryRun: false,
      requiresApproval: false,
      matchedRules: [],
      message,
      blockedByHostWhitelist: false,
    };
  }
}
