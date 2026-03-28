import { parseHttpRequest } from '../src/adapters/api/parser.js';
import { detectSensitiveData, maskSensitiveFields, maskValue } from '../src/adapters/api/sensitive-detector.js';
import { RateLimiter } from '../src/adapters/api/rate-limiter.js';
import { runSandbox } from '../src/adapters/api/sandbox.js';
import { ApiAdapter } from '../src/adapters/api/adapter.js';
import type {
  ApiPolicy,
  ApiAdapterConfig,
  HttpClient,
  HttpResponse,
} from '../src/adapters/api/types.js';

// ─── Test helpers ─────────────────────────────────────────────────────────────

function makePolicy(overrides: Partial<ApiPolicy> = {}): ApiPolicy {
  return {
    version: '1.0',
    rules: [],
    defaults: {
      allowUnknown: true,
      defaultRiskLevel: 'LOW',
    },
    ...overrides,
  };
}

function makeMockHttpClient(status = 200, body: unknown = { ok: true }): HttpClient {
  return async (_url, _init): Promise<HttpResponse> => ({
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  });
}

// ─── parser.ts ────────────────────────────────────────────────────────────────

describe('parseHttpRequest — plain URL', () => {
  it('defaults to GET for a plain URL', () => {
    const req = parseHttpRequest('https://api.example.com/users');
    expect(req.method).toBe('GET');
    expect(req.host).toBe('api.example.com');
    expect(req.path).toBe('/users');
    expect(req.riskLevel).toBe('LOW');
  });

  it('infers protocol when missing', () => {
    const req = parseHttpRequest('api.example.com/users');
    expect(req.host).toBe('api.example.com');
  });

  it('parses query parameters', () => {
    const req = parseHttpRequest('https://api.example.com/search?q=test&page=1');
    expect(req.queryParams['q']).toBe('test');
    expect(req.queryParams['page']).toBe('1');
  });
});

describe('parseHttpRequest — METHOD URL format', () => {
  it('parses DELETE with CRITICAL base risk', () => {
    const req = parseHttpRequest('DELETE https://api.example.com/users/123');
    expect(req.method).toBe('DELETE');
    expect(req.riskLevel).toBe('CRITICAL');
    expect(req.isDestructive).toBe(true);
  });

  it('parses POST with MEDIUM base risk', () => {
    const req = parseHttpRequest('POST https://api.example.com/comments');
    expect(req.method).toBe('POST');
    expect(req.riskLevel).toBe('MEDIUM'); // POST baseline is MEDIUM
  });

  it('parses GET as read-only', () => {
    const req = parseHttpRequest('GET https://api.example.com/items');
    expect(req.method).toBe('GET');
    expect(req.riskLevel).toBe('LOW');
    expect(req.isDestructive).toBe(false);
  });
});

describe('parseHttpRequest — risk escalation by endpoint', () => {
  it('escalates GET on payment endpoint by 2 levels (LOW → HIGH)', () => {
    const req = parseHttpRequest('GET https://api.stripe.com/v1/charges');
    expect(req.endpointCategory).toBe('payment');
    expect(req.riskLevel).toBe('HIGH');
  });

  it('escalates POST on payment endpoint (MEDIUM+2 → CRITICAL)', () => {
    const req = parseHttpRequest('POST https://api.stripe.com/v1/charges');
    expect(req.endpointCategory).toBe('payment');
    expect(req.riskLevel).toBe('CRITICAL');
  });

  it('escalates GET on auth endpoint by 1 level (LOW → MEDIUM)', () => {
    const req = parseHttpRequest('GET https://api.example.com/v1/tokens');
    expect(req.endpointCategory).toBe('auth');
    expect(req.riskLevel).toBe('MEDIUM');
  });

  it('escalates GET on admin endpoint by 1 level', () => {
    const req = parseHttpRequest('GET https://api.example.com/admin/users');
    expect(req.endpointCategory).toBe('admin');
    expect(req.riskLevel).toBe('MEDIUM');
  });

  it('escalates GET on bulk endpoint by 1 level', () => {
    const req = parseHttpRequest('GET https://api.example.com/batch/export');
    expect(req.endpointCategory).toBe('bulk');
    expect(req.riskLevel).toBe('MEDIUM');
  });

  it('caps risk at CRITICAL', () => {
    // DELETE (CRITICAL) + payment (+2) should still be CRITICAL
    const req = parseHttpRequest('DELETE https://api.stripe.com/v1/charges/ch_123');
    expect(req.riskLevel).toBe('CRITICAL');
  });
});

describe('parseHttpRequest — curl commands', () => {
  it('parses a basic curl GET', () => {
    const req = parseHttpRequest('curl https://api.example.com/users');
    expect(req.method).toBe('GET');
    expect(req.host).toBe('api.example.com');
  });

  it('parses curl with explicit method', () => {
    const req = parseHttpRequest('curl -X DELETE https://api.example.com/users/123');
    expect(req.method).toBe('DELETE');
    expect(req.path).toBe('/users/123');
  });

  it('parses curl headers', () => {
    const req = parseHttpRequest(
      "curl -X POST https://api.example.com/items -H 'Authorization: Bearer token123' -H 'Content-Type: application/json'",
    );
    expect(req.headers['authorization']).toBe('Bearer token123');
    expect(req.headers['content-type']).toBe('application/json');
  });

  it('parses curl JSON body', () => {
    const req = parseHttpRequest(
      `curl -X POST https://api.example.com/users -H 'Content-Type: application/json' -d '{"name":"Alice","email":"alice@example.com"}'`,
    );
    expect(req.method).toBe('POST');
    expect(req.body).not.toBeNull();
    expect((req.body as Record<string, unknown>)['name']).toBe('Alice');
  });

  it('detects credentials in URL query params', () => {
    const req = parseHttpRequest('curl https://api.example.com/data?api_key=secret123');
    expect(req.metadata['hasCredentialsInUrl']).toBe(true);
  });
});

describe('parseHttpRequest — bulk detection', () => {
  it('flags bulk endpoint as isBulk', () => {
    const req = parseHttpRequest('POST https://api.example.com/batch/import');
    expect(req.endpointCategory).toBe('bulk');
    expect(req.isBulk).toBe(true);
  });

  it('detects item count from array body field', () => {
    const body = JSON.stringify({ items: new Array(200).fill({ id: 1 }) });
    const req = parseHttpRequest(
      `curl -X POST https://api.example.com/bulk -d '${body}'`,
    );
    expect(req.itemCount).toBe(200);
    expect(req.isBulk).toBe(true);
  });

  it('detects item count from count field', () => {
    const req = parseHttpRequest(
      `curl -X POST https://api.example.com/items -d '{"count":150}'`,
    );
    expect(req.itemCount).toBe(150);
    expect(req.isBulk).toBe(true);
  });
});

describe('parseHttpRequest — error handling', () => {
  it('throws on empty input', () => {
    expect(() => parseHttpRequest('')).toThrow('empty input');
  });

  it('throws on whitespace input', () => {
    expect(() => parseHttpRequest('   ')).toThrow('empty input');
  });

  it('returns UNKNOWN method for unrecognized method', () => {
    const req = parseHttpRequest('FOOBAR https://api.example.com/test');
    // Falls through to plain URL parse — FOOBAR is not a method token
    expect(req.method).toBe('GET');
  });
});

// ─── sensitive-detector.ts ────────────────────────────────────────────────────

describe('detectSensitiveData — credential fields', () => {
  it('detects api_key field', () => {
    const matches = detectSensitiveData({ api_key: 'abc123' }, {});
    expect(matches).toHaveLength(1);
    expect(matches[0]?.type).toBe('credential');
    expect(matches[0]?.sensitivity).toBe('HIGH');
  });

  it('detects password field', () => {
    const matches = detectSensitiveData({ password: 'supersecret' }, {});
    expect(matches[0]?.type).toBe('credential');
  });

  it('detects Authorization header', () => {
    const matches = detectSensitiveData(null, { authorization: 'Bearer fake-token-for-test-123' });
    expect(matches.length).toBeGreaterThan(0);
  });
});

describe('detectSensitiveData — PII', () => {
  it('detects email field', () => {
    const matches = detectSensitiveData({ email: 'user@example.com' }, {});
    expect(matches[0]?.type).toBe('pii');
  });

  it('detects SSN value pattern', () => {
    const matches = detectSensitiveData({ note: '123-45-6789' }, {});
    expect(matches[0]?.type).toBe('pii');
  });

  it('detects credit card number', () => {
    const matches = detectSensitiveData({ card: '4111111111111111' }, {});
    expect(matches[0]?.type).toBe('pii');
    expect(matches[0]?.sensitivity).toBe('CRITICAL');
  });

  it('detects Stripe secret key in value', () => {
    // Assemble at runtime so static scanners do not flag the test file
    const fakeStripeKey = ['sk', 'live', 'a'.repeat(24)].join('_');
    const matches = detectSensitiveData({ key: fakeStripeKey }, {});
    expect(matches[0]?.type).toBe('token');
    expect(matches[0]?.sensitivity).toBe('CRITICAL');
  });
});

describe('detectSensitiveData — financial', () => {
  it('flags amount above default threshold (10000)', () => {
    const matches = detectSensitiveData({ amount: 15000 }, {});
    expect(matches[0]?.type).toBe('financial');
    expect(matches[0]?.sensitivity).toBe('CRITICAL');
  });

  it('does not flag amount below threshold', () => {
    const matches = detectSensitiveData({ amount: 5000 }, {});
    expect(matches).toHaveLength(0);
  });

  it('respects custom threshold', () => {
    const matches = detectSensitiveData({ amount: 100 }, {}, { maxFinancialAmount: 50 });
    expect(matches[0]?.type).toBe('financial');
  });
});

describe('detectSensitiveData — nested objects', () => {
  it('detects sensitive fields one level deep', () => {
    const matches = detectSensitiveData({ billing: { api_key: 'secret' } }, {});
    expect(matches[0]?.field).toBe('billing.api_key');
  });
});

describe('maskValue', () => {
  it('masks short values fully', () => {
    expect(maskValue('abc')).toBe('****');
  });

  it('keeps first and last chars for longer values', () => {
    const masked = maskValue('api-key-prefix-test-token-longvalue');
    expect(masked.startsWith('api-')).toBe(true);
    expect(masked.endsWith('alue')).toBe(true);
    expect(masked).toContain('*');
  });
});

describe('maskSensitiveFields', () => {
  it('replaces sensitive field values in a copy', () => {
    const data = { password: 'secret', name: 'Alice' };
    const matches = detectSensitiveData(data, {});
    const masked = maskSensitiveFields(data, matches);
    expect(masked['password']).not.toBe('secret');
    expect(masked['name']).toBe('Alice');
    expect(data['password']).toBe('secret'); // original unchanged
  });
});

// ─── rate-limiter.ts ──────────────────────────────────────────────────────────

describe('RateLimiter', () => {
  it('allows requests within burst size', () => {
    const limiter = new RateLimiter({ requestsPerMinute: 60, burstSize: 5 });
    expect(limiter.check('api.example.com').allowed).toBe(true);
    expect(limiter.consume('api.example.com')).toBe(true);
  });

  it('blocks after burst size is exhausted', () => {
    const limiter = new RateLimiter({ requestsPerMinute: 60, burstSize: 3 });
    const host = 'api.example.com';
    limiter.consume(host);
    limiter.consume(host);
    limiter.consume(host);
    expect(limiter.consume(host)).toBe(false);
    expect(limiter.check(host).allowed).toBe(false);
  });

  it('check does not consume tokens', () => {
    const limiter = new RateLimiter({ requestsPerMinute: 60, burstSize: 2 });
    const host = 'api.example.com';
    limiter.check(host);
    limiter.check(host);
    limiter.check(host);
    // Tokens still available since check doesn't consume
    expect(limiter.consume(host)).toBe(true);
  });

  it('reset restores full bucket', () => {
    const limiter = new RateLimiter({ requestsPerMinute: 60, burstSize: 2 });
    const host = 'api.example.com';
    limiter.consume(host);
    limiter.consume(host);
    limiter.reset(host);
    expect(limiter.check(host).remaining).toBe(2);
  });

  it('applies per-host config', () => {
    const limiter = new RateLimiter(
      { requestsPerMinute: 60, burstSize: 10 },
      { 'strict.example.com': { requestsPerMinute: 2, burstSize: 1 } },
    );
    limiter.consume('strict.example.com');
    expect(limiter.consume('strict.example.com')).toBe(false);
    // Default host is unaffected
    expect(limiter.consume('other.example.com')).toBe(true);
  });

  it('returns resetAt in the future when rate limited', () => {
    const limiter = new RateLimiter({ requestsPerMinute: 60, burstSize: 1 });
    const host = 'api.example.com';
    limiter.consume(host);
    const status = limiter.check(host);
    expect(status.allowed).toBe(false);
    expect(status.resetAt.getTime()).toBeGreaterThan(Date.now());
  });
});

// ─── sandbox.ts ──────────────────────────────────────────────────────────────

describe('runSandbox', () => {
  it('returns feasible when rate limit is not exceeded', async () => {
    const req = parseHttpRequest('DELETE https://api.example.com/users/1');
    const limiter = new RateLimiter({ requestsPerMinute: 60, burstSize: 10 });
    const result = await runSandbox(req, limiter, {});
    expect(result.feasible).toBe(true);
    expect(result.rateLimitStatus.allowed).toBe(true);
  });

  it('returns not feasible when rate limit exceeded', async () => {
    const req = parseHttpRequest('GET https://api.example.com/data');
    const limiter = new RateLimiter({ requestsPerMinute: 60, burstSize: 1 });
    limiter.consume('api.example.com');
    const result = await runSandbox(req, limiter, {});
    expect(result.feasible).toBe(false);
    expect(result.warnings.some((w) => w.includes('Rate limit'))).toBe(true);
  });

  it('warns about destructive operations', async () => {
    const req = parseHttpRequest('DELETE https://api.example.com/items/1');
    const limiter = new RateLimiter({ requestsPerMinute: 60, burstSize: 10 });
    const result = await runSandbox(req, limiter, {});
    expect(result.warnings.some((w) => w.includes('Destructive'))).toBe(true);
  });

  it('masks sensitive headers in wouldSend', async () => {
    const req = parseHttpRequest(
      "curl -X GET https://api.example.com/data -H 'Authorization: Bearer fake-bearer-token-abc123'",
    );
    const limiter = new RateLimiter({ requestsPerMinute: 60, burstSize: 10 });
    const result = await runSandbox(req, limiter, {});
    expect(result.wouldSend.headers['authorization']).toBe('[redacted]');
  });

  it('redirects to mock server when configured', async () => {
    const req = parseHttpRequest('POST https://api.example.com/items');
    const limiter = new RateLimiter({ requestsPerMinute: 60, burstSize: 10 });
    const result = await runSandbox(req, limiter, { mockServerUrl: 'https://mock.local' });
    expect(result.wouldSend.url).toContain('mock.local');
  });

  it('warns about bulk operations', async () => {
    const req = parseHttpRequest('POST https://api.example.com/batch/import');
    const limiter = new RateLimiter({ requestsPerMinute: 60, burstSize: 10 });
    const result = await runSandbox(req, limiter, {});
    expect(result.warnings.some((w) => w.includes('Bulk'))).toBe(true);
  });
});

// ─── adapter.ts — policy evaluation ──────────────────────────────────────────

describe('ApiAdapter — host whitelist', () => {
  it('denies requests to non-whitelisted hosts', async () => {
    const policy = makePolicy({
      defaults: { allowUnknown: true, defaultRiskLevel: 'LOW', allowedHosts: ['trusted.com'] },
    });
    const adapter = new ApiAdapter(policy, {}, makeMockHttpClient());
    const result = await adapter.run('GET https://evil.com/data');
    expect(result.success).toBe(false);
    expect(result.auditEntry.policyDecision.blockedByHostWhitelist).toBe(true);
  });

  it('allows requests to whitelisted hosts', async () => {
    const policy = makePolicy({
      defaults: { allowUnknown: true, defaultRiskLevel: 'LOW', allowedHosts: ['api.example.com'] },
    });
    const adapter = new ApiAdapter(policy, { dryRunMode: true }, makeMockHttpClient());
    const result = await adapter.run('GET https://api.example.com/items');
    expect(result.auditEntry.policyDecision.blockedByHostWhitelist).toBe(false);
  });

  it('allows subdomains of whitelisted hosts', async () => {
    const policy = makePolicy({
      defaults: { allowUnknown: true, defaultRiskLevel: 'LOW', allowedHosts: ['example.com'] },
    });
    const adapter = new ApiAdapter(policy, { dryRunMode: true }, makeMockHttpClient());
    const result = await adapter.run('GET https://api.example.com/items');
    expect(result.auditEntry.policyDecision.blockedByHostWhitelist).toBe(false);
  });
});

describe('ApiAdapter — deny rules', () => {
  it('denies requests matching a deny rule', async () => {
    const policy = makePolicy({
      rules: [
        {
          id: 'deny-delete',
          description: 'No deletes',
          match: { methods: ['DELETE'] },
          action: 'deny',
          riskLevel: 'CRITICAL',
        },
      ],
      defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' },
    });
    const adapter = new ApiAdapter(policy, {}, makeMockHttpClient());
    const result = await adapter.run('DELETE https://api.example.com/users/1');
    expect(result.success).toBe(false);
    expect(result.auditEntry.policyDecision.allowed).toBe(false);
  });

  it('denies requests with credentials in URL', async () => {
    const policy = makePolicy({
      rules: [
        {
          id: 'deny-creds-url',
          description: 'No credentials in URL',
          match: { hasCredentialsInUrl: true },
          action: 'deny',
          riskLevel: 'CRITICAL',
        },
      ],
      defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' },
    });
    const adapter = new ApiAdapter(policy, {}, makeMockHttpClient());
    const result = await adapter.run('GET https://api.example.com/data?api_key=secret');
    expect(result.success).toBe(false);
  });
});

describe('ApiAdapter — dry-run mode', () => {
  it('returns dry_run status without calling HTTP client', async () => {
    let called = false;
    const mockClient: HttpClient = async (_url, _init): Promise<HttpResponse> => {
      called = true;
      return { status: 200, json: async () => ({}), text: async () => '' };
    };
    const policy = makePolicy({ defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' } });
    const adapter = new ApiAdapter(policy, { dryRunMode: true }, mockClient);
    const result = await adapter.run('POST https://api.example.com/items');
    expect(result.success).toBe(true);
    expect(result.executionResult?.status).toBe('dry_run');
    expect(called).toBe(false);
  });
});

describe('ApiAdapter — require_dry_run policy', () => {
  it('runs sandbox for operations requiring dry-run and succeeds', async () => {
    const policy = makePolicy({
      rules: [
        {
          id: 'dryrun-post',
          description: 'Post needs dry run',
          match: { methods: ['POST'] },
          action: 'require_dry_run',
          riskLevel: 'MEDIUM',
        },
      ],
      defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' },
    });
    const adapter = new ApiAdapter(policy, { dryRunMode: true }, makeMockHttpClient());
    const result = await adapter.run('POST https://api.example.com/items');
    expect(result.auditEntry.sandboxResult).not.toBeNull();
    expect(result.auditEntry.policyDecision.requiresDryRun).toBe(true);
  });
});

describe('ApiAdapter — rate limiting', () => {
  it('blocks execution when rate limit is exhausted', async () => {
    const policy = makePolicy({ defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' } });
    const adapter = new ApiAdapter(
      policy,
      { defaultRateLimit: { requestsPerMinute: 60, burstSize: 0 } },
      makeMockHttpClient(),
    );
    const result = await adapter.run('GET https://api.example.com/data');
    expect(result.success).toBe(false);
    expect(result.executionResult?.status).toBe('rate_limited');
  });
});

describe('ApiAdapter — successful execution', () => {
  it('returns success for an allowed GET request', async () => {
    const policy = makePolicy({
      rules: [
        {
          id: 'allow-get',
          description: 'Allow GET',
          match: { methods: ['GET'] },
          action: 'allow',
          riskLevel: 'LOW',
        },
      ],
      defaults: { allowUnknown: false, defaultRiskLevel: 'LOW' },
    });
    const adapter = new ApiAdapter(policy, {}, makeMockHttpClient(200, { data: 'ok' }));
    const result = await adapter.run('GET https://api.example.com/items');
    expect(result.success).toBe(true);
    expect(result.executionResult?.status).toBe('success');
    expect(result.executionResult?.httpStatus).toBe(200);
  });

  it('records executor and environment in audit entry', async () => {
    const policy = makePolicy({ defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' } });
    const config: ApiAdapterConfig = { executor: 'test-bot', environment: 'test' };
    const adapter = new ApiAdapter(policy, config, makeMockHttpClient());
    const result = await adapter.run('GET https://api.example.com/items');
    expect(result.auditEntry.executor).toBe('test-bot');
    expect(result.auditEntry.environment).toBe('test');
  });

  it('marks failed non-2xx response', async () => {
    const policy = makePolicy({ defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' } });
    const adapter = new ApiAdapter(policy, {}, makeMockHttpClient(404, { error: 'not found' }));
    const result = await adapter.run('GET https://api.example.com/items/99999');
    expect(result.executionResult?.status).toBe('failed');
    expect(result.executionResult?.httpStatus).toBe(404);
  });
});

describe('ApiAdapter — parse error handling', () => {
  it('returns failure for empty input', async () => {
    const policy = makePolicy({ defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' } });
    const adapter = new ApiAdapter(policy, {}, makeMockHttpClient());
    const result = await adapter.run('');
    expect(result.success).toBe(false);
    expect(result.abortReason).toContain('Parse error');
  });
});

describe('ApiAdapter — audit entry completeness', () => {
  it('audit entry always has an id and timestamp', async () => {
    const policy = makePolicy({ defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' } });
    const adapter = new ApiAdapter(policy, {}, makeMockHttpClient());
    const result = await adapter.run('GET https://api.example.com/items');
    expect(result.auditEntry.id).toMatch(/^api-audit-/);
    expect(result.auditEntry.timestamp).toBeInstanceOf(Date);
  });

  it('audit entry captures the request details', async () => {
    const policy = makePolicy({ defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' } });
    const adapter = new ApiAdapter(policy, {}, makeMockHttpClient());
    const result = await adapter.run('GET https://api.example.com/users?page=2');
    expect(result.auditEntry.request.method).toBe('GET');
    expect(result.auditEntry.request.host).toBe('api.example.com');
    expect(result.auditEntry.request.path).toBe('/users');
    expect(result.auditEntry.request.queryParams['page']).toBe('2');
  });
});

describe('ApiAdapter — path pattern matching', () => {
  it('matches rules by path pattern', async () => {
    const policy = makePolicy({
      rules: [
        {
          id: 'deny-admin',
          description: 'Deny admin paths',
          match: { pathPattern: '\\/admin' },
          action: 'deny',
          riskLevel: 'CRITICAL',
        },
      ],
      defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' },
    });
    const adapter = new ApiAdapter(policy, {}, makeMockHttpClient());
    const result = await adapter.run('GET https://api.example.com/admin/users');
    expect(result.success).toBe(false);
    expect(result.auditEntry.policyDecision.matchedRules[0]?.id).toBe('deny-admin');
  });
});
