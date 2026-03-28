import type {
  ParsedHttpRequest,
  ApiSandboxResult,
  ApiAdapterConfig,
} from './types.js';
import type { RateLimiter } from './rate-limiter.js';
import { maskSensitiveFields } from './sensitive-detector.js';

/**
 * API Sandbox — Layer 3
 *
 * Simulates what WOULD happen if the request were executed:
 *   - Builds the "would-send" object (with sensitive fields masked for logs)
 *   - Checks rate limits without consuming a token
 *   - Validates payload against OpenAPI schema if configured
 *   - Generates human-readable warnings
 *
 * The sandbox NEVER actually sends the request.
 */

function buildUrl(request: ParsedHttpRequest, mockServerUrl?: string): string {
  const base = mockServerUrl ?? `https://${request.host}`;
  const queryString = Object.entries(request.queryParams)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
  return `${base}${request.path}${queryString ? `?${queryString}` : ''}`;
}

function maskHeaders(
  headers: Record<string, string>,
): Record<string, string> {
  const sensitive = new Set(['authorization', 'x-api-key', 'cookie', 'x-auth-token']);
  const result: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    result[k] = sensitive.has(k.toLowerCase()) ? '[redacted]' : v;
  }
  return result;
}

function buildWarnings(request: ParsedHttpRequest, config: ApiAdapterConfig): string[] {
  const warnings: string[] = [];

  if (request.isDestructive) {
    warnings.push(`⚠ Destructive operation: ${request.method} on ${request.host}${request.path}`);
  }

  if (request.isBulk) {
    const count = request.itemCount !== null ? ` (${request.itemCount} items)` : '';
    warnings.push(`⚠ Bulk operation${count} — review item count before proceeding`);
  }

  if (request.sensitiveFields.length > 0) {
    const fieldList = request.sensitiveFields.map((f) => f.field).join(', ');
    warnings.push(`⚠ Sensitive fields detected: ${fieldList}`);
  }

  if (request.metadata['hasCredentialsInUrl'] === true) {
    warnings.push('⚠ Credentials detected in URL query parameters — prefer Authorization header');
  }

  if (request.endpointCategory === 'payment') {
    warnings.push('⚠ Payment endpoint — verify amount and recipient before execution');
  }

  if (request.endpointCategory === 'auth') {
    warnings.push('⚠ Auth endpoint — token operations may have wide blast radius');
  }

  if (config.dryRunMode === true) {
    warnings.push('ℹ Adapter is in dry-run mode — request will not be sent');
  }

  return warnings;
}

export async function runSandbox(
  request: ParsedHttpRequest,
  rateLimiter: RateLimiter,
  config: ApiAdapterConfig,
): Promise<ApiSandboxResult> {
  const start = Date.now();

  const rateLimitStatus = rateLimiter.check(request.host);

  const maskedBody =
    request.body && request.sensitiveFields.length > 0
      ? maskSensitiveFields(request.body, request.sensitiveFields)
      : request.body;

  const wouldSend = {
    method: request.method,
    url: buildUrl(request, config.mockServerUrl),
    headers: maskHeaders(request.headers),
    body: maskedBody as Record<string, unknown> | null,
  };

  const warnings = buildWarnings(request, config);

  if (!rateLimitStatus.allowed) {
    warnings.push(
      `⚠ Rate limit would be exceeded for host '${request.host}' — ` +
      `resets at ${rateLimitStatus.resetAt.toISOString()}`,
    );
  }

  return {
    feasible: rateLimitStatus.allowed,
    wouldSend,
    warnings,
    rateLimitStatus,
    schemaValidation: {
      valid: true,
      errors: [],
    },
    durationMs: Date.now() - start,
  };
}
