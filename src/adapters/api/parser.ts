import type { ParsedHttpRequest, HttpMethod, EndpointCategory } from './types.js';
import type { RiskLevel } from '../../types/index.js';
import { detectSensitiveData } from './sensitive-detector.js';

/**
 * HTTP Request Parser — Layer 1
 *
 * Accepts three input formats:
 *   1. Plain URL:            "https://api.stripe.com/v1/charges"
 *   2. Method + URL:         "DELETE https://api.example.com/users/123"
 *   3. curl command:         "curl -X POST https://... -H 'Authorization: Bearer sk_...' -d '{...}'"
 *
 * Produces a ParsedHttpRequest with:
 *   - Structured URL components (host, path, queryParams)
 *   - Risk level (method baseline × endpoint escalation)
 *   - Endpoint category (payment, auth, admin, bulk, standard)
 *   - Sensitive field detections
 */

// ─── Risk tables ──────────────────────────────────────────────────────────────

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

const METHOD_RISK: Record<HttpMethod, RiskLevel> = {
  GET: 'LOW',
  HEAD: 'LOW',
  OPTIONS: 'LOW',
  POST: 'MEDIUM',
  PUT: 'HIGH',
  PATCH: 'HIGH',
  DELETE: 'CRITICAL',
  UNKNOWN: 'HIGH',
};

/** Escalate `current` risk by `steps` levels, capped at CRITICAL */
function escalate(current: RiskLevel, steps: number): RiskLevel {
  const idx = RISK_ORDER.indexOf(current);
  const newIdx = Math.min(idx + steps, RISK_ORDER.length - 1);
  return RISK_ORDER[newIdx] as RiskLevel;
}

// ─── Endpoint category patterns ───────────────────────────────────────────────

const PAYMENT_RE = /\/(charges|payments|transfers|invoices|subscriptions|refunds|payouts|billing)\b/i;
const AUTH_RE = /\/(tokens?|sessions?|oauth|login|auth|signin|signup|authenticate|authorize)\b/i;
const ADMIN_RE = /\/(admin|internal|management|superuser|staff|root)\b/i;
const BULK_RE = /\/(batch|bulk|import|export)\b/i;

function categorize(path: string): EndpointCategory {
  if (PAYMENT_RE.test(path)) return 'payment';
  if (AUTH_RE.test(path)) return 'auth';
  if (ADMIN_RE.test(path)) return 'admin';
  if (BULK_RE.test(path)) return 'bulk';
  return 'standard';
}

function riskForCategory(base: RiskLevel, category: EndpointCategory): RiskLevel {
  switch (category) {
    case 'payment': return escalate(base, 2);
    case 'auth':    return escalate(base, 1);
    case 'admin':   return escalate(base, 1);
    case 'bulk':    return escalate(base, 1);
    case 'standard': return base;
  }
}

// ─── Method parsing ───────────────────────────────────────────────────────────

const VALID_METHODS = new Set<HttpMethod>([
  'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE',
]);

function parseMethod(raw: string): HttpMethod {
  const upper = raw.trim().toUpperCase() as HttpMethod;
  return VALID_METHODS.has(upper) ? upper : 'UNKNOWN';
}

// ─── URL parsing ──────────────────────────────────────────────────────────────

interface ParsedUrl {
  host: string;
  path: string;
  queryParams: Record<string, string>;
}

function parseUrl(raw: string): ParsedUrl {
  try {
    const normalized = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    const url = new URL(normalized);
    const queryParams: Record<string, string> = {};
    url.searchParams.forEach((v, k) => { queryParams[k] = v; });
    return { host: url.host, path: url.pathname || '/', queryParams };
  } catch {
    // Unparseable URL — treat path as the whole string
    return { host: '', path: raw, queryParams: {} };
  }
}

// ─── Credential-in-URL detection ──────────────────────────────────────────────

const CREDENTIAL_QUERY_KEYS = new Set([
  'api_key', 'apikey', 'api-key', 'key',
  'token', 'access_token', 'refresh_token', 'auth_token',
  'secret', 'password', 'pass', 'auth',
]);

function hasCredentialsInUrl(queryParams: Record<string, string>): boolean {
  return Object.keys(queryParams).some((k) => CREDENTIAL_QUERY_KEYS.has(k.toLowerCase()));
}

// ─── Bulk item count detection ────────────────────────────────────────────────

function detectItemCount(body: Record<string, unknown> | null): number | null {
  if (!body) return null;
  // Explicit count/total fields
  if (typeof body['count'] === 'number') return body['count'] as number;
  if (typeof body['total'] === 'number') return body['total'] as number;
  // Array-valued field (batch payload)
  for (const value of Object.values(body)) {
    if (Array.isArray(value)) return value.length;
  }
  return null;
}

// ─── curl parser ─────────────────────────────────────────────────────────────

interface CurlParts {
  method: HttpMethod;
  host: string;
  path: string;
  queryParams: Record<string, string>;
  headers: Record<string, string>;
  body: Record<string, unknown> | null;
}

function parseCurl(input: string): CurlParts {
  // Method: -X METHOD or --request METHOD
  const methodMatch = input.match(/(?:-X|--request)\s+([A-Z]+)/i);
  const method = methodMatch ? parseMethod(methodMatch[1]) : 'GET';

  // URL: first http(s):// token
  const urlMatch = input.match(/https?:\/\/[^\s'"\\]+/i);
  const { host, path, queryParams } = parseUrl(urlMatch ? urlMatch[0] : '');

  // Headers: -H 'Name: value' or -H "Name: value"
  const headers: Record<string, string> = {};
  const headerRe = /(?:-H|--header)\s+(?:'([^']+)'|"([^"]+)")/g;
  let hm: RegExpExecArray | null;
  while ((hm = headerRe.exec(input)) !== null) {
    const raw = (hm[1] ?? hm[2]) as string;
    const colon = raw.indexOf(':');
    if (colon > 0) {
      const name = raw.slice(0, colon).trim().toLowerCase();
      const value = raw.slice(colon + 1).trim();
      headers[name] = value;
    }
  }

  // Body: -d '...' or --data '...' or --data-raw '...'
  let body: Record<string, unknown> | null = null;
  const bodyRe = /(?:-d|--data(?:-raw)?)\s+(?:'([^']*)'|"([^"]*)")/s;
  const bodyMatch = input.match(bodyRe);
  if (bodyMatch) {
    const raw = (bodyMatch[1] ?? bodyMatch[2]) as string;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
        body = parsed as Record<string, unknown>;
      }
    } catch {
      // Non-JSON body — leave as null
    }
  }

  return { method, host, path, queryParams, headers, body };
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface ParseOptions {
  /** Escalate risk to CRITICAL when financial amount exceeds this value */
  maxFinancialAmount?: number;
}

export function parseHttpRequest(
  input: string,
  options?: ParseOptions,
): ParsedHttpRequest {
  if (!input?.trim()) {
    throw new Error('HTTP Parser: empty input provided');
  }

  const trimmed = input.trim();
  let method: HttpMethod;
  let host: string;
  let path: string;
  let queryParams: Record<string, string>;
  let headers: Record<string, string>;
  let body: Record<string, unknown> | null;

  if (/^curl\b/i.test(trimmed)) {
    const parts = parseCurl(trimmed);
    ({ method, host, path, queryParams, headers, body } = parts);
  } else {
    // "METHOD https://..." or plain URL
    const methodUrlMatch = trimmed.match(
      /^(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)\s+(\S+)/i,
    );
    if (methodUrlMatch) {
      method = parseMethod(methodUrlMatch[1]);
      const parsed = parseUrl(methodUrlMatch[2] as string);
      ({ host, path, queryParams } = parsed);
    } else {
      method = 'GET';
      const parsed = parseUrl(trimmed);
      ({ host, path, queryParams } = parsed);
    }
    headers = {};
    body = null;
  }

  const category = categorize(path);
  const baseRisk = METHOD_RISK[method];
  let riskLevel = riskForCategory(baseRisk, category);

  const sensitiveFields = detectSensitiveData(body, headers, {
    maxFinancialAmount: options?.maxFinancialAmount,
  });

  // Further escalate if CRITICAL sensitive data was found
  const hasCritical = sensitiveFields.some((f) => f.sensitivity === 'CRITICAL');
  if (hasCritical) {
    riskLevel = 'CRITICAL';
  }

  const itemCount = detectItemCount(body);
  const isBulk = category === 'bulk' || (itemCount !== null && itemCount > 100);

  return {
    raw: trimmed,
    method,
    host,
    path,
    queryParams,
    headers,
    body,
    endpointCategory: category,
    riskLevel,
    isDestructive: method === 'DELETE',
    isBulk,
    itemCount,
    sensitiveFields,
    metadata: {
      parsedAt: new Date().toISOString(),
      hasCredentialsInUrl: hasCredentialsInUrl(queryParams),
    },
  };
}
