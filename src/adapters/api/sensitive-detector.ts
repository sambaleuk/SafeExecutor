import type { SensitiveDataMatch } from './types.js';

/**
 * Sensitive Data Detector
 *
 * Scans HTTP request body and headers for credentials, PII,
 * financial data, and API tokens.
 *
 * Detection strategies:
 *   1. Field name matching (api_key, password, email, amount…)
 *   2. Value pattern matching (credit card numbers, SSNs, bearer tokens…)
 *   3. Financial threshold escalation (amount > configurable limit)
 */

// ─── Value patterns ───────────────────────────────────────────────────────────

/** Credit card number patterns */
const CC_PATTERNS: RegExp[] = [
  /\b4[0-9]{12}(?:[0-9]{3})?\b/,              // Visa
  /\b5[1-5][0-9]{14}\b/,                      // Mastercard
  /\b3[47][0-9]{13}\b/,                       // American Express
  /\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b/,      // Diners Club
  /\b6(?:011|5[0-9]{2})[0-9]{12}\b/,         // Discover
];

/** US Social Security Number */
const SSN_PATTERN = /\b\d{3}-\d{2}-\d{4}\b/;

/** Known API token patterns */
const TOKEN_PATTERNS: RegExp[] = [
  /\bsk_(live|test)_[A-Za-z0-9]{24,}\b/,     // Stripe secret key
  /\bpk_(live|test)_[A-Za-z0-9]{24,}\b/,     // Stripe publishable key
  /\bAKIA[0-9A-Z]{16}\b/,                    // AWS access key ID
  /\bghp_[A-Za-z0-9]{36,}\b/,               // GitHub personal access token
  /\bghs_[A-Za-z0-9]{36,}\b/,               // GitHub server-to-server token
  /\bxox[bpas]-[0-9A-Za-z-]+/,              // Slack token
];

/** Email pattern for value-level detection */
const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;

// ─── Field name sets ──────────────────────────────────────────────────────────

const CREDENTIAL_FIELD_NAMES = new Set([
  'api_key', 'apikey', 'api-key',
  'secret', 'secret_key', 'client_secret',
  'password', 'passwd', 'pass',
  'token', 'access_token', 'refresh_token', 'auth_token', 'id_token',
  'private_key', 'signing_key',
  'x-api-key', 'authorization',
]);

const PII_FIELD_NAMES = new Set([
  'email', 'email_address', 'emailaddress',
  'phone', 'phone_number', 'mobile', 'cell',
  'ssn', 'social_security_number', 'social_security',
  'credit_card', 'card_number', 'cc_number', 'cvv', 'cvc',
  'date_of_birth', 'dob', 'birth_date', 'birthday',
  'full_name', 'first_name', 'last_name', 'surname',
  'address', 'street_address', 'zip_code', 'postal_code',
  'national_id', 'passport_number', 'drivers_license',
]);

const FINANCIAL_FIELD_NAMES = new Set([
  'amount', 'price', 'cost', 'total', 'subtotal',
  'balance', 'credit', 'debit', 'charge',
  'revenue', 'payment', 'transaction_amount',
  'fee', 'tax', 'discount', 'unit_amount',
]);

// ─── Masking ──────────────────────────────────────────────────────────────────

/**
 * Mask a string value for safe audit logging.
 * Keeps a few chars at start and end to aid debugging without exposing secrets.
 */
export function maskValue(value: string): string {
  if (value.length <= 4) return '****';
  if (value.length <= 8) {
    return value.slice(0, 2) + '*'.repeat(value.length - 4) + value.slice(-2);
  }
  return value.slice(0, 4) + '*'.repeat(value.length - 8) + value.slice(-4);
}

function stringify(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

// ─── Per-field detection ──────────────────────────────────────────────────────

function detectField(
  field: string,
  value: unknown,
  maxFinancialAmount: number,
): SensitiveDataMatch | null {
  const fieldLower = field.toLowerCase();
  const strValue = stringify(value);

  // 1. Credential field name
  if (CREDENTIAL_FIELD_NAMES.has(fieldLower)) {
    return {
      field,
      type: 'credential',
      sensitivity: 'HIGH',
      maskedValue: maskValue(strValue),
    };
  }

  // 2. PII field name
  if (PII_FIELD_NAMES.has(fieldLower)) {
    return {
      field,
      type: 'pii',
      sensitivity: 'HIGH',
      maskedValue: maskValue(strValue),
    };
  }

  // 3. Financial field name — escalate if amount exceeds threshold
  if (FINANCIAL_FIELD_NAMES.has(fieldLower) && typeof value === 'number') {
    if (value > maxFinancialAmount) {
      return {
        field,
        type: 'financial',
        sensitivity: 'CRITICAL',
        maskedValue: maskValue(strValue),
      };
    }
    // Below threshold — not flagged
    return null;
  }

  // 4. Known token pattern in value
  for (const pattern of TOKEN_PATTERNS) {
    if (pattern.test(strValue)) {
      return {
        field,
        type: 'token',
        sensitivity: 'CRITICAL',
        maskedValue: maskValue(strValue),
      };
    }
  }

  // 5. Credit card number in value
  for (const pattern of CC_PATTERNS) {
    const cleaned = strValue.replace(/[\s-]/g, '');
    if (pattern.test(cleaned)) {
      return {
        field,
        type: 'pii',
        sensitivity: 'CRITICAL',
        maskedValue: maskValue(strValue),
      };
    }
  }

  // 6. SSN in value
  if (SSN_PATTERN.test(strValue)) {
    return {
      field,
      type: 'pii',
      sensitivity: 'HIGH',
      maskedValue: maskValue(strValue),
    };
  }

  // 7. Email in value (field name didn't indicate PII)
  if (EMAIL_PATTERN.test(strValue)) {
    return {
      field,
      type: 'pii',
      sensitivity: 'LOW',
      maskedValue: maskValue(strValue),
    };
  }

  return null;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface DetectOptions {
  maxFinancialAmount?: number;
}

/**
 * Scan a request body and headers for sensitive data.
 *
 * Returns one match per field. For nested objects the field path uses dot notation.
 */
export function detectSensitiveData(
  body: Record<string, unknown> | null,
  headers: Record<string, string>,
  options?: DetectOptions,
): SensitiveDataMatch[] {
  const threshold = options?.maxFinancialAmount ?? 10_000;
  const matches: SensitiveDataMatch[] = [];
  const seen = new Set<string>();

  function add(match: SensitiveDataMatch): void {
    if (!seen.has(match.field)) {
      seen.add(match.field);
      matches.push(match);
    }
  }

  // Scan headers
  for (const [key, value] of Object.entries(headers)) {
    const m = detectField(key, value, threshold);
    if (m) {
      add(m);
      continue;
    }
    // Also check for Bearer token value in any header
    if (TOKEN_PATTERNS.some((p) => p.test(value))) {
      add({
        field: key,
        type: 'token',
        sensitivity: 'CRITICAL',
        maskedValue: maskValue(value),
      });
    }
  }

  if (!body) return matches;

  // Scan body fields (shallow + one level of nesting)
  for (const [key, value] of Object.entries(body)) {
    if (
      typeof value === 'object' &&
      value !== null &&
      !Array.isArray(value)
    ) {
      // Recurse one level
      const nested = detectSensitiveData(
        value as Record<string, unknown>,
        {},
        options,
      );
      for (const n of nested) {
        add({ ...n, field: `${key}.${n.field}` });
      }
    } else {
      const m = detectField(key, value, threshold);
      if (m) add(m);
    }
  }

  return matches;
}

/**
 * Return a copy of `data` with all sensitive field values replaced by their
 * masked equivalents. Used to produce safe audit log payloads.
 */
export function maskSensitiveFields(
  data: Record<string, unknown>,
  sensitiveFields: SensitiveDataMatch[],
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...data };
  for (const match of sensitiveFields) {
    const parts = match.field.split('.');
    if (parts.length === 1 && parts[0] !== undefined) {
      result[parts[0]] = match.maskedValue;
    }
    // Nested masking: mask the top-level key to avoid leaking sub-object data
    if (parts.length > 1 && parts[0] !== undefined) {
      result[parts[0]] = '[redacted]';
    }
  }
  return result;
}
