import type { LeakDetectionResult, LeakPattern } from './types.js';

/**
 * Secret Leak Detector
 *
 * Detects:
 *   - Known secret patterns embedded in commands (API keys, tokens, JWT, private keys)
 *   - Potential exfiltration attempts (pipe to curl, redirect to file, etc.)
 *
 * All matched values are masked in the returned `masked` string for safe audit logging.
 */

// ─── Known Secret Patterns ────────────────────────────────────────────────────

const LEAK_PATTERNS: LeakPattern[] = [
  {
    name: 'aws-access-key-id',
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    severity: 'CRITICAL',
  },
  {
    name: 'aws-secret-access-key',
    // 40-char base64 after the flag
    pattern: /(?:--secret-access-key|SecretAccessKey[":=\s]+)\s*([A-Za-z0-9/+]{40})\b/,
    severity: 'CRITICAL',
  },
  {
    name: 'github-token',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/,
    severity: 'CRITICAL',
  },
  {
    name: 'github-fine-grained-pat',
    pattern: /\bgithub_pat_[A-Za-z0-9_]{82}\b/,
    severity: 'CRITICAL',
  },
  {
    name: 'slack-token',
    pattern: /\bxox[baprs]-[0-9a-zA-Z-]{10,48}\b/,
    severity: 'HIGH',
  },
  {
    name: 'jwt-token',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    severity: 'HIGH',
  },
  {
    name: 'private-key-marker',
    pattern: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/,
    severity: 'CRITICAL',
  },
  {
    name: 'generic-secret-flag-value',
    // Long high-entropy value after a sensitive flag (not a file reference with @)
    pattern: /--(?:secret-string|value|password|token|api-key|apikey|secret)\s+(?!@)([A-Za-z0-9+/=_\-!@#$%^&*]{20,})\b/i,
    severity: 'HIGH',
  },
  {
    name: 'vault-inline-value',
    // vault kv put secret/path key=longvalue
    pattern: /\bvalue=([A-Za-z0-9+/=_\-!@#$%^&*]{16,})\b/,
    severity: 'HIGH',
  },
];

// ─── Exfiltration Patterns ────────────────────────────────────────────────────

const EXFILTRATION_PATTERNS: RegExp[] = [
  /\|\s*curl\b/i,                    // pipe to curl
  /\|\s*wget\b/i,                    // pipe to wget
  /\|\s*ncat?\b/i,                   // pipe to netcat/ncat
  /\|\s*base64\b/i,                  // pipe to base64 (encode for exfil)
  /\|\s*xxd\b/i,                     // pipe to hex dump
  /\|\s*python[0-9.]?\s/i,           // pipe to python
  /\|\s*node\b/i,                    // pipe to node
  />>?\s*\/(?!dev\/null)/,           // redirect to file path (not /dev/null)
  />>?\s*~\//,                       // redirect to home directory
  />>?\s*\.\//,                      // redirect to relative path
  />>?\s*[A-Za-z]:\\/,              // redirect to Windows path
  /\bscp\s/i,                        // secure copy (could be used to exfil)
  /\brsync\s.*--password/i,          // rsync with credentials
];

// ─── Masking ──────────────────────────────────────────────────────────────────

function maskMatches(command: string, pattern: RegExp): string {
  return command.replace(pattern, (match) => {
    // If the match starts with a flag (e.g. "--secret-string somevalue"), keep the flag name
    const flagMatch = match.match(/^(--[\w-]+\s+)/);
    if (flagMatch?.[1]) {
      return `${flagMatch[1]}[REDACTED]`;
    }
    // For key=value patterns, keep the key
    const kvMatch = match.match(/^(\w+=)/);
    if (kvMatch?.[1]) {
      return `${kvMatch[1]}[REDACTED]`;
    }
    return '[REDACTED]';
  });
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function detectLeaks(command: string): LeakDetectionResult {
  const matchedPatterns: string[] = [];
  let masked = command;
  let isExfiltration = false;

  for (const lp of LEAK_PATTERNS) {
    if (lp.pattern.test(command)) {
      matchedPatterns.push(`${lp.name}:${lp.severity}`);
      masked = maskMatches(masked, lp.pattern);
    }
  }

  for (const ep of EXFILTRATION_PATTERNS) {
    if (ep.test(command)) {
      isExfiltration = true;
      break;
    }
  }

  return {
    hasLeak: matchedPatterns.length > 0,
    patterns: matchedPatterns,
    masked,
    isExfiltration,
  };
}

export function maskSecrets(command: string): string {
  return detectLeaks(command).masked;
}
