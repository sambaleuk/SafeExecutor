import type { LeakDetectionResult, DetectedLeak, LeakType } from './types.js';

interface LeakPattern {
  type: LeakType;
  regex: RegExp;
  /** Minimum length for the captured group to count as a real match */
  minLength?: number;
}

const LEAK_PATTERNS: LeakPattern[] = [
  // AWS Access Key ID: starts with AKIA, 20 chars
  { type: 'aws-access-key', regex: /\b(AKIA[0-9A-Z]{16})\b/g },
  // AWS Secret Access Key: 40 base64 chars after known prefixes
  { type: 'aws-secret-key', regex: /(?:aws_secret_access_key|secret_access_key|AWS_SECRET_ACCESS_KEY)['"=:\s]+([A-Za-z0-9/+=]{40})/g },
  // GitHub Personal Access Token (classic: ghp_, fine-grained: github_pat_)
  { type: 'github-pat', regex: /\b(ghp_[A-Za-z0-9]{36,})\b/g },
  { type: 'github-pat', regex: /\b(github_pat_[A-Za-z0-9_]{22,})\b/g },
  // GitHub OAuth token
  { type: 'github-oauth', regex: /\b(gho_[A-Za-z0-9]{36,})\b/g },
  // JWT (3 dot-separated base64url segments)
  { type: 'jwt', regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g },
  // PEM private key
  { type: 'private-key', regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)/g },
  // Generic API key patterns (key=..., token=..., etc.)
  { type: 'generic-api-key', regex: /(?:api[_-]?key|api[_-]?token|access[_-]?token)['"=:\s]+["']?([A-Za-z0-9_\-./+=]{20,})["']?/gi, minLength: 20 },
  // Generic secret (password=..., secret=...)
  { type: 'generic-secret', regex: /(?:password|passwd|secret)['"=:\s]+["']?([^\s"']{8,})["']?/gi, minLength: 8 },
];

/**
 * Mask a secret value, keeping the first 4 and last 4 characters visible.
 */
export function maskSecret(value: string): string {
  if (value.length <= 12) return '*'.repeat(value.length);
  return value.slice(0, 4) + '*'.repeat(value.length - 8) + value.slice(-4);
}

/**
 * Scan a string for leaked secrets (API keys, tokens, private keys, etc.).
 * Returns detection results with masked values suitable for logging.
 */
export function detectLeaks(input: string): LeakDetectionResult {
  const leaks: DetectedLeak[] = [];
  const seenPositions = new Set<string>();

  for (const pattern of LEAK_PATTERNS) {
    // Reset regex lastIndex for global patterns
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = pattern.regex.exec(input)) !== null) {
      const captured = match[1] ?? match[0];
      const start = match.index + (match[0].indexOf(captured));
      const end = start + captured.length;
      const posKey = `${start}:${end}`;

      if (seenPositions.has(posKey)) continue;
      if (pattern.minLength && captured.length < pattern.minLength) continue;

      seenPositions.add(posKey);
      leaks.push({
        type: pattern.type,
        value: captured,
        masked: maskSecret(captured),
        position: { start, end },
      });
    }
  }

  // Sort by position
  leaks.sort((a, b) => a.position.start - b.position.start);

  // Build masked output
  let maskedValue = input;
  // Replace in reverse order to preserve positions
  for (let i = leaks.length - 1; i >= 0; i--) {
    const leak = leaks[i];
    maskedValue =
      maskedValue.slice(0, leak.position.start) +
      leak.masked +
      maskedValue.slice(leak.position.end);
  }

  return {
    hasLeaks: leaks.length > 0,
    leaks,
    maskedValue,
  };
}
