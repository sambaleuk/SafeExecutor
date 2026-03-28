/**
 * Auto-Detect — Determine which SafeExecutor domain an input belongs to.
 *
 * Uses keyword/prefix matching to classify raw command strings into one of
 * the supported domains: sql, cloud, kubernetes, filesystem, cicd, api,
 * secrets, git, network, queue.
 */

export type Domain =
  | 'sql'
  | 'cloud'
  | 'kubernetes'
  | 'filesystem'
  | 'cicd'
  | 'api'
  | 'secrets'
  | 'git'
  | 'network'
  | 'queue';

export const SUPPORTED_DOMAINS: readonly Domain[] = [
  'sql',
  'cloud',
  'kubernetes',
  'filesystem',
  'cicd',
  'api',
  'secrets',
  'git',
  'network',
  'queue',
] as const;

interface DetectionRule {
  domain: Domain;
  /** Prefix strings — matched against trimmed, lowercased input */
  prefixes?: string[];
  /** Keywords anywhere in the input (case-insensitive) */
  keywords?: RegExp[];
  /** Full-line regex patterns */
  patterns?: RegExp[];
}

const RULES: DetectionRule[] = [
  // ── SQL ──────────────────────────────────────────────────────────────────
  {
    domain: 'sql',
    patterns: [
      /^\s*(SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|TRUNCATE|ALTER\s+TABLE|DROP\s+TABLE|CREATE\s+TABLE|CREATE\s+INDEX|DROP\s+INDEX|EXPLAIN|WITH\s+\w+\s+AS)/i,
    ],
  },

  // ── Git ──────────────────────────────────────────────────────────────────
  {
    domain: 'git',
    prefixes: ['git '],
  },

  // ── Kubernetes ───────────────────────────────────────────────────────────
  {
    domain: 'kubernetes',
    prefixes: ['kubectl ', 'helm ', 'k9s ', 'kubectx ', 'kubens '],
  },

  // ── Cloud (Terraform / AWS / GCP / Azure) ────────────────────────────────
  {
    domain: 'cloud',
    prefixes: ['terraform ', 'aws ', 'gcloud ', 'az ', 'pulumi ', 'cdk '],
  },

  // ── CI/CD ────────────────────────────────────────────────────────────────
  {
    domain: 'cicd',
    prefixes: ['gh workflow ', 'gh run ', 'gitlab-ci ', 'jenkins ', 'circleci ', 'argocd '],
    patterns: [
      /^\s*gh\s+(workflow|run)\s/i,
    ],
  },

  // ── Secrets ──────────────────────────────────────────────────────────────
  {
    domain: 'secrets',
    prefixes: ['vault '],
    patterns: [
      /^\s*aws\s+secretsmanager\s/i,
      /^\s*az\s+keyvault\s/i,
      /^\s*gcloud\s+secrets?\s/i,
    ],
  },

  // ── Network ──────────────────────────────────────────────────────────────
  {
    domain: 'network',
    prefixes: [
      'iptables ', 'ip6tables ', 'ufw ', 'nmap ', 'netcat ', 'nc ',
      'telnet ', 'traceroute ', 'tracert ', 'dig ', 'nslookup ',
    ],
    patterns: [
      /^\s*ip\s+(addr|route|link|neigh|rule)\s/i,
      /^\s*route\s+(add|del|delete)\s/i,
      /^\s*ssh\s+/i,
      /^\s*ping\s+/i,
    ],
  },

  // ── API (HTTP requests) ──────────────────────────────────────────────────
  {
    domain: 'api',
    prefixes: ['curl ', 'wget ', 'httpie ', 'http '],
    patterns: [
      /^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+https?:\/\//i,
      /^\s*https?:\/\//i,
    ],
  },

  // ── Queue ────────────────────────────────────────────────────────────────
  {
    domain: 'queue',
    patterns: [
      /^\s*aws\s+sqs\s/i,
      /^\s*aws\s+sns\s/i,
      /^\s*gcloud\s+pubsub\s/i,
      /^\s*rabbitmqctl\s/i,
    ],
    prefixes: ['rabbitmqctl ', 'celery '],
  },

  // ── Filesystem (shell commands) — last, as a broad catch for common CLIs
  {
    domain: 'filesystem',
    prefixes: [
      'rm ', 'cp ', 'mv ', 'chmod ', 'chown ', 'mkdir ', 'rmdir ',
      'ln ', 'touch ', 'find ', 'ls ', 'cat ', 'tar ', 'zip ', 'unzip ',
    ],
    patterns: [
      /^\s*sudo\s+(rm|cp|mv|chmod|chown|mkdir|rmdir)\s/i,
    ],
  },
];

export interface DetectionResult {
  domain: Domain;
  confidence: 'high' | 'medium' | 'low';
}

/**
 * Auto-detect the domain of a raw command string.
 * Returns the best match with a confidence level, or null if no match.
 */
export function detectDomain(raw: string): DetectionResult | null {
  const trimmed = raw.trim();
  const lower = trimmed.toLowerCase();

  for (const rule of RULES) {
    // Check prefixes first (high confidence)
    if (rule.prefixes) {
      for (const prefix of rule.prefixes) {
        if (lower.startsWith(prefix)) {
          return { domain: rule.domain, confidence: 'high' };
        }
      }
    }

    // Check full-line patterns (high confidence)
    if (rule.patterns) {
      for (const pattern of rule.patterns) {
        if (pattern.test(trimmed)) {
          return { domain: rule.domain, confidence: 'high' };
        }
      }
    }

    // Check keywords (medium confidence)
    if (rule.keywords) {
      for (const keyword of rule.keywords) {
        if (keyword.test(trimmed)) {
          return { domain: rule.domain, confidence: 'medium' };
        }
      }
    }
  }

  return null;
}

/**
 * Validate that a domain hint is a known domain.
 */
export function isValidDomain(domain: string): domain is Domain {
  return (SUPPORTED_DOMAINS as readonly string[]).includes(domain);
}
