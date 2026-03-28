import type {
  ParsedGitCommand,
  GitAction,
  DangerousPattern,
} from './types.js';
import type { RiskLevel } from '../../types/index.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function escalateRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

const PROTECTED_BRANCHES = /^(main|master|release\/.*|hotfix\/.*)$/;

// ─── Subcommand extraction ────────────────────────────────────────────────────

function extractSubcommand(command: string): string {
  // Strip leading 'git' and whitespace
  const stripped = command.trim().replace(/^git\s+/, '');
  // First token is the subcommand
  const m = stripped.match(/^([\w-]+)/);
  return m?.[1] ?? 'unknown';
}

// ─── Flag extraction ──────────────────────────────────────────────────────────

function extractFlags(command: string): string[] {
  const matches = command.match(/--?[\w-]+=?/g) ?? [];
  return [...new Set(matches)];
}

// ─── Ref extraction ───────────────────────────────────────────────────────────

function extractRefs(command: string, subcommand: string): string[] {
  // Remove the binary name and subcommand to isolate arguments
  const stripped = command
    .trim()
    .replace(/^git\s+/, '')
    .replace(new RegExp(`^${subcommand}\\s*`), '');

  const refs: string[] = [];

  // Refspec pattern: HEAD, SHAs, branch/tag names
  const tokens = stripped.split(/\s+/);
  for (const token of tokens) {
    if (token.startsWith('-')) continue; // skip flags
    if (!token) continue;
    // Looks like a ref: alphanumeric, slashes, dots, tildes, carets
    if (/^[\w./~^@{}:-]+$/.test(token)) {
      refs.push(token);
    }
  }
  return refs;
}

// ─── Remote extraction ────────────────────────────────────────────────────────

function extractRemote(command: string, subcommand: string): string | undefined {
  if (!['push', 'fetch', 'pull'].includes(subcommand)) return undefined;

  // git push [remote] [refspec]
  const stripped = command
    .trim()
    .replace(/^git\s+/, '')
    .replace(new RegExp(`^${subcommand}\\s*`), '');

  const tokens = stripped.split(/\s+/).filter(t => t && !t.startsWith('-'));
  return tokens[0];
}

// ─── Branch extraction ────────────────────────────────────────────────────────

function extractBranch(command: string, subcommand: string, refs: string[]): string | undefined {
  // git push origin <branch>
  if (subcommand === 'push' || subcommand === 'fetch') {
    const tokens = command
      .trim()
      .replace(/^git\s+/, '')
      .replace(new RegExp(`^${subcommand}\\s*`), '')
      .split(/\s+/)
      .filter(t => t && !t.startsWith('-'));
    // tokens[0] = remote, tokens[1] = branch/refspec
    if (tokens.length >= 2) {
      const refspec = tokens[1];
      // refspec can be src:dst — we want the destination
      const parts = refspec.split(':');
      return parts[parts.length - 1] || parts[0];
    }
    return undefined;
  }

  // git checkout / switch: last non-flag token
  if (subcommand === 'checkout' || subcommand === 'switch') {
    return refs[refs.length - 1];
  }

  // git branch -d <branch>
  if (subcommand === 'branch') {
    return refs[refs.length - 1];
  }

  // git reset [--soft|--hard] <ref>
  if (subcommand === 'reset') {
    return refs[refs.length - 1];
  }

  return undefined;
}

// ─── Action classification ────────────────────────────────────────────────────

function classifyAction(
  subcommand: string,
  flags: string[],
  branch: string | undefined,
  refs: string[],
): GitAction {
  const hasForce = flags.includes('--force') || flags.includes('-f') || flags.includes('--force-with-lease');
  const hasAmend = flags.includes('--amend');

  switch (subcommand) {
    case 'push':
      return hasForce ? 'force-push' : 'push';

    case 'rebase':
      return 'rebase';

    case 'reset':
      return 'reset';

    case 'checkout':
      return 'checkout';

    case 'branch': {
      const hasForceDelete = flags.includes('-D');
      const hasDelete = flags.includes('-d') || flags.includes('--delete');
      if (hasForceDelete || hasDelete) return 'branch-delete';
      const hasList = flags.includes('-l') || flags.includes('--list') || flags.length === 0;
      return hasList ? 'branch-list' : 'checkout';
    }

    case 'tag': {
      const hasDelete = flags.includes('-d') || flags.includes('--delete');
      return hasDelete ? 'tag-delete' : 'unknown';
    }

    case 'merge':
      return 'merge';

    case 'cherry-pick':
      return 'cherry-pick';

    case 'stash': {
      if (refs.includes('list') || branch === 'list') return 'stash-list';
      if (refs.includes('drop') || branch === 'drop') return 'stash-drop';
      return 'stash';
    }

    case 'reflog': {
      if (refs.includes('expire') || branch === 'expire') return 'reflog-expire';
      return 'unknown';
    }

    case 'gc':
      return 'gc';

    case 'clean':
      return 'clean';

    case 'commit':
      return hasAmend ? 'commit-amend' : 'commit';

    case 'fetch':
      return 'fetch';

    case 'status':
      return 'status';

    case 'log':
      return 'log';

    case 'diff':
      return 'diff';

    case 'show':
      return 'show';

    case 'remote':
      return 'remote';

    default:
      return 'unknown';
  }
}

// ─── Protected branch detection ───────────────────────────────────────────────

function detectProtectedBranch(branch: string | undefined, refs: string[]): boolean {
  const candidates = [...refs, branch].filter(Boolean) as string[];
  return candidates.some(ref => {
    // Check the full ref name first (e.g. release/1.2.0, main)
    if (PROTECTED_BRANCHES.test(ref)) return true;
    // Also check with remote prefix stripped (e.g. origin/main → main)
    if (ref.includes('/')) {
      const withoutRemote = ref.split('/').slice(1).join('/');
      return PROTECTED_BRANCHES.test(withoutRemote);
    }
    return false;
  });
}

// ─── History rewrite detection ────────────────────────────────────────────────

function detectHistoryRewrite(
  subcommand: string,
  action: GitAction,
  flags: string[],
): boolean {
  if (action === 'force-push') return true;
  if (action === 'commit-amend') return true;
  if (subcommand === 'rebase') return true;
  if (subcommand === 'reset' && flags.includes('--hard')) return true;
  if (subcommand === 'filter-branch') return true;
  if (command_contains_filter_repo(flags)) return true;
  return false;
}

function command_contains_filter_repo(flags: string[]): boolean {
  // git filter-repo detection via flags presence
  return flags.some(f => f === '--filter-repo' || f === 'filter-repo');
}

// ─── Dangerous patterns ───────────────────────────────────────────────────────

const DANGEROUS_PATTERNS: Array<{
  regex: RegExp;
  pattern: string;
  description: string;
  severity: DangerousPattern['severity'];
}> = [
  {
    regex: /push\s+.*--force(?!-with-lease)\b.*(?:origin|upstream)\s+(?:main|master)\b/,
    pattern: 'force-push-to-main',
    description: 'Force push to main/master — overwrites shared history',
    severity: 'DENY',
  },
  {
    regex: /reset\s+--hard\s+.*(?:main|master)\b/,
    pattern: 'hard-reset-main',
    description: 'Hard reset on main/master — destroys unpushed commits',
    severity: 'DENY',
  },
  {
    regex: /filter-branch\b/,
    pattern: 'filter-branch',
    description: 'git filter-branch rewrites shared refs — use git filter-repo instead',
    severity: 'DENY',
  },
  {
    regex: /push\s+(?:\S+\s+)?--force(?!-with-lease)\b/,
    pattern: 'force-push',
    description: 'Force push without --force-with-lease — risk of overwriting remote changes',
    severity: 'CRITICAL',
  },
  {
    regex: /reset\s+--hard\b/,
    pattern: 'reset-hard',
    description: 'Hard reset discards all local changes and commits — unrecoverable without reflog',
    severity: 'CRITICAL',
  },
  {
    regex: /clean\s+(?:.*-[a-zA-Z]*f[a-zA-Z]*d[a-zA-Z]*|.*-[a-zA-Z]*d[a-zA-Z]*f[a-zA-Z]*)(?:\s+-x\b|\s+\/)?/,
    pattern: 'clean-fdx',
    description: 'git clean -fdx removes all untracked files including ignored ones',
    severity: 'CRITICAL',
  },
  {
    regex: /clean\s+.*-[a-zA-Z]*[fd][a-zA-Z]*/,
    pattern: 'clean-fd',
    description: 'git clean -fd removes all untracked files and directories',
    severity: 'HIGH',
  },
  {
    regex: /rebase\s+(?:-i\s+|--interactive\s+).+/,
    pattern: 'rebase-interactive',
    description: 'Interactive rebase rewrites commit history',
    severity: 'HIGH',
  },
  {
    regex: /reflog\s+expire\b/,
    pattern: 'reflog-expire',
    description: 'Expiring reflog entries makes past states unrecoverable',
    severity: 'CRITICAL',
  },
  {
    regex: /gc\s+--prune\b/,
    pattern: 'gc-prune',
    description: 'gc --prune permanently deletes unreachable objects',
    severity: 'CRITICAL',
  },
  {
    regex: /branch\s+(?:.*\s+)?-D\s+\S/,
    pattern: 'branch-force-delete',
    description: 'Force branch deletion (-D) skips merge check',
    severity: 'HIGH',
  },
  {
    regex: /commit\s+.*--amend\b/,
    pattern: 'commit-amend',
    description: 'Amending commits rewrites history — dangerous if already pushed',
    severity: 'HIGH',
  },
  {
    regex: /push\s+.*--force-with-lease\b/,
    pattern: 'force-with-lease',
    description: 'Force push with lease — safer than --force but still rewrites remote history',
    severity: 'HIGH',
  },
];

function detectDangerousPatterns(command: string): DangerousPattern[] {
  const results: DangerousPattern[] = [];
  for (const dp of DANGEROUS_PATTERNS) {
    if (dp.regex.test(command)) {
      results.push({ pattern: dp.pattern, description: dp.description, severity: dp.severity });
    }
  }
  return results;
}

// ─── Risk classification ──────────────────────────────────────────────────────

function classifyRisk(
  action: GitAction,
  isProtectedBranch: boolean,
  rewritesHistory: boolean,
  dangerousPatterns: DangerousPattern[],
  flags: string[],
): RiskLevel {
  // DENY patterns → CRITICAL
  for (const dp of dangerousPatterns) {
    if (dp.severity === 'DENY' || dp.severity === 'CRITICAL') return 'CRITICAL';
  }

  let risk: RiskLevel = 'LOW';

  // Base risk per action
  switch (action) {
    case 'status':
    case 'log':
    case 'diff':
    case 'show':
    case 'branch-list':
    case 'fetch':
    case 'stash-list':
    case 'remote':
      risk = 'LOW';
      break;

    case 'commit':
    case 'push':
    case 'checkout':
    case 'merge':
    case 'cherry-pick':
    case 'stash':
      risk = 'MEDIUM';
      break;

    case 'reset':
      risk = flags.includes('--soft') ? 'HIGH' : 'MEDIUM';
      break;

    case 'force-push':
    case 'rebase':
    case 'branch-delete':
    case 'tag-delete':
    case 'commit-amend':
      risk = 'HIGH';
      break;

    case 'stash-drop':
    case 'clean':
    case 'reflog-expire':
    case 'gc':
      risk = 'HIGH';
      break;

    default:
      risk = 'MEDIUM';
  }

  // Protected branch escalation
  if (isProtectedBranch) {
    risk = escalateRisk(risk, 'HIGH');
  }

  // History rewrite escalation
  if (rewritesHistory) {
    risk = escalateRisk(risk, 'HIGH');
  }

  // HIGH dangerous patterns
  for (const dp of dangerousPatterns) {
    if (dp.severity === 'HIGH') risk = escalateRisk(risk, 'HIGH');
  }

  return risk;
}

// ─── Destructive detection ────────────────────────────────────────────────────

function isDestructiveAction(action: GitAction, flags: string[]): boolean {
  const destructive: GitAction[] = [
    'force-push',
    'branch-delete',
    'tag-delete',
    'stash-drop',
    'reflog-expire',
    'gc',
    'clean',
  ];
  if (destructive.includes(action)) return true;
  if (action === 'reset' && flags.includes('--hard')) return true;
  return false;
}

// ─── Main parser ──────────────────────────────────────────────────────────────

export function parseGitCommand(raw: string): ParsedGitCommand {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('Empty git command');

  const subcommand = extractSubcommand(trimmed);
  const flags = extractFlags(trimmed);
  const refs = extractRefs(trimmed, subcommand);
  const remote = extractRemote(trimmed, subcommand);
  const branch = extractBranch(trimmed, subcommand, refs);

  const action = classifyAction(subcommand, flags, branch, refs);
  const isForce =
    flags.includes('--force') ||
    flags.includes('-f') ||
    flags.includes('--force-with-lease') ||
    flags.includes('-D');
  const isProtectedBranch = detectProtectedBranch(branch, refs);
  const rewritesHistory = detectHistoryRewrite(subcommand, action, flags);
  const dangerousPatterns = detectDangerousPatterns(trimmed);
  const isDestructive = isDestructiveAction(action, flags);

  const riskLevel = classifyRisk(action, isProtectedBranch, rewritesHistory, dangerousPatterns, flags);

  return {
    raw: trimmed,
    subcommand,
    action,
    flags,
    refs,
    remote,
    branch,
    riskLevel,
    isDestructive,
    isForce,
    isProtectedBranch,
    rewritesHistory,
    dangerousPatterns,
    parameters: {
      ...(remote ? { remote } : {}),
      ...(branch ? { branch } : {}),
    },
    metadata: {},
  };
}
