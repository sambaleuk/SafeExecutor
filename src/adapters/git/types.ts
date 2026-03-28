import type { RiskLevel } from '../../types/index.js';

// ─── Git Action Types ──────────────────────────────────────────────────────────

export type GitAction =
  | 'push'
  | 'force-push'
  | 'rebase'
  | 'reset'
  | 'checkout'
  | 'branch-delete'
  | 'tag-delete'
  | 'merge'
  | 'cherry-pick'
  | 'stash-drop'
  | 'reflog-expire'
  | 'gc'
  | 'clean'
  | 'commit-amend'
  | 'fetch'
  | 'status'
  | 'log'
  | 'diff'
  | 'show'
  | 'branch-list'
  | 'stash-list'
  | 'remote'
  | 'commit'
  | 'stash'
  | 'unknown';

// ─── Dangerous Pattern ────────────────────────────────────────────────────────

export interface DangerousPattern {
  pattern: string;
  description: string;
  severity: 'HIGH' | 'CRITICAL' | 'DENY';
}

// ─── Parsed Git Command ────────────────────────────────────────────────────────

export interface ParsedGitCommand {
  raw: string;
  /** Git subcommand: push, commit, rebase, reset, etc. */
  subcommand: string;
  /** Classified action (may differ from subcommand for compound ops like force-push) */
  action: GitAction;
  /** All flags found in the command */
  flags: string[];
  /** Ref names (branches, tags, SHAs) extracted from the command */
  refs: string[];
  /** Remote name (e.g. origin, upstream) */
  remote: string | undefined;
  /** Target branch name */
  branch: string | undefined;
  /** Risk classification */
  riskLevel: RiskLevel;
  /** True when the operation is irreversible or destructive */
  isDestructive: boolean;
  /** True if --force / -f / --force-with-lease is present */
  isForce: boolean;
  /** True if targeting a protected branch (main, master, release/*) */
  isProtectedBranch: boolean;
  /** True when the command rewrites published history */
  rewritesHistory: boolean;
  /** Dangerous patterns detected */
  dangerousPatterns: DangerousPattern[];
  parameters: Record<string, string>;
  metadata: Record<string, unknown>;
}

// ─── Git Snapshot (for rollback) ─────────────────────────────────────────────

export interface GitSnapshot {
  commandId: string;
  timestamp: Date;
  /** SHA of HEAD before the operation */
  headSha?: string;
  /** Branch name before the operation */
  branchName?: string;
  preState: string;
}

// ─── Policy types ─────────────────────────────────────────────────────────────

export interface GitRuleMatch {
  actions?: GitAction[];
  isForce?: boolean;
  isProtectedBranch?: boolean;
  rewritesHistory?: boolean;
  isDestructive?: boolean;
  flags?: string[];
}

export interface GitPolicyRule {
  id: string;
  description: string;
  match: GitRuleMatch;
  action: 'allow' | 'deny' | 'require_approval' | 'require_dry_run';
  riskLevel: RiskLevel;
  message?: string;
}

export interface GitPolicy {
  version: string;
  rules: GitPolicyRule[];
  defaults: {
    allowUnknown: boolean;
    defaultRiskLevel: RiskLevel;
  };
}

export interface GitPolicyDecision {
  allowed: boolean;
  riskLevel: RiskLevel;
  requiresDryRun: boolean;
  requiresApproval: boolean;
  matchedRules: GitPolicyRule[];
  message: string;
}
