import { readFileSync } from 'fs';
import { parseGitCommand } from '../src/adapters/git/parser.js';
import { simulateGitCommand } from '../src/adapters/git/sandbox.js';
import { GitAdapter, evaluateGitPolicy } from '../src/adapters/git/adapter.js';
import type { GitPolicy } from '../src/adapters/git/types.js';

// ─── Fixtures ──────────────────────────────────────────────────────────────────

const defaultPolicy = JSON.parse(
  readFileSync(new URL('../config/policies/git-default-policy.json', import.meta.url), 'utf-8'),
) as GitPolicy;

// ─── Parser: subcommand extraction ────────────────────────────────────────────

describe('parseGitCommand — subcommand extraction', () => {
  test('extracts push subcommand', () => {
    const r = parseGitCommand('git push origin main');
    expect(r.subcommand).toBe('push');
  });

  test('extracts rebase subcommand', () => {
    const r = parseGitCommand('git rebase main');
    expect(r.subcommand).toBe('rebase');
  });

  test('extracts reset subcommand', () => {
    const r = parseGitCommand('git reset --hard HEAD~1');
    expect(r.subcommand).toBe('reset');
  });

  test('extracts clean subcommand', () => {
    const r = parseGitCommand('git clean -fd');
    expect(r.subcommand).toBe('clean');
  });

  test('extracts commit subcommand', () => {
    const r = parseGitCommand('git commit -m "fix: update"');
    expect(r.subcommand).toBe('commit');
  });

  test('throws on empty command', () => {
    expect(() => parseGitCommand('')).toThrow('Empty git command');
  });
});

// ─── Parser: action classification ────────────────────────────────────────────

describe('parseGitCommand — action classification', () => {
  test('push → action push', () => {
    const r = parseGitCommand('git push origin feature/my-feature');
    expect(r.action).toBe('push');
  });

  test('push --force → action force-push', () => {
    const r = parseGitCommand('git push --force origin feature/test');
    expect(r.action).toBe('force-push');
  });

  test('push -f → action force-push', () => {
    const r = parseGitCommand('git push -f origin feature/test');
    expect(r.action).toBe('force-push');
  });

  test('push --force-with-lease → action force-push', () => {
    const r = parseGitCommand('git push --force-with-lease origin feature/test');
    expect(r.action).toBe('force-push');
  });

  test('rebase → action rebase', () => {
    const r = parseGitCommand('git rebase origin/main');
    expect(r.action).toBe('rebase');
  });

  test('reset --hard → action reset', () => {
    const r = parseGitCommand('git reset --hard HEAD~1');
    expect(r.action).toBe('reset');
  });

  test('checkout → action checkout', () => {
    const r = parseGitCommand('git checkout feature/my-branch');
    expect(r.action).toBe('checkout');
  });

  test('branch -d → action branch-delete', () => {
    const r = parseGitCommand('git branch -d feature/old');
    expect(r.action).toBe('branch-delete');
  });

  test('branch -D → action branch-delete', () => {
    const r = parseGitCommand('git branch -D feature/old');
    expect(r.action).toBe('branch-delete');
  });

  test('tag -d → action tag-delete', () => {
    const r = parseGitCommand('git tag -d v1.0.0');
    expect(r.action).toBe('tag-delete');
  });

  test('merge → action merge', () => {
    const r = parseGitCommand('git merge feature/new-feature');
    expect(r.action).toBe('merge');
  });

  test('cherry-pick → action cherry-pick', () => {
    const r = parseGitCommand('git cherry-pick abc1234');
    expect(r.action).toBe('cherry-pick');
  });

  test('stash drop → action stash-drop', () => {
    const r = parseGitCommand('git stash drop stash@{0}');
    expect(r.action).toBe('stash-drop');
  });

  test('reflog expire → action reflog-expire', () => {
    const r = parseGitCommand('git reflog expire --expire=now --all');
    expect(r.action).toBe('reflog-expire');
  });

  test('gc → action gc', () => {
    const r = parseGitCommand('git gc --prune=now');
    expect(r.action).toBe('gc');
  });

  test('clean → action clean', () => {
    const r = parseGitCommand('git clean -fd');
    expect(r.action).toBe('clean');
  });

  test('commit --amend → action commit-amend', () => {
    const r = parseGitCommand('git commit --amend --no-edit');
    expect(r.action).toBe('commit-amend');
  });

  test('status → action status', () => {
    const r = parseGitCommand('git status');
    expect(r.action).toBe('status');
  });

  test('log → action log', () => {
    const r = parseGitCommand('git log --oneline');
    expect(r.action).toBe('log');
  });

  test('diff → action diff', () => {
    const r = parseGitCommand('git diff HEAD');
    expect(r.action).toBe('diff');
  });

  test('fetch → action fetch', () => {
    const r = parseGitCommand('git fetch origin');
    expect(r.action).toBe('fetch');
  });

  test('branch (no flags) → action branch-list', () => {
    const r = parseGitCommand('git branch');
    expect(r.action).toBe('branch-list');
  });
});

// ─── Parser: risk classification ──────────────────────────────────────────────

describe('parseGitCommand — risk classification', () => {
  test('status is LOW risk', () => {
    expect(parseGitCommand('git status').riskLevel).toBe('LOW');
  });

  test('log is LOW risk', () => {
    expect(parseGitCommand('git log --oneline').riskLevel).toBe('LOW');
  });

  test('fetch is LOW risk', () => {
    expect(parseGitCommand('git fetch origin').riskLevel).toBe('LOW');
  });

  test('commit is MEDIUM risk', () => {
    expect(parseGitCommand('git commit -m "chore: update"').riskLevel).toBe('MEDIUM');
  });

  test('push to feature branch is MEDIUM risk', () => {
    expect(parseGitCommand('git push origin feature/test').riskLevel).toBe('MEDIUM');
  });

  test('push to main is HIGH risk', () => {
    expect(parseGitCommand('git push origin main').riskLevel).toBe('HIGH');
  });

  test('rebase is HIGH risk', () => {
    expect(parseGitCommand('git rebase origin/main').riskLevel).toBe('HIGH');
  });

  test('reset --soft is HIGH risk', () => {
    expect(parseGitCommand('git reset --soft HEAD~1').riskLevel).toBe('HIGH');
  });

  test('commit --amend is HIGH risk', () => {
    expect(parseGitCommand('git commit --amend --no-edit').riskLevel).toBe('HIGH');
  });

  test('push --force is CRITICAL risk', () => {
    expect(parseGitCommand('git push --force origin feature/test').riskLevel).toBe('CRITICAL');
  });

  test('push --force to main is CRITICAL risk', () => {
    expect(parseGitCommand('git push --force origin main').riskLevel).toBe('CRITICAL');
  });

  test('reset --hard is CRITICAL risk', () => {
    expect(parseGitCommand('git reset --hard HEAD~3').riskLevel).toBe('CRITICAL');
  });

  test('clean -fdx is CRITICAL risk', () => {
    expect(parseGitCommand('git clean -fdx').riskLevel).toBe('CRITICAL');
  });

  test('reflog expire is CRITICAL risk', () => {
    expect(parseGitCommand('git reflog expire --expire=now --all').riskLevel).toBe('CRITICAL');
  });

  test('gc --prune is CRITICAL risk', () => {
    expect(parseGitCommand('git gc --prune=now').riskLevel).toBe('CRITICAL');
  });
});

// ─── Parser: dangerous patterns ───────────────────────────────────────────────

describe('parseGitCommand — dangerous pattern detection', () => {
  test('detects force-push to main as DENY', () => {
    const r = parseGitCommand('git push --force origin main');
    const deny = r.dangerousPatterns.find(d => d.severity === 'DENY');
    expect(deny).toBeDefined();
    expect(deny?.pattern).toBe('force-push-to-main');
  });

  test('detects reset --hard as CRITICAL', () => {
    const r = parseGitCommand('git reset --hard HEAD~1');
    const crit = r.dangerousPatterns.find(d => d.pattern === 'reset-hard');
    expect(crit).toBeDefined();
    expect(crit?.severity).toBe('CRITICAL');
  });

  test('detects force-push (non-main) as CRITICAL', () => {
    const r = parseGitCommand('git push --force origin feature/test');
    const p = r.dangerousPatterns.find(d => d.pattern === 'force-push');
    expect(p).toBeDefined();
    expect(p?.severity).toBe('CRITICAL');
  });

  test('detects branch force-delete as HIGH', () => {
    const r = parseGitCommand('git branch -D feature/old');
    const p = r.dangerousPatterns.find(d => d.pattern === 'branch-force-delete');
    expect(p).toBeDefined();
    expect(p?.severity).toBe('HIGH');
  });

  test('detects commit --amend as HIGH', () => {
    const r = parseGitCommand('git commit --amend --no-edit');
    const p = r.dangerousPatterns.find(d => d.pattern === 'commit-amend');
    expect(p).toBeDefined();
    expect(p?.severity).toBe('HIGH');
  });

  test('detects reflog expire as CRITICAL', () => {
    const r = parseGitCommand('git reflog expire --expire=now --all');
    const p = r.dangerousPatterns.find(d => d.pattern === 'reflog-expire');
    expect(p).toBeDefined();
    expect(p?.severity).toBe('CRITICAL');
  });

  test('detects gc --prune as CRITICAL', () => {
    const r = parseGitCommand('git gc --prune=now');
    const p = r.dangerousPatterns.find(d => d.pattern === 'gc-prune');
    expect(p).toBeDefined();
    expect(p?.severity).toBe('CRITICAL');
  });

  test('no dangerous patterns for git status', () => {
    const r = parseGitCommand('git status');
    expect(r.dangerousPatterns).toHaveLength(0);
  });

  test('no dangerous patterns for git fetch', () => {
    const r = parseGitCommand('git fetch origin');
    expect(r.dangerousPatterns).toHaveLength(0);
  });
});

// ─── Parser: flags & refs ─────────────────────────────────────────────────────

describe('parseGitCommand — flags and refs extraction', () => {
  test('extracts --force flag', () => {
    const r = parseGitCommand('git push --force origin feature/test');
    expect(r.flags).toContain('--force');
    expect(r.isForce).toBe(true);
  });

  test('extracts -D flag (force delete)', () => {
    const r = parseGitCommand('git branch -D my-branch');
    expect(r.flags).toContain('-D');
    expect(r.isForce).toBe(true);
  });

  test('extracts remote', () => {
    const r = parseGitCommand('git push origin feature/test');
    expect(r.remote).toBe('origin');
  });

  test('extracts branch from push', () => {
    const r = parseGitCommand('git push origin feature/my-branch');
    expect(r.branch).toBe('feature/my-branch');
  });

  test('isProtectedBranch true for main', () => {
    const r = parseGitCommand('git push origin main');
    expect(r.isProtectedBranch).toBe(true);
  });

  test('isProtectedBranch true for master', () => {
    const r = parseGitCommand('git push origin master');
    expect(r.isProtectedBranch).toBe(true);
  });

  test('isProtectedBranch true for release branch', () => {
    const r = parseGitCommand('git push origin release/1.2.0');
    expect(r.isProtectedBranch).toBe(true);
  });

  test('isProtectedBranch false for feature branch', () => {
    const r = parseGitCommand('git push origin feature/test');
    expect(r.isProtectedBranch).toBe(false);
  });
});

// ─── Sandbox ─────────────────────────────────────────────────────────────────

describe('simulateGitCommand', () => {
  test('DENY pattern returns feasible:false', async () => {
    const intent = parseGitCommand('git push --force origin main');
    const result = await simulateGitCommand(intent);
    expect(result.feasible).toBe(false);
    expect(result.summary).toContain('DENIED');
  });

  test('hard reset returns feasible:true with warning', async () => {
    const intent = parseGitCommand('git reset --hard HEAD~1');
    const result = await simulateGitCommand(intent);
    expect(result.feasible).toBe(true);
    expect(result.warnings.some(w => w.includes('CRITICAL') || w.includes('HARD'))).toBe(true);
  });

  test('protected branch push includes warning', async () => {
    const intent = parseGitCommand('git push origin main');
    const result = await simulateGitCommand(intent);
    expect(result.feasible).toBe(true);
    expect(result.warnings.some(w => w.toLowerCase().includes('protected'))).toBe(true);
  });

  test('git status returns no warnings', async () => {
    const intent = parseGitCommand('git status');
    const result = await simulateGitCommand(intent);
    expect(result.feasible).toBe(true);
    expect(result.warnings).toHaveLength(0);
  });

  test('branch delete includes destructive warning', async () => {
    const intent = parseGitCommand('git branch -D feature/old');
    const result = await simulateGitCommand(intent);
    expect(result.feasible).toBe(true);
    expect(result.warnings.length).toBeGreaterThan(0);
  });

  test('stash drop includes irreversible warning', async () => {
    const intent = parseGitCommand('git stash drop stash@{0}');
    const result = await simulateGitCommand(intent);
    expect(result.feasible).toBe(true);
    expect(result.summary).toContain('STASH DROP');
  });
});

// ─── Policy evaluation ────────────────────────────────────────────────────────

describe('evaluateGitPolicy', () => {
  test('force push to main → denied', () => {
    const intent = parseGitCommand('git push --force origin main');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.allowed).toBe(false);
  });

  test('force push to feature branch → requires approval', () => {
    const intent = parseGitCommand('git push --force origin feature/test');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('rebase → requires approval', () => {
    const intent = parseGitCommand('git rebase origin/main');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('branch -D → requires approval', () => {
    const intent = parseGitCommand('git branch -D feature/old');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('tag -d → requires approval', () => {
    const intent = parseGitCommand('git tag -d v1.0.0');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('git clean → requires approval', () => {
    const intent = parseGitCommand('git clean -fd');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('reflog expire → requires approval', () => {
    const intent = parseGitCommand('git reflog expire --expire=now --all');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('gc --prune → requires approval', () => {
    const intent = parseGitCommand('git gc --prune=now');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('commit --amend → requires dry-run', () => {
    const intent = parseGitCommand('git commit --amend --no-edit');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.requiresDryRun).toBe(true);
  });

  test('reset → requires dry-run', () => {
    const intent = parseGitCommand('git reset --hard HEAD~1');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.requiresDryRun).toBe(true);
  });

  test('git status → allowed', () => {
    const intent = parseGitCommand('git status');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.allowed).toBe(true);
    expect(decision.requiresApproval).toBe(false);
  });

  test('git log → allowed', () => {
    const intent = parseGitCommand('git log --oneline');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.allowed).toBe(true);
    expect(decision.riskLevel).toBe('LOW');
  });

  test('git fetch → allowed', () => {
    const intent = parseGitCommand('git fetch origin');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.allowed).toBe(true);
    expect(decision.requiresApproval).toBe(false);
  });

  test('push to main → dry-run required', () => {
    const intent = parseGitCommand('git push origin main');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.requiresDryRun).toBe(true);
  });

  test('push to feature branch → medium risk allowed', () => {
    const intent = parseGitCommand('git push origin feature/my-feature');
    const decision = evaluateGitPolicy(intent, defaultPolicy);
    expect(decision.allowed).toBe(true);
    expect(decision.requiresApproval).toBe(false);
  });
});

// ─── Adapter ──────────────────────────────────────────────────────────────────

describe('GitAdapter', () => {
  const adapter = new GitAdapter();

  test('adapter name is git', () => {
    expect(adapter.name).toBe('git');
  });

  test('parseIntent returns ParsedGitCommand', () => {
    const r = adapter.parseIntent('git status');
    expect(r.action).toBe('status');
    expect(r.riskLevel).toBe('LOW');
  });

  test('sandbox rejects DENY pattern', async () => {
    const intent = adapter.parseIntent('git push --force origin main');
    const result = await adapter.sandbox(intent);
    expect(result.feasible).toBe(false);
  });

  test('sandbox returns simulation for safe command', async () => {
    const intent = adapter.parseIntent('git status');
    const result = await adapter.sandbox(intent);
    expect(result.feasible).toBe(true);
    expect(result.summary).toBeDefined();
  });

  test('rollback throws without headSha', async () => {
    const intent = adapter.parseIntent('git reset --hard HEAD~1');
    const snapshot = {
      commandId: 'test-123',
      timestamp: new Date(),
      preState: 'before-reset',
    };
    await expect(adapter.rollback(intent, snapshot)).rejects.toThrow();
  });

  test('parseIntent preserves raw command', () => {
    const cmd = 'git push origin feature/test';
    const r = adapter.parseIntent(cmd);
    expect(r.raw).toBe(cmd);
  });
});
