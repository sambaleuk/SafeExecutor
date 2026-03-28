import { spawnSync } from 'child_process';
import type { SimulationResult } from '../../core/types.js';
import type { ParsedGitCommand } from './types.js';

// ─── Dry-run helpers ──────────────────────────────────────────────────────────

/**
 * Runs git push --dry-run to preview what would be pushed.
 * Returns stdout/stderr output.
 */
function dryRunPush(parsed: ParsedGitCommand): string {
  const args = ['push', '--dry-run'];
  if (parsed.remote) args.push(parsed.remote);
  if (parsed.branch) args.push(parsed.branch);

  const result = spawnSync('git', args, { encoding: 'utf8', timeout: 15_000, shell: false });
  const out = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
  return out || '(no output from git push --dry-run)';
}

/**
 * Runs git clean -n (--dry-run) to preview files that would be removed.
 */
function dryRunClean(parsed: ParsedGitCommand): string {
  // Preserve original flags but add -n, remove any -f
  const cleanFlags = parsed.flags
    .filter(f => f !== '-f' && f !== '--force' && f !== '-F')
    .join('');
  const args = ['clean', '-n'];
  if (/d/.test(cleanFlags)) args.push('-d');
  if (/x/.test(cleanFlags)) args.push('-x');

  const result = spawnSync('git', args, { encoding: 'utf8', timeout: 10_000, shell: false });
  const out = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
  return out || '(nothing would be removed)';
}

/**
 * Runs git merge --no-commit --no-ff to preview merge outcome.
 * Always resets back with git merge --abort to leave no side effects.
 */
function dryRunMerge(parsed: ParsedGitCommand): string {
  const ref = parsed.branch ?? parsed.refs[0];
  if (!ref) return '(no target branch specified for merge preview)';

  const mergeResult = spawnSync('git', ['merge', '--no-commit', '--no-ff', ref], {
    encoding: 'utf8',
    timeout: 15_000,
    shell: false,
  });

  // Always abort so no side effects remain
  spawnSync('git', ['merge', '--abort'], { encoding: 'utf8', shell: false });

  const out = [mergeResult.stdout, mergeResult.stderr].filter(Boolean).join('\n').trim();
  return out || '(merge would succeed with no conflicts)';
}

// ─── Summary builder ──────────────────────────────────────────────────────────

function buildSummary(
  parsed: ParsedGitCommand,
  dryRunOutput: string,
  warnings: string[],
): string {
  const lines: string[] = [
    '[DRY-RUN] Git Command Preview',
    `Subcommand : ${parsed.subcommand}`,
    `Action     : ${parsed.action}`,
    `Risk       : ${parsed.riskLevel}`,
  ];
  if (parsed.remote) lines.push(`Remote     : ${parsed.remote}`);
  if (parsed.branch) lines.push(`Branch     : ${parsed.branch}`);
  if (parsed.refs.length > 0) lines.push(`Refs       : ${parsed.refs.join(', ')}`);

  if (dryRunOutput) {
    lines.push('');
    lines.push('Simulation output:');
    for (const l of dryRunOutput.split('\n')) lines.push(`  ${l}`);
  }

  if (warnings.length > 0) {
    lines.push('');
    lines.push('Warnings:');
    for (const w of warnings) lines.push(`  ⚠  ${w}`);
  }

  return lines.join('\n');
}

// ─── Main sandbox function ────────────────────────────────────────────────────

/**
 * Simulates a git command without committing side effects.
 *
 * - push          → git push --dry-run
 * - clean         → git clean -n
 * - merge         → git merge --no-commit --no-ff + merge --abort
 * - destructive   → describe what would happen, no execution
 */
export async function simulateGitCommand(parsed: ParsedGitCommand): Promise<SimulationResult> {
  const start = Date.now();
  const warnings: string[] = [];

  // ── Hard denies — never simulate, just reject ─────────────────────────────
  for (const dp of parsed.dangerousPatterns) {
    if (dp.severity === 'DENY') {
      return {
        feasible: false,
        resourcesImpacted: 0,
        summary: `DENIED: ${dp.description}`,
        warnings: [`Dangerous pattern '${dp.pattern}': ${dp.description}`],
        durationMs: Date.now() - start,
      };
    }
  }

  // Collect warnings from dangerous patterns
  for (const dp of parsed.dangerousPatterns) {
    if (dp.severity === 'HIGH' || dp.severity === 'CRITICAL') {
      warnings.push(`${dp.severity}: ${dp.description}`);
    }
  }

  if (parsed.isProtectedBranch) {
    warnings.push(`Targeting protected branch '${parsed.branch ?? parsed.refs.join(', ')}' — high impact`);
  }

  if (parsed.rewritesHistory) {
    warnings.push('This operation rewrites published history — may require force-push and team coordination');
  }

  if (parsed.isDestructive) {
    warnings.push(`Destructive operation '${parsed.action}' — may cause irreversible data loss`);
  }

  // ── Per-action simulation ─────────────────────────────────────────────────
  let dryRunOutput = '';
  let resourcesImpacted = -1;

  switch (parsed.action) {
    case 'push':
    case 'force-push':
      dryRunOutput = dryRunPush(parsed);
      resourcesImpacted = 1;
      break;

    case 'clean':
      dryRunOutput = dryRunClean(parsed);
      // Count lines that start with "Would remove"
      resourcesImpacted = (dryRunOutput.match(/Would remove/g) ?? []).length;
      break;

    case 'merge':
      dryRunOutput = dryRunMerge(parsed);
      resourcesImpacted = 1;
      break;

    case 'reset':
      dryRunOutput = parsed.flags.includes('--hard')
        ? `HARD RESET to '${parsed.branch ?? parsed.refs[0] ?? 'HEAD'}': all uncommitted changes will be permanently lost`
        : `SOFT RESET to '${parsed.branch ?? parsed.refs[0] ?? 'HEAD'}': staged changes preserved`;
      resourcesImpacted = 1;
      break;

    case 'rebase':
      dryRunOutput = `REBASE onto '${parsed.branch ?? parsed.refs[0] ?? 'HEAD'}': commits will be replayed — conflicts possible`;
      resourcesImpacted = 1;
      break;

    case 'branch-delete':
      dryRunOutput = `BRANCH DELETE '${parsed.branch}': branch reference will be removed${parsed.isForce ? ' (force — ignores unmerged commits)' : ''}`;
      resourcesImpacted = 1;
      break;

    case 'tag-delete':
      dryRunOutput = `TAG DELETE '${parsed.refs.join(', ')}': tag reference(s) will be removed`;
      resourcesImpacted = parsed.refs.length;
      break;

    case 'stash-drop':
      dryRunOutput = 'STASH DROP: stash entry will be permanently deleted';
      resourcesImpacted = 1;
      break;

    case 'reflog-expire':
      dryRunOutput = 'REFLOG EXPIRE: reflog entries will be pruned — past states become unrecoverable without them';
      resourcesImpacted = -1;
      break;

    case 'gc':
      dryRunOutput = 'GC --prune: unreachable objects (dangling commits, blobs) will be permanently deleted';
      resourcesImpacted = -1;
      break;

    case 'commit-amend':
      dryRunOutput = 'COMMIT AMEND: HEAD commit will be rewritten — if already pushed, remote history diverges';
      resourcesImpacted = 1;
      break;

    default:
      // Read-only or low-risk commands — no dry-run needed
      dryRunOutput = `No destructive effects for '${parsed.action}'`;
      resourcesImpacted = 0;
  }

  const summary = buildSummary(parsed, dryRunOutput, warnings);

  return {
    feasible: true,
    resourcesImpacted,
    summary,
    warnings,
    durationMs: Date.now() - start,
  };
}
