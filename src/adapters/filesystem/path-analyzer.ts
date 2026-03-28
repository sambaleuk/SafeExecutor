import { homedir } from 'node:os';
import { resolve, normalize, isAbsolute } from 'node:path';
import type { PathRiskInfo } from './types.js';
import { pathRiskEntry, maxRisk } from './risk-matrix.js';
import type { RiskLevel } from '../../types/index.js';

// ─── Constants ────────────────────────────────────────────────────────────────

export const SYSTEM_PATHS: ReadonlyArray<string> = [
  '/', '/etc', '/usr', '/var', '/boot',
  '/sys', '/proc', '/dev', '/lib', '/lib64',
  '/bin', '/sbin', '/root',
];

export const SENSITIVE_HOME_PATHS: ReadonlyArray<string> = [
  '.ssh', '.gnupg', '.config', '.aws', '.kube',
  '.npmrc', '.gitconfig', '.env',
  '.bash_history', '.zsh_history', '.profile',
];

// ─── Pure helpers ─────────────────────────────────────────────────────────────

/**
 * Return true if the path contains an unresolved shell variable.
 * Empty-var risk: `rm -rf $TARGET/` when $TARGET='' → `rm -rf /`
 */
export function hasVariableExpansion(path: string): boolean {
  return /\$[A-Za-z_][A-Za-z0-9_]*/.test(path) || /\$\{[^}]+\}/.test(path);
}

/**
 * Resolve a shell-style path to an absolute, normalised POSIX path.
 *   ~          → $HOME
 *   ~/foo      → $HOME/foo
 *   $HOME/foo  → actual value
 *   $PWD/foo   → actual value
 *   relative   → resolved from process.cwd()
 */
export function resolvePath(raw: string): string {
  let p = raw.trim();

  if (p === '~' || p.startsWith('~/')) {
    p = homedir() + p.slice(1);
  }

  p = p.replace(/\$HOME(?=\/|$)/g, homedir());
  p = p.replace(/\$PWD(?=\/|$)/g, process.cwd());

  if (!isAbsolute(p)) {
    p = resolve(process.cwd(), p);
  }

  return normalize(p);
}

/** Return true if the path falls inside a known system path. */
export function isSystemPath(normalizedPath: string): boolean {
  return SYSTEM_PATHS.some(
    (sp) => normalizedPath === sp || normalizedPath.startsWith(sp + '/'),
  );
}

/** Return true if the path is a sensitive sub-path under $HOME. */
export function isSensitiveHomePath(normalizedPath: string): boolean {
  const home = homedir();
  if (!normalizedPath.startsWith(home + '/')) return false;
  const rel = normalizedPath.slice(home.length + 1);
  return SENSITIVE_HOME_PATHS.some(
    (sp) => rel === sp || rel.startsWith(sp + '/'),
  );
}

// ─── Full analysis ────────────────────────────────────────────────────────────

/**
 * Perform a static risk analysis of a single path.
 * Does not touch the filesystem — pure function.
 */
export function analyzePath(rawPath: string): PathRiskInfo {
  const hasVar = hasVariableExpansion(rawPath);

  // Do not attempt to resolve paths with unresolved variables.
  const normalizedPath = hasVar ? rawPath : resolvePath(rawPath);

  const sysPath = hasVar ? false : isSystemPath(normalizedPath);
  const sensPath = hasVar ? false : isSensitiveHomePath(normalizedPath);
  const matrixEntry = hasVar ? null : pathRiskEntry(normalizedPath);

  let riskLevel: RiskLevel = 'LOW';
  let reason = 'standard path';

  if (hasVar) {
    riskLevel = 'CRITICAL';
    reason = 'unresolved variable expansion — empty-var collapse risk';
  } else if (matrixEntry?.deny === true) {
    riskLevel = 'CRITICAL';
    reason = `protected system path: ${matrixEntry.prefix}`;
  } else if (matrixEntry !== null) {
    riskLevel = matrixEntry.risk;
    reason = `system path area: ${matrixEntry.prefix}`;
  } else if (sensPath) {
    riskLevel = maxRisk('HIGH', riskLevel);
    reason = 'sensitive home directory path';
  } else if (sysPath) {
    riskLevel = maxRisk('HIGH', riskLevel);
    reason = 'system path';
  }

  return {
    path: normalizedPath,
    riskLevel,
    isSystemPath: sysPath,
    isSensitivePath: sensPath,
    reason,
  };
}
