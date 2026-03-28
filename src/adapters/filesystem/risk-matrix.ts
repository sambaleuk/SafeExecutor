import type { RiskLevel } from '../../types/index.js';
import type { FsCommandType } from './types.js';

// ─── Base risk by command ─────────────────────────────────────────────────────

export const COMMAND_BASE_RISK: Partial<Record<FsCommandType, RiskLevel>> = {
  RM:      'MEDIUM',
  MV:      'MEDIUM',
  CP:      'MEDIUM',
  MKDIR:   'LOW',
  RMDIR:   'HIGH',
  TOUCH:   'LOW',
  CHMOD:   'MEDIUM',
  CHOWN:   'HIGH',
  CHGRP:   'MEDIUM',
  LN:      'MEDIUM',
  FIND:    'LOW',
  XARGS:   'HIGH',
  RSYNC:   'MEDIUM',
  DD:      'CRITICAL',
  MKFS:    'CRITICAL',
  FDISK:   'CRITICAL',
  MOUNT:   'HIGH',
  UMOUNT:  'MEDIUM',
  TAR:     'MEDIUM',
  ZIP:     'LOW',
  UNZIP:   'MEDIUM',
  LS:      'LOW',
  CAT:     'LOW',
  STAT:    'LOW',
  FILE_CMD:'LOW',
  HEAD:    'LOW',
  TAIL:    'LOW',
  WC:      'LOW',
  UNKNOWN: 'MEDIUM',
};

// ─── Path risk matrix ─────────────────────────────────────────────────────────

/** Entries ordered from most specific to least specific.  */
export const PATH_RISK_MATRIX: ReadonlyArray<{
  prefix: string;
  risk: RiskLevel;
  deny?: boolean;
}> = [
  { prefix: '/root',    risk: 'CRITICAL', deny: true },
  { prefix: '/proc',    risk: 'CRITICAL', deny: true },
  { prefix: '/sys',     risk: 'CRITICAL', deny: true },
  { prefix: '/dev',     risk: 'CRITICAL', deny: true },
  { prefix: '/boot',    risk: 'CRITICAL', deny: true },
  { prefix: '/lib64',   risk: 'CRITICAL', deny: true },
  { prefix: '/lib',     risk: 'CRITICAL', deny: true },
  { prefix: '/sbin',    risk: 'CRITICAL', deny: true },
  { prefix: '/bin',     risk: 'CRITICAL', deny: true },
  { prefix: '/etc',     risk: 'CRITICAL', deny: true },
  { prefix: '/usr',     risk: 'CRITICAL', deny: true },
  { prefix: '/var',     risk: 'CRITICAL' },
  { prefix: '/home',    risk: 'HIGH' },
  { prefix: '/tmp',     risk: 'LOW' },
  { prefix: '/var/tmp', risk: 'LOW' },
  { prefix: '/',        risk: 'CRITICAL', deny: true },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

/** Escalate a risk level by N steps, capped at CRITICAL. */
export function escalateRisk(base: RiskLevel, steps: number): RiskLevel {
  const idx = RISK_ORDER.indexOf(base);
  return RISK_ORDER[Math.min(idx + steps, RISK_ORDER.length - 1)];
}

/** Return whichever risk level is higher. */
export function maxRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

/**
 * Compute flag-based escalation steps from a flat list of flag chars.
 *
 * -rf / -fr  → +2 (recursive + force: highest escalation)
 * -r / -R    → +1
 * -f         → +1
 * --dry-run / -n → 0 (explicitly safe)
 */
export function flagEscalationSteps(flagChars: string[]): number {
  const hasR = flagChars.includes('r') || flagChars.includes('R') || flagChars.includes('recursive');
  const hasF = flagChars.includes('f') || flagChars.includes('force');
  if (hasR && hasF) return 2;
  if (hasR || hasF) return 1;
  return 0;
}

/**
 * Look up a path in the risk matrix.
 * Returns the most specific matching entry, or null if no match.
 */
export function pathRiskEntry(
  normalizedPath: string,
): (typeof PATH_RISK_MATRIX)[number] | null {
  // Entries are already ordered most-specific first in the const above,
  // but we want to guarantee longest-prefix match regardless of order.
  const sorted = [...PATH_RISK_MATRIX].sort(
    (a, b) => b.prefix.length - a.prefix.length,
  );
  for (const entry of sorted) {
    if (
      normalizedPath === entry.prefix ||
      normalizedPath.startsWith(entry.prefix + '/')
    ) {
      return entry;
    }
  }
  return null;
}

/**
 * Escalate risk based on the number of files that would be impacted.
 * >100 files → +1, >1000 files → +2.
 */
export function escalateByFileCount(base: RiskLevel, fileCount: number): RiskLevel {
  if (fileCount > 1000) return escalateRisk(base, 2);
  if (fileCount > 100) return escalateRisk(base, 1);
  return base;
}
