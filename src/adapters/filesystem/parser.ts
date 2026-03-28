/**
 * Filesystem / Shell Command Parser
 *
 * Converts a raw shell command string into a FilesystemIntent with inline
 * risk classification and deny-rule evaluation.
 *
 * Pure function — no I/O, no process spawning.
 */

import { homedir } from 'node:os';
import { basename } from 'node:path';
import type { RiskLevel } from '../../types/index.js';
import type {
  FilesystemIntent,
  FsCommandType,
  FsOperationCategory,
  ParsedFlag,
  Redirection,
} from './types.js';
import {
  analyzePath,
  hasVariableExpansion,
  resolvePath,
} from './path-analyzer.js';
import {
  COMMAND_BASE_RISK,
  escalateRisk,
  maxRisk,
  flagEscalationSteps,
} from './risk-matrix.js';

// ─── Command lookup tables ────────────────────────────────────────────────────

const COMMAND_MAP: Record<string, FsCommandType> = {
  rm: 'RM', mv: 'MV', cp: 'CP',
  mkdir: 'MKDIR', rmdir: 'RMDIR', touch: 'TOUCH',
  chmod: 'CHMOD', chown: 'CHOWN', chgrp: 'CHGRP', ln: 'LN',
  find: 'FIND', xargs: 'XARGS', rsync: 'RSYNC',
  dd: 'DD', mkfs: 'MKFS', fdisk: 'FDISK', mount: 'MOUNT', umount: 'UMOUNT',
  tar: 'TAR', zip: 'ZIP', unzip: 'UNZIP',
  ls: 'LS', cat: 'CAT', stat: 'STAT', file: 'FILE_CMD',
  head: 'HEAD', tail: 'TAIL', wc: 'WC',
};

/** Resolve a command name to its type, handling variants like mkfs.ext4. */
function resolveCommandType(cmd: string): FsCommandType {
  const name = basename(cmd).toLowerCase();
  if (COMMAND_MAP[name] !== undefined) return COMMAND_MAP[name];
  if (name.startsWith('mkfs')) return 'MKFS';
  if (name.startsWith('fdisk') || name === 'parted') return 'FDISK';
  return 'UNKNOWN';
}

const CATEGORY_MAP: Partial<Record<FsCommandType, FsOperationCategory>> = {
  RM: 'DESTROY', RMDIR: 'DESTROY', DD: 'DESTROY', MKFS: 'DESTROY', FDISK: 'DESTROY',
  XARGS: 'DESTROY',
  MV: 'WRITE', CP: 'WRITE', MKDIR: 'WRITE', TOUCH: 'WRITE',
  TAR: 'WRITE', ZIP: 'WRITE', UNZIP: 'WRITE', RSYNC: 'WRITE',
  CHMOD: 'MODIFY', CHOWN: 'MODIFY', CHGRP: 'MODIFY', LN: 'MODIFY',
  MOUNT: 'MODIFY', UMOUNT: 'MODIFY',
  FIND: 'READ', LS: 'READ', CAT: 'READ', STAT: 'READ',
  FILE_CMD: 'READ', HEAD: 'READ', TAIL: 'READ', WC: 'READ',
};

// ─── Tokeniser ────────────────────────────────────────────────────────────────

/** Split a command on unquoted pipe operators. */
function splitOnPipes(cmd: string): string[] {
  const segments: string[] = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    if (ch === "'" && !inDouble) { inSingle = !inSingle; current += ch; }
    else if (ch === '"' && !inSingle) { inDouble = !inDouble; current += ch; }
    else if (ch === '|' && !inSingle && !inDouble) {
      segments.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.length > 0) segments.push(current);
  return segments;
}

/** Tokenise a shell segment respecting single/double quotes. */
function tokenize(segment: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i];
    if (ch === "'" && !inDouble) { inSingle = !inSingle; }
    else if (ch === '"' && !inSingle) { inDouble = !inDouble; }
    else if ((ch === ' ' || ch === '\t') && !inSingle && !inDouble) {
      if (current.length > 0) { tokens.push(current); current = ''; }
    } else {
      current += ch;
    }
  }
  if (current.length > 0) tokens.push(current);
  return tokens;
}

// ─── Flag helpers ─────────────────────────────────────────────────────────────

function parseFlag(token: string): ParsedFlag {
  if (token.startsWith('--')) {
    return { raw: token, chars: [token.slice(2)] };
  }
  // Short flags: -rf → ['r', 'f']
  return { raw: token, chars: token.slice(1).split('') };
}

function isFlag(token: string): boolean {
  return token.startsWith('-') && token.length > 1 && token !== '--';
}

function allFlagChars(flags: ParsedFlag[]): string[] {
  return flags.flatMap((f) => f.chars);
}

// ─── Glob / variable helpers ──────────────────────────────────────────────────

function containsGlob(token: string): boolean {
  return /[*?{}[\]]/.test(token);
}

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * Parse a raw shell/filesystem command string into a FilesystemIntent.
 *
 * Handles: flags, args, pipes, redirections, sudo, globs, variable expansion.
 * Applies inline deny-rules and computes a RiskLevel.
 */
export function parseIntent(raw: string): FilesystemIntent {
  const trimmed = raw.trim();

  const pipeSegments = splitOnPipes(trimmed);
  const tokens = tokenize(pipeSegments[0]);
  const pipes = pipeSegments.slice(1).map((s) => tokenize(s.trim()));

  let idx = 0;

  // ── sudo detection ────────────────────────────────────────────────────────
  let hasSudo = false;
  if (tokens[idx] === 'sudo') { hasSudo = true; idx++; }

  const command = tokens[idx] ?? '';
  idx++;

  const commandType: FsCommandType = resolveCommandType(command);
  const category: FsOperationCategory = CATEGORY_MAP[commandType] ?? 'UNKNOWN';

  // ── Token classification ──────────────────────────────────────────────────
  const flags: ParsedFlag[] = [];
  const args: string[] = [];
  const redirections: Redirection[] = [];

  while (idx < tokens.length) {
    const token = tokens[idx];

    // Standalone redirection operators
    if (token === '>>' || token === '>' || token === '<') {
      const type: Redirection['type'] =
        token === '>>' ? 'append' : token === '>' ? 'output' : 'input';
      idx++;
      if (idx < tokens.length) {
        redirections.push({ type, target: tokens[idx] });
        idx++;
      }
      continue;
    }

    // Embedded redirection: ">>file" or ">file"
    if (token.startsWith('>>') && token.length > 2) {
      redirections.push({ type: 'append', target: token.slice(2) });
      idx++; continue;
    }
    if (token.startsWith('>') && token.length > 1) {
      redirections.push({ type: 'output', target: token.slice(1) });
      idx++; continue;
    }

    // dd key=value operands are args, not flags
    if (commandType === 'DD' && token.includes('=') && !token.startsWith('-')) {
      args.push(token);
      idx++; continue;
    }

    if (isFlag(token)) {
      flags.push(parseFlag(token));
    } else {
      args.push(token);
    }
    idx++;
  }

  const flagChars = allFlagChars(flags);
  const hasRecursiveFlag =
    flagChars.includes('r') || flagChars.includes('R') || flagChars.includes('recursive');
  const hasForceFlag =
    flagChars.includes('f') || flagChars.includes('force');

  // ── Path extraction (command-specific) ────────────────────────────────────
  let targetPaths: string[] = [];
  let sourcePaths: string[] = [];
  let modeArg: string | undefined; // chmod mode or chown owner:group

  if (['CP', 'MV', 'LN'].includes(commandType) && args.length >= 2) {
    sourcePaths = args.slice(0, -1);
    targetPaths = [args[args.length - 1]];
  } else if (['CHMOD'].includes(commandType) && args.length >= 1) {
    // First arg is the mode (755, u+x, etc.), rest are paths
    modeArg = args[0];
    targetPaths = args.slice(1);
  } else if (['CHOWN', 'CHGRP'].includes(commandType) && args.length >= 1) {
    // First arg is owner[:group]
    modeArg = args[0];
    targetPaths = args.slice(1);
  } else if (commandType === 'DD') {
    const ofArg = args.find((a) => a.startsWith('of='));
    const ifArg = args.find((a) => a.startsWith('if='));
    if (ofArg) targetPaths = [ofArg.slice(3)];
    if (ifArg) sourcePaths = [ifArg.slice(3)];
  } else {
    targetPaths = args.filter((a) => a !== '--');
  }

  // ── Glob / variable expansion detection ───────────────────────────────────
  const allPathTokens = [...targetPaths, ...sourcePaths, ...args];
  const hasGlobs = allPathTokens.some(containsGlob);
  const hasVarExpansion = allPathTokens.some(hasVariableExpansion);

  // ── Pipe-to-rm detection ──────────────────────────────────────────────────
  const pipesToRm = pipes.some((seg) => {
    const pipeCmd = seg[0];
    return (
      pipeCmd === 'rm' ||
      (pipeCmd === 'xargs' && seg.some((t) => t === 'rm'))
    );
  });

  // ── Risk computation ──────────────────────────────────────────────────────
  let riskLevel: RiskLevel = COMMAND_BASE_RISK[commandType] ?? 'MEDIUM';

  // Flag escalation
  riskLevel = escalateRisk(riskLevel, flagEscalationSteps(flagChars));

  // Path escalation — skipped for pure READ commands (cat /etc/hosts is safe to read)
  if (category !== 'READ') {
    for (const path of targetPaths) {
      const info = analyzePath(path);
      riskLevel = maxRisk(riskLevel, info.riskLevel);
    }
  }

  // sudo escalation
  if (hasSudo) riskLevel = escalateRisk(riskLevel, 1);

  // Variable expansion is always CRITICAL
  if (hasVarExpansion) riskLevel = 'CRITICAL';

  // ── Deny rules (non-bypassable) ────────────────────────────────────────────
  let isDenied = false;
  let denyReason: string | undefined;

  const deny = (reason: string): void => {
    if (isDenied) return;
    isDenied = true;
    denyReason = reason;
    riskLevel = 'CRITICAL';
  };

  // rm without any path argument
  if (commandType === 'RM' && targetPaths.length === 0) {
    deny('rm with no path argument');
  }

  // rm -rf with variable expansion ($VAR could be empty → rm -rf /) — check first
  if (!isDenied && commandType === 'RM' && hasRecursiveFlag && hasForceFlag && hasVarExpansion) {
    deny('rm -rf with variable expansion — empty-var collapse risk');
  }

  // rm -rf with glob expansion (blast radius unknown)
  if (!isDenied && commandType === 'RM' && hasRecursiveFlag && hasForceFlag && hasGlobs) {
    deny('rm -rf with glob — blast radius unbound');
  }

  // rm -rf / or rm -rf ~ (exact root/home targets)
  if (!isDenied && commandType === 'RM' && hasRecursiveFlag && hasForceFlag) {
    const home = homedir();
    const dangerous = targetPaths.filter((p) => {
      if (hasVariableExpansion(p)) return false; // already handled above
      const resolved = resolvePath(p);
      return resolved === '/' || resolved === home;
    });
    if (dangerous.length > 0) {
      deny(`rm -rf on root or home: ${dangerous.join(', ')}`);
    }
  }

  // rm -rf on system paths
  if (!isDenied && commandType === 'RM' && hasRecursiveFlag && hasForceFlag) {
    const SYSTEM = ['/etc', '/usr', '/var', '/bin', '/sbin', '/lib', '/lib64', '/boot', '/proc', '/sys', '/dev', '/root'];
    const systemTarget = targetPaths.find((p) => {
      if (hasVariableExpansion(p)) return false;
      const r = resolvePath(p);
      return SYSTEM.some((sp) => r === sp || r.startsWith(sp + '/'));
    });
    if (systemTarget) deny(`rm -rf on system path: ${systemTarget}`);
  }

  // dd to a block device
  if (!isDenied && commandType === 'DD') {
    const of = targetPaths[0] ?? '';
    if (of.startsWith('/dev/')) deny(`dd targeting block device: ${of}`);
  }

  // Output / append redirection to /dev/*
  if (!isDenied) {
    const devRedir = redirections.find(
      (r) => r.type !== 'input' && r.target.startsWith('/dev/'),
    );
    if (devRedir) deny(`output redirection to device: ${devRedir.target}`);
  }

  // mv to /dev/null
  if (!isDenied && commandType === 'MV') {
    const toNull = targetPaths.some(
      (p) => p === '/dev/null' || (!hasVariableExpansion(p) && resolvePath(p) === '/dev/null'),
    );
    if (toNull) deny('mv to /dev/null — silent data destruction');
  }

  // find -delete or find -exec rm
  // Note: find uses single-dash "long" flags like -delete, -exec, -name.
  // These are stored in flags[].raw, not decomposed into chars.
  if (!isDenied && commandType === 'FIND') {
    const hasDeleteFlag =
      flags.some((f) => f.raw === '-delete') ||
      args.includes('-delete');
    const hasExecRm =
      (flags.some((f) => f.raw === '-exec') || args.some((a) => a === '-exec')) &&
      args.some((a) => a === 'rm' || a.startsWith('rm '));
    if (hasDeleteFlag) deny('find -delete');
    else if (hasExecRm) deny('find -exec rm');
  }

  // chown / chgrp on system paths
  if (!isDenied && (commandType === 'CHOWN' || commandType === 'CHGRP')) {
    const BLOCKED = ['/etc', '/usr', '/var', '/bin', '/sbin', '/lib', '/lib64'];
    const systemTarget = targetPaths.find((p) => {
      if (hasVariableExpansion(p)) return false;
      const r = resolvePath(p);
      return BLOCKED.some((sp) => r === sp || r.startsWith(sp + '/'));
    });
    if (systemTarget) deny(`chown/chgrp on system path: ${systemTarget}`);
  }

  // chmod -R on system paths
  if (!isDenied && commandType === 'CHMOD' && hasRecursiveFlag) {
    const BLOCKED = ['/etc', '/usr', '/var', '/bin', '/sbin', '/lib', '/lib64'];
    const systemTarget = targetPaths.find((p) => {
      if (hasVariableExpansion(p)) return false;
      const r = resolvePath(p);
      return BLOCKED.some((sp) => r === sp || r.startsWith(sp + '/'));
    });
    if (systemTarget) deny(`chmod -R on system path: ${systemTarget}`);
  }

  // mkfs / fdisk — always deny
  if (!isDenied && (commandType === 'MKFS' || commandType === 'FDISK')) {
    deny(`${command} is a disk-level destructive operation`);
  }

  // Pipe into bare rm (blast radius unknown without explicit filtering)
  if (!isDenied && pipesToRm) {
    deny('pipe into rm without explicit path filter — blast radius unknown');
  }

  // ── requiresApproval ──────────────────────────────────────────────────────
  const isChmod777 =
    commandType === 'CHMOD' && modeArg !== undefined && /^0?777$/.test(modeArg);

  const requiresApproval =
    !isDenied &&
    (riskLevel === 'CRITICAL' ||
      riskLevel === 'HIGH' ||
      isChmod777 ||
      (hasSudo && category === 'DESTROY'));

  return {
    raw: trimmed,
    command,
    commandType,
    category,
    args,
    flags,
    targetPaths,
    sourcePaths,
    pipes,
    redirections,
    hasSudo,
    isDenied,
    ...(denyReason !== undefined && { denyReason }),
    requiresApproval,
    hasGlobs,
    hasVarExpansion,
    riskLevel,
    isDestructive: category === 'DESTROY' || isDenied,
    metadata: {
      flagChars,
      hasRecursiveFlag,
      hasForceFlag,
      ...(modeArg !== undefined && { modeArg }),
    },
  };
}
