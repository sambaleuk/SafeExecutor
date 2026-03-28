/**
 * Filesystem Sandbox
 *
 * Simulates filesystem operations without executing them.
 * Uses lightweight shell probes (find, stat, df) to estimate impact.
 */

import { exec } from 'node:child_process';
import { stat } from 'node:fs/promises';
import { promisify } from 'node:util';
// Internal simulation result — converted to core/types SimulationResult by the adapter
interface SimulationResult {
  feasible: boolean;
  filesAffected: number;
  totalSizeBytes: number;
  plan: string;
  warnings: string[];
  durationMs: number;
}
import type { FilesystemIntent } from './types.js';
import { escalateByFileCount } from './risk-matrix.js';

const execAsync = promisify(exec);

// ─── Internal helpers ─────────────────────────────────────────────────────────

/** Count files under a path using find (cross-platform Unix). */
async function countFiles(path: string): Promise<number> {
  try {
    const { stdout } = await execAsync(
      `find ${shellEscape(path)} -mindepth 1 | wc -l`,
    );
    return parseInt(stdout.trim(), 10) || 0;
  } catch {
    return 0;
  }
}

/** Get total size of a path in bytes using du. */
async function totalBytes(path: string): Promise<number> {
  try {
    // du -sk gives KiB on both macOS and Linux; multiply × 1024
    const { stdout } = await execAsync(
      `du -sk ${shellEscape(path)} 2>/dev/null | cut -f1`,
    );
    const kib = parseInt(stdout.trim(), 10);
    return isNaN(kib) ? 0 : kib * 1024;
  } catch {
    return 0;
  }
}

/** Minimally safe shell escaping for single-argument probes (no exec). */
function shellEscape(p: string): string {
  return `'${p.replace(/'/g, "'\\''")}'`;
}

/** Human-readable byte size. */
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

// ─── Per-command simulations ──────────────────────────────────────────────────

async function simulateRm(intent: FilesystemIntent): Promise<SimulationResult> {
  const start = Date.now();
  const warnings: string[] = [];
  const planLines: string[] = [];
  let filesAffected = 0;
  let sizeBytes = 0;
  const hasRecursive =
    intent.metadata['hasRecursiveFlag'] === true;

  for (const path of intent.targetPaths) {
    try {
      const s = await stat(path);
      if (s.isDirectory() && hasRecursive) {
        const count = await countFiles(path);
        const bytes = await totalBytes(path);
        filesAffected += count;
        sizeBytes += bytes;
        planLines.push(
          `[DRY-RUN] Would delete directory ${path} (${count} files, ${formatBytes(bytes)})`,
        );
      } else if (!s.isDirectory()) {
        filesAffected++;
        sizeBytes += s.size;
        planLines.push(`[DRY-RUN] Would delete file ${path} (${formatBytes(s.size)})`);
      } else {
        planLines.push(`[DRY-RUN] Directory ${path} requires -r to delete`);
        warnings.push(`${path}: is a directory, -r not set — would be skipped`);
      }
    } catch {
      planLines.push(`[DRY-RUN] ${path}: not found or inaccessible`);
      warnings.push(`${path}: not found or no read permission`);
    }
  }

  if (filesAffected > 1000) warnings.push('DANGER: >1 000 files would be deleted');
  else if (filesAffected > 100) warnings.push('WARNING: >100 files would be deleted');

  return {
    feasible: true,
    filesAffected,
    totalSizeBytes: sizeBytes,
    plan: planLines.join('\n') || '[DRY-RUN] No targets to process',
    warnings,
    durationMs: Date.now() - start,
  };
}

async function simulateCpMv(intent: FilesystemIntent): Promise<SimulationResult> {
  const start = Date.now();
  const warnings: string[] = [];
  const planLines: string[] = [];
  let filesAffected = 0;
  let sizeBytes = 0;
  const verb = intent.commandType === 'CP' ? 'copy' : 'move';
  const target = intent.targetPaths[0] ?? '(unknown)';

  for (const src of intent.sourcePaths) {
    try {
      const s = await stat(src);
      if (s.isDirectory()) {
        const count = await countFiles(src);
        const bytes = await totalBytes(src);
        filesAffected += count;
        sizeBytes += bytes;
        planLines.push(
          `[DRY-RUN] Would ${verb} directory ${src} → ${target} (${count} files, ${formatBytes(bytes)})`,
        );
      } else {
        filesAffected++;
        sizeBytes += s.size;
        planLines.push(
          `[DRY-RUN] Would ${verb} file ${src} → ${target} (${formatBytes(s.size)})`,
        );
      }
    } catch {
      planLines.push(`[DRY-RUN] ${src}: not found or inaccessible`);
      warnings.push(`${src}: not found or no read permission`);
    }
  }

  return {
    feasible: warnings.length === 0,
    filesAffected,
    totalSizeBytes: sizeBytes,
    plan: planLines.join('\n') || '[DRY-RUN] No sources to process',
    warnings,
    durationMs: Date.now() - start,
  };
}

async function simulateChmodChown(intent: FilesystemIntent): Promise<SimulationResult> {
  const start = Date.now();
  const warnings: string[] = [];
  const planLines: string[] = [];
  let filesAffected = 0;
  let sizeBytes = 0;
  const hasRecursive = intent.metadata['hasRecursiveFlag'] === true;
  const modeArg = intent.metadata['modeArg'] as string | undefined;
  const verb = intent.commandType === 'CHMOD' ? 'chmod' : intent.commandType === 'CHOWN' ? 'chown' : 'chgrp';

  for (const path of intent.targetPaths) {
    try {
      const s = await stat(path);
      if (s.isDirectory() && hasRecursive) {
        const count = await countFiles(path);
        filesAffected += count;
        sizeBytes += await totalBytes(path);
        planLines.push(
          `[DRY-RUN] Would ${verb} ${modeArg ?? '?'} recursively in ${path} (${count} files)`,
        );
        if (count > 100) warnings.push(`${path}: ${count} files — requires approval`);
      } else {
        filesAffected++;
        sizeBytes += s.size;
        planLines.push(
          `[DRY-RUN] Would ${verb} ${modeArg ?? '?'} on ${path}`,
        );
      }
    } catch {
      planLines.push(`[DRY-RUN] ${path}: not found or inaccessible`);
      warnings.push(`${path}: not found or no read permission`);
    }
  }

  return {
    feasible: true,
    filesAffected,
    totalSizeBytes: sizeBytes,
    plan: planLines.join('\n') || '[DRY-RUN] No targets to process',
    warnings,
    durationMs: Date.now() - start,
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Simulate a filesystem intent and return what would happen.
 *
 * Never modifies the filesystem.
 * Escalates risk level if file count exceeds thresholds.
 */
export async function simulateIntent(intent: FilesystemIntent): Promise<SimulationResult> {
  // Denied operations produce an immediate infeasible result
  if (intent.isDenied) {
    return {
      feasible: false,
      filesAffected: 0,
      totalSizeBytes: 0,
      plan: `[DENIED] ${intent.denyReason ?? 'operation not permitted'}`,
      warnings: [`This operation is denied and cannot be executed.`],
      durationMs: 0,
    };
  }

  let result: SimulationResult;

  switch (intent.commandType) {
    case 'RM':
    case 'RMDIR':
      result = await simulateRm(intent);
      break;
    case 'CP':
    case 'MV':
      result = await simulateCpMv(intent);
      break;
    case 'CHMOD':
    case 'CHOWN':
    case 'CHGRP':
      result = await simulateChmodChown(intent);
      break;
    default:
      // Generic: count the target paths we can stat
      result = await simulateGeneric(intent);
      break;
  }

  // Post-simulation risk escalation warning
  const escalated = escalateByFileCount(intent.riskLevel, result.filesAffected);
  if (escalated !== intent.riskLevel) {
    result.warnings.push(
      `Risk escalated from ${intent.riskLevel} to ${escalated} due to file count (${result.filesAffected})`,
    );
  }

  return result;
}

async function simulateGeneric(intent: FilesystemIntent): Promise<SimulationResult> {
  const start = Date.now();
  const warnings: string[] = [];
  const planLines: string[] = [];
  let filesAffected = 0;
  let sizeBytes = 0;

  for (const path of intent.targetPaths) {
    try {
      const s = await stat(path);
      filesAffected++;
      sizeBytes += s.size;
      planLines.push(
        `[DRY-RUN] Would run ${intent.command} on ${path} (${formatBytes(s.size)})`,
      );
    } catch {
      planLines.push(`[DRY-RUN] ${path}: not found`);
      warnings.push(`${path}: not found`);
    }
  }

  return {
    feasible: true,
    filesAffected,
    totalSizeBytes: sizeBytes,
    plan: planLines.join('\n') || `[DRY-RUN] ${intent.command} (no explicit targets)`,
    warnings,
    durationMs: Date.now() - start,
  };
}
