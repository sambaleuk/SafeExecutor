/**
 * FilesystemAdapter
 *
 * Implements SafeAdapter<FilesystemIntent, FilesystemSnapshot> from core/types.
 * Follows the same pattern as CloudAdapter.
 *
 * Gate contract (enforced by callers):
 *   parseIntent → sandbox → (approval) → execute → (rollback if needed)
 */

import { exec } from 'node:child_process';
import { stat, copyFile, mkdir, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import type { SafeAdapter, SimulationResult, AdapterExecutionResult } from '../../core/types.js';
import type { FilesystemIntent, FilesystemSnapshot, SnapshotEntry } from './types.js';
import { parseIntent } from './parser.js';
import { simulateIntent } from './sandbox.js';

const execAsync = promisify(exec);

// ─── Checksum helper ──────────────────────────────────────────────────────────

async function sha256(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

// ─── Permission string helper ─────────────────────────────────────────────────

function formatMode(mode: number): string {
  const types: Record<number, string> = {
    0o140000: 's', 0o120000: 'l', 0o100000: '-',
    0o060000: 'b', 0o040000: 'd', 0o020000: 'c', 0o010000: 'p',
  };
  const fileType = types[mode & 0o170000] ?? '?';
  const bits = [0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001];
  const chars = 'rwxrwxrwx';
  return fileType + chars.split('').map((c, i) => (mode & bits[i]) ? c : '-').join('');
}

// ─── Snapshot helpers ─────────────────────────────────────────────────────────

const MAX_CHECKSUM_SIZE = 100 * 1024 * 1024; // 100 MB

async function captureEntry(path: string, backupDir: string): Promise<SnapshotEntry> {
  try {
    const s = await stat(path);
    const entry: SnapshotEntry = {
      path,
      exists: true,
      isDirectory: s.isDirectory(),
      sizeBytes: s.size,
      permissions: formatMode(s.mode),
      owner: String(s.uid),
      group: String(s.gid),
      mtime: new Date(s.mtimeMs).toISOString(),
    };
    if (!s.isDirectory() && s.size <= MAX_CHECKSUM_SIZE) {
      entry.checksum = await sha256(path);
      const safeName = path.replace(/\//g, '__');
      await copyFile(path, join(backupDir, safeName));
    }
    return entry;
  } catch {
    return {
      path, exists: false, isDirectory: false, sizeBytes: 0,
      permissions: '', owner: '', group: '', mtime: '',
    };
  }
}

// ─── FilesystemAdapter ────────────────────────────────────────────────────────

export class FilesystemAdapter implements SafeAdapter<FilesystemIntent, FilesystemSnapshot> {
  readonly name = 'filesystem';

  /**
   * Parse a raw shell command into a classified FilesystemIntent.
   * Pure — no I/O.
   */
  parseIntent(raw: string): FilesystemIntent {
    return parseIntent(raw);
  }

  /**
   * Simulate the operation (count affected files, estimate size).
   * Maps to SimulationResult from core/types.ts.
   * Never modifies the filesystem.
   */
  async sandbox(intent: FilesystemIntent): Promise<SimulationResult> {
    const result = await simulateIntent(intent);
    return {
      feasible: result.feasible,
      resourcesImpacted: result.filesAffected,
      summary: result.plan,
      warnings: result.warnings,
      durationMs: result.durationMs,
    };
  }

  /**
   * Execute the command for real.
   * Callers MUST ensure all safety gates have passed before calling this.
   * Double-guards against isDenied as defence-in-depth.
   */
  async execute(intent: FilesystemIntent): Promise<AdapterExecutionResult> {
    if (intent.isDenied) {
      return {
        success: false,
        output: '',
        resourcesAffected: 0,
        durationMs: 0,
        error: `Refused to execute denied operation: ${intent.denyReason ?? 'policy violation'}`,
      };
    }

    const start = Date.now();
    try {
      const { stdout, stderr } = await execAsync(intent.raw, {
        timeout: 30_000,
        maxBuffer: 10 * 1024 * 1024,
      });
      return {
        success: true,
        output: [stdout.trim(), stderr.trim()].filter(Boolean).join('\n'),
        resourcesAffected: intent.targetPaths.length,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      return {
        success: false,
        output: '',
        resourcesAffected: 0,
        durationMs: Date.now() - start,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /**
   * Restore files from a previously captured snapshot.
   * Only restores files that were backed up (regular files ≤ 100 MB).
   */
  async rollback(intent: FilesystemIntent, snapshot: FilesystemSnapshot): Promise<void> {
    const backupDir = snapshot.backupDir;
    if (!backupDir) {
      throw new Error(`Rollback not possible for '${intent.raw}': snapshot has no backupDir`);
    }

    for (const entry of snapshot.entries) {
      if (!entry.exists || entry.isDirectory) continue;
      const safeName = entry.path.replace(/\//g, '__');
      const backupPath = join(backupDir, safeName);
      try {
        if (entry.checksum) {
          const check = await sha256(backupPath);
          if (check !== entry.checksum) {
            throw new Error(`Backup checksum mismatch for ${entry.path}`);
          }
        }
        await copyFile(backupPath, entry.path);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        throw new Error(`Rollback failed for ${entry.path}: ${msg}`);
      }
    }

    // Restore deleted directories (shallow, best-effort)
    for (const entry of snapshot.entries) {
      if (entry.exists && entry.isDirectory) {
        await mkdir(entry.path, { recursive: true }).catch(() => { /* best-effort */ });
      }
    }
  }

  /**
   * Capture the current state of all target paths before execution.
   */
  async snapshot(targets: string[]): Promise<FilesystemSnapshot> {
    const backupDir = mkdtempSync(join(tmpdir(), 'safe-executor-snap-'));
    const entries: SnapshotEntry[] = [];
    let totalFiles = 0;
    let totalBytes = 0;

    for (const target of targets) {
      const entry = await captureEntry(target, backupDir);
      entries.push(entry);
      if (entry.exists && !entry.isDirectory) {
        totalFiles++;
        totalBytes += entry.sizeBytes;
      }
    }

    return { capturedAt: new Date().toISOString(), entries, totalFiles, totalBytes, backupDir };
  }

  /** Clean up the backup directory after a successful execution. */
  async cleanupSnapshot(snapshot: FilesystemSnapshot): Promise<void> {
    if (snapshot.backupDir) {
      await rm(snapshot.backupDir, { recursive: true, force: true });
    }
  }
}
