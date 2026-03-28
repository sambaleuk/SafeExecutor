import type { RiskLevel } from '../../types/index.js';

// ─── Command classification ───────────────────────────────────────────────────

export type FsCommandType =
  | 'RM'
  | 'MV'
  | 'CP'
  | 'MKDIR'
  | 'RMDIR'
  | 'TOUCH'
  | 'CHMOD'
  | 'CHOWN'
  | 'CHGRP'
  | 'LN'
  | 'FIND'
  | 'XARGS'
  | 'RSYNC'
  | 'DD'
  | 'MKFS'
  | 'FDISK'
  | 'MOUNT'
  | 'UMOUNT'
  | 'TAR'
  | 'ZIP'
  | 'UNZIP'
  | 'LS'
  | 'CAT'
  | 'STAT'
  | 'FILE_CMD'
  | 'HEAD'
  | 'TAIL'
  | 'WC'
  | 'UNKNOWN';

export type FsOperationCategory = 'READ' | 'WRITE' | 'MODIFY' | 'DESTROY' | 'UNKNOWN';

// ─── Parsed command components ────────────────────────────────────────────────

export interface ParsedFlag {
  raw: string;     // e.g., "-rf" or "--recursive"
  chars: string[]; // e.g., ['r', 'f'] or ['recursive']
}

export interface Redirection {
  type: 'input' | 'output' | 'append';
  target: string;
}

// ─── Filesystem intent ────────────────────────────────────────────────────────

/** Domain-specific parsed intent produced by the filesystem parser. */
export interface FilesystemIntent {
  raw: string;
  command: string;
  commandType: FsCommandType;
  category: FsOperationCategory;
  args: string[];
  flags: ParsedFlag[];
  targetPaths: string[];    // resolved destination / target paths
  sourcePaths: string[];    // for cp, mv, ln: the source paths
  pipes: string[][];        // downstream pipe segments as token arrays
  redirections: Redirection[];
  hasSudo: boolean;
  isDenied: boolean;
  denyReason?: string;
  requiresApproval: boolean;
  hasGlobs: boolean;
  hasVarExpansion: boolean; // $VAR in paths → empty-var risk
  riskLevel: RiskLevel;
  isDestructive: boolean;
  metadata: Record<string, unknown>;
}

// ─── Snapshot ─────────────────────────────────────────────────────────────────

export interface SnapshotEntry {
  path: string;
  exists: boolean;
  isDirectory: boolean;
  sizeBytes: number;
  permissions: string; // e.g., "drwxr-xr-x"
  owner: string;       // uid
  group: string;       // gid
  mtime: string;       // ISO 8601
  checksum?: string;   // SHA-256 hex for regular files ≤ 100 MB
}

export interface FilesystemSnapshot {
  capturedAt: string;      // ISO 8601
  entries: SnapshotEntry[];
  totalFiles: number;
  totalBytes: number;
  backupDir?: string;      // temp dir where files were copied before execution
}

// ─── Path risk info ───────────────────────────────────────────────────────────

export interface PathRiskInfo {
  path: string;
  riskLevel: RiskLevel;
  isSystemPath: boolean;
  isSensitivePath: boolean;
  reason: string;
}
