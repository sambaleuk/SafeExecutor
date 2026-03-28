export { FilesystemAdapter } from './adapter.js';
export { parseIntent } from './parser.js';
export { simulateIntent } from './sandbox.js';
export { analyzePath, resolvePath, hasVariableExpansion } from './path-analyzer.js';
export {
  escalateRisk,
  maxRisk,
  flagEscalationSteps,
  escalateByFileCount,
  pathRiskEntry,
} from './risk-matrix.js';
export type {
  FilesystemIntent,
  FilesystemSnapshot,
  SnapshotEntry,
  PathRiskInfo,
  FsCommandType,
  FsOperationCategory,
  ParsedFlag,
  Redirection,
} from './types.js';
