export { GitAdapter, evaluateGitPolicy } from './adapter.js';
export { parseGitCommand } from './parser.js';
export { simulateGitCommand } from './sandbox.js';
export type {
  GitAction,
  ParsedGitCommand,
  GitSnapshot,
  GitPolicy,
  GitPolicyRule,
  GitPolicyDecision,
  GitRuleMatch,
  DangerousPattern as GitDangerousPattern,
} from './types.js';
