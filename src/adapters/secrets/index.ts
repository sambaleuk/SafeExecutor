export { SecretsAdapter, evaluateSecretPolicy } from './adapter.js';
export { parseSecretCommand } from './parser.js';
export { simulateSecretCommand } from './sandbox.js';
export { detectLeaks, maskSecret } from './leak-detector.js';
export type {
  SecretTool,
  SecretAction,
  SecretScope,
  ParsedSecretCommand,
  SecretSnapshot,
  SecretPolicy,
  SecretPolicyRule,
  SecretPolicyDecision,
  LeakDetectionResult,
  DetectedLeak,
  LeakType,
  DangerousPattern,
  ValidationResult,
} from './types.js';
