export { SecretsAdapter } from './adapter.js';
export { parseSecretCommand } from './parser.js';
export { detectLeaks, maskSecrets } from './leak-detector.js';
export { SecretSandbox } from './sandbox.js';
export type {
  ParsedSecretCommand,
  LeakDetectionResult,
  LeakPattern,
  SecretSandboxOutcome,
  SecretsAdapterOptions,
  SecretTool,
  SecretAction,
  SecretEnvironment,
} from './types.js';
