import type { TargetEnvironment } from './types.js';

const PRODUCTION_KEYWORDS = ['prod', 'production', 'live'];
const STAGING_KEYWORDS = ['staging', 'stage', 'stg', 'uat', 'demo'];
const PREVIEW_KEYWORDS = ['preview', 'canary', 'review'];
const DEVELOPMENT_KEYWORDS = ['dev', 'development', 'develop', 'feature/', 'feat/'];
const LOCAL_KEYWORDS = ['localhost', '127.0.0.1', 'local'];

function matchesKeywords(text: string, keywords: string[]): boolean {
  const lower = text.toLowerCase();
  return keywords.some((kw) => lower.includes(kw));
}

/**
 * Infers environment from free-form text (command fragment, env var value, etc.)
 * Production is checked first to avoid false negatives (e.g. "non-production" still contains "prod").
 */
function detectFromText(text: string): TargetEnvironment {
  if (matchesKeywords(text, PRODUCTION_KEYWORDS)) return 'production';
  if (matchesKeywords(text, STAGING_KEYWORDS)) return 'staging';
  if (matchesKeywords(text, PREVIEW_KEYWORDS)) return 'preview';
  if (matchesKeywords(text, LOCAL_KEYWORDS)) return 'local';
  if (matchesKeywords(text, DEVELOPMENT_KEYWORDS)) return 'development';
  return 'unknown';
}

/**
 * Maps well-known branch names to environments.
 */
function matchBranchToEnvironment(branch: string): TargetEnvironment | null {
  const lower = branch.toLowerCase();
  if (lower === 'main' || lower === 'master' || lower.startsWith('release')) return 'production';
  if (lower === 'staging' || lower === 'stage') return 'staging';
  if (lower === 'develop' || lower === 'dev') return 'development';
  if (lower.startsWith('feature/') || lower.startsWith('feat/')) return 'development';
  if (lower.startsWith('pr-') || lower.startsWith('preview/')) return 'preview';
  return null;
}

/**
 * Classifies the target environment of a CI/CD command.
 *
 * Priority:
 *   1. Explicit --env / --environment / --field env parameter value
 *   2. --ref branch name (GitHub Actions / GitLab CI)
 *   3. Keywords anywhere in the raw command
 */
export function classifyEnvironment(
  command: string,
  parameters: Record<string, string> = {},
): TargetEnvironment {
  const explicitEnv =
    parameters['env'] ?? parameters['environment'] ?? parameters['field.env'];
  if (explicitEnv) {
    const fromText = detectFromText(explicitEnv);
    if (fromText !== 'unknown') return fromText;
  }

  const ref = parameters['ref'];
  if (ref) {
    const fromBranch = matchBranchToEnvironment(ref);
    if (fromBranch) return fromBranch;
    const fromText = detectFromText(ref);
    if (fromText !== 'unknown') return fromText;
  }

  return detectFromText(command);
}
