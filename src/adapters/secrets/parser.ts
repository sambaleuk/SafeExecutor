import type { ParsedSecretCommand, SecretAction, SecretEnvironment, SecretTool } from './types.js';

/**
 * Secret Command Parser
 *
 * Parses raw secret management commands into a structured ParsedSecretCommand.
 * Supports: vault, aws secretsmanager, aws ssm, gcloud secrets,
 *           az keyvault, kubectl secret, docker secret, export/.env
 */

// ─── Environment Detection ────────────────────────────────────────────────────

const PROD_RE = /\b(prod|production|prd)\b/i;
const STAGING_RE = /\b(stag|staging|stg)\b/i;
const DEV_RE = /\b(dev|development|local|test|sandbox)\b/i;

function detectEnvironment(text: string): SecretEnvironment {
  if (PROD_RE.test(text)) return 'production';
  if (STAGING_RE.test(text)) return 'staging';
  if (DEV_RE.test(text)) return 'development';
  return 'unknown';
}

function isWildcardPath(path: string): boolean {
  return path === '' || path === '/' || path.endsWith('/') || path.includes('*');
}

// ─── Inline Secret Detection ──────────────────────────────────────────────────

function detectInlinePlaintext(command: string): boolean {
  // vault kv put secret/path key=value  (value= pattern implies a value assignment)
  if (/\bvalue\s*=\s*\S+/i.test(command)) return true;
  // --secret-string, --value, --password flags with actual values (not file references)
  if (/--(?:secret-string|value|password|token)\s+(?!@)\S+/i.test(command)) return true;
  // --from-literal=key=actualvalue (kubectl)
  if (/--from-literal\s*=\s*\w+=\S+/.test(command)) return true;
  // export VAR=actualvalue (non-empty value)
  if (/^export\s+\w+=\S+/i.test(command.trim())) return true;
  return false;
}

function detectRawOutput(command: string): boolean {
  if (/-o\s+(?:yaml|json)\b/i.test(command)) return true;
  if (/--output\s+(?:yaml|json)\b/i.test(command)) return true;
  // aws secretsmanager --query SecretString exposes the secret value
  if (/--query\s+SecretString/i.test(command)) return true;
  if (/-format\s*=\s*(?:json|yaml)/i.test(command)) return true;
  return false;
}

// ─── Flag Extraction ──────────────────────────────────────────────────────────

function extractFlag(parts: string[], flag: string): string | undefined {
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i]!;
    if (p === `--${flag}` && i + 1 < parts.length) return parts[i + 1];
    const eqMatch = p.match(new RegExp(`^--${flag}=(.+)$`));
    if (eqMatch?.[1]) return eqMatch[1];
  }
  return undefined;
}

// ─── Internal partial type ────────────────────────────────────────────────────

interface PartialParsed {
  action: SecretAction;
  secretPath: string;
  version?: string;
}

// ─── Vault ────────────────────────────────────────────────────────────────────

function parseVault(parts: string[]): PartialParsed {
  const sub = parts[1] ?? '';

  if (sub === 'kv') {
    const kvOp = parts[2] ?? '';
    let action: SecretAction;
    switch (kvOp) {
      case 'get':      action = 'read';   break;
      case 'put':      action = 'write';  break;
      case 'patch':    action = 'write';  break;
      case 'delete':   action = 'delete'; break;
      case 'list':     action = 'list';   break;
      case 'undelete': action = 'write';  break;
      default:         action = 'read';   break;
    }

    let secretPath = '';
    let version: string | undefined;

    for (let i = 3; i < parts.length; i++) {
      const p = parts[i]!;
      const versionMatch = p.match(/^-?-versions?=(.+)$/);
      if (versionMatch?.[1]) { version = versionMatch[1]; continue; }
      if (p.startsWith('-')) continue;
      // For write, stop at first non-flag token that has no '=' (the path)
      if (!p.includes('=') || action === 'read') { secretPath = p; break; }
    }

    return { action, secretPath, version };
  }

  // vault read / write / delete / list / unwrap
  let action: SecretAction;
  switch (sub) {
    case 'read':   action = 'read';   break;
    case 'write':  action = 'write';  break;
    case 'delete': action = 'delete'; break;
    case 'list':   action = 'list';   break;
    case 'unwrap': action = 'read';   break;
    default:       action = 'read';   break;
  }

  let secretPath = '';
  for (let i = 2; i < parts.length; i++) {
    const p = parts[i]!;
    if (p.startsWith('-')) continue;
    if (!p.includes('=')) { secretPath = p; break; }
  }

  return { action, secretPath };
}

// ─── AWS Secrets Manager ──────────────────────────────────────────────────────

function parseAwsSecrets(parts: string[]): PartialParsed {
  // aws secretsmanager <subcommand> [flags]
  const subCmd = parts[2] ?? '';
  let action: SecretAction;
  switch (subCmd) {
    case 'get-secret-value':   action = 'read';   break;
    case 'describe-secret':    action = 'read';   break;
    case 'create-secret':      action = 'write';  break;
    case 'update-secret':      action = 'write';  break;
    case 'put-secret-value':   action = 'write';  break;
    case 'delete-secret':      action = 'delete'; break;
    case 'list-secrets':       action = 'list';   break;
    case 'rotate-secret':      action = 'rotate'; break;
    case 'restore-secret':     action = 'write';  break;
    default:                   action = 'read';   break;
  }

  const secretPath =
    extractFlag(parts, 'secret-id') ??
    extractFlag(parts, 'name') ??
    '';

  const version =
    extractFlag(parts, 'version-id') ??
    extractFlag(parts, 'version-stage');

  return { action, secretPath, version };
}

// ─── AWS SSM Parameter Store ──────────────────────────────────────────────────

function parseAwsSsm(parts: string[]): PartialParsed {
  // aws ssm <subcommand> [flags]
  const subCmd = parts[2] ?? '';
  let action: SecretAction;
  switch (subCmd) {
    case 'get-parameter':          action = 'read';   break;
    case 'get-parameters':         action = 'read';   break;
    case 'get-parameters-by-path': action = 'list';   break;
    case 'put-parameter':          action = 'write';  break;
    case 'delete-parameter':       action = 'delete'; break;
    case 'delete-parameters':      action = 'delete'; break;
    case 'describe-parameters':    action = 'list';   break;
    default:                       action = 'read';   break;
  }

  const secretPath =
    extractFlag(parts, 'name') ??
    extractFlag(parts, 'path') ??
    '';

  return { action, secretPath };
}

// ─── GCP Secret Manager ───────────────────────────────────────────────────────

function parseGcloudSecrets(parts: string[]): PartialParsed {
  // gcloud secrets <subcommand> [name] [flags]
  // gcloud secrets versions <subcommand> [version] --secret=<name>
  const sub = parts[2] ?? '';

  if (sub === 'versions') {
    const vSub = parts[3] ?? '';
    let action: SecretAction;
    switch (vSub) {
      case 'access':  action = 'read';   break;
      case 'add':     action = 'write';  break;
      case 'destroy': action = 'delete'; break;
      case 'disable': action = 'write';  break;
      case 'enable':  action = 'write';  break;
      case 'list':    action = 'list';   break;
      default:        action = 'read';   break;
    }
    const version = parts[4] && !parts[4].startsWith('-') ? parts[4] : undefined;
    const secretPath = extractFlag(parts, 'secret') ?? '';
    return { action, secretPath, version };
  }

  let action: SecretAction;
  switch (sub) {
    case 'create':   action = 'write';  break;
    case 'delete':   action = 'delete'; break;
    case 'update':   action = 'write';  break;
    case 'list':     action = 'list';   break;
    case 'describe': action = 'read';   break;
    default:         action = 'read';   break;
  }

  const nameArg = parts[3] && !parts[3].startsWith('-') ? parts[3] : undefined;
  const secretPath = nameArg ?? extractFlag(parts, 'secret') ?? '';

  return { action, secretPath };
}

// ─── Azure Key Vault ──────────────────────────────────────────────────────────

function parseAzureKeyVault(parts: string[]): PartialParsed {
  // az keyvault secret <subcommand> [flags]
  const sub = parts[3] ?? '';
  let action: SecretAction;
  switch (sub) {
    case 'show':          action = 'read';   break;
    case 'download':      action = 'read';   break;
    case 'list':          action = 'list';   break;
    case 'list-versions': action = 'list';   break;
    case 'set':           action = 'write';  break;
    case 'delete':        action = 'delete'; break;
    case 'recover':       action = 'write';  break;
    case 'purge':         action = 'delete'; break;
    case 'restore':       action = 'write';  break;
    default:              action = 'read';   break;
  }

  const secretPath = extractFlag(parts, 'name') ?? '';
  return { action, secretPath };
}

// ─── Kubernetes Secrets ───────────────────────────────────────────────────────

function parseKubernetes(parts: string[]): PartialParsed {
  // kubectl <verb> secret[s] [name] [flags]
  const verb = parts[1] ?? '';
  let action: SecretAction;
  switch (verb) {
    case 'get':      action = 'read';   break;
    case 'describe': action = 'read';   break;
    case 'create':   action = 'write';  break;
    case 'apply':    action = 'write';  break;
    case 'delete':   action = 'delete'; break;
    case 'patch':    action = 'write';  break;
    default:         action = 'read';   break;
  }

  // Extract secret name — skip verb, "secret"/"secrets", and subtype keywords
  const SKIP_TOKENS = new Set(['secret', 'secrets', 'generic', 'docker-registry', 'tls']);
  let secretPath = '';
  for (let i = 2; i < parts.length; i++) {
    const p = parts[i]!;
    if (p.startsWith('-')) continue;
    if (SKIP_TOKENS.has(p)) continue;
    secretPath = p;
    break;
  }

  return { action, secretPath };
}

// ─── Docker Secrets ───────────────────────────────────────────────────────────

function parseDocker(parts: string[]): PartialParsed {
  // docker secret <subcommand> [name]
  const sub = parts[2] ?? '';
  let action: SecretAction;
  switch (sub) {
    case 'create':  action = 'write';  break;
    case 'rm':      action = 'delete'; break;
    case 'remove':  action = 'delete'; break;
    case 'ls':      action = 'list';   break;
    case 'inspect': action = 'read';   break;
    default:        action = 'read';   break;
  }

  const nameCandidate = parts[3];
  const secretPath = nameCandidate && !nameCandidate.startsWith('-') ? nameCandidate : '';
  return { action, secretPath };
}

// ─── Environment Variables ────────────────────────────────────────────────────

function parseEnv(raw: string): PartialParsed {
  const trimmed = raw.trim();

  if (/^export\s+(\w+)/i.test(trimmed)) {
    const m = trimmed.match(/^export\s+(\w+)/i);
    return { action: 'write', secretPath: m?.[1] ?? '' };
  }

  if (/\.env\b/.test(trimmed)) {
    return { action: 'write', secretPath: '.env' };
  }

  return { action: 'write', secretPath: '' };
}

// ─── Main Entry Point ─────────────────────────────────────────────────────────

export function parseSecretCommand(raw: string): ParsedSecretCommand {
  if (!raw || !raw.trim()) {
    throw new Error('Secret parser: empty command provided');
  }

  const trimmed = raw.trim();
  const parts = trimmed.split(/\s+/);
  const cmd = parts[0] ?? '';

  let tool: SecretTool = 'unknown';
  let action: SecretAction = 'read';
  let secretPath = '';
  let version: string | undefined;

  if (cmd === 'vault') {
    tool = 'vault';
    const parsed = parseVault(parts);
    action = parsed.action;
    secretPath = parsed.secretPath;
    version = parsed.version;
  } else if (cmd === 'aws') {
    const awsSub = parts[1] ?? '';
    if (awsSub === 'secretsmanager') {
      tool = 'aws-secrets-manager';
      const parsed = parseAwsSecrets(parts);
      action = parsed.action;
      secretPath = parsed.secretPath;
      version = parsed.version;
    } else if (awsSub === 'ssm') {
      tool = 'aws-ssm';
      const parsed = parseAwsSsm(parts);
      action = parsed.action;
      secretPath = parsed.secretPath;
    }
  } else if (cmd === 'gcloud') {
    const gSub = parts[1] ?? '';
    if (gSub === 'secrets') {
      tool = 'gcp-secret-manager';
      const parsed = parseGcloudSecrets(parts);
      action = parsed.action;
      secretPath = parsed.secretPath;
      version = parsed.version;
    }
  } else if (cmd === 'az') {
    const azSub1 = parts[1] ?? '';
    const azSub2 = parts[2] ?? '';
    if (azSub1 === 'keyvault' && azSub2 === 'secret') {
      tool = 'azure-key-vault';
      const parsed = parseAzureKeyVault(parts);
      action = parsed.action;
      secretPath = parsed.secretPath;
    }
  } else if (cmd === 'kubectl') {
    const hasSecret = parts.some((p) => p === 'secret' || p === 'secrets');
    if (hasSecret) {
      tool = 'kubernetes';
      const parsed = parseKubernetes(parts);
      action = parsed.action;
      secretPath = parsed.secretPath;
    }
  } else if (cmd === 'docker') {
    const dockerSub = parts[1] ?? '';
    if (dockerSub === 'secret') {
      tool = 'docker';
      const parsed = parseDocker(parts);
      action = parsed.action;
      secretPath = parsed.secretPath;
    }
  } else if (cmd === 'export' || trimmed.includes('.env')) {
    tool = 'env';
    const parsed = parseEnv(trimmed);
    action = parsed.action;
    secretPath = parsed.secretPath;
  }

  // Environment is inferred from the secret path first, then the full command
  const environment = detectEnvironment(secretPath || raw);
  const isWildcard = isWildcardPath(secretPath);
  const hasPlaintextSecret = detectInlinePlaintext(raw);
  const isRawOutput = detectRawOutput(raw);

  const result: ParsedSecretCommand = {
    raw: trimmed,
    tool,
    action,
    secretPath,
    environment,
    isWildcard,
    hasPlaintextSecret,
    isRawOutput,
    metadata: {
      parsedAt: new Date().toISOString(),
    },
  };

  if (version !== undefined) {
    result.version = version;
  }

  return result;
}
