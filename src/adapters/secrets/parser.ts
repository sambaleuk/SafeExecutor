import type {
  ParsedSecretCommand,
  SecretTool,
  SecretAction,
  SecretScope,
  DangerousPattern,
} from './types.js';
import type { RiskLevel } from '../../types/index.js';

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function escalateRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

// ─── Tool detection ─────────────────────────────────────────────────────────

function detectTool(command: string): SecretTool {
  const cmd = command.trim();
  if (/^vault\s/.test(cmd)) return 'vault';
  if (/^aws\s+secretsmanager\b/.test(cmd)) return 'aws-secrets';
  if (/^aws\s+ssm\b/.test(cmd)) return 'aws-ssm';
  if (/^gcloud\s+secrets?\b/.test(cmd)) return 'gcloud-secrets';
  if (/^az\s+keyvault\b/.test(cmd)) return 'az-keyvault';
  if (/^kubectl\s.*\bsecret/.test(cmd)) return 'kubectl-secrets';
  if (/^docker\s+secret\b/.test(cmd)) return 'docker-secrets';
  if (/^export\s+\w+=/.test(cmd) || /^printenv\b/.test(cmd) || /^env\b/.test(cmd)) {
    return 'env-export';
  }
  return 'unknown';
}

// ─── Action detection ───────────────────────────────────────────────────────

function detectAction(command: string, tool: SecretTool): SecretAction {
  const cmd = command.toLowerCase();

  switch (tool) {
    case 'vault':
      if (/\bread\b/.test(cmd) || /\bget\b/.test(cmd)) return 'read';
      if (/\bwrite\b/.test(cmd) || /\bput\b/.test(cmd)) return 'write';
      if (/\bdelete\b/.test(cmd) || /\bdestroy\b/.test(cmd)) return 'delete';
      if (/\blist\b/.test(cmd)) return 'list';
      return 'read';

    case 'aws-secrets':
      if (/get-secret-value/.test(cmd)) return 'read';
      if (/create-secret/.test(cmd)) return 'create';
      if (/put-secret-value/.test(cmd) || /update-secret/.test(cmd)) return 'write';
      if (/delete-secret/.test(cmd)) return 'delete';
      if (/list-secrets/.test(cmd)) return 'list';
      if (/rotate-secret/.test(cmd)) return 'rotate';
      return 'read';

    case 'aws-ssm':
      if (/get-parameter/.test(cmd)) return 'read';
      if (/put-parameter/.test(cmd)) return 'write';
      if (/delete-parameter/.test(cmd)) return 'delete';
      if (/get-parameters-by-path/.test(cmd) || /describe-parameters/.test(cmd)) return 'list';
      return 'read';

    case 'gcloud-secrets':
      if (/\bversions\s+access\b/.test(cmd) || /\baccess\b/.test(cmd)) return 'read';
      if (/\bcreate\b/.test(cmd)) return 'create';
      if (/\bversions\s+add\b/.test(cmd) || /\bset\b/.test(cmd)) return 'write';
      if (/\bdelete\b/.test(cmd)) return 'delete';
      if (/\blist\b/.test(cmd)) return 'list';
      return 'read';

    case 'az-keyvault':
      if (/secret\s+show\b/.test(cmd) || /secret\s+download\b/.test(cmd)) return 'read';
      if (/secret\s+set\b/.test(cmd)) return 'write';
      if (/secret\s+delete\b/.test(cmd) || /secret\s+purge\b/.test(cmd)) return 'delete';
      if (/secret\s+list\b/.test(cmd)) return 'list';
      if (/secret\s+set-attributes\b/.test(cmd)) return 'write';
      return 'read';

    case 'kubectl-secrets':
      if (/\bget\b/.test(cmd)) return 'read';
      if (/\bcreate\b/.test(cmd) || /\bapply\b/.test(cmd)) return 'create';
      if (/\bdelete\b/.test(cmd)) return 'delete';
      if (/\bedit\b/.test(cmd) || /\bpatch\b/.test(cmd)) return 'write';
      return 'read';

    case 'docker-secrets':
      if (/secret\s+inspect\b/.test(cmd)) return 'read';
      if (/secret\s+create\b/.test(cmd)) return 'create';
      if (/secret\s+rm\b/.test(cmd)) return 'delete';
      if (/secret\s+ls\b/.test(cmd)) return 'list';
      return 'read';

    case 'env-export':
      if (/^export\s/.test(cmd)) return 'export';
      return 'read';

    default:
      return 'unknown';
  }
}

// ─── Scope detection ────────────────────────────────────────────────────────

function detectScope(command: string, tool: SecretTool, action: SecretAction): SecretScope {
  if (action === 'list') return 'namespace';
  if (/--recursive/.test(command) || /by-path/.test(command)) return 'namespace';

  // Wildcard paths indicate namespace scope
  if (/[/*]$/.test(command) || /\*/.test(command)) return 'namespace';

  // Global destructive operations
  if (tool === 'vault' && action === 'delete' && /\bmetadata\b/.test(command)) return 'global';

  return 'single';
}

// ─── Secret path extraction ─────────────────────────────────────────────────

function extractSecretPath(command: string, tool: SecretTool): string | undefined {
  // Vault: vault read secret/data/myapp/db-password
  if (tool === 'vault') {
    const m = command.match(/(?:read|write|delete|list|get|put|destroy)\s+([\w/.-]+)/);
    return m?.[1];
  }
  // AWS: --secret-id <name> or --name <name>
  if (tool === 'aws-secrets' || tool === 'aws-ssm') {
    const m = command.match(/--(?:secret-id|name|path)\s+["']?([^\s"']+)/);
    return m?.[1];
  }
  // GCloud: gcloud secrets versions access latest --secret=<name>
  if (tool === 'gcloud-secrets') {
    const m = command.match(/--secret[=\s]+["']?([^\s"']+)/) ??
              command.match(/secrets?\s+\w+\s+([\w/.-]+)/);
    return m?.[1];
  }
  // AZ: --name <name> --vault-name <vault>
  if (tool === 'az-keyvault') {
    const m = command.match(/--name\s+["']?([^\s"']+)/);
    return m?.[1];
  }
  // Kubectl: kubectl get secret <name>
  if (tool === 'kubectl-secrets') {
    const m = command.match(/secret\s+(?:get|create|delete|edit|patch|apply)\s+(?:-[fnol]\s+\S+\s+)*(\S+)/);
    return m?.[1];
  }
  return undefined;
}

// ─── Namespace extraction ───────────────────────────────────────────────────

function extractNamespace(command: string): string | undefined {
  const m = command.match(/-n\s+["']?([^\s"']+)/) ??
            command.match(/--namespace[=\s]+["']?([^\s"']+)/) ??
            command.match(/--vault-name[=\s]+["']?([^\s"']+)/);
  return m?.[1];
}

// ─── Production detection ───────────────────────────────────────────────────

function isProductionContext(command: string, secretPath?: string): boolean {
  const combined = `${command} ${secretPath ?? ''}`.toLowerCase();
  return /\bprod(?:uction)?\b/.test(combined) ||
         /--vault-name\s+\S*prod/i.test(command) ||
         /\brelease\b/.test(combined);
}

// ─── Dangerous patterns ─────────────────────────────────────────────────────

const DANGEROUS_PATTERNS: Array<{ regex: RegExp; pattern: string; description: string; severity: DangerousPattern['severity'] }> = [
  { regex: /--force-delete-without-recovery/, pattern: '--force-delete-without-recovery', description: 'Permanently deletes secret without recovery window', severity: 'DENY' },
  { regex: /\bpurge\b/, pattern: 'purge', description: 'Permanently purges deleted secret — unrecoverable', severity: 'DENY' },
  { regex: /secret\s+delete\s+--id\s+\*/, pattern: 'wildcard-delete', description: 'Wildcard secret deletion — mass data loss', severity: 'DENY' },
  { regex: /\bdestroy\b.*\bversions=all\b/, pattern: 'destroy-all-versions', description: 'Destroys all versions of a secret — unrecoverable', severity: 'DENY' },
  { regex: /--output\s+(?:text|table).*get-secret-value/, pattern: 'plaintext-output', description: 'Secret value printed in plaintext to stdout', severity: 'HIGH' },
  { regex: /get-secret-value.*--output\s+(?:text|table)/, pattern: 'plaintext-output', description: 'Secret value printed in plaintext to stdout', severity: 'HIGH' },
  { regex: /-o\s+(?:yaml|json|jsonpath).*secret/, pattern: 'k8s-secret-decode', description: 'Kubernetes secret decoded to stdout', severity: 'HIGH' },
  { regex: /\|\s*(?:base64|jq|grep|awk)/, pattern: 'pipe-secret', description: 'Secret value piped to another command — risk of logging', severity: 'HIGH' },
  { regex: />\s*\S+/, pattern: 'redirect-to-file', description: 'Secret value redirected to file — may persist on disk', severity: 'HIGH' },
  { regex: /--force/, pattern: '--force', description: 'Force flag bypasses safety confirmations', severity: 'HIGH' },
];

function detectDangerousPatterns(command: string): DangerousPattern[] {
  const results: DangerousPattern[] = [];
  for (const dp of DANGEROUS_PATTERNS) {
    if (dp.regex.test(command)) {
      results.push({ pattern: dp.pattern, description: dp.description, severity: dp.severity });
    }
  }
  return results;
}

// ─── Flag extraction ────────────────────────────────────────────────────────

function extractFlags(command: string): string[] {
  const matches = command.match(/--?[\w-]+/g) ?? [];
  return [...new Set(matches)];
}

// ─── Risk classification ────────────────────────────────────────────────────

function classifyRisk(
  action: SecretAction,
  scope: SecretScope,
  isProduction: boolean,
  dangerousPatterns: DangerousPattern[],
): RiskLevel {
  let risk: RiskLevel = 'LOW';

  // Action-based risk
  if (action === 'read' || action === 'list') risk = 'LOW';
  else if (action === 'export') risk = 'MEDIUM';
  else if (action === 'create' || action === 'write') risk = 'MEDIUM';
  else if (action === 'rotate') risk = 'HIGH';
  else if (action === 'delete') risk = 'HIGH';

  // Scope escalation
  if (scope === 'namespace') risk = escalateRisk(risk, 'MEDIUM');
  if (scope === 'global') risk = escalateRisk(risk, 'HIGH');

  // Production escalation
  if (isProduction && (action !== 'read' && action !== 'list')) {
    risk = escalateRisk(risk, 'HIGH');
  }

  // Dangerous patterns escalation
  for (const dp of dangerousPatterns) {
    if (dp.severity === 'DENY' || dp.severity === 'CRITICAL') risk = escalateRisk(risk, 'CRITICAL');
    else if (dp.severity === 'HIGH') risk = escalateRisk(risk, 'HIGH');
  }

  return risk;
}

// ─── Main parser ────────────────────────────────────────────────────────────

export function parseSecretCommand(raw: string): ParsedSecretCommand {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('Empty command');

  const tool = detectTool(trimmed);
  const action = detectAction(trimmed, tool);
  const scope = detectScope(trimmed, tool, action);
  const secretPath = extractSecretPath(trimmed, tool);
  const namespace = extractNamespace(trimmed);
  const isProduction = isProductionContext(trimmed, secretPath);
  const dangerousPatterns = detectDangerousPatterns(trimmed);
  const flags = extractFlags(trimmed);

  const exposesValue = action === 'read' || action === 'export' ||
    /get-secret-value/.test(trimmed) || /versions\s+access/.test(trimmed) ||
    /secret\s+show/.test(trimmed);

  const isOverwrite = (action === 'write' || action === 'create') &&
    (/--overwrite/.test(trimmed) || tool === 'aws-ssm');

  const isForce = /--force/.test(trimmed);

  const isDestructive = action === 'delete' || action === 'rotate' ||
    dangerousPatterns.some(dp => dp.severity === 'DENY');

  const riskLevel = classifyRisk(action, scope, isProduction, dangerousPatterns);

  return {
    raw: trimmed,
    tool,
    action,
    scope,
    riskLevel,
    isDestructive,
    secretPath,
    namespace,
    exposesValue,
    isOverwrite,
    isProduction,
    isForce,
    dangerousPatterns,
    parameters: {
      ...(secretPath ? { secretPath } : {}),
      ...(namespace ? { namespace } : {}),
    },
    flags,
    metadata: {},
  };
}
