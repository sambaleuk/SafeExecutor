import type {
  CloudCommand,
  CloudIntent,
  CloudProvider,
  CloudActionType,
  CloudRiskLevel,
} from './types.js';
import { lookupRisk } from './risk-matrix.js';

// ─── Action Classification Sets ──────────────────────────────────────────────

const DESTROY_VERBS = new Set([
  'destroy', 'delete', 'terminate', 'rm', 'remove', 'rb', 'drop',
]);

const STATE_VERBS = new Set(['taint', 'untaint']);

const READ_VERBS = new Set([
  'plan', 'describe', 'list', 'get', 'show', 'ls',
  'inspect', 'diff', 'output', 'validate', 'refresh', 'pull',
]);

const WRITE_VERBS = new Set([
  'apply', 'create', 'update', 'modify', 'scale', 'deploy',
  'put', 'post', 'patch', 'add', 'attach', 'set', 'import', 'push',
  'stop', 'start', 'reboot', 'restart', 'reset', 'deallocate',
  'run', 'launch', 'upload', 'mb', 'cp', 'mv', 'sync',
  'authorize', 'revoke', 'enable', 'disable',
]);

/**
 * Classify an action verb into one of the four action types.
 * Handles both exact verbs ('delete') and compound forms ('delete-db-instance').
 */
function classifyAction(action: string): CloudActionType {
  const a = action.toLowerCase();

  // Exact match first
  if (DESTROY_VERBS.has(a)) return 'DESTROY';
  if (STATE_VERBS.has(a)) return 'STATE_MODIFY';
  if (READ_VERBS.has(a)) return 'READ';
  if (WRITE_VERBS.has(a)) return 'WRITE';

  // Prefix match for compound AWS-style actions (e.g. 'terminate-instances', 'delete-db-instance')
  for (const verb of Array.from(DESTROY_VERBS)) {
    if (a.startsWith(verb + '-')) return 'DESTROY';
  }
  for (const verb of Array.from(READ_VERBS)) {
    if (a.startsWith(verb + '-')) return 'READ';
  }
  for (const verb of Array.from(WRITE_VERBS)) {
    if (a.startsWith(verb + '-')) return 'WRITE';
  }

  return 'WRITE'; // conservative default
}

function escalateRisk(level: CloudRiskLevel): CloudRiskLevel {
  switch (level) {
    case 'LOW':      return 'MEDIUM';
    case 'MEDIUM':   return 'HIGH';
    case 'HIGH':     return 'CRITICAL';
    case 'CRITICAL': return 'CRITICAL';
  }
}

// ─── Flag Parser ─────────────────────────────────────────────────────────────

/**
 * Parse a flat list of CLI argument tokens into flags and positional resources.
 *
 * Handles:
 *   --key value     → flags['key'] = 'value'
 *   --key=value     → flags['key'] = 'value'
 *   --flag          → flags['flag'] = true
 *   -key=value      → flags['key'] = 'value'  (Terraform style: -target=aws_instance.foo)
 *   -key value      → flags['key'] = 'value'
 *   -f              → flags['f'] = true
 *   positional      → resources[]
 */
function parseFlags(args: string[]): {
  flags: Record<string, string | boolean>;
  resources: string[];
} {
  const flags: Record<string, string | boolean> = {};
  const resources: string[] = [];
  let i = 0;

  while (i < args.length) {
    const arg = args[i];

    if (arg.startsWith('-')) {
      // Strip leading dashes to get the key part
      const keyPart = arg.startsWith('--') ? arg.slice(2) : arg.slice(1);

      if (keyPart.includes('=')) {
        // --key=value or -key=value
        const eqIdx = keyPart.indexOf('=');
        flags[keyPart.slice(0, eqIdx)] = keyPart.slice(eqIdx + 1);
        i++;
      } else {
        // --key value or -key value (next token is value only if it's not a flag)
        const next = args[i + 1];
        if (next !== undefined && !next.startsWith('-')) {
          flags[keyPart] = next;
          i += 2;
        } else {
          flags[keyPart] = true;
          i++;
        }
      }
    } else {
      resources.push(arg);
      i++;
    }
  }

  return { flags, resources };
}

// ─── Provider-specific Parsers ────────────────────────────────────────────────

function parseTerraform(tokens: string[]): CloudCommand {
  // terraform <subcommand> [options...]
  // terraform state <action> [options...]
  const subcommand = tokens[1] ?? 'unknown';

  if (subcommand === 'state' && tokens[2]) {
    // terraform state rm|mv|pull|push ...
    const stateAction = tokens[2];
    const { flags, resources } = parseFlags(tokens.slice(3));
    return {
      provider: 'terraform',
      service: 'state',
      action: stateAction,
      resources,
      flags,
      raw: tokens.join(' '),
    };
  }

  const { flags, resources } = parseFlags(tokens.slice(2));
  return {
    provider: 'terraform',
    service: subcommand,
    action: subcommand,
    resources,
    flags,
    raw: tokens.join(' '),
  };
}

function parseAws(tokens: string[]): CloudCommand {
  // aws [global-options] <service> <command> [options...]
  const service = tokens[1] ?? 'unknown';
  const action = tokens[2] ?? 'unknown';
  const { flags, resources } = parseFlags(tokens.slice(3));
  return {
    provider: 'aws',
    service,
    action,
    resources,
    flags,
    raw: tokens.join(' '),
  };
}

function parseGcloud(tokens: string[]): CloudCommand {
  // gcloud <service> <resource-type> <action> [name] [options...]
  // e.g.: gcloud compute instances delete my-vm --zone=us-east1-b
  // e.g.: gcloud sql instances delete my-db
  // e.g.: gcloud storage buckets delete gs://my-bucket
  const service = tokens[1] ?? 'unknown';
  const resourceType = tokens[2] ?? 'unknown';
  const action = tokens[3] ?? 'unknown';
  const { flags, resources } = parseFlags(tokens.slice(4));
  return {
    provider: 'gcloud',
    service: `${service}:${resourceType}`,
    action,
    resources,
    flags,
    raw: tokens.join(' '),
  };
}

/**
 * Returns true if a token looks like an action verb (not a sub-resource name).
 * Used to distinguish `az vm delete` (2-level) from `az sql db delete` (3-level).
 */
function isAzureActionVerb(token: string): boolean {
  const t = token.toLowerCase();
  if (DESTROY_VERBS.has(t) || READ_VERBS.has(t) || WRITE_VERBS.has(t) || STATE_VERBS.has(t)) {
    return true;
  }
  for (const v of Array.from(DESTROY_VERBS)) {
    if (t.startsWith(v + '-')) return true;
  }
  for (const v of Array.from(READ_VERBS)) {
    if (t.startsWith(v + '-')) return true;
  }
  for (const v of Array.from(WRITE_VERBS)) {
    if (t.startsWith(v + '-')) return true;
  }
  return false;
}

function parseAz(tokens: string[]): CloudCommand {
  // Azure uses two different command depths:
  //   2-level: az <service> <action> [options...]
  //     e.g.: az vm delete --name my-vm
  //   3-level: az <service> <sub-resource> <action> [options...]
  //     e.g.: az sql db delete --name mydb
  //     e.g.: az storage account delete --name acct
  //     e.g.: az ad app delete --id 12345
  //
  // Heuristic: if tokens[2] is NOT a recognized action verb, treat it as a
  // sub-resource and use tokens[3] as the action.
  const baseService = tokens[1] ?? 'unknown';
  const second = tokens[2] ?? 'unknown';

  let service: string;
  let action: string;
  let restStart: number;

  if (tokens[3] && !isAzureActionVerb(second) && isAzureActionVerb(tokens[3])) {
    // 3-level: az sql db delete
    service = `${baseService}:${second}`;
    action = tokens[3];
    restStart = 4;
  } else {
    // 2-level: az vm delete
    service = baseService;
    action = second;
    restStart = 3;
  }

  const { flags, resources } = parseFlags(tokens.slice(restStart));
  return {
    provider: 'az',
    service,
    action,
    resources,
    flags,
    raw: tokens.join(' '),
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function parseCloudCommand(raw: string): CloudCommand {
  const tokens = raw.trim().split(/\s+/);
  const cli = tokens[0].toLowerCase() as CloudProvider;

  switch (cli) {
    case 'terraform': return parseTerraform(tokens);
    case 'aws':       return parseAws(tokens);
    case 'gcloud':    return parseGcloud(tokens);
    case 'az':        return parseAz(tokens);
    default:
      throw new Error(
        `Unsupported cloud CLI: '${tokens[0]}'. Supported: terraform, aws, gcloud, az`,
      );
  }
}

export function buildCloudIntent(raw: string): CloudIntent {
  const command = parseCloudCommand(raw);
  const { provider, service, action, flags, resources } = command;

  // Classify the action
  let actionType = classifyAction(action);

  // terraform state rm/mv always override to STATE_MODIFY (rm is in DESTROY_VERBS)
  if (provider === 'terraform' && service === 'state') {
    actionType = 'STATE_MODIFY';
  }

  // Determine base risk from the matrix
  let riskLevel = lookupRisk(provider, service, action);

  // ── Dangerous pattern overrides ──────────────────────────────────────────

  // 1. terraform destroy without -target → CRITICAL, marks affectsAll
  const affectsAll =
    provider === 'terraform' &&
    action === 'destroy' &&
    flags['target'] === undefined &&
    resources.length === 0;

  // 2. Any aws iam operation → HIGH minimum
  if (provider === 'aws' && service === 'iam') {
    if (riskLevel === 'LOW' || riskLevel === 'MEDIUM') {
      riskLevel = 'HIGH';
    }
  }

  // 3. --force on any command → escalate one level
  if (flags['force'] !== undefined || flags['f'] === true) {
    riskLevel = escalateRisk(riskLevel);
  }

  const isDestructive =
    actionType === 'DESTROY' ||
    actionType === 'STATE_MODIFY' ||
    riskLevel === 'CRITICAL';

  return {
    raw,
    command,
    riskLevel,
    actionType,
    isDestructive,
    affectsAll,
    metadata: { provider, service, action, flags },
  };
}
