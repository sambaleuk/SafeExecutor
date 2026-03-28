import type {
  ParsedCicdCommand,
  CicdTool,
  CicdAction,
  DangerousPattern,
} from './types.js';
import type { RiskLevel } from '../../types/index.js';
import { classifyEnvironment } from './environment-classifier.js';

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function escalateRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

// ─── Tool detection ────────────────────────────────────────────────────────────

function detectTool(command: string): CicdTool {
  const cmd = command.trim();
  if (/^gh\s/.test(cmd)) return 'github-actions';
  if (/^glab\s/.test(cmd) || /curl[^|]*gitlab/i.test(cmd)) return 'gitlab-ci';
  if (/curl[^|]*jenkins/i.test(cmd) || /java[^|]*jenkins/i.test(cmd)) return 'jenkins';
  if (/^docker(-compose|\s+compose)\s/i.test(cmd)) return 'docker-compose';
  if (/^docker\s/.test(cmd)) return 'docker';
  if (
    // Any .sh script invoked with ./ or bash/sh/zsh
    /(?:^|\s)(?:\.\/|bash\s+|sh\s+|zsh\s+)[\w./\\-]+\.sh\b/.test(cmd) ||
    // Named deploy/rollback/release scripts (even without extension)
    /(?:^|\s)(?:\.\/|bash\s+|sh\s+)?[\w./\\-]*(?:deploy|rollback|release)[\w.-]*\b/.test(cmd) ||
    /\brsync\b/.test(cmd) ||
    /\bscp\b/.test(cmd)
  ) {
    return 'deploy-script';
  }
  return 'unknown';
}

// ─── Action detection ──────────────────────────────────────────────────────────

function detectAction(command: string, tool: CicdTool): CicdAction {
  const cmd = command.toLowerCase();

  switch (tool) {
    case 'github-actions':
      if (/workflow\s+run/.test(cmd)) return 'trigger';
      if (/deployment/.test(cmd)) return 'deploy';
      return 'trigger';

    case 'gitlab-ci':
      if (/deploy/.test(cmd)) return 'deploy';
      return 'trigger';

    case 'jenkins':
      if (/deploy/.test(cmd)) return 'deploy';
      return 'trigger';

    case 'docker':
      if (/\bdocker\s+build\b/.test(cmd)) return 'build';
      if (/\bdocker\s+push\b/.test(cmd)) return 'push';
      if (/\bdocker\s+run\b/.test(cmd)) return 'run';
      if (/\bdocker\s+pull\b/.test(cmd)) return 'build';
      return 'unknown';

    case 'docker-compose':
      if (/\bup\b/.test(cmd)) return 'compose-up';
      if (/\bdown\b/.test(cmd)) return 'compose-down';
      return 'unknown';

    case 'deploy-script':
      if (/rollback/.test(cmd)) return 'rollback';
      return 'deploy';

    default:
      return 'unknown';
  }
}

// ─── Image / registry extraction ──────────────────────────────────────────────

function extractImageTag(command: string, tool: CicdTool): string | undefined {
  if (tool !== 'docker') return undefined;

  // docker build -t registry/image:tag .
  const buildTag = command.match(/(?:-t|--tag)\s+(\S+)/);
  if (buildTag) return buildTag[1];

  // docker push <image> or docker run <image>
  const pushRunMatch = command.match(/docker\s+(?:push|run)\s+(?:-\S+\s+)*(\S+)/);
  if (pushRunMatch) {
    const candidate = pushRunMatch[1];
    // Skip flag values
    if (!candidate.startsWith('-')) return candidate;
  }

  return undefined;
}

function extractRegistry(imageTag: string | undefined): string | undefined {
  if (!imageTag) return undefined;
  // registry.io/org/image:tag → registry.io
  // org/image:tag (docker hub) → no registry
  const slashIndex = imageTag.indexOf('/');
  if (slashIndex === -1) return undefined;
  const prefix = imageTag.substring(0, slashIndex);
  // A registry hostname contains a dot or colon (port)
  if (prefix.includes('.') || prefix.includes(':')) return prefix;
  return undefined;
}

const PUBLIC_REGISTRIES = [
  'docker.io',
  'registry.hub.docker.com',
  'hub.docker.com',
  'ghcr.io',
  'quay.io',
  'registry-1.docker.io',
];

function computeIsPublicRegistry(
  registry: string | undefined,
  imageTag: string | undefined,
): boolean {
  if (!imageTag) return false;
  if (!registry) {
    // No registry prefix → docker.io (public hub)
    return true;
  }
  return PUBLIC_REGISTRIES.some((r) => registry.toLowerCase() === r);
}

function computeHasSpecificTag(imageTag: string | undefined): boolean {
  if (!imageTag) return false;
  const colonIndex = imageTag.lastIndexOf(':');
  if (colonIndex === -1) return false; // no tag → implicitly "latest"
  const tag = imageTag.substring(colonIndex + 1);
  return tag !== '' && tag !== 'latest';
}

// ─── Flag detection ────────────────────────────────────────────────────────────

function detectIsForceDeployment(command: string): boolean {
  return /--force\b|--skip-checks\b|--no-verify\b/.test(command);
}

function detectIsPrivileged(command: string): boolean {
  return /--privileged\b/.test(command);
}

function detectHasDangerousMount(command: string): boolean {
  // -v /:/anything or --volume /:/anything
  return /(?:-v|--volume)\s+\/\s*:/.test(command);
}

function detectDangerousPatterns(command: string): DangerousPattern[] {
  const patterns: DangerousPattern[] = [];

  if (detectHasDangerousMount(command)) {
    patterns.push({
      pattern: '-v /:/host',
      description: 'Root filesystem mounted into container — full host access',
      severity: 'DENY',
    });
  }

  if (detectIsPrivileged(command)) {
    patterns.push({
      pattern: '--privileged',
      description: 'Container running with full host privileges',
      severity: 'CRITICAL',
    });
  }

  if (detectIsForceDeployment(command)) {
    patterns.push({
      pattern: '--force/--skip-checks',
      description: 'Force deployment bypasses CI safety gates',
      severity: 'HIGH',
    });
  }

  return patterns;
}

// ─── Parameter / flag extraction ──────────────────────────────────────────────

function extractParameters(command: string): Record<string, string> {
  const params: Record<string, string> = {};

  // --key=value or --key value (when value doesn't start with -)
  for (const match of command.matchAll(/--(\w[\w-]*)(?:=(\S+))?/g)) {
    const key = match[1];
    const value = match[2];
    if (value !== undefined) {
      params[key] = value;
    } else {
      // Peek at next token
      const afterFlag = command.slice((match.index ?? 0) + match[0].length).trimStart();
      const nextToken = afterFlag.match(/^([^\s-]\S*)/);
      params[key] = nextToken ? nextToken[1] : 'true';
    }
  }

  // -e KEY=VALUE (docker environment)
  for (const match of command.matchAll(/-e\s+(\w+)=(\S+)/g)) {
    params[`env.${match[1]}`] = match[2];
  }

  // GitHub Actions --field key=value
  for (const match of command.matchAll(/--field\s+(\w+)=(\S+)/g)) {
    params[`field.${match[1]}`] = match[2];
  }

  return params;
}

function extractFlags(command: string): string[] {
  const flags = new Set<string>();
  for (const match of command.matchAll(/(?:^|\s)(-[a-zA-Z])\b/g)) {
    flags.add(match[1]);
  }
  return [...flags];
}

// ─── Risk computation ──────────────────────────────────────────────────────────

interface RiskInputs {
  action: CicdAction;
  environment: ParsedCicdCommand['environment'];
  isPublicRegistry: boolean;
  hasSpecificTag: boolean;
  isForceDeployment: boolean;
  isPrivileged: boolean;
  hasDangerousMount: boolean;
}

const SAFE_ACTIONS = new Set<CicdAction>(['build', 'test', 'lint']);

function computeRiskLevel(inputs: RiskInputs): RiskLevel {
  let risk: RiskLevel = 'LOW';

  const actionRisk: Record<CicdAction, RiskLevel> = {
    build: 'LOW',
    test: 'LOW',
    lint: 'LOW',
    'compose-up': 'MEDIUM',
    'compose-down': 'MEDIUM',
    trigger: 'MEDIUM',
    run: 'MEDIUM',
    push: 'HIGH',
    deploy: 'HIGH',
    rollback: 'HIGH',
    unknown: 'MEDIUM',
  };
  risk = escalateRisk(risk, actionRisk[inputs.action]);

  // Build / test / lint are non-destructive — environment does not escalate their risk
  if (!SAFE_ACTIONS.has(inputs.action)) {
    const envRisk: Record<ParsedCicdCommand['environment'], RiskLevel> = {
      local: 'LOW',
      development: 'LOW',
      staging: 'MEDIUM',
      preview: 'MEDIUM',
      production: 'CRITICAL',
      unknown: 'MEDIUM',
    };
    risk = escalateRisk(risk, envRisk[inputs.environment]);
  }

  if (inputs.isPublicRegistry && inputs.action === 'push') risk = escalateRisk(risk, 'HIGH');
  if (inputs.isForceDeployment) risk = escalateRisk(risk, 'HIGH');
  if (inputs.isPrivileged) risk = escalateRisk(risk, 'CRITICAL');
  if (inputs.hasDangerousMount) risk = escalateRisk(risk, 'CRITICAL');

  // Deploy latest to production → CRITICAL
  if (
    inputs.action === 'deploy' &&
    inputs.environment === 'production' &&
    !inputs.hasSpecificTag
  ) {
    risk = 'CRITICAL';
  }

  // Push without specific tag → escalate to HIGH
  if (inputs.action === 'push' && !inputs.hasSpecificTag) {
    risk = escalateRisk(risk, 'HIGH');
  }

  return risk;
}

// ─── Public API ────────────────────────────────────────────────────────────────

export function parseCicdCommand(command: string): ParsedCicdCommand {
  if (!command || !command.trim()) {
    throw new Error('CicdParser: empty command');
  }

  const raw = command.trim();
  const tool = detectTool(raw);
  const action = detectAction(raw, tool);
  const parameters = extractParameters(raw);
  const flags = extractFlags(raw);
  const environment = classifyEnvironment(raw, parameters);

  const imageTag = extractImageTag(raw, tool);
  const registry = extractRegistry(imageTag);
  const isPublicRegistry = computeIsPublicRegistry(registry, imageTag);
  const hasSpecificTag = computeHasSpecificTag(imageTag);
  const isForceDeployment = detectIsForceDeployment(raw);
  const isPrivileged = detectIsPrivileged(raw);
  const hasDangerousMount = detectHasDangerousMount(raw);
  const dangerousPatterns = detectDangerousPatterns(raw);

  const riskLevel = computeRiskLevel({
    action,
    environment,
    isPublicRegistry,
    hasSpecificTag,
    isForceDeployment,
    isPrivileged,
    hasDangerousMount,
  });

  const isDestructive =
    action === 'rollback' ||
    action === 'compose-down' ||
    hasDangerousMount ||
    isPrivileged;

  return {
    raw,
    tool,
    action,
    environment,
    imageTag,
    registry,
    isPublicRegistry,
    hasSpecificTag,
    isForceDeployment,
    isPrivileged,
    hasDangerousMount,
    dangerousPatterns,
    parameters,
    flags,
    riskLevel,
    isDestructive,
    metadata: {
      parsedAt: new Date().toISOString(),
      hasDenyPattern: dangerousPatterns.some((p) => p.severity === 'DENY'),
    },
  };
}
