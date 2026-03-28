import { readFileSync } from 'fs';
import { parseCicdCommand } from '../src/adapters/cicd/parser.js';
import { classifyEnvironment } from '../src/adapters/cicd/environment-classifier.js';
import { simulateCicdCommand } from '../src/adapters/cicd/sandbox.js';
import { CicdAdapter, evaluateCicdPolicy } from '../src/adapters/cicd/adapter.js';
import type { CicdPolicy, ParsedCicdCommand } from '../src/adapters/cicd/types.js';

// ─── Fixtures ──────────────────────────────────────────────────────────────────

const defaultPolicy = JSON.parse(
  readFileSync(new URL('../config/policies/cicd-default-policy.json', import.meta.url), 'utf-8'),
) as CicdPolicy;

// ─── Parser: tool detection ────────────────────────────────────────────────────

describe('parseCicdCommand — tool detection', () => {
  test('detects github-actions from gh workflow run', () => {
    const r = parseCicdCommand('gh workflow run deploy.yml --ref main');
    expect(r.tool).toBe('github-actions');
    expect(r.action).toBe('trigger');
  });

  test('detects docker build', () => {
    const r = parseCicdCommand('docker build -t myapp:1.2.3 .');
    expect(r.tool).toBe('docker');
    expect(r.action).toBe('build');
  });

  test('detects docker push', () => {
    const r = parseCicdCommand('docker push myregistry.internal/myapp:1.2.3');
    expect(r.tool).toBe('docker');
    expect(r.action).toBe('push');
  });

  test('detects docker run', () => {
    const r = parseCicdCommand('docker run myapp:latest');
    expect(r.tool).toBe('docker');
    expect(r.action).toBe('run');
  });

  test('detects docker-compose up', () => {
    const r = parseCicdCommand('docker-compose up -d');
    expect(r.tool).toBe('docker-compose');
    expect(r.action).toBe('compose-up');
  });

  test('detects docker-compose down', () => {
    const r = parseCicdCommand('docker compose down');
    expect(r.tool).toBe('docker-compose');
    expect(r.action).toBe('compose-down');
  });

  test('detects deploy script', () => {
    const r = parseCicdCommand('./deploy.sh --env production');
    expect(r.tool).toBe('deploy-script');
    expect(r.action).toBe('deploy');
  });

  test('detects rollback from rollback.sh', () => {
    const r = parseCicdCommand('./rollback.sh --env production');
    expect(r.tool).toBe('deploy-script');
    expect(r.action).toBe('rollback');
  });

  test('detects rsync as deploy-script', () => {
    const r = parseCicdCommand('rsync -avz ./dist/ user@prod-server:/app/');
    expect(r.tool).toBe('deploy-script');
  });
});

// ─── Parser: image tag handling ────────────────────────────────────────────────

describe('parseCicdCommand — image tag handling', () => {
  test('extracts specific tag from docker build -t', () => {
    const r = parseCicdCommand('docker build -t myapp:1.2.3 .');
    expect(r.imageTag).toBe('myapp:1.2.3');
    expect(r.hasSpecificTag).toBe(true);
  });

  test('detects latest tag as not specific', () => {
    const r = parseCicdCommand('docker push myapp:latest');
    expect(r.hasSpecificTag).toBe(false);
  });

  test('detects missing tag as not specific', () => {
    const r = parseCicdCommand('docker push myapp');
    expect(r.hasSpecificTag).toBe(false);
  });

  test('extracts registry from image tag with domain', () => {
    const r = parseCicdCommand('docker push myregistry.internal/myapp:1.0.0');
    expect(r.registry).toBe('myregistry.internal');
    expect(r.isPublicRegistry).toBe(false);
  });

  test('marks docker.io images as public registry', () => {
    const r = parseCicdCommand('docker push myapp:1.0.0');
    expect(r.isPublicRegistry).toBe(true);
  });

  test('marks ghcr.io as public registry', () => {
    const r = parseCicdCommand('docker push ghcr.io/org/myapp:1.0.0');
    expect(r.registry).toBe('ghcr.io');
    expect(r.isPublicRegistry).toBe(true);
  });
});

// ─── Parser: dangerous patterns ────────────────────────────────────────────────

describe('parseCicdCommand — dangerous patterns', () => {
  test('detects --privileged flag', () => {
    const r = parseCicdCommand('docker run --privileged myapp:1.0.0');
    expect(r.isPrivileged).toBe(true);
    expect(r.dangerousPatterns.some((p) => p.severity === 'CRITICAL')).toBe(true);
  });

  test('detects root filesystem mount -v /:/host', () => {
    const r = parseCicdCommand('docker run -v /:/host myapp:1.0.0');
    expect(r.hasDangerousMount).toBe(true);
    expect(r.dangerousPatterns.some((p) => p.severity === 'DENY')).toBe(true);
  });

  test('detects --force flag', () => {
    const r = parseCicdCommand('./deploy.sh --env production --force');
    expect(r.isForceDeployment).toBe(true);
  });

  test('detects --skip-checks flag', () => {
    const r = parseCicdCommand('./deploy.sh --env staging --skip-checks');
    expect(r.isForceDeployment).toBe(true);
  });

  test('clean docker run has no dangerous patterns', () => {
    const r = parseCicdCommand('docker run myapp:1.2.3');
    expect(r.dangerousPatterns).toHaveLength(0);
    expect(r.isPrivileged).toBe(false);
    expect(r.hasDangerousMount).toBe(false);
  });
});

// ─── Parser: risk levels ───────────────────────────────────────────────────────

describe('parseCicdCommand — risk levels', () => {
  test('docker build is LOW risk', () => {
    const r = parseCicdCommand('docker build -t myapp:1.0.0 .');
    expect(r.riskLevel).toBe('LOW');
  });

  test('deploy to staging is MEDIUM risk', () => {
    const r = parseCicdCommand('gh workflow run deploy.yml --ref staging');
    expect(r.riskLevel).toBe('MEDIUM');
  });

  test('deploy to production is CRITICAL', () => {
    const r = parseCicdCommand('./deploy.sh --env production');
    expect(r.riskLevel).toBe('CRITICAL');
  });

  test('docker push to public registry is HIGH', () => {
    const r = parseCicdCommand('docker push myapp:1.0.0');
    expect(r.riskLevel).toBe('HIGH');
  });

  test('docker run --privileged is CRITICAL', () => {
    const r = parseCicdCommand('docker run --privileged myapp:1.0.0');
    expect(r.riskLevel).toBe('CRITICAL');
  });
});

// ─── Environment classifier ────────────────────────────────────────────────────

describe('classifyEnvironment', () => {
  test('detects production from --env prod', () => {
    expect(classifyEnvironment('deploy.sh', { env: 'prod' })).toBe('production');
  });

  test('detects staging from --env staging', () => {
    expect(classifyEnvironment('deploy.sh', { env: 'staging' })).toBe('staging');
  });

  test('detects development from --env dev', () => {
    expect(classifyEnvironment('deploy.sh', { env: 'dev' })).toBe('development');
  });

  test('detects production from branch main', () => {
    expect(classifyEnvironment('gh workflow run', { ref: 'main' })).toBe('production');
  });

  test('detects production from branch master', () => {
    expect(classifyEnvironment('gh workflow run', { ref: 'master' })).toBe('production');
  });

  test('detects development from branch develop', () => {
    expect(classifyEnvironment('gh workflow run', { ref: 'develop' })).toBe('development');
  });

  test('detects development from feature branch', () => {
    expect(classifyEnvironment('gh workflow run', { ref: 'feature/my-feature' })).toBe('development');
  });

  test('detects preview from pr- branch', () => {
    expect(classifyEnvironment('gh workflow run', { ref: 'pr-123' })).toBe('preview');
  });

  test('falls back to command keyword scanning', () => {
    expect(classifyEnvironment('deploy to production server', {})).toBe('production');
  });

  test('returns unknown for unrecognized context', () => {
    expect(classifyEnvironment('something vague', {})).toBe('unknown');
  });
});

// ─── Sandbox ───────────────────────────────────────────────────────────────────

describe('simulateCicdCommand', () => {
  test('denies root filesystem mount immediately', async () => {
    const intent = parseCicdCommand('docker run -v /:/host myapp:1.0.0');
    const result = await simulateCicdCommand(intent);
    expect(result.feasible).toBe(false);
    expect(result.summary).toMatch(/DENIED/);
  });

  test('denies deploy latest to production', async () => {
    const intent = parseCicdCommand('./deploy.sh --env production');
    const modified: ParsedCicdCommand = { ...intent, action: 'deploy', hasSpecificTag: false };
    const result = await simulateCicdCommand(modified);
    expect(result.feasible).toBe(false);
    expect(result.summary).toMatch(/DENIED/);
  });

  test('warns about production target but stays feasible', async () => {
    const intent = parseCicdCommand('./deploy.sh --env production');
    const modified: ParsedCicdCommand = { ...intent, action: 'deploy', hasSpecificTag: true };
    const result = await simulateCicdCommand(modified);
    expect(result.warnings.some((w) => w.includes('PRODUCTION'))).toBe(true);
    expect(result.feasible).toBe(true);
  });

  test('warns about force flag', async () => {
    const intent = parseCicdCommand('./deploy.sh --env staging --force');
    const result = await simulateCicdCommand(intent);
    expect(result.warnings.some((w) => w.toLowerCase().includes('force'))).toBe(true);
  });

  test('warns about public registry push', async () => {
    const intent = parseCicdCommand('docker push myapp:1.0.0');
    const result = await simulateCicdCommand(intent);
    expect(result.warnings.some((w) => w.includes('public'))).toBe(true);
  });

  test('passes build without warnings', async () => {
    const intent = parseCicdCommand('docker build -t myapp:1.0.0 .');
    const result = await simulateCicdCommand(intent);
    expect(result.feasible).toBe(true);
    expect(result.warnings).toHaveLength(0);
  });

  test('warns when docker image uses latest tag', async () => {
    const intent = parseCicdCommand('docker push myapp:latest');
    const result = await simulateCicdCommand(intent);
    expect(result.warnings.some((w) => w.includes('latest'))).toBe(true);
  });

  test('summary contains tool and action info', async () => {
    const intent = parseCicdCommand('docker build -t myapp:1.0.0 .');
    const result = await simulateCicdCommand(intent);
    expect(result.summary).toContain('docker');
    expect(result.summary).toContain('build');
  });

  test('returns SimulationResult shape', async () => {
    const intent = parseCicdCommand('docker build -t myapp:1.0.0 .');
    const result = await simulateCicdCommand(intent);
    expect(typeof result.feasible).toBe('boolean');
    expect(typeof result.resourcesImpacted).toBe('number');
    expect(typeof result.summary).toBe('string');
    expect(Array.isArray(result.warnings)).toBe(true);
    expect(typeof result.durationMs).toBe('number');
  });
});

// ─── Policy evaluator ──────────────────────────────────────────────────────────

describe('evaluateCicdPolicy', () => {
  test('auto-approves docker build (LOW risk)', () => {
    const intent = parseCicdCommand('docker build -t myapp:1.0.0 .');
    const decision = evaluateCicdPolicy(intent, defaultPolicy);
    expect(decision.allowed).toBe(true);
    expect(decision.riskLevel).toBe('LOW');
    expect(decision.requiresApproval).toBe(false);
  });

  test('denies docker run --privileged', () => {
    const intent = parseCicdCommand('docker run --privileged myapp:1.0.0');
    const decision = evaluateCicdPolicy(intent, defaultPolicy);
    expect(decision.allowed).toBe(false);
  });

  test('denies root filesystem mount', () => {
    const intent = parseCicdCommand('docker run -v /:/host myapp:1.0.0');
    const decision = evaluateCicdPolicy(intent, defaultPolicy);
    expect(decision.allowed).toBe(false);
  });

  test('requires approval for production deploy', () => {
    const intent = parseCicdCommand('gh workflow run deploy.yml --ref main --field env=production --field tag=1.2.3');
    const decision = evaluateCicdPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('requires approval for force deploy', () => {
    const intent = parseCicdCommand('./deploy.sh --env staging --force');
    const decision = evaluateCicdPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('requires approval for public registry push', () => {
    const intent = parseCicdCommand('docker push myapp:1.0.0');
    const decision = evaluateCicdPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('requires dry-run for staging deploy', () => {
    const intent = parseCicdCommand('gh workflow run deploy.yml --ref staging');
    const decision = evaluateCicdPolicy(intent, defaultPolicy);
    expect(decision.requiresDryRun).toBe(true);
  });

  test('rollback in production requires approval', () => {
    const intent = parseCicdCommand('./rollback.sh --env production');
    const decision = evaluateCicdPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('allowUnknown=true allows unmatched commands', () => {
    const permissive: CicdPolicy = {
      version: '1.0',
      rules: [],
      defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' },
    };
    const intent = parseCicdCommand('docker build -t myapp:1.0.0 .');
    const decision = evaluateCicdPolicy(intent, permissive);
    expect(decision.allowed).toBe(true);
  });

  test('allowUnknown=false denies unmatched commands', () => {
    const strict: CicdPolicy = {
      version: '1.0',
      rules: [],
      defaults: { allowUnknown: false, defaultRiskLevel: 'LOW' },
    };
    const intent = parseCicdCommand('docker build -t myapp:1.0.0 .');
    const decision = evaluateCicdPolicy(intent, strict);
    expect(decision.allowed).toBe(false);
  });

  test('CRITICAL risk always sets requiresApproval + requiresDryRun', () => {
    const intent = parseCicdCommand('./deploy.sh --env production');
    const decision = evaluateCicdPolicy(intent, defaultPolicy);
    expect(decision.riskLevel).toBe('CRITICAL');
    expect(decision.requiresApproval).toBe(true);
    expect(decision.requiresDryRun).toBe(true);
  });

  test('matchedRules is populated', () => {
    const intent = parseCicdCommand('docker build -t myapp:1.0.0 .');
    const decision = evaluateCicdPolicy(intent, defaultPolicy);
    expect(decision.matchedRules.length).toBeGreaterThan(0);
  });
});

// ─── CicdAdapter interface ─────────────────────────────────────────────────────

describe('CicdAdapter', () => {
  const adapter = new CicdAdapter();

  test('adapter name is cicd', () => {
    expect(adapter.name).toBe('cicd');
  });

  test('parseIntent returns ParsedCicdCommand', () => {
    const intent = adapter.parseIntent('docker build -t myapp:1.0.0 .');
    expect(intent.tool).toBe('docker');
    expect(intent.action).toBe('build');
    expect(intent.riskLevel).toBe('LOW');
  });

  test('parseIntent throws on empty command', () => {
    expect(() => adapter.parseIntent('')).toThrow();
  });

  test('sandbox returns SimulationResult', async () => {
    const intent = adapter.parseIntent('docker build -t myapp:1.0.0 .');
    const sim = await adapter.sandbox(intent);
    expect(sim.feasible).toBe(true);
    expect(typeof sim.summary).toBe('string');
    expect(Array.isArray(sim.warnings)).toBe(true);
  });

  test('sandbox returns infeasible for DENY patterns', async () => {
    const intent = adapter.parseIntent('docker run -v /:/host myapp:1.0.0');
    const sim = await adapter.sandbox(intent);
    expect(sim.feasible).toBe(false);
  });

  test('rollback throws for non-rollback actions', async () => {
    const intent = adapter.parseIntent('docker push myapp:1.0.0');
    const snapshot = {
      commandId: 'test-id',
      timestamp: new Date(),
      preState: '{}',
    };
    await expect(adapter.rollback(intent, snapshot)).rejects.toThrow(/not supported/);
  });
});
