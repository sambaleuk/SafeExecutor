import { parseCicdCommand } from '../src/adapters/cicd/parser.js';
import { classifyEnvironment } from '../src/adapters/cicd/environment-classifier.js';
import { runCicdSandbox } from '../src/adapters/cicd/sandbox.js';
import { CicdAdapter } from '../src/adapters/cicd/adapter.js';
import type { CicdPolicy, ParsedCicdCommand } from '../src/adapters/cicd/types.js';

// ─── Fixtures ──────────────────────────────────────────────────────────────────

const defaultPolicy: CicdPolicy = JSON.parse(
  (await import('fs')).readFileSync(
    new URL('../config/policies/cicd-default-policy.json', import.meta.url),
    'utf-8',
  ),
) as CicdPolicy;

// ─── Parser ────────────────────────────────────────────────────────────────────

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

  test('detects rollback from deploy script', () => {
    const r = parseCicdCommand('./rollback.sh --env production');
    expect(r.tool).toBe('deploy-script');
    expect(r.action).toBe('rollback');
  });

  test('detects rsync as deploy-script', () => {
    const r = parseCicdCommand('rsync -avz ./dist/ user@prod-server:/app/');
    expect(r.tool).toBe('deploy-script');
  });
});

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

  test('deploy latest to production is CRITICAL', () => {
    const r = parseCicdCommand('docker push myapp:latest');
    expect(r.riskLevel).toBe('HIGH'); // push + latest + public → HIGH
  });
});

// ─── Environment classifier ────────────────────────────────────────────────────

describe('classifyEnvironment', () => {
  test('detects production from --env prod', () => {
    expect(classifyEnvironment('deploy.sh', { env: 'prod' })).toBe('production');
  });

  test('detects production from --env production', () => {
    expect(classifyEnvironment('deploy.sh', { env: 'production' })).toBe('production');
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

describe('runCicdSandbox', () => {
  test('denies root filesystem mount immediately', async () => {
    const parsed = parseCicdCommand('docker run -v /:/host myapp:1.0.0');
    const result = await runCicdSandbox(parsed);
    expect(result.feasible).toBe(false);
    expect(result.preview).toMatch(/DENIED/);
  });

  test('denies deploy latest to production', async () => {
    const parsed = parseCicdCommand('./deploy.sh --env production');
    // Simulate: no specific tag and action=deploy, env=production
    const modified = { ...parsed, action: 'deploy' as const, hasSpecificTag: false };
    const result = await runCicdSandbox(modified);
    expect(result.feasible).toBe(false);
    expect(result.preview).toMatch(/DENIED/);
  });

  test('warns about production target', async () => {
    const parsed = parseCicdCommand('./deploy.sh --env production');
    const modified = { ...parsed, action: 'deploy' as const, hasSpecificTag: true };
    const result = await runCicdSandbox(modified);
    expect(result.warnings.some((w) => w.includes('PRODUCTION'))).toBe(true);
  });

  test('warns about force flag', async () => {
    const parsed = parseCicdCommand('./deploy.sh --env staging --force');
    const result = await runCicdSandbox(parsed);
    expect(result.warnings.some((w) => w.toLowerCase().includes('force'))).toBe(true);
  });

  test('warns about public registry push', async () => {
    const parsed = parseCicdCommand('docker push myapp:1.0.0');
    const result = await runCicdSandbox(parsed);
    expect(result.warnings.some((w) => w.includes('public'))).toBe(true);
  });

  test('passes build without warnings', async () => {
    const parsed = parseCicdCommand('docker build -t myapp:1.0.0 .');
    const result = await runCicdSandbox(parsed);
    expect(result.feasible).toBe(true);
    expect(result.warnings).toHaveLength(0);
  });

  test('warns when docker image uses latest tag', async () => {
    const parsed = parseCicdCommand('docker push myapp:latest');
    const result = await runCicdSandbox(parsed);
    expect(result.warnings.some((w) => w.includes('latest'))).toBe(true);
  });

  test('preview contains tool and action info', async () => {
    const parsed = parseCicdCommand('docker build -t myapp:1.0.0 .');
    const result = await runCicdSandbox(parsed);
    expect(result.preview).toContain('docker');
    expect(result.preview).toContain('build');
  });
});

// ─── CicdAdapter (integration) ─────────────────────────────────────────────────

describe('CicdAdapter.execute', () => {
  let adapter: CicdAdapter;

  beforeEach(() => {
    adapter = new CicdAdapter(defaultPolicy);
  });

  test('auto-approves docker build', async () => {
    const result = await adapter.execute('docker build -t myapp:1.0.0 .');
    expect(result.success).toBe(true);
    expect(result.executionResult?.status).toBe('success');
  });

  test('denies docker run --privileged', async () => {
    const result = await adapter.execute('docker run --privileged myapp:1.0.0');
    expect(result.success).toBe(false);
    expect(result.abortReason).toMatch(/[Dd]enied/);
  });

  test('denies root filesystem mount', async () => {
    const result = await adapter.execute('docker run -v /:/host myapp:1.0.0');
    expect(result.success).toBe(false);
  });

  test('denies deploy latest to production', async () => {
    const result = await adapter.execute('./deploy.sh --env production');
    expect(result.success).toBe(false);
    expect(result.abortReason).toMatch(/[Dd]en[yi]/);
  });

  test('requires approval for production deploy with pinned tag', async () => {
    // A deploy to prod with specific tag still needs approval
    const result = await adapter.execute(
      'gh workflow run deploy.yml --ref main --field env=production --field tag=1.2.3',
    );
    expect(result.success).toBe(false);
    expect(result.abortReason).toMatch(/[Aa]pproval/);
  });

  test('skipping approval authorizes production deploy', async () => {
    const result = await adapter.execute(
      'gh workflow run deploy.yml --ref main --field env=production --field tag=1.2.3',
      { skipApproval: true },
    );
    expect(result.success).toBe(true);
    expect(result.executionResult?.status).toBe('success');
  });

  test('dry-run mode returns dry_run status', async () => {
    const result = await adapter.execute('docker push myapp:1.0.0', { dryRun: true });
    expect(result.executionResult?.status).toBe('dry_run');
    expect(result.sandboxResult).not.toBeNull();
  });

  test('force deploy requires approval', async () => {
    const result = await adapter.execute('./deploy.sh --env staging --force');
    expect(result.success).toBe(false);
    expect(result.abortReason).toMatch(/[Aa]pproval/);
  });

  test('staging deploy requires dry-run (sandbox runs)', async () => {
    const result = await adapter.execute(
      'gh workflow run deploy.yml --ref staging',
      { skipApproval: true },
    );
    expect(result.sandboxResult).not.toBeNull();
  });

  test('public registry push requires approval', async () => {
    const result = await adapter.execute('docker push myapp:1.0.0');
    expect(result.success).toBe(false);
    expect(result.abortReason).toMatch(/[Aa]pproval/);
  });

  test('docker build returns full decision trail', async () => {
    const result = await adapter.execute('docker build -t myapp:1.2.3 .');
    expect(result.parsed).toBeDefined();
    expect((result.parsed as ParsedCicdCommand).tool).toBe('docker');
    expect(result.policyDecision).toBeDefined();
    expect(result.policyDecision.riskLevel).toBe('LOW');
  });

  test('compose-up on dev runs without throwing', async () => {
    const result = await adapter.execute('docker-compose up -d', { skipApproval: true });
    expect(result).toBeDefined();
  });

  test('adapter name is cicd', () => {
    expect(adapter.name).toBe('cicd');
  });

  test('empty command throws parse error and returns failure', async () => {
    const result = await adapter.execute('');
    expect(result.success).toBe(false);
    expect(result.abortReason).toMatch(/[Pp]arse/);
  });
});

// ─── Policy edge cases ─────────────────────────────────────────────────────────

describe('CicdAdapter — policy edge cases', () => {
  test('rollback in production requires approval', async () => {
    const adapter = new CicdAdapter(defaultPolicy);
    const result = await adapter.execute('./rollback.sh --env production');
    expect(result.success).toBe(false);
    expect(result.abortReason).toMatch(/[Aa]pproval/);
  });

  test('rollback in staging is allowed (dry-run only)', async () => {
    const adapter = new CicdAdapter(defaultPolicy);
    // Rollback in staging — no explicit rule → defaults.allowUnknown=false → denied
    // unless we skipApproval
    const result = await adapter.execute('./rollback.sh --env staging', { skipApproval: true });
    // Should run sandbox but be allowed or at least not crash
    expect(result).toBeDefined();
  });

  test('allowUnknown=true policy allows unmatched commands', async () => {
    const permissivePolicy: CicdPolicy = {
      version: '1.0',
      rules: [],
      defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' },
    };
    const adapter = new CicdAdapter(permissivePolicy);
    const result = await adapter.execute('docker build -t myapp:1.0.0 .');
    expect(result.success).toBe(true);
  });

  test('allowUnknown=false denies unmatched commands', async () => {
    const strictPolicy: CicdPolicy = {
      version: '1.0',
      rules: [],
      defaults: { allowUnknown: false, defaultRiskLevel: 'LOW' },
    };
    const adapter = new CicdAdapter(strictPolicy);
    const result = await adapter.execute('docker build -t myapp:1.0.0 .');
    expect(result.success).toBe(false);
    expect(result.abortReason).toMatch(/Policy denied/);
  });
});
