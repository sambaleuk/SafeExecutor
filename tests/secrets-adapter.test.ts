import { readFileSync } from 'fs';
import { parseSecretCommand } from '../src/adapters/secrets/parser.js';
import { simulateSecretCommand } from '../src/adapters/secrets/sandbox.js';
import { detectLeaks, maskSecret } from '../src/adapters/secrets/leak-detector.js';
import { SecretsAdapter, evaluateSecretPolicy } from '../src/adapters/secrets/adapter.js';
import type { SecretPolicy } from '../src/adapters/secrets/types.js';

// ─── Fixtures ──────────────────────────────────────────────────────────────────

const defaultPolicy = JSON.parse(
  readFileSync(new URL('../config/policies/secrets-default-policy.json', import.meta.url), 'utf-8'),
) as SecretPolicy;

// ─── Parser: tool detection ────────────────────────────────────────────────────

describe('parseSecretCommand — tool detection', () => {
  test('detects HashiCorp Vault', () => {
    const r = parseSecretCommand('vault read secret/data/myapp/db-password');
    expect(r.tool).toBe('vault');
    expect(r.action).toBe('read');
  });

  test('detects AWS Secrets Manager', () => {
    const r = parseSecretCommand('aws secretsmanager get-secret-value --secret-id prod/db-password');
    expect(r.tool).toBe('aws-secrets');
    expect(r.action).toBe('read');
  });

  test('detects AWS SSM Parameter Store', () => {
    const r = parseSecretCommand('aws ssm get-parameter --name /app/config/api-key --with-decryption');
    expect(r.tool).toBe('aws-ssm');
    expect(r.action).toBe('read');
  });

  test('detects GCloud Secret Manager', () => {
    const r = parseSecretCommand('gcloud secrets versions access latest --secret=my-api-key');
    expect(r.tool).toBe('gcloud-secrets');
    expect(r.action).toBe('read');
  });

  test('detects Azure Key Vault', () => {
    const r = parseSecretCommand('az keyvault secret show --name db-password --vault-name prod-vault');
    expect(r.tool).toBe('az-keyvault');
    expect(r.action).toBe('read');
  });

  test('detects kubectl secrets', () => {
    const r = parseSecretCommand('kubectl get secret db-credentials -n production');
    expect(r.tool).toBe('kubectl-secrets');
    expect(r.action).toBe('read');
  });

  test('detects docker secrets', () => {
    const r = parseSecretCommand('docker secret create my-secret ./secret.txt');
    expect(r.tool).toBe('docker-secrets');
    expect(r.action).toBe('create');
  });

  test('detects env export', () => {
    const r = parseSecretCommand('export API_KEY=abc123');
    expect(r.tool).toBe('env-export');
    expect(r.action).toBe('export');
  });

  test('returns unknown for unrecognized commands', () => {
    const r = parseSecretCommand('some-random-tool get-secret');
    expect(r.tool).toBe('unknown');
  });

  test('throws on empty command', () => {
    expect(() => parseSecretCommand('')).toThrow('Empty command');
  });
});

// ─── Parser: action detection ──────────────────────────────────────────────────

describe('parseSecretCommand — action detection', () => {
  test('Vault write', () => {
    const r = parseSecretCommand('vault write secret/data/myapp api_key=abc123');
    expect(r.action).toBe('write');
  });

  test('Vault delete', () => {
    const r = parseSecretCommand('vault delete secret/data/myapp');
    expect(r.action).toBe('delete');
  });

  test('Vault list', () => {
    const r = parseSecretCommand('vault list secret/data/myapp/');
    expect(r.action).toBe('list');
  });

  test('AWS create-secret', () => {
    const r = parseSecretCommand('aws secretsmanager create-secret --name my-secret --secret-string "abc"');
    expect(r.action).toBe('create');
  });

  test('AWS delete-secret', () => {
    const r = parseSecretCommand('aws secretsmanager delete-secret --secret-id my-secret');
    expect(r.action).toBe('delete');
  });

  test('AWS rotate-secret', () => {
    const r = parseSecretCommand('aws secretsmanager rotate-secret --secret-id my-secret');
    expect(r.action).toBe('rotate');
  });

  test('AWS list-secrets', () => {
    const r = parseSecretCommand('aws secretsmanager list-secrets');
    expect(r.action).toBe('list');
  });

  test('AWS SSM put-parameter', () => {
    const r = parseSecretCommand('aws ssm put-parameter --name /app/key --value "xyz" --overwrite');
    expect(r.action).toBe('write');
    expect(r.isOverwrite).toBe(true);
  });

  test('AWS SSM delete-parameter', () => {
    const r = parseSecretCommand('aws ssm delete-parameter --name /app/key');
    expect(r.action).toBe('delete');
  });

  test('GCloud create secret', () => {
    const r = parseSecretCommand('gcloud secrets create my-secret --data-file=./secret.txt');
    expect(r.action).toBe('create');
  });

  test('GCloud delete secret', () => {
    const r = parseSecretCommand('gcloud secrets delete my-secret');
    expect(r.action).toBe('delete');
  });

  test('GCloud list secrets', () => {
    const r = parseSecretCommand('gcloud secrets list');
    expect(r.action).toBe('list');
  });

  test('Azure Key Vault set', () => {
    const r = parseSecretCommand('az keyvault secret set --name api-key --vault-name myvault --value "abc"');
    expect(r.action).toBe('write');
  });

  test('Azure Key Vault delete', () => {
    const r = parseSecretCommand('az keyvault secret delete --name api-key --vault-name myvault');
    expect(r.action).toBe('delete');
  });

  test('Azure Key Vault list', () => {
    const r = parseSecretCommand('az keyvault secret list --vault-name myvault');
    expect(r.action).toBe('list');
  });

  test('kubectl create secret', () => {
    const r = parseSecretCommand('kubectl create secret generic my-secret --from-literal=key=value');
    expect(r.action).toBe('create');
  });

  test('kubectl delete secret', () => {
    const r = parseSecretCommand('kubectl delete secret my-secret');
    expect(r.action).toBe('delete');
  });

  test('docker secret inspect', () => {
    const r = parseSecretCommand('docker secret inspect my-secret');
    expect(r.action).toBe('read');
  });

  test('docker secret rm', () => {
    const r = parseSecretCommand('docker secret rm my-secret');
    expect(r.action).toBe('delete');
  });

  test('docker secret ls', () => {
    const r = parseSecretCommand('docker secret ls');
    expect(r.action).toBe('list');
  });
});

// ─── Parser: risk classification ───────────────────────────────────────────────

describe('parseSecretCommand — risk classification', () => {
  test('read is LOW risk', () => {
    const r = parseSecretCommand('vault read secret/data/myapp/key');
    expect(r.riskLevel).toBe('LOW');
  });

  test('list is MEDIUM risk (namespace scope escalation)', () => {
    const r = parseSecretCommand('aws secretsmanager list-secrets');
    expect(r.riskLevel).toBe('MEDIUM');
  });

  test('write is MEDIUM risk', () => {
    const r = parseSecretCommand('vault write secret/data/myapp key=value');
    expect(r.riskLevel).toBe('MEDIUM');
  });

  test('delete is HIGH risk', () => {
    const r = parseSecretCommand('vault delete secret/data/myapp');
    expect(r.riskLevel).toBe('HIGH');
  });

  test('production write is HIGH risk', () => {
    const r = parseSecretCommand('vault write secret/data/production/db password=abc');
    expect(r.riskLevel).toBe('HIGH');
  });

  test('force-delete-without-recovery is CRITICAL', () => {
    const r = parseSecretCommand('aws secretsmanager delete-secret --secret-id my-secret --force-delete-without-recovery');
    expect(r.riskLevel).toBe('CRITICAL');
  });
});

// ─── Parser: production detection ──────────────────────────────────────────────

describe('parseSecretCommand — production detection', () => {
  test('detects production in secret path', () => {
    const r = parseSecretCommand('vault read secret/data/production/db-password');
    expect(r.isProduction).toBe(true);
  });

  test('detects prod in vault-name', () => {
    const r = parseSecretCommand('az keyvault secret show --name key --vault-name prod-vault');
    expect(r.isProduction).toBe(true);
  });

  test('non-production path', () => {
    const r = parseSecretCommand('vault read secret/data/staging/db-password');
    expect(r.isProduction).toBe(false);
  });
});

// ─── Parser: dangerous patterns ────────────────────────────────────────────────

describe('parseSecretCommand — dangerous patterns', () => {
  test('detects force-delete-without-recovery', () => {
    const r = parseSecretCommand('aws secretsmanager delete-secret --secret-id x --force-delete-without-recovery');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: '--force-delete-without-recovery', severity: 'DENY' }),
      ]),
    );
  });

  test('detects purge', () => {
    const r = parseSecretCommand('az keyvault secret purge --name key --vault-name myvault');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: 'purge', severity: 'DENY' }),
      ]),
    );
  });

  test('detects piping secret to another command', () => {
    const r = parseSecretCommand('vault read secret/data/key | jq .data');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: 'pipe-secret' }),
      ]),
    );
  });

  test('detects redirect to file', () => {
    const r = parseSecretCommand('vault read secret/data/key > /tmp/secret.txt');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: 'redirect-to-file' }),
      ]),
    );
  });

  test('detects --force flag', () => {
    const r = parseSecretCommand('vault delete --force secret/data/key');
    expect(r.isForce).toBe(true);
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: '--force' }),
      ]),
    );
  });
});

// ─── Leak Detector ─────────────────────────────────────────────────────────────

describe('detectLeaks', () => {
  test('detects AWS access key', () => {
    const result = detectLeaks('AKIAIOSFODNN7EXAMPLE');
    expect(result.hasLeaks).toBe(true);
    expect(result.leaks[0].type).toBe('aws-access-key');
  });

  test('detects GitHub PAT (classic)', () => {
    const result = detectLeaks('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij');
    expect(result.hasLeaks).toBe(true);
    expect(result.leaks[0].type).toBe('github-pat');
  });

  test('detects GitHub PAT (fine-grained)', () => {
    const result = detectLeaks('github_pat_11ABCDEFGH0123456789_abcdefghijklmnopqrstuvwxyz');
    expect(result.hasLeaks).toBe(true);
    expect(result.leaks[0].type).toBe('github-pat');
  });

  test('detects JWT', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const result = detectLeaks(jwt);
    expect(result.hasLeaks).toBe(true);
    expect(result.leaks[0].type).toBe('jwt');
  });

  test('detects private key', () => {
    const pk = '-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALOQZVW28xB+hXz\n-----END RSA PRIVATE KEY-----';
    const result = detectLeaks(pk);
    expect(result.hasLeaks).toBe(true);
    expect(result.leaks[0].type).toBe('private-key');
  });

  test('returns no leaks for clean text', () => {
    const result = detectLeaks('just a normal string with no secrets');
    expect(result.hasLeaks).toBe(false);
    expect(result.leaks).toHaveLength(0);
  });

  test('detects multiple leaks in one string', () => {
    const input = 'key=AKIAIOSFODNN7EXAMPLE token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';
    const result = detectLeaks(input);
    expect(result.hasLeaks).toBe(true);
    expect(result.leaks.length).toBeGreaterThanOrEqual(2);
  });
});

describe('maskSecret', () => {
  test('masks long secrets keeping first/last 4 chars', () => {
    expect(maskSecret('AKIAIOSFODNN7EXAMPLE')).toBe('AKIA************MPLE');
  });

  test('fully masks short secrets', () => {
    expect(maskSecret('short')).toBe('*****');
  });

  test('fully masks 12-char boundary', () => {
    expect(maskSecret('123456789012')).toBe('************');
  });

  test('partially masks 13-char value', () => {
    const masked = maskSecret('1234567890123');
    expect(masked).toBe('1234*****0123');
  });
});

// ─── Sandbox ───────────────────────────────────────────────────────────────────

describe('simulateSecretCommand', () => {
  test('denies DENY-severity patterns', async () => {
    const parsed = parseSecretCommand('aws secretsmanager delete-secret --secret-id x --force-delete-without-recovery');
    const result = await simulateSecretCommand(parsed);
    expect(result.feasible).toBe(false);
    expect(result.summary).toContain('DENIED');
  });

  test('denies production delete', async () => {
    const parsed = parseSecretCommand('vault delete secret/data/production/key');
    const result = await simulateSecretCommand(parsed);
    expect(result.feasible).toBe(false);
    expect(result.summary).toContain('DENIED');
  });

  test('allows non-destructive list', async () => {
    const parsed = parseSecretCommand('aws secretsmanager list-secrets');
    const result = await simulateSecretCommand(parsed);
    expect(result.feasible).toBe(true);
  });

  test('warns about value exposure', async () => {
    const parsed = parseSecretCommand('vault read secret/data/myapp/key');
    const result = await simulateSecretCommand(parsed);
    expect(result.feasible).toBe(true);
    expect(result.warnings).toEqual(
      expect.arrayContaining([expect.stringContaining('expose')]),
    );
  });

  test('warns about production target', async () => {
    const parsed = parseSecretCommand('vault read secret/data/production/key');
    const result = await simulateSecretCommand(parsed);
    expect(result.warnings).toEqual(
      expect.arrayContaining([expect.stringContaining('PRODUCTION')]),
    );
  });

  test('warns about force flag', async () => {
    const parsed = parseSecretCommand('vault delete --force secret/data/staging/key');
    const result = await simulateSecretCommand(parsed);
    expect(result.warnings).toEqual(
      expect.arrayContaining([expect.stringContaining('Force flag')]),
    );
  });

  test('warns about overwrite', async () => {
    const parsed = parseSecretCommand('aws ssm put-parameter --name /app/key --value "new" --overwrite');
    const result = await simulateSecretCommand(parsed);
    expect(result.warnings).toEqual(
      expect.arrayContaining([expect.stringContaining('overwrite')]),
    );
  });

  test('detects inline leaks in command', async () => {
    const parsed = parseSecretCommand('vault write secret/data/myapp api_key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij');
    const result = await simulateSecretCommand(parsed);
    expect(result.warnings).toEqual(
      expect.arrayContaining([expect.stringContaining('secret')]),
    );
  });
});

// ─── Policy evaluator ──────────────────────────────────────────────────────────

describe('evaluateSecretPolicy', () => {
  test('denies force delete via policy', () => {
    const parsed = parseSecretCommand('aws secretsmanager delete-secret --secret-id x --force');
    const decision = evaluateSecretPolicy(parsed, defaultPolicy);
    expect(decision.allowed).toBe(false);
  });

  test('denies production delete via policy', () => {
    const parsed = parseSecretCommand('vault delete secret/data/production/key');
    const decision = evaluateSecretPolicy(parsed, defaultPolicy);
    expect(decision.allowed).toBe(false);
  });

  test('requires approval for production write', () => {
    const parsed = parseSecretCommand('vault write secret/data/production/db password=abc');
    const decision = evaluateSecretPolicy(parsed, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('requires approval for rotation', () => {
    const parsed = parseSecretCommand('aws secretsmanager rotate-secret --secret-id my-secret');
    const decision = evaluateSecretPolicy(parsed, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('requires dry-run for secret write', () => {
    const parsed = parseSecretCommand('vault write secret/data/staging/key value=abc');
    const decision = evaluateSecretPolicy(parsed, defaultPolicy);
    expect(decision.requiresDryRun).toBe(true);
  });

  test('auto-approves list', () => {
    const parsed = parseSecretCommand('aws secretsmanager list-secrets');
    const decision = evaluateSecretPolicy(parsed, defaultPolicy);
    expect(decision.allowed).toBe(true);
    expect(decision.riskLevel).toBe('LOW');
  });

  test('auto-approves env export', () => {
    const parsed = parseSecretCommand('export API_KEY=test123');
    const decision = evaluateSecretPolicy(parsed, defaultPolicy);
    expect(decision.allowed).toBe(true);
  });

  test('blocks unknown commands when allowUnknown is false', () => {
    const parsed = parseSecretCommand('some-unknown-tool get-secret foo');
    const decision = evaluateSecretPolicy(parsed, defaultPolicy);
    expect(decision.allowed).toBe(false);
  });

  test('CRITICAL risk forces dry-run + approval', () => {
    const parsed = parseSecretCommand('vault write secret/data/production/critical-key value=x');
    const decision = evaluateSecretPolicy(parsed, defaultPolicy);
    expect(decision.riskLevel).toBe('CRITICAL');
    expect(decision.requiresDryRun).toBe(true);
    expect(decision.requiresApproval).toBe(true);
  });
});

// ─── Adapter class ─────────────────────────────────────────────────────────────

describe('SecretsAdapter', () => {
  const adapter = new SecretsAdapter();

  test('has name "secrets"', () => {
    expect(adapter.name).toBe('secrets');
  });

  test('parseIntent delegates to parser', () => {
    const result = adapter.parseIntent('vault read secret/data/myapp/key');
    expect(result.tool).toBe('vault');
    expect(result.action).toBe('read');
  });

  test('sandbox delegates to simulator', async () => {
    const intent = adapter.parseIntent('aws secretsmanager list-secrets');
    const result = await adapter.sandbox(intent);
    expect(result.feasible).toBe(true);
  });

  test('rollback throws without previousVersionId', async () => {
    const intent = adapter.parseIntent('vault write secret/data/myapp key=val');
    const snapshot = {
      commandId: 'test-123',
      timestamp: new Date(),
      preState: '{}',
    };
    await expect(adapter.rollback(intent, snapshot)).rejects.toThrow('Manual intervention');
  });

  test('rollback throws with previousVersionId', async () => {
    const intent = adapter.parseIntent('vault write secret/data/myapp key=val');
    const snapshot = {
      commandId: 'test-123',
      timestamp: new Date(),
      previousVersionId: 'v1',
      preState: '{}',
    };
    await expect(adapter.rollback(intent, snapshot)).rejects.toThrow('manual intervention');
  });
});

// ─── Parser: secret path extraction ────────────────────────────────────────────

describe('parseSecretCommand — secret path extraction', () => {
  test('extracts Vault path', () => {
    const r = parseSecretCommand('vault read secret/data/myapp/db-password');
    expect(r.secretPath).toBe('secret/data/myapp/db-password');
  });

  test('extracts AWS secret-id', () => {
    const r = parseSecretCommand('aws secretsmanager get-secret-value --secret-id prod/db-password');
    expect(r.secretPath).toBe('prod/db-password');
  });

  test('extracts GCloud secret name', () => {
    const r = parseSecretCommand('gcloud secrets versions access latest --secret=my-api-key');
    expect(r.secretPath).toBe('my-api-key');
  });

  test('extracts Azure Key Vault name', () => {
    const r = parseSecretCommand('az keyvault secret show --name db-password --vault-name prod-vault');
    expect(r.secretPath).toBe('db-password');
  });
});

// ─── Parser: namespace extraction ──────────────────────────────────────────────

describe('parseSecretCommand — namespace extraction', () => {
  test('extracts -n namespace from kubectl', () => {
    const r = parseSecretCommand('kubectl get secret db-creds -n production');
    expect(r.namespace).toBe('production');
  });

  test('extracts --vault-name from Azure', () => {
    const r = parseSecretCommand('az keyvault secret show --name key --vault-name my-vault');
    expect(r.namespace).toBe('my-vault');
  });
});
