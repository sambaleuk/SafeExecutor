/**
 * E2E MCP Tools Tests — safeAnalyze() and safePolicyCheck() functions.
 */

import { safeAnalyze, safePolicyCheck } from '../src/mcp-server/tools.js';

// ─── safeAnalyze ──────────────────────────────────────────────────────────────

describe('MCP Tools E2E — safeAnalyze()', () => {
  test('returns proper structure for SQL SELECT', async () => {
    const result = await safeAnalyze('SELECT * FROM users WHERE id = 1');
    expect(result).toHaveProperty('domain', 'sql');
    expect(result).toHaveProperty('operation');
    expect(result).toHaveProperty('riskLevel');
    expect(result).toHaveProperty('blocked');
    expect(result).toHaveProperty('policy_decision');
    expect(result).toHaveProperty('note');
    expect(result.note).toContain('no execution');
  });

  test('SQL SELECT is ALLOWED', async () => {
    const result = await safeAnalyze('SELECT id, name FROM users WHERE active = true');
    expect(result.policy_decision).toBe('ALLOWED');
    expect(result.blocked).toBe(false);
  });

  test('SQL DROP TABLE is BLOCKED', async () => {
    const result = await safeAnalyze('DROP TABLE users');
    expect(result.policy_decision).toBe('BLOCKED');
    expect(result.blocked).toBe(true);
  });

  test('SQL DELETE without WHERE is BLOCKED', async () => {
    const result = await safeAnalyze('DELETE FROM orders');
    expect(result.policy_decision).toBe('BLOCKED');
    expect(result.blocked).toBe(true);
  });

  test('returns proper structure for filesystem', async () => {
    const result = await safeAnalyze('rm -rf /tmp/cache');
    expect(result).toHaveProperty('domain', 'filesystem');
    expect(result).toHaveProperty('riskLevel');
    expect(result).toHaveProperty('policy_decision');
  });

  test('filesystem rm -rf / is BLOCKED', async () => {
    const result = await safeAnalyze('rm -rf /');
    expect(result.policy_decision).toBe('BLOCKED');
    expect(result.blocked).toBe(true);
  });

  test('terraform plan is ALLOWED', async () => {
    const result = await safeAnalyze('terraform plan');
    expect(result.domain).toBe('cloud');
    expect(result.policy_decision).toBe('ALLOWED');
  });

  test('terraform destroy is BLOCKED', async () => {
    const result = await safeAnalyze('terraform destroy');
    expect(result.domain).toBe('cloud');
    expect(result.policy_decision).toBe('BLOCKED');
    expect(result.blocked).toBe(true);
  });

  test('kubectl get pods is ALLOWED', async () => {
    const result = await safeAnalyze('kubectl get pods');
    expect(result.domain).toBe('kubernetes');
    expect(result.policy_decision).toBe('ALLOWED');
  });

  test('kubectl delete namespace production is BLOCKED', async () => {
    const result = await safeAnalyze('kubectl delete namespace production');
    expect(result.domain).toBe('kubernetes');
    expect(result.policy_decision).toBe('BLOCKED');
  });

  test('git status is ALLOWED', async () => {
    const result = await safeAnalyze('git status');
    expect(result.domain).toBe('git');
    expect(result.policy_decision).toBe('ALLOWED');
  });

  test('git push --force origin main is BLOCKED', async () => {
    const result = await safeAnalyze('git push --force origin main');
    expect(result.domain).toBe('git');
    expect(result.policy_decision).toBe('BLOCKED');
  });

  test('redis-cli FLUSHALL is BLOCKED', async () => {
    const result = await safeAnalyze('redis-cli FLUSHALL');
    expect(result.domain).toBe('queue');
    expect(result.policy_decision).toBe('BLOCKED');
  });

  test('iptables -F is BLOCKED', async () => {
    const result = await safeAnalyze('iptables -F');
    expect(result.domain).toBe('network');
    expect(result.policy_decision).toBe('BLOCKED');
  });

  test('explicit domain override works', async () => {
    const result = await safeAnalyze('SELECT * FROM users', 'sql');
    expect(result.domain).toBe('sql');
  });
});

// ─── safePolicyCheck ──────────────────────────────────────────────────────────

describe('MCP Tools E2E — safePolicyCheck()', () => {
  test('returns proper structure', async () => {
    const result = await safePolicyCheck('SELECT * FROM users');
    expect(result).toHaveProperty('allowed');
    expect(result).toHaveProperty('risk');
    expect(result).toHaveProperty('domain');
    expect(result).toHaveProperty('reason');
  });

  test('SQL SELECT is allowed', async () => {
    const result = await safePolicyCheck('SELECT id FROM users WHERE id = 1');
    expect(result.allowed).toBe(true);
    expect(result.domain).toBe('sql');
  });

  test('SQL DELETE without WHERE is denied', async () => {
    const result = await safePolicyCheck('DELETE FROM users');
    expect(result.allowed).toBe(false);
    expect(result.domain).toBe('sql');
  });

  test('SQL DROP TABLE is denied', async () => {
    const result = await safePolicyCheck('DROP TABLE users');
    expect(result.allowed).toBe(false);
    expect(result.risk).toMatch(/^(HIGH|CRITICAL)$/);
  });

  test('kubectl get pods is allowed', async () => {
    const result = await safePolicyCheck('kubectl get pods');
    expect(result.allowed).toBe(true);
    expect(result.domain).toBe('kubernetes');
  });

  test('kubectl delete namespace production is denied', async () => {
    const result = await safePolicyCheck('kubectl delete namespace production');
    expect(result.allowed).toBe(false);
    expect(result.domain).toBe('kubernetes');
  });

  test('terraform plan is allowed', async () => {
    const result = await safePolicyCheck('terraform plan');
    expect(result.allowed).toBe(true);
    expect(result.domain).toBe('cloud');
  });

  test('terraform destroy is denied', async () => {
    const result = await safePolicyCheck('terraform destroy');
    expect(result.allowed).toBe(false);
    expect(result.domain).toBe('cloud');
  });

  test('git status is allowed', async () => {
    const result = await safePolicyCheck('git status');
    expect(result.allowed).toBe(true);
    expect(result.domain).toBe('git');
  });

  test('git push --force origin main is denied', async () => {
    const result = await safePolicyCheck('git push --force origin main');
    expect(result.allowed).toBe(false);
    expect(result.domain).toBe('git');
  });

  test('redis-cli FLUSHALL is denied', async () => {
    const result = await safePolicyCheck('redis-cli FLUSHALL');
    expect(result.allowed).toBe(false);
    expect(result.domain).toBe('queue');
  });

  test('iptables -F is denied', async () => {
    const result = await safePolicyCheck('iptables -F');
    expect(result.allowed).toBe(false);
    expect(result.domain).toBe('network');
  });

  test('vault kv delete is denied', async () => {
    const result = await safePolicyCheck('vault kv delete secret/production/db');
    expect(result.allowed).toBe(false);
    expect(result.domain).toBe('secrets');
  });

  test('reason field is populated for denied commands', async () => {
    const result = await safePolicyCheck('DROP TABLE users');
    expect(result.reason).toBeTruthy();
    expect(typeof result.reason).toBe('string');
  });

  test('reason field is populated for allowed commands', async () => {
    const result = await safePolicyCheck('SELECT id FROM users WHERE id = 1');
    expect(result.reason).toBeTruthy();
  });

  test('risk field matches HIGH or CRITICAL for blocked commands', async () => {
    const dangerous = [
      'DELETE FROM users',
      'DROP TABLE sessions',
      'terraform destroy',
      'kubectl delete namespace production',
      'git push --force origin main',
    ];
    for (const cmd of dangerous) {
      const result = await safePolicyCheck(cmd);
      expect(['HIGH', 'CRITICAL']).toContain(result.risk);
    }
  });
});
