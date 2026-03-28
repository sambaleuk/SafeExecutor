import {
  handleSafeExecute,
  handleSafeAnalyze,
  handleSafePolicyCheck,
  handleConfigurePolicy,
  getActivePolicy,
} from '../src/mcp-server/tools.js';

// ─── Helper ──────────────────────────────────────────────────────────────────

function parseResult(result: { content: Array<{ type: string; text: string }>; isError: boolean }) {
  return JSON.parse(result.content[0].text);
}

// ─── safe_execute ────────────────────────────────────────────────────────────

describe('handleSafeExecute', () => {
  beforeEach(() => {
    handleConfigurePolicy({ action: 'reset' });
  });

  test('allowed SQL SELECT', () => {
    const result = handleSafeExecute({ command: 'SELECT * FROM users WHERE id = 1' });
    expect(result.isError).toBe(false);
    const data = parseResult(result);
    expect(data.status).toBe('ALLOWED');
    expect(data.domain).toBe('sql');
    expect(data.operationType).toBe('SELECT');
  });

  test('denied DROP TABLE', () => {
    const result = handleSafeExecute({ command: 'DROP TABLE users' });
    expect(result.isError).toBe(false);
    const data = parseResult(result);
    expect(data.status).toBe('DENIED');
    expect(data.domain).toBe('sql');
    expect(data.operationType).toBe('DROP');
  });

  test('require approval for DELETE without WHERE', () => {
    const result = handleSafeExecute({ command: 'DELETE FROM users' });
    expect(result.isError).toBe(false);
    const data = parseResult(result);
    // CRITICAL risk → require_approval
    expect(['REQUIRE_APPROVAL', 'DENIED']).toContain(data.status);
  });

  test('auto-detects cloud domain', () => {
    const result = handleSafeExecute({ command: 'terraform plan' });
    expect(result.isError).toBe(false);
    const data = parseResult(result);
    expect(data.domain).toBe('cloud');
  });

  test('respects domain hint', () => {
    const result = handleSafeExecute({ command: 'terraform plan', domain: 'cloud' });
    expect(result.isError).toBe(false);
    const data = parseResult(result);
    expect(data.domain).toBe('cloud');
  });

  test('auto-detects kubernetes domain', () => {
    const result = handleSafeExecute({ command: 'kubectl get pods -n default' });
    expect(result.isError).toBe(false);
    const data = parseResult(result);
    expect(data.domain).toBe('kubernetes');
  });

  test('auto-detects filesystem domain', () => {
    const result = handleSafeExecute({ command: 'rm -rf /tmp/cache' });
    expect(result.isError).toBe(false);
    const data = parseResult(result);
    expect(data.domain).toBe('filesystem');
    expect(data.isDestructive).toBe(true);
  });

  test('returns error for malformed input', () => {
    const result = handleSafeExecute({ command: '', domain: 'network' });
    expect(result.isError).toBe(true);
  });
});

// ─── safe_analyze ────────────────────────────────────────────────────────────

describe('handleSafeAnalyze', () => {
  beforeEach(() => {
    handleConfigurePolicy({ action: 'reset' });
  });

  test('analyzes SQL DELETE with risk factors', () => {
    const result = handleSafeAnalyze({ command: 'DELETE FROM users' });
    expect(result.isError).toBe(false);
    const data = parseResult(result);
    expect(data.domain).toBe('sql');
    expect(data.operationType).toBe('DELETE');
    expect(data.isDestructive).toBe(true);
    expect(data.riskFactors.length).toBeGreaterThan(0);
  });

  test('analyzes cloud command', () => {
    const result = handleSafeAnalyze({ command: 'terraform destroy' });
    expect(result.isError).toBe(false);
    const data = parseResult(result);
    expect(data.domain).toBe('cloud');
    expect(data.isDestructive).toBe(true);
  });

  test('returns policy decision', () => {
    const result = handleSafeAnalyze({ command: 'SELECT 1' });
    expect(result.isError).toBe(false);
    const data = parseResult(result);
    expect(data.policy).toBeDefined();
    expect(data.policy.allowed).toBe(true);
    expect(data.policy.riskLevel).toBeDefined();
  });
});

// ─── safe_policy_check ───────────────────────────────────────────────────────

describe('handleSafePolicyCheck', () => {
  beforeEach(() => {
    handleConfigurePolicy({ action: 'reset' });
  });

  test('ALLOW for safe SELECT', () => {
    const result = handleSafePolicyCheck({ command: 'SELECT * FROM users' });
    const data = parseResult(result);
    expect(data.status).toBe('ALLOW');
  });

  test('DENY for DROP TABLE', () => {
    const result = handleSafePolicyCheck({ command: 'DROP TABLE users' });
    const data = parseResult(result);
    expect(data.status).toBe('DENY');
    expect(data.riskLevel).toBe('CRITICAL');
  });

  test('DENY for TRUNCATE', () => {
    const result = handleSafePolicyCheck({ command: 'TRUNCATE TABLE logs' });
    const data = parseResult(result);
    expect(data.status).toBe('DENY');
  });
});

// ─── configure_policy ────────────────────────────────────────────────────────

describe('handleConfigurePolicy', () => {
  beforeEach(() => {
    handleConfigurePolicy({ action: 'reset' });
  });

  test('add_rule', () => {
    const result = handleConfigurePolicy({
      action: 'add_rule',
      rule: {
        id: 'test-block-select',
        description: 'Block all SELECTs',
        match: { operationType: ['SELECT'] },
        action: 'deny',
        riskLevel: 'LOW',
        message: 'Test: SELECTs blocked',
      },
    });
    const data = parseResult(result);
    expect(data.status).toBe('ok');

    // Verify the rule is active
    const check = handleSafePolicyCheck({ command: 'SELECT * FROM users' });
    const checkData = parseResult(check);
    expect(checkData.status).toBe('DENY');
  });

  test('remove_rule', () => {
    const result = handleConfigurePolicy({ action: 'remove_rule', rule_id: 'deny-drop-table' });
    const data = parseResult(result);
    expect(data.status).toBe('ok');

    // DROP TABLE should now be allowed (no matching deny rule)
    const check = handleSafePolicyCheck({ command: 'DROP TABLE users' });
    const checkData = parseResult(check);
    expect(checkData.status).toBe('ALLOW');
  });

  test('replace_all', () => {
    const result = handleConfigurePolicy({
      action: 'replace_all',
      rules: [],
    });
    const data = parseResult(result);
    expect(data.status).toBe('ok');
    expect(getActivePolicy().rules).toHaveLength(0);
  });

  test('reset restores default rules', () => {
    // First clear, then reset
    handleConfigurePolicy({ action: 'replace_all', rules: [] });
    expect(getActivePolicy().rules).toHaveLength(0);

    handleConfigurePolicy({ action: 'reset' });
    expect(getActivePolicy().rules.length).toBeGreaterThan(0);
  });

  test('add_rule without rule returns error', () => {
    const result = handleConfigurePolicy({ action: 'add_rule' });
    expect(result.isError).toBe(true);
  });

  test('remove_rule without rule_id returns error', () => {
    const result = handleConfigurePolicy({ action: 'remove_rule' });
    expect(result.isError).toBe(true);
  });
});
