/**
 * E2E tests for MCP Server tool handlers.
 *
 * Exercises safeExecute, safeAnalyze, and safePolicyCheck across all 10
 * supported domains, verifying return shape, domain routing, override
 * behavior, consistency between analyze/execute, and edge-case handling.
 *
 * All tests verify actual runtime behavior after tools.ts fixes: all
 * domains now return correct operation, riskLevel, blocked, and targets.
 */

import { safeExecute, safeAnalyze, safePolicyCheck } from '../src/mcp-server/tools.js';
import { detectDomain } from '../src/mcp-server/auto-detect.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

function expectValidPolicyDecision(decision: unknown) {
  expect(['BLOCKED', 'ALLOWED']).toContain(decision);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. safe_analyze — All 10 Domains
// ─────────────────────────────────────────────────────────────────────────────

describe('safe_analyze — all 10 domains', () => {
  const ANALYSIS_NOTE = 'Analysis only — no execution performed';

  // ── SQL ──────────────────────────────────────────────────────────────────

  describe('SQL domain', () => {
    test('SELECT * FROM users', async () => {
      const r = await safeAnalyze('SELECT * FROM users');
      expect(r.domain).toBe('sql');
      expect(r.operation).toBe('SELECT');
      expect(r.riskLevel).toBeDefined();
      expect(r.targets).toContain('users');
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.blocked).toBe(false);
      expect(r.policy_decision).toBe('ALLOWED');
    });

    test('DELETE FROM orders', async () => {
      const r = await safeAnalyze('DELETE FROM orders');
      expect(r.domain).toBe('sql');
      expect(r.operation).toBe('DELETE');
      expect(r.riskLevel).toMatch(/^(HIGH|CRITICAL)$/);
      expect(r.blocked).toBe(true);
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.policy_decision).toBe('BLOCKED');
    });
  });

  // ── Filesystem ───────────────────────────────────────────────────────────

  describe('filesystem domain', () => {
    test('rm -rf /home/test', async () => {
      const r = await safeAnalyze('rm -rf /home/test');
      expect(r.domain).toBe('filesystem');
      expect(r.operation).toBeDefined();
      expect(typeof r.operation).toBe('string');
      expect(r.riskLevel).toBeDefined();
      // blocked is a proper boolean now
      expect(typeof r.blocked).toBe('boolean');
      expect(r.note).toBe(ANALYSIS_NOTE);
      expectValidPolicyDecision(r.policy_decision);
    });

    test('chmod 644 file.txt', async () => {
      const r = await safeAnalyze('chmod 644 file.txt');
      expect(r.domain).toBe('filesystem');
      expect(r.operation).toBeDefined();
      expect(r.note).toBe(ANALYSIS_NOTE);
      expectValidPolicyDecision(r.policy_decision);
    });
  });

  // ── Cloud ────────────────────────────────────────────────────────────────

  describe('cloud domain', () => {
    test('aws s3 ls', async () => {
      const r = await safeAnalyze('aws s3 ls');
      expect(r.domain).toBe('cloud');
      expect(r.operation).toBeDefined();
      expect(r.riskLevel).toBeDefined();
      expect(Array.isArray(r.targets)).toBe(true);
      expect(r.blocked).toBe(false);
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.policy_decision).toBe('ALLOWED');
    });

    test('terraform destroy', async () => {
      const r = await safeAnalyze('terraform destroy');
      expect(r.domain).toBe('cloud');
      expect(r.operation).toBe('DESTROY');
      // terraform destroy has riskLevel CRITICAL and is blocked
      expect(r.blocked).toBe(true);
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.policy_decision).toBe('BLOCKED');
    });
  });

  // ── Kubernetes ───────────────────────────────────────────────────────────

  describe('kubernetes domain', () => {
    test('kubectl get pods', async () => {
      const r = await safeAnalyze('kubectl get pods');
      expect(r.domain).toBe('kubernetes');
      expect(r.operation).toBe('get');
      expect(r.riskLevel).toBeDefined();
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.policy_decision).toBe('ALLOWED');
    });

    test('kubectl delete namespace prod', async () => {
      const r = await safeAnalyze('kubectl delete namespace prod');
      expect(r.domain).toBe('kubernetes');
      expect(r.operation).toBe('delete');
      expect(r.blocked).toBe(true);
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.policy_decision).toBe('BLOCKED');
    });
  });

  // ── CI/CD ────────────────────────────────────────────────────────────────

  describe('cicd domain', () => {
    test('docker build -t app .', async () => {
      const r = await safeAnalyze('docker build -t app .');
      expect(r.domain).toBe('cicd');
      expect(r.operation).toBe('build');
      expect(r.riskLevel).toBeDefined();
      expect(Array.isArray(r.targets)).toBe(true);
      expect(r.blocked).toBe(false);
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.policy_decision).toBe('ALLOWED');
    });

    test('docker run --privileged alpine', async () => {
      const r = await safeAnalyze('docker run --privileged alpine');
      expect(r.domain).toBe('cicd');
      expect(r.operation).toBe('run');
      expect(r.blocked).toBe(true);
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.policy_decision).toBe('BLOCKED');
    });
  });

  // ── API ──────────────────────────────────────────────────────────────────

  describe('api domain', () => {
    test('GET https://api.example.com/users', async () => {
      const r = await safeAnalyze('GET https://api.example.com/users');
      expect(r.domain).toBe('api');
      // intent.method exists, so operation is defined.
      expect(r.operation).toBeDefined();
      expect(r.operation).toBe('GET');
      expect(r.riskLevel).toBeDefined();
      expect(r.blocked).toBe(false);
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.policy_decision).toBe('ALLOWED');
    });

    test('curl -X DELETE https://api.example.com/users/1', async () => {
      const r = await safeAnalyze('curl -X DELETE https://api.example.com/users/1');
      expect(r.domain).toBe('api');
      expect(r.operation).toBe('DELETE');
      expect(r.note).toBe(ANALYSIS_NOTE);
      expectValidPolicyDecision(r.policy_decision);
    });
  });

  // ── Secrets ──────────────────────────────────────────────────────────────

  describe('secrets domain', () => {
    test('vault read secret/data/db', async () => {
      const r = await safeAnalyze('vault read secret/data/db');
      expect(r.domain).toBe('secrets');
      expect(r.operation).toBe('read');
      expect(r.riskLevel).toBeDefined();
      expect(r.targets).toContain('secret/data/db');
      expect(r.blocked).toBe(false);
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.policy_decision).toBe('ALLOWED');
    });

    test('aws secretsmanager get-secret-value --secret-id prod/db', async () => {
      // aws secretsmanager routes to 'secrets' domain
      const r = await safeAnalyze('aws secretsmanager get-secret-value --secret-id prod/db');
      expect(r.domain).toBe('secrets');
      expect(r.operation).toBe('read');
      expect(r.blocked).toBe(false);
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.policy_decision).toBe('ALLOWED');
    });
  });

  // ── Network ──────────────────────────────────────────────────────────────

  describe('network domain', () => {
    test('dig example.com — auto-detected as unknown (not network)', async () => {
      // detectDomain only maps iptables/ufw/ip/nmap to 'network'.
      // dig is not in that list, so it falls to 'unknown'.
      expect(detectDomain('dig example.com')).toBe('unknown');
      const r = await safeAnalyze('dig example.com');
      expect(r.domain).toBe('unknown');
      expect(r.operation).toBe('unknown');
      expect(r.note).toBe(ANALYSIS_NOTE);
    });

    test('iptables -F INPUT — detected as network', async () => {
      expect(detectDomain('iptables -F INPUT')).toBe('network');
      const r = await safeAnalyze('iptables -F INPUT');
      expect(r.domain).toBe('network');
      expect(r.operation).toBe('configure');
      expect(r.riskLevel).toBeDefined();
      expect(r.blocked).toBe(true);
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.policy_decision).toBe('BLOCKED');
    });
  });

  // ── Git ──────────────────────────────────────────────────────────────────

  describe('git domain (has dedicated parser)', () => {
    test('git status', async () => {
      const r = await safeAnalyze('git status');
      expect(r.domain).toBe('git');
      expect(r.operation).toBe('status');
      expect(r.riskLevel).toBeDefined();
      expect(r.blocked).toBe(false);
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.policy_decision).toBe('ALLOWED');
    });

    test('git push --force origin main', async () => {
      const r = await safeAnalyze('git push --force origin main');
      expect(r.domain).toBe('git');
      expect(r.operation).toBe('force-push');
      expect(r.blocked).toBe(true);
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.policy_decision).toBe('BLOCKED');
    });
  });

  // ── Queue ────────────────────────────────────────────────────────────────

  describe('queue domain (has dedicated parser)', () => {
    test('redis-cli FLUSHALL', async () => {
      const r = await safeAnalyze('redis-cli FLUSHALL');
      expect(r.domain).toBe('queue');
      expect(r.operation).toBe('purge');
      expect(r.riskLevel).toMatch(/^(HIGH|CRITICAL)$/);
      expect(r.blocked).toBe(true);
      expect(r.note).toBe(ANALYSIS_NOTE);
      expect(r.policy_decision).toBe('BLOCKED');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. safe_policy_check — DENY, ALLOW, and edge cases
// ─────────────────────────────────────────────────────────────────────────────

describe('safe_policy_check — DENY / ALLOW / edge cases', () => {
  describe('allowed (safe) commands', () => {
    test('SELECT * FROM users — allowed, risk is defined', async () => {
      const r = await safePolicyCheck('SELECT * FROM users');
      expect(r.allowed).toBe(true);
      expect(r.domain).toBe('sql');
      expect(r.risk).toBeDefined();
    });

    test('find /tmp -name test — allowed', async () => {
      const r = await safePolicyCheck('find /tmp -name test');
      expect(r.allowed).toBe(true);
      expect(r.domain).toBe('filesystem');
      expect(r.risk).toBeDefined();
    });

    test('cp a b — allowed', async () => {
      const r = await safePolicyCheck('cp a b');
      expect(r.allowed).toBe(true);
      expect(r.domain).toBe('filesystem');
    });
  });

  describe('dangerous commands are properly blocked', () => {
    test('rm -rf / — allowed=false (blocked=true)', async () => {
      const r = await safePolicyCheck('rm -rf /');
      expect(r.allowed).toBe(false);
      expect(r.domain).toBe('filesystem');
      expect(r.reason).toBeTruthy();
    });

    test('dd if=/dev/zero of=/dev/sda — allowed=false (blocked=true)', async () => {
      const r = await safePolicyCheck('dd if=/dev/zero of=/dev/sda');
      expect(r.allowed).toBe(false);
      expect(r.domain).toBe('filesystem');
    });

    test('iptables -F INPUT — allowed=false (CRITICAL risk, properly blocked)', async () => {
      const r = await safePolicyCheck('iptables -F INPUT');
      expect(r.domain).toBe('network');
      expect(r.risk).toBeDefined();
      expect(r.allowed).toBe(false);
    });
  });

  describe('return shape', () => {
    test('result has allowed, risk, domain, reason fields', async () => {
      const r = await safePolicyCheck('SELECT 1');
      expect(r).toHaveProperty('allowed');
      expect(r).toHaveProperty('risk');
      expect(r).toHaveProperty('domain');
      expect(r).toHaveProperty('reason');
      expect(typeof r.allowed).toBe('boolean');
      expect(typeof r.domain).toBe('string');
      expect(typeof r.reason).toBe('string');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. safe_execute — Proper Structure
// ─────────────────────────────────────────────────────────────────────────────

describe('safe_execute — return structure', () => {
  test('result contains all expected fields', async () => {
    const r = await safeExecute('rm -rf /tmp/test');
    expect(r).toHaveProperty('domain');
    expect(r).toHaveProperty('operation');
    expect(r).toHaveProperty('targets');
    expect(r).toHaveProperty('riskLevel');
    expect(r).toHaveProperty('blocked');
    expect(r).toHaveProperty('reason');
    expect(r).toHaveProperty('policy_decision');
  });

  test('domain is a string', async () => {
    const r = await safeExecute('chmod 755 /tmp/test');
    expect(typeof r.domain).toBe('string');
  });

  test('operation is a string for filesystem (commandType works)', async () => {
    const r = await safeExecute('chmod 755 /tmp/test');
    expect(typeof r.operation).toBe('string');
  });

  test('operation is defined for SQL (returns SELECT)', async () => {
    const r = await safeExecute('SELECT * FROM users');
    expect(r.operation).toBe('SELECT');
  });

  test('targets is an array', async () => {
    const r = await safeExecute('cp a.txt b.txt');
    expect(Array.isArray(r.targets)).toBe(true);
  });

  test('blocked is always boolean across all domains', async () => {
    const git = await safeExecute('git status');
    expect(typeof git.blocked).toBe('boolean');

    // For filesystem, blocked is now a proper boolean
    const fs = await safeExecute('find /tmp -name test');
    expect(typeof fs.blocked).toBe('boolean');
  });

  test('reason is string or null', async () => {
    const r = await safeExecute('mv a.txt b.txt');
    expect(r.reason === null || typeof r.reason === 'string').toBe(true);
  });

  test('policy_decision is BLOCKED or ALLOWED', async () => {
    const r = await safeExecute('aws s3 ls');
    expectValidPolicyDecision(r.policy_decision);
  });

  test('filesystem blocked=true for rm -rf /, policy_decision=BLOCKED', async () => {
    const r = await safeExecute('rm -rf /');
    expect(r.blocked).toBe(true);
    expect(r.policy_decision).toBe('BLOCKED');
  });

  test('default-case domain has blocked=false, policy_decision=ALLOWED', async () => {
    const r = await safeExecute('git status');
    expect(r.blocked).toBe(false);
    expect(r.policy_decision).toBe('ALLOWED');
  });

  test('SQL domain has blocked=true for destructive DELETE', async () => {
    const r = await safeExecute('DELETE FROM users');
    expect(r.blocked).toBe(true);
    expect(r.policy_decision).toBe('BLOCKED');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Domain Override
// ─────────────────────────────────────────────────────────────────────────────

describe('domain override', () => {
  test('explicit domain overrides auto-detect', async () => {
    // 'rm -rf /' normally detects as 'filesystem'.
    expect(detectDomain('rm -rf /')).toBe('filesystem');

    // Force SQL parsing — the SQL parser will attempt to parse 'rm -rf /'
    // as SQL. It will either throw (and fallback to regex) or produce a
    // result with domain='sql'.
    const r = await safeExecute('rm -rf /', 'sql');
    expect(r.domain).toBe('sql');
  });

  test('SELECT 1 forced to filesystem domain', async () => {
    expect(detectDomain('SELECT 1')).toBe('sql');

    // Force filesystem parsing — the parser will see 'SELECT' as an
    // unrecognized command.
    const r = await safeExecute('SELECT 1', 'filesystem');
    expect(r.domain).toBe('filesystem');
  });

  test('override to unknown domain hits default branch', async () => {
    const r = await safeExecute('SELECT 1', 'nonexistent');
    expect(r.domain).toBe('nonexistent');
    expect(r.operation).toBe('unknown');
    // default case returns 'unknown' as RiskLevel
    expect(r.riskLevel).toBe('unknown');
    expect(r.blocked).toBe(false);
    expect(r.reason).toBe('No parser available for this domain');
  });

  test('safeAnalyze respects domain override to a compatible parser', async () => {
    // Override kubectl command to 'sql' (will attempt SQL parsing).
    const r = await safeAnalyze('kubectl get pods', 'sql');
    expect(r.domain).toBe('sql');
    expect(r.note).toBe('Analysis only — no execution performed');
  });

  test('overriding to cloud with incompatible CLI throws', async () => {
    // The cloud parser only supports terraform/aws/gcloud/az and will
    // throw for kubectl.
    await expect(safeAnalyze('kubectl get pods', 'cloud')).rejects.toThrow(
      /Unsupported cloud CLI/,
    );
  });

  test('safePolicyCheck does NOT accept domain override (always auto-detects)', async () => {
    const r = await safePolicyCheck('rm -rf /');
    expect(r.domain).toBe('filesystem');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Error Handling
// ─────────────────────────────────────────────────────────────────────────────

describe('error handling — edge cases', () => {
  describe('empty input', () => {
    test('safeExecute with empty string falls to unknown domain', async () => {
      // detectDomain('') returns 'unknown', so hits default branch.
      const r = await safeExecute('');
      expect(r.domain).toBe('unknown');
      expect(r.operation).toBe('unknown');
      expect(r.blocked).toBe(false);
    });

    test('safeAnalyze with empty string falls to unknown domain', async () => {
      const r = await safeAnalyze('');
      expect(r.domain).toBe('unknown');
      expect(r.operation).toBe('unknown');
      expect(r.note).toBe('Analysis only — no execution performed');
    });

    test('safePolicyCheck with empty string returns unknown domain', async () => {
      const r = await safePolicyCheck('');
      expect(r.domain).toBe('unknown');
      expect(r.allowed).toBe(true);
    });
  });

  describe('very long input', () => {
    test('safeExecute handles 1000+ character command', async () => {
      const longPath = '/tmp/' + 'a'.repeat(1000);
      const cmd = `rm -rf ${longPath}`;
      const r = await safeExecute(cmd);
      expect(r.domain).toBe('filesystem');
      expect(r).toHaveProperty('policy_decision');
    });

    test('safeAnalyze handles very long SQL', async () => {
      const columns = Array.from({ length: 200 }, (_, i) => `col_${i}`).join(', ');
      const cmd = `SELECT ${columns} FROM users`;
      const r = await safeAnalyze(cmd);
      expect(r.domain).toBe('sql');
      expect(r.note).toBe('Analysis only — no execution performed');
    });
  });

  describe('special characters', () => {
    test('command with unicode characters', async () => {
      const r = await safeExecute('rm -rf /tmp/\u65E5\u672C\u8A9E\u30D5\u30A1\u30A4\u30EB');
      expect(r.domain).toBe('filesystem');
      expect(r).toHaveProperty('policy_decision');
    });

    test('command with null bytes in path', async () => {
      const cmd = 'rm -rf /tmp/file\x00name';
      const r = await safeExecute(cmd);
      expect(r.domain).toBe('filesystem');
      expect(r).toHaveProperty('policy_decision');
    });

    test('command with shell metacharacters', async () => {
      const cmd = 'rm -rf /tmp/$(whoami)';
      const r = await safeExecute(cmd);
      expect(r.domain).toBe('filesystem');
      expect(r).toHaveProperty('blocked');
    });

    test('command with backtick injection', async () => {
      const cmd = 'rm -rf /tmp/`cat /etc/passwd`';
      const r = await safeExecute(cmd);
      expect(r.domain).toBe('filesystem');
    });

    test('command with newlines', async () => {
      const cmd = 'rm -rf\n/tmp/test';
      const r = await safeExecute(cmd);
      // Domain detection works on the full trimmed string.
      expect(r).toHaveProperty('domain');
      expect(r).toHaveProperty('policy_decision');
    });
  });

  describe('malformed curl commands', () => {
    test('bare curl (no space after) detects as unknown', async () => {
      // detectDomain checks cmd.startsWith('curl ') with trailing space.
      // Bare 'curl' does not match, falls to 'unknown'.
      expect(detectDomain('curl')).toBe('unknown');
      const r = await safeExecute('curl');
      expect(r.domain).toBe('unknown');
      expect(r.operation).toBe('unknown');
    });

    test('curl with space detects as api', async () => {
      const r = await safeExecute('curl not-a-url');
      expect(r.domain).toBe('api');
      expect(r).toHaveProperty('policy_decision');
    });

    test('curl with invalid URL still parses', async () => {
      const r = await safeExecute('curl http://');
      expect(r.domain).toBe('api');
      expect(r).toHaveProperty('policy_decision');
    });

    test('curl with multiple conflicting methods', async () => {
      const r = await safeExecute('curl -X GET -X POST -X DELETE https://example.com');
      expect(r.domain).toBe('api');
      expect(r).toHaveProperty('operation');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. MCP Tool JSON Schema Validation (functional verification)
// ─────────────────────────────────────────────────────────────────────────────

describe('MCP tool functions — schema-aligned behavior', () => {
  test('safeExecute accepts (command) — single argument', async () => {
    const r = await safeExecute('SELECT 1');
    expect(r).toHaveProperty('domain');
    expect(r).toHaveProperty('policy_decision');
  });

  test('safeExecute accepts (command, domain) — two arguments', async () => {
    const r = await safeExecute('SELECT 1', 'sql');
    expect(r.domain).toBe('sql');
  });

  test('safeAnalyze accepts (command) — single argument', async () => {
    const r = await safeAnalyze('SELECT 1');
    expect(r).toHaveProperty('note');
  });

  test('safeAnalyze accepts (command, domain) — two arguments', async () => {
    const r = await safeAnalyze('SELECT 1', 'filesystem');
    expect(r.domain).toBe('filesystem');
    expect(r).toHaveProperty('note');
  });

  test('safePolicyCheck accepts (command) — single argument only', async () => {
    const r = await safePolicyCheck('SELECT 1');
    expect(r).toHaveProperty('allowed');
    expect(r).toHaveProperty('risk');
    expect(r).toHaveProperty('domain');
    expect(r).toHaveProperty('reason');
  });

  test('safeExecute result has no "note" field', async () => {
    const r = await safeExecute('SELECT 1');
    expect(r).not.toHaveProperty('note');
  });

  test('safeAnalyze result has "note" field', async () => {
    const r = await safeAnalyze('SELECT 1');
    expect(r).toHaveProperty('note');
    expect(r.note).toBe('Analysis only — no execution performed');
  });

  test('safePolicyCheck result has no "note" or "policy_decision" field', async () => {
    const r = await safePolicyCheck('SELECT 1');
    expect(r).not.toHaveProperty('note');
    expect(r).not.toHaveProperty('policy_decision');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. safeAnalyze vs safeExecute Consistency
// ─────────────────────────────────────────────────────────────────────────────

describe('safeAnalyze vs safeExecute — consistency', () => {
  const testCommands = [
    'SELECT * FROM users',
    'rm -rf /home/test',
    'aws s3 ls',
    'kubectl get pods',
    'docker build -t app .',
    'GET https://api.example.com/users',
    'vault read secret/data/db',
    'iptables -F INPUT',
    'git status',
    'redis-cli FLUSHALL',
  ];

  test.each(testCommands)(
    'analyze and execute return identical fields for: %s',
    async (cmd) => {
      const analyze = await safeAnalyze(cmd);
      const execute = await safeExecute(cmd);

      // All common fields must match.
      expect(analyze.domain).toBe(execute.domain);
      expect(analyze.operation).toBe(execute.operation);
      expect(analyze.targets).toEqual(execute.targets);
      expect(analyze.riskLevel).toBe(execute.riskLevel);
      expect(analyze.blocked).toBe(execute.blocked);
      expect(analyze.reason).toBe(execute.reason);
      expect(analyze.policy_decision).toBe(execute.policy_decision);

      // safeAnalyze has an extra 'note' that safeExecute lacks.
      expect(analyze.note).toBe('Analysis only — no execution performed');
      expect(execute).not.toHaveProperty('note');
    },
  );

  test('domain override produces consistent results between analyze and execute', async () => {
    // Use a nonexistent domain to avoid parser-specific errors.
    const cmd = 'rm -rf /tmp/test';
    const analyze = await safeAnalyze(cmd, 'nonexistent');
    const execute = await safeExecute(cmd, 'nonexistent');

    expect(analyze.domain).toBe(execute.domain);
    expect(analyze.domain).toBe('nonexistent');
    expect(analyze.operation).toBe(execute.operation);
    expect(analyze.blocked).toBe(execute.blocked);
    expect(analyze.policy_decision).toBe(execute.policy_decision);
    expect(analyze.note).toBeDefined();
    expect(execute).not.toHaveProperty('note');
  });
});
