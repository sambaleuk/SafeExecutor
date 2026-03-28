import { evaluatePolicy } from '../src/core/policy-engine.js';
import type {
  SafeIntent,
  Policy,
  PolicyDecision,
  OperationType,
  RiskLevel,
  RiskFactor,
  Target,
  Scope,
} from '../src/types/index.js';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeIntent(overrides: Partial<SafeIntent>): SafeIntent {
  return {
    domain: 'sql',
    type: 'SELECT',
    raw: 'SELECT 1',
    target: { name: 'unknown', type: 'table', affectedResources: [] },
    scope: 'single',
    riskFactors: [],
    tables: [],
    hasWhereClause: false,
    estimatedRowsAffected: null,
    isDestructive: false,
    isMassive: false,
    metadata: {},
    ...overrides,
  };
}

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadPolicy(relativePath: string): Policy {
  const fullPath = resolve(__dirname, '..', relativePath);
  return JSON.parse(readFileSync(fullPath, 'utf-8')) as Policy;
}

const defaultPolicy = loadPolicy('config/default-policy.json');

// ─── 1. Every DENY Rule Blocks ───────────────────────────────────────────────

describe('Every DENY rule blocks', () => {
  test('DELETE without WHERE is denied with CRITICAL risk', () => {
    const intent = makeIntent({
      type: 'DELETE',
      raw: 'DELETE FROM users',
      hasWhereClause: false,
      isDestructive: true,
    });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.allowed).toBe(false);
    expect(decision.riskLevel).toBe('CRITICAL');
    expect(decision.matchedRules.some((r) => r.id === 'deny-delete-no-where')).toBe(true);
  });

  test('TRUNCATE is allowed but requires approval with CRITICAL risk', () => {
    const intent = makeIntent({
      type: 'TRUNCATE',
      raw: 'TRUNCATE TABLE users',
      isDestructive: true,
    });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.allowed).toBe(true);
    expect(decision.requiresApproval).toBe(true);
    expect(decision.riskLevel).toBe('CRITICAL');
    expect(decision.matchedRules.some((r) => r.id === 'deny-truncate')).toBe(true);
  });

  test('DROP is allowed but requires approval with CRITICAL risk', () => {
    const intent = makeIntent({
      type: 'DROP',
      raw: 'DROP TABLE users',
      isDestructive: true,
    });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.allowed).toBe(true);
    expect(decision.requiresApproval).toBe(true);
    expect(decision.riskLevel).toBe('CRITICAL');
    expect(decision.matchedRules.some((r) => r.id === 'deny-drop')).toBe(true);
  });

  test('ALTER requires approval with HIGH risk', () => {
    const intent = makeIntent({
      type: 'ALTER',
      raw: 'ALTER TABLE users ADD COLUMN email TEXT',
    });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.allowed).toBe(true);
    expect(decision.requiresApproval).toBe(true);
    expect(decision.riskLevel).toBe('HIGH');
    expect(decision.matchedRules.some((r) => r.id === 'alter-large-table')).toBe(true);
  });

  test('DELETE with WHERE requires dry-run with HIGH risk', () => {
    const intent = makeIntent({
      type: 'DELETE',
      raw: 'DELETE FROM users WHERE id = 1',
      hasWhereClause: true,
      isDestructive: true,
    });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.allowed).toBe(true);
    expect(decision.requiresDryRun).toBe(true);
    expect(decision.riskLevel).toBe('HIGH');
    expect(decision.matchedRules.some((r) => r.id === 'delete-with-where-dry-run')).toBe(true);
  });
});

// ─── 2. Every REQUIRE_APPROVAL Rule Returns Right Status ─────────────────────

describe('Every REQUIRE_APPROVAL rule returns right status', () => {
  test('TRUNCATE sets requiresApproval=true', () => {
    const intent = makeIntent({ type: 'TRUNCATE', raw: 'TRUNCATE TABLE orders' });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.requiresApproval).toBe(true);
  });

  test('DROP sets requiresApproval=true', () => {
    const intent = makeIntent({ type: 'DROP', raw: 'DROP TABLE orders' });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.requiresApproval).toBe(true);
  });

  test('ALTER sets requiresApproval=true', () => {
    const intent = makeIntent({ type: 'ALTER', raw: 'ALTER TABLE orders RENAME TO archive' });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.requiresApproval).toBe(true);
  });

  test('UPDATE without WHERE sets requiresApproval=true', () => {
    const intent = makeIntent({
      type: 'UPDATE',
      raw: 'UPDATE users SET active = false',
      hasWhereClause: false,
    });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.requiresApproval).toBe(true);
    expect(decision.riskLevel).toBe('HIGH');
    expect(decision.matchedRules.some((r) => r.id === 'update-no-where')).toBe(true);
  });
});

// ─── 3. CRITICAL Risk Forces DryRun + Approval ──────────────────────────────

describe('CRITICAL risk forces dryRun + approval', () => {
  test('DELETE without WHERE (deny + CRITICAL) forces both flags', () => {
    const intent = makeIntent({
      type: 'DELETE',
      raw: 'DELETE FROM users',
      hasWhereClause: false,
    });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.riskLevel).toBe('CRITICAL');
    expect(decision.requiresDryRun).toBe(true);
    expect(decision.requiresApproval).toBe(true);
  });

  test('TRUNCATE (require_approval + CRITICAL) forces both flags', () => {
    const intent = makeIntent({ type: 'TRUNCATE', raw: 'TRUNCATE TABLE users' });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.riskLevel).toBe('CRITICAL');
    expect(decision.requiresDryRun).toBe(true);
    expect(decision.requiresApproval).toBe(true);
  });

  test('DROP (require_approval + CRITICAL) forces both flags', () => {
    const intent = makeIntent({ type: 'DROP', raw: 'DROP INDEX idx_users_email' });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.riskLevel).toBe('CRITICAL');
    expect(decision.requiresDryRun).toBe(true);
    expect(decision.requiresApproval).toBe(true);
  });

  test('non-CRITICAL risk does not force both flags', () => {
    const intent = makeIntent({
      type: 'UPDATE',
      raw: 'UPDATE users SET name = $1 WHERE id = $2',
      hasWhereClause: true,
    });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.riskLevel).toBe('MEDIUM');
    expect(decision.requiresDryRun).toBe(true);
    // MEDIUM risk does not auto-force approval
    expect(decision.requiresApproval).toBe(false);
  });
});

// ─── 4. Policy Rules Don't Interfere Across Domains ─────────────────────────

describe('Policy rules do not interfere across domains', () => {
  test('SELECT with domain=cloud still matches select-allow rule', () => {
    const intent = makeIntent({ domain: 'cloud', type: 'SELECT', raw: 'cloud:read' });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.allowed).toBe(true);
    expect(decision.riskLevel).toBe('LOW');
    expect(decision.matchedRules.some((r) => r.id === 'select-allow')).toBe(true);
  });

  test('DELETE with domain=filesystem still matches deny-delete-no-where rule', () => {
    const intent = makeIntent({
      domain: 'filesystem',
      type: 'DELETE',
      raw: 'fs:delete',
      hasWhereClause: false,
    });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.allowed).toBe(false);
    expect(decision.riskLevel).toBe('CRITICAL');
  });

  test('INSERT with domain=api still matches insert-allow rule', () => {
    const intent = makeIntent({ domain: 'api', type: 'INSERT', raw: 'api:create' });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.allowed).toBe(true);
    expect(decision.requiresDryRun).toBe(true);
    expect(decision.riskLevel).toBe('LOW');
  });

  test('UNKNOWN type with domain=cloud falls to defaults (denied)', () => {
    const intent = makeIntent({ domain: 'cloud', type: 'UNKNOWN', raw: 'cloud:unknown-op' });
    const decision = evaluatePolicy(intent, defaultPolicy);

    // No rule matches UNKNOWN, defaults kick in: allowUnknown=false
    expect(decision.allowed).toBe(false);
    expect(decision.riskLevel).toBe('HIGH');
    expect(decision.matchedRules).toHaveLength(0);
  });
});

// ─── 5. Default Policy (No Custom Rules) ────────────────────────────────────

describe('Default policy with no custom rules', () => {
  const permissivePolicy: Policy = {
    version: '1.0',
    rules: [],
    defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' },
  };

  const restrictivePolicy: Policy = {
    version: '1.0',
    rules: [],
    defaults: { allowUnknown: false, defaultRiskLevel: 'HIGH' },
  };

  test('permissive empty policy allows any intent at LOW risk', () => {
    const intent = makeIntent({ type: 'DELETE', raw: 'DELETE FROM users' });
    const decision = evaluatePolicy(intent, permissivePolicy);

    expect(decision.allowed).toBe(true);
    expect(decision.riskLevel).toBe('LOW');
    expect(decision.matchedRules).toHaveLength(0);
    expect(decision.requiresDryRun).toBe(false);
    expect(decision.requiresApproval).toBe(false);
  });

  test('restrictive empty policy denies any intent at HIGH risk', () => {
    const intent = makeIntent({ type: 'SELECT', raw: 'SELECT 1' });
    const decision = evaluatePolicy(intent, restrictivePolicy);

    expect(decision.allowed).toBe(false);
    expect(decision.riskLevel).toBe('HIGH');
    expect(decision.matchedRules).toHaveLength(0);
  });

  test('permissive policy returns correct message for no-match', () => {
    const intent = makeIntent({ type: 'UNKNOWN' });
    const decision = evaluatePolicy(intent, permissivePolicy);

    expect(decision.message).toContain('default');
  });

  test('restrictive policy returns correct message for no-match', () => {
    const intent = makeIntent({ type: 'UNKNOWN' });
    const decision = evaluatePolicy(intent, restrictivePolicy);

    expect(decision.message).toContain('allowUnknown');
  });
});

// ─── 6. Rule Ordering / Escalation ──────────────────────────────────────────

describe('Rule ordering and risk escalation', () => {
  test('DELETE without WHERE matches deny-delete-no-where first with CRITICAL risk', () => {
    const intent = makeIntent({
      type: 'DELETE',
      raw: 'DELETE FROM users',
      hasWhereClause: false,
    });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.riskLevel).toBe('CRITICAL');
    expect(decision.matchedRules[0].id).toBe('deny-delete-no-where');
  });

  test('risk only escalates up, never down', () => {
    // Custom policy where a CRITICAL rule comes before a LOW rule for same type
    const escalationPolicy: Policy = {
      version: '1.0',
      rules: [
        {
          id: 'critical-first',
          description: 'High risk first',
          match: { operationType: ['SELECT'] },
          action: 'allow',
          riskLevel: 'CRITICAL',
        },
        {
          id: 'low-second',
          description: 'Low risk second',
          match: { operationType: ['SELECT'] },
          action: 'allow',
          riskLevel: 'LOW',
        },
      ],
      defaults: { allowUnknown: false, defaultRiskLevel: 'LOW' },
    };

    const intent = makeIntent({ type: 'SELECT', raw: 'SELECT 1' });
    const decision = evaluatePolicy(intent, escalationPolicy);

    // Both rules match, risk should stay at CRITICAL (not drop to LOW)
    expect(decision.matchedRules).toHaveLength(2);
    expect(decision.riskLevel).toBe('CRITICAL');
  });

  test('risk escalates from LOW to HIGH when multiple rules match', () => {
    const multiMatchPolicy: Policy = {
      version: '1.0',
      rules: [
        {
          id: 'low-rule',
          description: 'Low risk',
          match: { operationType: ['UPDATE'] },
          action: 'allow',
          riskLevel: 'LOW',
        },
        {
          id: 'high-rule',
          description: 'High risk for no WHERE',
          match: { operationType: ['UPDATE'], hasWhereClause: false },
          action: 'require_approval',
          riskLevel: 'HIGH',
        },
      ],
      defaults: { allowUnknown: false, defaultRiskLevel: 'LOW' },
    };

    const intent = makeIntent({
      type: 'UPDATE',
      raw: 'UPDATE users SET active = false',
      hasWhereClause: false,
    });
    const decision = evaluatePolicy(intent, multiMatchPolicy);

    expect(decision.matchedRules).toHaveLength(2);
    expect(decision.riskLevel).toBe('HIGH');
    expect(decision.requiresApproval).toBe(true);
  });
});

// ─── 7. Tables Pattern Matching ─────────────────────────────────────────────

describe('Tables pattern matching', () => {
  const policyWithTablePattern: Policy = {
    version: '1.0',
    rules: [
      {
        id: 'block-users-table',
        description: 'Block operations on users table',
        match: { tablesPattern: ['users'] },
        action: 'deny',
        riskLevel: 'CRITICAL',
      },
    ],
    defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' },
  };

  test('intent targeting users table is denied', () => {
    const intent = makeIntent({
      type: 'SELECT',
      raw: 'SELECT * FROM users',
      tables: ['users'],
    });
    const decision = evaluatePolicy(intent, policyWithTablePattern);

    expect(decision.allowed).toBe(false);
    expect(decision.riskLevel).toBe('CRITICAL');
    expect(decision.matchedRules.some((r) => r.id === 'block-users-table')).toBe(true);
  });

  test('intent targeting orders table is allowed (no matching rule)', () => {
    const intent = makeIntent({
      type: 'SELECT',
      raw: 'SELECT * FROM orders',
      tables: ['orders'],
    });
    const decision = evaluatePolicy(intent, policyWithTablePattern);

    expect(decision.allowed).toBe(true);
    expect(decision.riskLevel).toBe('LOW');
    expect(decision.matchedRules).toHaveLength(0);
  });

  test('regex pattern matches table names', () => {
    const regexPolicy: Policy = {
      version: '1.0',
      rules: [
        {
          id: 'block-pii-tables',
          description: 'Block PII tables',
          match: { tablesPattern: ['^(users|customers|accounts)$'] },
          action: 'deny',
          riskLevel: 'CRITICAL',
        },
      ],
      defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' },
    };

    const usersIntent = makeIntent({ tables: ['users'] });
    expect(evaluatePolicy(usersIntent, regexPolicy).allowed).toBe(false);

    const customersIntent = makeIntent({ tables: ['customers'] });
    expect(evaluatePolicy(customersIntent, regexPolicy).allowed).toBe(false);

    const logsIntent = makeIntent({ tables: ['logs'] });
    expect(evaluatePolicy(logsIntent, regexPolicy).allowed).toBe(true);
  });

  test('empty tables array does not match tablesPattern rule', () => {
    const intent = makeIntent({ tables: [] });
    const decision = evaluatePolicy(intent, policyWithTablePattern);

    // No tables means no match on tablesPattern; falls to default
    expect(decision.allowed).toBe(true);
    expect(decision.matchedRules).toHaveLength(0);
  });

  test('intent with multiple tables matches if any table matches', () => {
    const intent = makeIntent({
      type: 'SELECT',
      raw: 'SELECT * FROM orders JOIN users ON ...',
      tables: ['orders', 'users'],
    });
    const decision = evaluatePolicy(intent, policyWithTablePattern);

    expect(decision.allowed).toBe(false);
    expect(decision.matchedRules.some((r) => r.id === 'block-users-table')).toBe(true);
  });
});

// ─── 8. MinRowsAffected Matching ────────────────────────────────────────────

describe('MinRowsAffected matching', () => {
  const rowThresholdPolicy: Policy = {
    version: '1.0',
    rules: [
      {
        id: 'large-update-approval',
        description: 'Large updates need approval',
        match: { operationType: ['UPDATE'], minRowsAffected: 1000 },
        action: 'require_approval',
        riskLevel: 'HIGH',
      },
    ],
    defaults: { allowUnknown: true, defaultRiskLevel: 'LOW' },
  };

  test('estimatedRowsAffected below threshold does not match', () => {
    const intent = makeIntent({
      type: 'UPDATE',
      raw: 'UPDATE users SET active = false WHERE region = $1',
      estimatedRowsAffected: 500,
    });
    const decision = evaluatePolicy(intent, rowThresholdPolicy);

    // 500 < 1000, so the minRowsAffected condition rejects the rule match
    expect(decision.matchedRules).toHaveLength(0);
    expect(decision.allowed).toBe(true);
    expect(decision.riskLevel).toBe('LOW');
  });

  test('estimatedRowsAffected above threshold matches', () => {
    const intent = makeIntent({
      type: 'UPDATE',
      raw: 'UPDATE users SET active = false WHERE region = $1',
      estimatedRowsAffected: 1500,
    });
    const decision = evaluatePolicy(intent, rowThresholdPolicy);

    expect(decision.matchedRules).toHaveLength(1);
    expect(decision.matchedRules[0].id).toBe('large-update-approval');
    expect(decision.requiresApproval).toBe(true);
    expect(decision.riskLevel).toBe('HIGH');
  });

  test('estimatedRowsAffected exactly at threshold matches', () => {
    const intent = makeIntent({
      type: 'UPDATE',
      raw: 'UPDATE users SET active = false',
      estimatedRowsAffected: 1000,
    });
    const decision = evaluatePolicy(intent, rowThresholdPolicy);

    // 1000 is NOT < 1000, so the condition does not reject — rule matches
    expect(decision.matchedRules).toHaveLength(1);
    expect(decision.requiresApproval).toBe(true);
  });

  test('estimatedRowsAffected=null does not reject the rule (unknown count passes through)', () => {
    const intent = makeIntent({
      type: 'UPDATE',
      raw: 'UPDATE users SET active = false',
      estimatedRowsAffected: null,
    });
    const decision = evaluatePolicy(intent, rowThresholdPolicy);

    // When estimatedRowsAffected is null, the minRowsAffected guard is skipped,
    // so the rule still matches (unknown row count is treated conservatively)
    expect(decision.matchedRules).toHaveLength(1);
    expect(decision.requiresApproval).toBe(true);
  });
});

// ─── 9. Load and Test All Domain Policies ───────────────────────────────────

describe('Load and validate all domain policies', () => {
  const domainPolicyFiles = [
    'api',
    'cicd',
    'cloud',
    'filesystem',
    'git',
    'kubernetes',
    'network',
    'queue',
    'secrets',
  ];

  for (const domain of domainPolicyFiles) {
    const fileName = `${domain}-default-policy.json`;

    describe(`${domain} policy (${fileName})`, () => {
      let rawContent: string;
      let policy: Record<string, unknown>;

      beforeAll(() => {
        const fullPath = resolve(__dirname, '..', 'config', 'policies', fileName);
        rawContent = readFileSync(fullPath, 'utf-8');
        policy = JSON.parse(rawContent) as Record<string, unknown>;
      });

      test('parses as valid JSON', () => {
        expect(() => JSON.parse(rawContent)).not.toThrow();
      });

      test('has a version field', () => {
        expect(policy).toHaveProperty('version');
        expect(typeof policy.version).toBe('string');
      });

      test('has a rules array', () => {
        expect(policy).toHaveProperty('rules');
        expect(Array.isArray(policy.rules)).toBe(true);
      });

      test('has a non-empty rules array', () => {
        expect((policy.rules as unknown[]).length).toBeGreaterThan(0);
      });

      test('has a defaults object with required fields', () => {
        expect(policy).toHaveProperty('defaults');
        const defaults = policy.defaults as Record<string, unknown>;
        expect(defaults).toHaveProperty('allowUnknown');
        expect(defaults).toHaveProperty('defaultRiskLevel');
        expect(typeof defaults.allowUnknown).toBe('boolean');
        expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(defaults.defaultRiskLevel);
      });

      test('every rule has id, description, match, action, and riskLevel', () => {
        const rules = policy.rules as Record<string, unknown>[];
        for (const rule of rules) {
          expect(rule).toHaveProperty('id');
          expect(rule).toHaveProperty('description');
          expect(rule).toHaveProperty('match');
          expect(rule).toHaveProperty('action');
          expect(rule).toHaveProperty('riskLevel');
          expect(typeof rule.id).toBe('string');
          expect(typeof rule.description).toBe('string');
          expect(['allow', 'deny', 'require_approval', 'require_dry_run']).toContain(rule.action);
          expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(rule.riskLevel);
        }
      });
    });
  }
});

// ─── 10. Default SQL Policy Complete Coverage ───────────────────────────────

describe('Default SQL policy complete coverage', () => {
  test('SELECT is allowed at LOW risk with no extra requirements', () => {
    const intent = makeIntent({ type: 'SELECT', raw: 'SELECT * FROM users' });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.allowed).toBe(true);
    expect(decision.riskLevel).toBe('LOW');
    expect(decision.requiresDryRun).toBe(false);
    expect(decision.requiresApproval).toBe(false);
  });

  test('INSERT requires dry-run at LOW risk', () => {
    const intent = makeIntent({
      type: 'INSERT',
      raw: 'INSERT INTO users (name) VALUES ($1)',
    });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.allowed).toBe(true);
    expect(decision.requiresDryRun).toBe(true);
    expect(decision.riskLevel).toBe('LOW');
  });

  test('CREATE requires dry-run at MEDIUM risk', () => {
    const intent = makeIntent({
      type: 'CREATE',
      raw: 'CREATE TABLE archive (id INT)',
    });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.allowed).toBe(true);
    expect(decision.requiresDryRun).toBe(true);
    expect(decision.riskLevel).toBe('MEDIUM');
    expect(decision.matchedRules.some((r) => r.id === 'create-allow')).toBe(true);
  });

  test('UPDATE with WHERE requires dry-run at MEDIUM risk', () => {
    const intent = makeIntent({
      type: 'UPDATE',
      raw: 'UPDATE users SET name = $1 WHERE id = $2',
      hasWhereClause: true,
    });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.allowed).toBe(true);
    expect(decision.requiresDryRun).toBe(true);
    expect(decision.requiresApproval).toBe(false);
    expect(decision.riskLevel).toBe('MEDIUM');
    expect(decision.matchedRules.some((r) => r.id === 'update-with-where')).toBe(true);
  });

  test('UNKNOWN type falls to defaults and is denied', () => {
    const intent = makeIntent({ type: 'UNKNOWN', raw: 'EXPLAIN SELECT 1' });
    const decision = evaluatePolicy(intent, defaultPolicy);

    expect(decision.allowed).toBe(false);
    expect(decision.riskLevel).toBe('HIGH');
    expect(decision.matchedRules).toHaveLength(0);
  });
});
