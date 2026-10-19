import { parseIntent } from '../src/adapters/sql/parser.js';
import { SQLAdapter } from '../src/adapters/sql/index.js';
import type { PostgresAdapter } from '../src/adapters/sql/index.js';
import type { DatabaseAdapter } from '../src/adapters/adapter.interface.js';
import { loadPolicy } from '../src/config/loader.js';
import { evaluatePolicy } from '../src/core/policy-engine.js';
import { SafeExecutorPipeline } from '../src/core/pipeline.js';
import { safeExecute, safePolicyCheck } from '../src/mcp-server/tools.js';
import type { Policy, SafeExecutorConfig } from '../src/types/index.js';

const BYPASS = 'SELECT 1; DROP TABLE users';

const defaultPolicy = loadPolicy('./config/default-policy.json');

const config: SafeExecutorConfig = {
  version: '1.0',
  environment: 'test',
  executor: 'jest',
  database: { adapter: 'postgres', connectionString: 'postgresql://unused', maxRowsThreshold: 1000 },
  policy: { file: './config/default-policy.json', strictMode: true },
  approval: { mode: 'auto', timeoutSeconds: 30 },
  audit: { enabled: false, output: 'console' },
};

/** In-memory DatabaseAdapter that records every statement sent for execution. */
function fakeDatabase(): DatabaseAdapter & { executed: string[] } {
  const executed: string[] = [];
  return {
    name: 'fake',
    executed,
    ping: async () => {},
    explainQuery: async () => 'Seq Scan',
    explainAnalyzeQuery: async () => 'Seq Scan',
    runInDryRunTransaction: async () => ({ feasible: true, rowsAffected: 0, plan: 'Seq Scan' }),
    beginTransaction: async () => {},
    setSavepoint: async () => {},
    rollbackToSavepoint: async () => {},
    commitTransaction: async () => {},
    rollbackTransaction: async () => {},
    execute: async (sql: string) => {
      executed.push(sql);
      return { rowsAffected: 0 };
    },
    close: async () => {},
  };
}

function pipelineWith(policy: Policy) {
  const db = fakeDatabase();
  const adapter = new SQLAdapter(db as unknown as PostgresAdapter);
  return { db, pipeline: new SafeExecutorPipeline(config, policy, adapter) };
}

// ─── Parser: every statement is evaluated ────────────────────────────────────

describe('SQL parser evaluates every statement', () => {
  test('the most dangerous statement drives type and risk', async () => {
    const intent = await parseIntent(BYPASS);
    expect(intent.type).toBe('DROP');
    expect(intent.metadata['statementCount']).toBe(2);
    expect(intent.isDestructive).toBe(true);
    const codes = intent.riskFactors.map((f) => f.code);
    expect(codes).toEqual(expect.arrayContaining(['DROP_OP', 'MULTI_STATEMENT']));
    expect(intent.tables).toContain('users');
  });

  test('a later DELETE without WHERE is not hidden by an earlier one with WHERE', async () => {
    const intent = await parseIntent('DELETE FROM a WHERE id = 1; DELETE FROM b');
    expect(intent.type).toBe('DELETE');
    expect(intent.hasWhereClause).toBe(false);
    expect(intent.riskFactors.map((f) => f.code)).toContain('NO_WHERE_CLAUSE');
  });

  test('a single statement is unchanged', async () => {
    const intent = await parseIntent('SELECT 1;');
    expect(intent.type).toBe('SELECT');
    expect(intent.metadata['statementCount']).toBe(1);
    expect(intent.riskFactors).toEqual([]);
  });

  test('the regex fallback also splits statements', async () => {
    const intent = await parseIntent('VACUUM users; DROP TABLE users');
    expect(intent.metadata['parser']).toBe('regex-fallback');
    expect(intent.metadata['statementCount']).toBe(2);
    expect(intent.type).toBe('DROP');
  });

  test('the regex fallback does not split inside dollar-quoted bodies', async () => {
    const intent = await parseIntent(
      'CREATE FUNCTION f() RETURNS void AS $$ BEGIN DELETE FROM t; END $$ LANGUAGE plpgsql',
    );
    expect(intent.metadata['statementCount']).toBe(1);
    expect(intent.type).toBe('CREATE');
  });
});

// ─── MCP path ────────────────────────────────────────────────────────────────

describe('MCP path blocks multi-statement SQL', () => {
  test(`${BYPASS} → BLOCKED`, async () => {
    const r = await safeExecute(BYPASS);
    expect(r.policy_decision).toBe('BLOCKED');
    expect(r.riskLevel).toBe('CRITICAL');
  });

  test('even a batch of reads is blocked', async () => {
    const r = await safePolicyCheck('SELECT 1; SELECT 2');
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/2 statements/);
  });
});

// ─── Library path with config/default-policy.json ────────────────────────────

describe('Library path denies multi-statement SQL with the default policy', () => {
  test('policy engine denies the batch', async () => {
    const decision = evaluatePolicy(await parseIntent(BYPASS), defaultPolicy);
    expect(decision.allowed).toBe(false);
    expect(decision.message).toMatch(/2 statements/);
  });

  test('pipeline aborts at the policy gate and executes nothing', async () => {
    const { db, pipeline } = pipelineWith(defaultPolicy);
    const result = await pipeline.run(BYPASS);
    expect(result.success).toBe(false);
    expect(result.abortReason).toMatch(/^Policy denied/);
    expect(db.executed).toEqual([]);
  });

  test('a single SELECT still executes', async () => {
    const { db, pipeline } = pipelineWith(defaultPolicy);
    const result = await pipeline.run('SELECT 1');
    expect(result.success).toBe(true);
    expect(db.executed).toEqual(['SELECT 1']);
  });

  test('with allowMultiStatement, the batch is judged by its most dangerous statement', async () => {
    const optIn: Policy = { ...defaultPolicy, defaults: { ...defaultPolicy.defaults, allowMultiStatement: true } };
    const decision = evaluatePolicy(await parseIntent(BYPASS), optIn);
    expect(decision.matchedRules.map((r) => r.id)).toContain('deny-drop');
    expect(decision.riskLevel).toBe('CRITICAL');
    expect(decision.requiresApproval).toBe(true);

    const { db, pipeline } = pipelineWith(optIn);
    const result = await pipeline.run(BYPASS);
    expect(result.abortReason).toMatch(/^Approval rejected/);
    expect(db.executed).toEqual([]);
  });
});
