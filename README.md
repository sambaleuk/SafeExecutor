# SafeExecutor

**A generic safe execution framework for autonomous agents.**

SafeExecutor wraps any operation — SQL, cloud infrastructure, filesystem, API calls, CI/CD deployments — in a 6-gate pipeline that cannot be bypassed. Before anything touches a sensitive system, it must pass through intent classification, policy evaluation, dry-run simulation, human approval, and rollback-protected execution — with a complete audit trail at every step.

Inspired by [Modragor](https://github.com/sambaleuk/Modragor)'s structural harness pattern. Same philosophy: **the harness is non-bypassable by design.**

> **v2 is in active development.** v1 shipped the SQL pipeline. v2 generalizes it to any domain. See [ROADMAP_V2.md](./ROADMAP_V2.md) for the full plan.

---

## The Problem

Autonomous agents make mistakes. The mistakes that matter most share a pattern:

1. An AI agent runs `DELETE FROM users` without a `WHERE` clause
2. A Terraform apply silently destroys a production RDS instance
3. A CI/CD pipeline deploys to production without running tests
4. `rm -rf` runs one directory up from where it should
5. No one knows exactly what ran, when, or why

SafeExecutor makes these scenarios structurally impossible — for any domain, not just SQL.

---

## Architecture

Every operation passes through 6 gates in strict sequence. No gate can be skipped.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SafeExecutor Pipeline                        │
│                                                                     │
│  raw operation (SQL / terraform plan / shell cmd / HTTP request)    │
│      │                                                              │
│      ▼                                                              │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Gate 1: Intent Parser        [adapter.parseIntent()]         │  │
│  │  Parse input → SafeIntent                                     │  │
│  │  Extract: operation type, target resources, risk factors      │  │
│  └─────────────────────────────┬────────────────────────────────┘  │
│                                │  SafeIntent                        │
│                                ▼                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Gate 2: Policy Engine                                        │  │
│  │  Evaluate SafeIntent against JSON policy rules                │  │
│  │  → ALLOW / DENY / require_dry_run / require_approval          │  │
│  └─────────────────────────────┬────────────────────────────────┘  │
│                                │  PolicyDecision                    │
│                                ▼                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Gate 3: Sandbox / Dry-Run    [adapter.sandbox()]  (optional) │  │
│  │  SQL    → BEGIN → EXECUTE → capture stats → ROLLBACK          │  │
│  │  Cloud  → terraform plan --out                                │  │
│  │  Files  → dry-run simulation (cp -n, rm preview)              │  │
│  └─────────────────────────────┬────────────────────────────────┘  │
│                                │  SandboxResult                     │
│                                ▼                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Gate 4: Approval Gate                          (optional)    │  │
│  │  auto    → LOW/MEDIUM auto-approve, HIGH/CRITICAL reject      │  │
│  │  cli     → interactive terminal prompt                        │  │
│  │  webhook → POST to Slack/PagerDuty/custom endpoint            │  │
│  └─────────────────────────────┬────────────────────────────────┘  │
│                                │  ApprovalResponse                  │
│                                ▼                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Gate 5: Executor             [adapter.execute()]             │  │
│  │  Execute with rollback protection                             │  │
│  │  SQL   → savepoint + auto-rollback if rows > estimated * 1.5  │  │
│  │  Cloud → apply + state snapshot for rollback                  │  │
│  └─────────────────────────────┬────────────────────────────────┘  │
│                                │  ExecutionResult                   │
│                                ▼                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Gate 6: Audit Trail                                          │  │
│  │  who · what · when · why · before/after · plan · duration     │  │
│  │  Output: console | file | database                            │  │
│  └─────────────────────────────┬────────────────────────────────┘  │
│                                │  AuditEntry + PipelineResult       │
└────────────────────────────────┼────────────────────────────────────┘
                                 ▼
                           caller receives result
```

The pipeline core is **completely domain-agnostic**. All domain knowledge lives in adapters.

---

## Design Principles

Inherited from [Modragor](https://github.com/sambaleuk/Modragor):

| Principle | Implementation |
|-----------|----------------|
| **Non-bypassable gates** | No `--force`, no `--skip`. Every gate executes in order |
| **Universal intent format** | `SafeIntent` is the lingua franca — all adapters speak it |
| **Domain isolation** | Adapters encapsulate all domain knowledge. The pipeline knows nothing about SQL/Terraform/etc. |
| **Source of truth** | `config.json` + `policy.json` are AJV-validated at startup. Config drives behavior, not runtime state |

---

## Universal Intent Format

Every adapter produces a `SafeIntent` that the pipeline and policy engine operate on:

```typescript
interface SafeIntent {
  domain: string;              // "sql", "cloud", "filesystem", "api", "cicd"
  type: OperationType;         // SELECT | INSERT | UPDATE | DELETE | TRUNCATE | DROP | …
  raw: string;                 // original input verbatim
  target: Target;              // what is being operated on
  scope: Scope;                // "single" | "batch" | "all"
  riskFactors: RiskFactor[];   // explicit risk signals extracted by the adapter

  // SQL-compatible backward-compat fields (used by current policy engine)
  tables: string[];
  hasWhereClause: boolean;
  estimatedRowsAffected: number | null;
  isDestructive: boolean;
  isMassive: boolean;

  ast?: unknown;               // domain-specific parsed representation
  metadata: Record<string, unknown>;
}
```

---

## Adapter System

Each domain implements `SafeAdapter`:

```typescript
interface SafeAdapter {
  readonly domain: string;
  ping(): Promise<void>;
  parseIntent(raw: string): Promise<SafeIntent>;
  sandbox(intent: SafeIntent): Promise<SandboxResult>;
  execute(intent: SafeIntent, config: SafeExecutorConfig, estimatedRows: number | null): Promise<ExecutionResult>;
  close(): Promise<void>;
}
```

### Implemented Adapters

| Adapter | Domain | Status | Parser |
|---------|--------|--------|--------|
| `SQLAdapter` | `sql` | ✅ Ready | AST-based (`node-sql-parser`) with regex fallback |

### Planned Adapters

| Adapter | Domain | Status | Notes |
|---------|--------|--------|-------|
| `CloudAdapter` | `cloud` | 🔲 Phase 4 | Terraform plan JSON → SafeIntent |
| `FilesystemAdapter` | `filesystem` | 🔲 Phase 5 | Shell command → SafeIntent |
| `APIAdapter` | `api` | 🔲 Phase 6 | HTTP request → SafeIntent + PII detection |
| `CICDAdapter` | `cicd` | 🔲 Phase 7 | Pipeline trigger → SafeIntent |

---

## Quickstart

### 1. Install

```bash
npm install safe-executor pg
```

### 2. Create a config file

```json
{
  "version": "1.0",
  "environment": "production",
  "executor": "migration-bot",
  "database": {
    "adapter": "postgres",
    "connectionString": "postgresql://user:pass@localhost:5432/mydb",
    "maxRowsThreshold": 50000
  },
  "policy": {
    "file": "./config/default-policy.json",
    "strictMode": true
  },
  "approval": {
    "mode": "cli",
    "timeoutSeconds": 300
  },
  "audit": {
    "enabled": true,
    "output": "file",
    "filePath": "./logs/audit.log"
  }
}
```

### 3. Run

```typescript
import { SafeExecutor } from 'safe-executor';

const executor = new SafeExecutor({
  configPath: './config/my-config.json',
});

// The SQL adapter uses node-sql-parser (AST) for accurate intent parsing.
// This will:
//   1. Parse intent via AST (extracts tables, detects WHERE, classifies risks)
//   2. Match the `delete-with-where-dry-run` policy rule
//   3. Run a dry-run transaction to count affected rows
//   4. Prompt for CLI approval (showing estimated row count + warnings)
//   5. Execute with savepoint protection + auto-rollback guard
//   6. Write the audit entry

const result = await executor.run(
  "DELETE FROM sessions WHERE last_seen < NOW() - INTERVAL '30 days'",
  'ops-engineer-alice'
);

if (result.success) {
  console.log(`Deleted ${result.executionResult?.rowsAffected} rows`);
} else {
  console.error(`Aborted: ${result.abortReason}`);
}

await executor.close();
```

### Custom adapter

```typescript
import type { SafeAdapter } from 'safe-executor';
import { SafeExecutorPipeline } from 'safe-executor';

class MyCloudAdapter implements SafeAdapter {
  readonly domain = 'cloud';
  async ping() { /* verify terraform CLI */ }
  async parseIntent(raw) { /* parse terraform plan JSON → SafeIntent */ }
  async sandbox(intent) { /* run terraform plan --out */ }
  async execute(intent, config, estimatedRows) { /* terraform apply */ }
  async close() { /* cleanup */ }
}

const pipeline = new SafeExecutorPipeline(config, policy, new MyCloudAdapter());
```

---

## SQL Adapter Details

### AST-based parser

The SQL adapter uses `node-sql-parser` to produce a full parse tree. This enables:

- **Accurate table extraction**: Finds tables in FROM, JOINs, CTEs, subqueries — not just the first FROM clause
- **Risk factor classification**: Based on AST structure, not regex patterns
- **CTE detection**: `WITH ... AS (SELECT ...)` modifying data is flagged as `CTE_WITH_DML` (HIGH)
- **Subquery detection**: Subqueries in DELETE/UPDATE raise `SUBQUERY_IN_DESTRUCTIVE` (HIGH)
- **Parameterized query support**: `$1`, `$2` placeholders handled correctly
- **Fallback safety**: Exotic syntax falls back to the regex parser with `parserFallback: true` metadata

### Risk factors extracted

| Code | Trigger | Severity |
|------|---------|----------|
| `NO_WHERE_CLAUSE` | DELETE without WHERE | CRITICAL |
| `TRUNCATE_OP` | TRUNCATE statement | CRITICAL |
| `DROP_OP` | DROP TABLE/INDEX/etc | CRITICAL |
| `NO_WHERE_CLAUSE_UPDATE` | UPDATE without WHERE | HIGH |
| `SCHEMA_CHANGE` | ALTER TABLE | HIGH |
| `MASSIVE_OPERATION` | Operation affects >10k rows | HIGH |
| `CTE_WITH_DML` | WITH clause + INSERT/UPDATE/DELETE | HIGH |
| `SUBQUERY_IN_DESTRUCTIVE` | Subquery in DELETE/UPDATE | HIGH |

---

## Default Policy Rules (SQL)

| Rule | Operation | Action | Risk |
|------|-----------|--------|------|
| `deny-delete-no-where` | `DELETE` (no WHERE) | **DENY** | CRITICAL |
| `deny-truncate` | `TRUNCATE` | Require approval | CRITICAL |
| `deny-drop` | `DROP` | Require approval | CRITICAL |
| `alter-large-table` | `ALTER` | Require approval | HIGH |
| `delete-with-where-dry-run` | `DELETE` (WHERE) | Dry-run + approval | HIGH |
| `update-no-where` | `UPDATE` (no WHERE) | Require approval | HIGH |
| `update-with-where` | `UPDATE` (WHERE) | Dry-run | MEDIUM |
| `insert-allow` | `INSERT` | Dry-run | LOW |
| `select-allow` | `SELECT` | Allow | LOW |

### Custom policy rule example

```json
{
  "id": "protect-payments-table",
  "description": "Any mutation on payments table requires human approval",
  "match": {
    "operationType": ["INSERT", "UPDATE", "DELETE"],
    "tablesPattern": ["^payments$", "^payment_.*"]
  },
  "action": "require_approval",
  "riskLevel": "CRITICAL",
  "message": "Mutations on payment tables require DBA approval."
}
```

---

## Audit Trail

Every operation — approved or denied — produces an immutable audit entry:

```json
{
  "id": "audit-1748000000-1",
  "timestamp": "2026-03-28T14:32:00.000Z",
  "executor": "migration-bot",
  "environment": "production",
  "operation": {
    "domain": "sql",
    "type": "DELETE",
    "tables": ["sessions"],
    "hasWhereClause": true,
    "estimatedRowsAffected": 142831,
    "isDestructive": true,
    "isMassive": true,
    "riskFactors": [
      { "code": "MASSIVE_OPERATION", "severity": "HIGH", "description": "..." }
    ]
  },
  "policyDecision": {
    "allowed": true,
    "riskLevel": "HIGH",
    "requiresDryRun": true,
    "requiresApproval": true
  },
  "sandboxResult": {
    "feasible": true,
    "estimatedRowsAffected": 142831,
    "warnings": ["Large operation: 142831 rows would be affected"]
  },
  "approvalResponse": {
    "status": "approved",
    "approvedBy": "alice",
    "approvedAt": "2026-03-28T14:32:45.000Z"
  },
  "executionResult": {
    "status": "success",
    "rowsAffected": 142831,
    "savepointUsed": true,
    "rolledBack": false
  },
  "totalDurationMs": 3847
}
```

---

## File Structure

```
src/
├── core/                    # Domain-agnostic pipeline
│   ├── pipeline.ts          # 6-gate orchestrator (uses SafeAdapter, not SQL)
│   ├── policy-engine.ts     # Rule evaluation
│   ├── approval-gate.ts     # auto / cli / webhook approval
│   └── audit.ts             # Immutable audit trail
├── adapters/
│   ├── adapter.interface.ts # SafeAdapter + DatabaseAdapter interfaces
│   ├── sql/                 # SQL domain adapter
│   │   ├── parser.ts        # AST-based SQL parser (node-sql-parser + regex fallback)
│   │   ├── sandbox.ts       # SQL dry-run simulation
│   │   ├── executor.ts      # SQL execution with savepoint protection
│   │   ├── postgres.ts      # PostgreSQL connection adapter
│   │   └── index.ts         # SQLAdapter class
│   ├── cloud/               # 🔲 Phase 4 — Terraform adapter (placeholder)
│   ├── filesystem/           # 🔲 Phase 5 — Shell adapter (placeholder)
│   ├── api/                  # 🔲 Phase 6 — HTTP adapter (placeholder)
│   └── cicd/                 # 🔲 Phase 7 — CI/CD adapter (placeholder)
├── plugins/
│   └── registry.ts          # Adapter registration
├── types/
│   └── index.ts             # SafeIntent, SafeAdapter, all shared types
└── config/
    └── loader.ts            # AJV-validated config loading
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SAFE_EXECUTOR_VERBOSE` | Set to `true` to log full JSON audit entries to console |

---

## Roadmap

See [ROADMAP_V2.md](./ROADMAP_V2.md) for the complete v2 plan.

| Phase | Description | Status |
|-------|-------------|--------|
| v1 core | 6-gate pipeline, PostgreSQL adapter, CLI/webhook approval | ✅ Done |
| v2 restructure | Multi-domain file structure, SafeAdapter interface | ✅ Done |
| v2 SQL parser | AST-based SQL parser (node-sql-parser) | ✅ Done |
| Phase 1 | Universal OperationType (read/write/destroy/…) | 🔲 Next |
| Phase 4 | Cloud Infrastructure Adapter (Terraform) | 🔲 Pending |
| Phase 5 | Filesystem Adapter (shell commands) | 🔲 Pending |
| Phase 6 | API Adapter (HTTP calls + PII detection) | 🔲 Pending |
| Phase 7 | CI/CD Adapter (deployment pipelines) | 🔲 Pending |
| Phase 8 | Plugin system + NPM packages per adapter | 🔲 Pending |

---

## License

MIT — see [LICENSE](./LICENSE)
