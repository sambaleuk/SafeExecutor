# SafeExecutor

**A harness for safe, gate-enforced execution of operations on sensitive systems.**

SafeExecutor wraps every database operation in a 6-layer validation pipeline that cannot be bypassed. Before any SQL touches your production database, it must pass through intent classification, policy evaluation, dry-run simulation, human approval, and rollback-protected execution — with a complete audit trail at every step.

Inspired by [Modragor](https://github.com/sambaleuk/Modragor)'s structural harness pattern. Same philosophy: **the harness is non-bypassable by design.**

---

## The Problem

Database incidents follow a predictable pattern:

1. Someone (or an AI agent) runs a `DELETE` without a `WHERE` clause
2. An `ALTER TABLE` locks a 50M-row table during peak traffic
3. A migration script affects 10x more rows than expected
4. No one knows exactly what ran, when, or why

SafeExecutor makes these scenarios structurally impossible.

---

## Architecture

Every operation passes through 6 gates in strict sequence. No gate can be skipped.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SafeExecutor Pipeline                        │
│                                                                     │
│  SQL Input                                                          │
│      │                                                              │
│      ▼                                                              │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Gate 1: Intent Parser                                        │  │
│  │  Parse SQL → classify operation type, extract tables,        │  │
│  │  detect WHERE clause, flag destructive/massive operations     │  │
│  └─────────────────────────────┬────────────────────────────────┘  │
│                                │  ParsedIntent                      │
│                                ▼                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Gate 2: Policy Engine                                        │  │
│  │  Evaluate against JSON policy rules                          │  │
│  │  → ALLOW / DENY / require_dry_run / require_approval         │  │
│  │  DELETE without WHERE → DENY (non-bypassable)                │  │
│  └─────────────────────────────┬────────────────────────────────┘  │
│                                │  PolicyDecision                    │
│                                ▼                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Gate 3: Sandbox / Dry-Run              (if required)         │  │
│  │  SELECT    → EXPLAIN ANALYZE                                  │  │
│  │  DML       → BEGIN → EXECUTE → capture stats → ROLLBACK       │  │
│  │  DDL       → EXPLAIN + schema inspection                      │  │
│  └─────────────────────────────┬────────────────────────────────┘  │
│                                │  SandboxResult                     │
│                                ▼                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Gate 4: Approval Gate                  (if required)         │  │
│  │  auto   → LOW/MEDIUM auto-approve, HIGH/CRITICAL reject       │  │
│  │  cli    → interactive terminal prompt                         │  │
│  │  webhook → POST to Slack/PagerDuty/custom endpoint            │  │
│  └─────────────────────────────┬────────────────────────────────┘  │
│                                │  ApprovalResponse                  │
│                                ▼                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Gate 5: Executor + Rollback                                  │  │
│  │  BEGIN TRANSACTION                                            │  │
│  │    SAVEPOINT se_sp_<timestamp>                                │  │
│  │      EXECUTE sql                                              │  │
│  │      if rowsAffected > estimated * 1.5 → ROLLBACK            │  │
│  │    COMMIT                                                     │  │
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

---

## Design Principles

Inherited from [Modragor](https://github.com/sambaleuk/Modragor):

| Principle | Implementation |
|-----------|----------------|
| **Non-bypassable gates** | No `--force`, no `--skip`. `set -euo pipefail` equivalent at pipeline level |
| **Context injection curé** | Adapter only sees tables listed in `allowedTables`. Blocked tables are invisible |
| **Branchement par convention** | Tools connect via env vars + JSON config. No magic, no implicit wiring |
| **Source de vérité** | `config.json` + `policy.json` are the only source of truth. AJV-validated at startup |

---

## Quickstart

### 1. Install

```bash
npm install safe-executor pg
```

### 2. Create a config file

```json
// config/my-config.json
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

### 3. Copy the default policy

```bash
cp node_modules/safe-executor/config/default-policy.json ./config/default-policy.json
```

### 4. Run

```typescript
import { SafeExecutor } from 'safe-executor';

const executor = new SafeExecutor({
  configPath: './config/my-config.json',
});

// This will:
//   1. Parse the intent (DELETE + WHERE)
//   2. Match the `delete-with-where-dry-run` policy rule
//   3. Run a dry-run transaction to count affected rows
//   4. Prompt for CLI approval
//   5. Execute with savepoint protection
//   6. Write the audit entry

const result = await executor.run(
  'DELETE FROM sessions WHERE last_seen < NOW() - INTERVAL \'30 days\'',
  'ops-engineer-alice'
);

if (result.success) {
  console.log(`Deleted ${result.executionResult?.rowsAffected} rows`);
} else {
  console.error(`Aborted: ${result.abortReason}`);
}

await executor.close();
```

### What the CLI approval looks like

```
════════════════════════════════════════════════════════════
  SAFEEXECUTOR — APPROVAL REQUIRED
════════════════════════════════════════════════════════════
  Request ID : approval-1748000000-1
  Risk Level : HIGH
  Operation  : DELETE
  Tables     : sessions
  WHERE      : yes
  Est. Rows  : 142,831
  Warnings   :
    ⚠  Large operation: 142831 rows would be affected
  Policy     : DELETE with WHERE requires dry-run impact assessment.
────────────────────────────────────────────────────────────
  SQL:
  DELETE FROM sessions WHERE last_seen < NOW() - INTERVAL '30 days'
════════════════════════════════════════════════════════════
  Approve? [yes/no]: yes
  Your name/ID: alice
```

---

## Policy Rules

SafeExecutor ships with a default policy that covers the most dangerous PostgreSQL patterns.

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

### Writing custom rules

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

## Custom Adapters

SafeExecutor supports any database through the `DatabaseAdapter` interface:

```typescript
import type { DatabaseAdapter } from 'safe-executor';

export class MySQLAdapter implements DatabaseAdapter {
  readonly name = 'mysql';

  async ping() { /* ... */ }
  async explainQuery(sql) { /* ... */ }
  async explainAnalyzeQuery(sql) { /* ... */ }
  async runInDryRunTransaction(sql) { /* ... */ }
  async beginTransaction() { /* ... */ }
  async setSavepoint(name) { /* ... */ }
  async rollbackToSavepoint(name) { /* ... */ }
  async commitTransaction() { /* ... */ }
  async rollbackTransaction() { /* ... */ }
  async execute(sql) { /* ... */ }
  async close() { /* ... */ }
}

const executor = new SafeExecutor({
  configPath: './config.json',
  adapter: new MySQLAdapter('mysql://...'),
});
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
    "type": "DELETE",
    "tables": ["sessions"],
    "hasWhereClause": true,
    "estimatedRowsAffected": 142831,
    "isDestructive": true,
    "isMassive": true
  },
  "policyDecision": {
    "allowed": true,
    "riskLevel": "HIGH",
    "requiresDryRun": true,
    "requiresApproval": true,
    "message": "DELETE with WHERE requires dry-run impact assessment."
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

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SAFE_EXECUTOR_VERBOSE` | Set to `true` to log full JSON audit entries to console |

---

## Roadmap

See [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) for the full phased plan.

- [x] Phase 1 — Core pipeline + Intent Parser + Types
- [x] Phase 2 — Policy Engine + default PostgreSQL rules
- [x] Phase 3 — Sandbox / Dry-Run (PostgreSQL)
- [x] Phase 4 — Approval Gate (auto + CLI + webhook)
- [x] Phase 5 — Execution + automatic rollback
- [x] Phase 6 — Audit Trail
- [x] Phase 7 — Adapter system
- [ ] Phase 8 — Tests + full documentation
- [ ] MySQL adapter
- [ ] Slack webhook approval integration
- [ ] Web UI for approval queue
- [ ] `audit_log` table output
- [ ] Schema diff for ALTER operations

---

## License

MIT — see [LICENSE](./LICENSE)
