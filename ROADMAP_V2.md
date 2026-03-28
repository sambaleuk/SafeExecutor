# SafeExecutor v2 — Roadmap

## Vision

SafeExecutor v1 proved the 6-gate pipeline concept against PostgreSQL. v2 makes it a **generic safe execution framework for autonomous agents** — any domain (SQL, cloud infra, filesystem, APIs, CI/CD) plugs into the same non-bypassable pipeline.

The core pipeline (Intent → Policy → Sandbox → Approval → Executor → Audit) doesn't change. What changes is that "Intent" is no longer SQL-specific and "Adapter" is no longer database-specific.

---

## Architecture Change

### v1 (current)

```
SQL string → [SQL intent parser] → [policy] → [postgres sandbox] → [approval] → [postgres executor] → [audit]
```

### v2 (target)

```
raw operation → [domain adapter: parseIntent] → [policy engine] → [domain adapter: sandbox] → [approval] → [domain adapter: execute] → [audit]
                      ↑                                                                                                       ↑
              domain-specific parsing                                                                              domain-specific execution
```

The core pipeline is completely domain-agnostic. Each domain provides an `SafeAdapter` that handles parsing, sandboxing, execution, and rollback. The `SafeIntent` type becomes the universal language between the pipeline and the policy engine.

---

## Universal Intent Format (Phase 1)

Replaces `ParsedIntent` (SQL-specific) with `SafeIntent` (domain-agnostic):

```typescript
interface SafeIntent {
  domain: string;              // "sql", "cloud", "filesystem", "api", "cicd"
  operation: OperationType;    // "read", "write", "delete", "create", "modify", "destroy"
  target: Target;              // what we operate on
  scope: Scope;                // "single" | "batch" | "all"
  riskFactors: RiskFactor[];   // extracted risk signals
  rawOperation: string;        // original input verbatim
  ast?: unknown;               // domain-specific parsed representation
  metadata?: Record<string, unknown>; // domain-specific extra data
}

interface Target {
  name: string;                // primary resource name (table, bucket, file path, endpoint)
  type: string;                // resource type (table, s3_bucket, file, url, pipeline)
  affectedResources: string[]; // all resources touched (joins, dependencies)
  estimatedRows?: number;      // for SQL: row count estimate
}

type Scope = "single" | "batch" | "all";

interface RiskFactor {
  code: string;          // e.g. "NO_WHERE_CLAUSE", "DESTRUCTIVE_OP", "PROD_RESOURCE"
  severity: RiskLevel;   // LOW | MEDIUM | HIGH | CRITICAL
  description: string;
}
```

**Why this matters:** The policy engine currently pattern-matches on SQL-specific fields (`hasWhereClause`, `operationType` as SQL verbs). v2 policy rules use domain-agnostic fields — operation type, scope, risk factors, target name patterns — that work across all domains.

---

## Phase 1 — Universal Intent Format

**Goal:** Define `SafeIntent` as the lingua franca of the pipeline.

**Deliverables:**
- `src/types/index.ts` updated with `SafeIntent`, `Target`, `RiskFactor`, `Scope`
- `OperationType` generalized: `read | write | delete | create | modify | destroy | unknown`
- Policy engine updated to evaluate `SafeIntent` instead of `ParsedIntent`
- SQL adapter v1 updated to produce `SafeIntent` (wraps current `ParsedIntent`)
- Existing tests pass unchanged

**Status:** 🔲 Not started

---

## Phase 2 — Adapter System Refactor

**Goal:** Define the `SafeAdapter` interface that every domain must implement.

```typescript
interface SafeAdapter<TConfig = unknown> {
  readonly domain: string;

  // Parse raw operation into normalized SafeIntent
  parseIntent(raw: string, context?: AdapterContext): Promise<SafeIntent>;

  // Simulate the operation without side effects. Returns what WOULD happen.
  sandbox(intent: SafeIntent): Promise<SimulationResult>;

  // Execute the operation (called only after policy + approval pass)
  execute(intent: SafeIntent): Promise<ExecutionResult>;

  // Roll back the effect of a previous execute()
  rollback(intent: SafeIntent, snapshot: StateSnapshot): Promise<RollbackResult>;

  // Capture current state before execution (for rollback)
  snapshot(target: Target): Promise<StateSnapshot>;

  // Verify adapter is connected/ready
  ping(): Promise<void>;

  // Release resources
  close(): Promise<void>;
}
```

**Deliverables:**
- `src/adapters/adapter.interface.ts` — `SafeAdapter` interface (replaces `DatabaseAdapter`)
- `src/core/pipeline.ts` — updated to use `SafeAdapter` instead of `DatabaseAdapter`
- `src/adapters/sql/` — SQL adapter refactored to implement `SafeAdapter`
- Backward compatibility: `DatabaseAdapter` kept as alias/extends for migration period

**Status:** 🔲 Not started

---

## Phase 3 — SQL Adapter v2 (AST-based)

**Goal:** Replace regex-based SQL parser with `node-sql-parser` for accurate, deep SQL analysis.

**Current problem with regex parser:**
- False positives: `SELECT * FROM deleted_users` matches DELETE pattern
- Can't extract nested tables from subqueries, CTEs, JOINs
- Can't detect column-level operations (useful for PII detection later)
- Can't handle PostgreSQL-specific syntax reliably ($1 params, RETURNING, etc.)

**Solution: node-sql-parser**
- Full AST for PostgreSQL, MySQL, MariaDB, SQLite, T-SQL
- Handles CTEs (`WITH ... AS`), subqueries, JOINs, RETURNING
- Table extraction from ALL clauses, not just the first FROM
- Prepared statement parameters ($1, $2 in PostgreSQL)

**New capabilities from AST:**
```typescript
interface SQLIntent extends SafeIntent {
  ast: {
    type: string;              // SELECT | INSERT | UPDATE | DELETE | ...
    tables: SQLTable[];        // all tables across all clauses
    columns: SQLColumn[];      // columns touched
    whereClause: boolean;      // has WHERE
    whereColumns: string[];    // columns in WHERE (for PII detection)
    hasCTE: boolean;           // has WITH clause
    hasSubquery: boolean;      // has nested SELECT
    hasJoin: boolean;          // has JOIN
    isParameterized: boolean;  // uses $1/$2 placeholders
    affectedEstimate?: number; // from EXPLAIN
  };
}
```

**Risk classification from AST (not regex):**
| AST Node | Risk Factor | Severity |
|----------|-------------|----------|
| DELETE without WHERE | NO_WHERE_CLAUSE | CRITICAL |
| TRUNCATE | TRUNCATE_OP | CRITICAL |
| DROP | DROP_OP | CRITICAL |
| UPDATE without WHERE | NO_WHERE_CLAUSE_UPDATE | HIGH |
| ALTER | SCHEMA_CHANGE | HIGH |
| DELETE/UPDATE with WHERE | SCOPED_DESTRUCTIVE | MEDIUM |
| INSERT | INSERT_OP | LOW |
| SELECT | READ_OP | LOW |
| CTE with DML | NESTED_WRITE | HIGH |
| Subquery in DELETE | SUBQUERY_DELETE | HIGH |

**Fallback strategy:** If `node-sql-parser` throws (edge case, unsupported syntax), fall back to the current regex parser and flag `intent.metadata.parserFallback = true` so the policy engine can escalate risk.

**Deliverables:**
- `src/adapters/sql/parser.ts` — AST-based parser using `node-sql-parser`
- `src/adapters/sql/sandbox.ts` — existing sandbox logic moved here
- `src/adapters/sql/executor.ts` — existing executor logic moved here
- `src/adapters/sql/postgres.ts` — PostgreSQL connection adapter (currently `src/adapters/postgres.ts`)
- `src/adapters/sql/index.ts` — `SQLAdapter` class implementing `SafeAdapter`
- All existing e2e tests pass

**Status:** ✅ In progress (SQL parser + file restructure)

---

## Phase 4 — Cloud Infrastructure Adapter

**Goal:** Safe execution for Terraform and cloud resource operations.

**Supported operations:**
- `terraform plan` → parse JSON plan → `SafeIntent` (read)
- `terraform apply` → `SafeIntent` (write)
- `terraform destroy` → `SafeIntent` (destroy)

**Risk signals extracted from Terraform plan:**
- Resources being destroyed (`resource_changes[].change.actions = ["delete"]`)
- Resources being replaced (destroy + create)
- Sensitive resource types: RDS instances, IAM roles, security groups, VPCs
- Change count: modifying >10 resources in one apply is HIGH risk
- Production environment detection (naming patterns: `-prod`, `_production`)

**Sandbox:** `terraform plan --out=tfplan && terraform show -json tfplan` — shows exact changes without applying.

**Rollback:** `terraform state` manipulation or re-applying previous state snapshot. Note: not all Terraform changes are reversible; adapter must flag this clearly.

**Adapter interface:**
```typescript
class CloudAdapter implements SafeAdapter {
  domain = "cloud";
  async parseIntent(raw: string): Promise<SafeIntent>  // raw = terraform plan JSON
  async sandbox(intent: SafeIntent): Promise<SimulationResult>
  async execute(intent: SafeIntent): Promise<ExecutionResult>
  async rollback(intent: SafeIntent, snapshot: StateSnapshot): Promise<RollbackResult>
  async snapshot(target: Target): Promise<StateSnapshot>
}
```

**Files:**
```
src/adapters/cloud/
├── parser.ts         # Terraform plan JSON → SafeIntent
├── sandbox.ts        # terraform plan dry-run
├── executor.ts       # terraform apply execution
├── rollback.ts       # terraform state rollback
└── index.ts          # CloudAdapter class
```

**Status:** 🔲 Not started (separate PR)

---

## Phase 5 — Filesystem Adapter

**Goal:** Safe execution for shell filesystem operations.

**Supported operations:**
- `rm`, `rm -rf` → destroy
- `mv`, `cp` → write
- `chmod`, `chown` → modify
- `mkdir`, `touch` → create
- `ls`, `cat`, `find` → read

**Risk signals:**
- `rm -rf` + path is `/`, `~`, `/etc`, `/usr`, `/var` → CRITICAL
- `chmod 777` on system paths → HIGH
- Recursive operations on large directories → HIGH
- Operations outside working directory → MEDIUM
- Operations on hidden files (`.env`, `.ssh/`) → HIGH

**Sandbox:** Dry-run mode:
- `rm -i` simulation (list files that would be deleted)
- `cp -n` (no-overwrite check)
- `mv` to temp location first

**Snapshot:** File checksums + metadata before destructive operations. For directories: recursive checksum list.

**Rollback:** Restore from snapshot (copy back from temp location or restore checksum-verified backup).

**Files:**
```
src/adapters/filesystem/
├── parser.ts         # shell command → SafeIntent
├── sandbox.ts        # dry-run simulation
├── executor.ts       # actual execution
├── rollback.ts       # restore from snapshot
└── index.ts          # FilesystemAdapter class
```

**Status:** 🔲 Not started (separate PR)

---

## Phase 6 — API Adapter

**Goal:** Safe execution for external HTTP API calls from autonomous agents.

**Supported operations:**
- `GET` → read
- `POST` → write
- `PUT`, `PATCH` → modify
- `DELETE` → delete

**Risk signals:**
- DELETE method → HIGH by default
- POST/PUT/PATCH to production endpoints → MEDIUM
- Payload contains PII patterns (email, SSN, credit card regex) → HIGH
- Payload contains credential patterns (password, token, secret fields) → CRITICAL
- External domain not in allowlist → HIGH
- Rate limit context (N calls/minute to same endpoint) → MEDIUM

**Sandbox:** Route to a mock/staging endpoint if configured. Otherwise, simulate with request inspection only (no actual send).

**Rate limiting:** Built-in token bucket per endpoint. Configurable via policy.

**Files:**
```
src/adapters/api/
├── parser.ts         # HTTP request object → SafeIntent
├── sandbox.ts        # mock/staging routing
├── executor.ts       # actual HTTP call
├── pii-detector.ts   # payload scanning
└── index.ts          # APIAdapter class
```

**Status:** 🔲 Not started (separate PR)

---

## Phase 7 — CI/CD Adapter

**Goal:** Safe execution for deployment pipeline operations.

**Supported operations:**
- Build → read (no side effects on production)
- Deploy to staging → write
- Deploy to production → destroy-level (irreversible if something breaks)
- Rollback deployment → modify
- Cancel pipeline → modify

**Risk signals:**
- Target environment is `production` or `prod` → HIGH
- Skip tests flag → CRITICAL
- Force deploy (bypass health checks) → CRITICAL
- Canary percentage = 100% → HIGH
- No staging deploy in this release → HIGH

**Sandbox:** Trigger deploy to staging first and verify health checks before allowing production deploy.

**Rollback:** Re-trigger last stable deployment pipeline run.

**Files:**
```
src/adapters/cicd/
├── parser.ts         # pipeline config/trigger → SafeIntent
├── sandbox.ts        # staging deploy simulation
├── executor.ts       # pipeline trigger
├── rollback.ts       # revert to last stable
└── index.ts          # CICDAdapter class
```

**Status:** 🔲 Not started (separate PR)

---

## Phase 8 — Plugin System

**Goal:** Allow third parties to create and distribute SafeExecutor adapters as NPM packages.

**Adapter registration:**
```typescript
import { SafeExecutorPipeline } from "@safe-executor/core";
import { SQLAdapter } from "@safe-executor/sql";
import { MyCustomAdapter } from "./my-adapter";

const executor = new SafeExecutorPipeline({
  adapters: [
    new SQLAdapter({ connectionString: "..." }),
    new MyCustomAdapter({ ... }),
  ],
  policy: loadPolicy("./policy.json"),
  approval: { mode: "cli" },
  audit: { output: "file", filePath: "./audit.log" },
});

await executor.run("sql", "DELETE FROM users WHERE id = 42");
await executor.run("filesystem", "rm -rf ./temp");
```

**NPM packages planned:**
- `@safe-executor/core` — pipeline, policy engine, approval, audit (no adapters)
- `@safe-executor/sql` — SQL adapter with node-sql-parser
- `@safe-executor/cloud` — Terraform/cloud adapter
- `@safe-executor/filesystem` — shell filesystem adapter
- `@safe-executor/api` — HTTP API adapter
- `@safe-executor/cicd` — CI/CD adapter

**Plugin interface:**
```typescript
interface SafeAdapterPlugin {
  name: string;                    // package name
  version: string;                 // semver
  adapter: new (...args: unknown[]) => SafeAdapter;
  defaultPolicy?: PolicyRule[];    // domain-specific default rules
  configSchema?: JSONSchema;       // AJV-validated adapter config
}
```

**Status:** 🔲 Not started (separate PR)

---

## Current Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Universal Intent Format | 🔲 Pending |
| 2 | SafeAdapter interface | 🔲 Pending |
| 3 | SQL Adapter v2 (AST parser) | ✅ In progress |
| 4 | Cloud Infrastructure Adapter | 🔲 Pending |
| 5 | Filesystem Adapter | 🔲 Pending |
| 6 | API Adapter | 🔲 Pending |
| 7 | CI/CD Adapter | 🔲 Pending |
| 8 | Plugin System + NPM packages | 🔲 Pending |

**This PR covers:** Phase 3 (SQL Adapter v2 with AST parser) + code restructure to support Phases 1-8.

---

## Migration Guide (v1 → v2)

### Breaking changes

1. **`ParsedIntent` → `SafeIntent`**: The intent type is now domain-agnostic. SQL-specific fields move to `intent.ast`.
2. **`DatabaseAdapter` → `SafeAdapter`**: The adapter interface is generalized. Existing PostgreSQL adapter implements the new interface.
3. **File structure**: `src/core/intent-parser.ts` → `src/adapters/sql/parser.ts`. The public API (`SafeExecutor` class in `src/index.ts`) is unchanged.

### Non-breaking

- Policy rule format unchanged (rules match on `operationType` which maps to new values)
- Approval gate unchanged
- Audit trail schema unchanged (entry structure extended, not modified)
- Config file format unchanged for SQL usage
- `SafeExecutor` class public API unchanged

---

## Design Decisions

### Why normalize to `SafeIntent` instead of keeping domain-specific types?

The policy engine needs a common type to evaluate. If every domain has its own intent type, the policy engine needs domain-specific logic — defeating the purpose of a generic framework. `SafeIntent` is the minimal normalized representation that the policy engine can reason about universally.

### Why keep `ast` as `unknown` in `SafeIntent`?

The AST is domain-specific and opaque to the pipeline core. Only the adapter that produced it can interpret it (for sandbox and execution). The policy engine only uses top-level `SafeIntent` fields. This keeps the core truly domain-agnostic.

### Why AST-based SQL parsing instead of regex?

Regex SQL parsing has a fundamental problem: SQL is not a regular language. CTEs, nested subqueries, function calls, and quoted identifiers all break regex assumptions. `node-sql-parser` gives us a proper parse tree, enabling accurate table extraction, risk classification, and future column-level analysis (PII detection, sensitive column flagging).

### Why fallback to regex on parser failure?

`node-sql-parser` covers >99% of standard SQL but may fail on exotic syntax (custom PL/pgSQL, unusual casts, vendor extensions). In these cases, we fall back to the regex parser with elevated risk (`parserFallback: true`) rather than rejecting the query or crashing. The policy engine can be configured to treat fallback cases as HIGH risk.
