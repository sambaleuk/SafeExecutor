# SafeExecutor

![License](https://img.shields.io/badge/license-MIT-lightgrey)

**A gate-enforced execution layer for operations an AI agent wants to run on sensitive systems.**

An agent proposes an operation; SafeExecutor parses it, checks it against a policy, dry-runs it when the policy asks for it, routes it for approval, executes it with rollback protection, and writes an audit entry, or refuses with a reason at the first gate that fails.

> Status: v0.1.0, **not published on npm** — install from source. The SQL/PostgreSQL path is the most complete and the only one exercised end-to-end against a live database (Supabase Postgres, see [TESTING_REPORT.md](TESTING_REPORT.md)). Other domains are covered by unit tests.
>
> Inspired by [Modragor](https://github.com/sambaleuk/Modragor), a model-driven agent orchestrator.

---

## Two entry points

| | Library pipeline (`SafeExecutor`) | MCP server (`safe-executor-mcp`) |
|---|---|---|
| What it does | Runs the 6 gates, **executes** the operation if every gate passes | **Classifies** a command and returns `BLOCKED` / `ALLOWED`; never executes |
| Domains | SQL/PostgreSQL built in; any `SafeAdapter` via `options.adapter` | sql, filesystem, git, kubernetes, cloud, cicd, api, secrets, network, queue |
| Decision source | JSON policy (`config/default-policy.json`) | Per-domain parsers and risk factors, fail-closed |

---

## Library pipeline

```
raw operation
  → 1. Intent parser     adapter.parseIntent()  → SafeIntent (type, tables, WHERE, risk factors, statement count)
  → 2. Policy engine     JSON rules             → allow / deny / require_dry_run / require_approval
  → 3. Sandbox           adapter.sandbox()      → dry-run, only when the policy requires it
  → 4. Approval gate     auto / cli / webhook   → only when the policy requires it
  → 5. Executor          adapter.execute()      → transaction + savepoint, rollback on threshold breach
  → 6. Audit trail       JSON entry (console or file), written for completed and aborted runs
```

| Gate | Behavior (SQL adapter) |
|---|---|
| Intent parser | AST via `node-sql-parser` (PostgreSQL dialect), regex fallback for syntax it cannot parse. **Every statement** is evaluated; the most dangerous one drives the intent. |
| Policy engine | Rules match on operation type, WHERE presence, table name patterns and estimated rows. No match → `defaults.allowUnknown` (false in the default policy). More than one statement → denied unless `defaults.allowMultiStatement` is true. |
| Sandbox | DML runs inside `BEGIN … ROLLBACK` to count affected rows; `ALTER`/`CREATE` use `EXPLAIN`; `DROP`/`TRUNCATE` cannot be dry-run and go straight to approval. |
| Approval | `auto` approves LOW/MEDIUM and rejects HIGH/CRITICAL; `cli` prompts in the terminal; `webhook` posts and polls. |
| Executor | Runs in a transaction with a savepoint; rolls back if rows affected exceed 1.5× the dry-run estimate or `database.maxRowsThreshold`. |
| Audit | One JSON record per run with intent, policy decision, sandbox, approval and execution results. |

### Usage

```bash
git clone https://github.com/sambaleuk/SafeExecutor.git
cd SafeExecutor
npm ci
npm run build
npm test            # Jest suite, no database required
```

From another project: `npm install /path/to/SafeExecutor`, then:

```typescript
import { SafeExecutor } from 'safe-executor';

// config/example-config.json holds "${SAFE_EXECUTOR_DATABASE_URL}" instead of a
// connection string; loadConfig resolves it from the environment and fails if unset.
const executor = new SafeExecutor({ configPath: './config/example-config.json' });

const result = await executor.run('DELETE FROM users');
// result.success     === false
// result.abortReason === 'Policy denied: DELETE without WHERE clause is not allowed. ...'

await executor.close();
```

`run()` pings the database before the pipeline starts, so a reachable PostgreSQL is required even for operations that will be refused.

Outcomes with `config/default-policy.json` and `approval.mode: "auto"` (from a run against an in-memory database adapter that records what it is asked to execute):

| Operation | Policy | Outcome | Sent to the database |
|---|---|---|---|
| `DELETE FROM users` | denied, CRITICAL | aborted at gate 2 | nothing |
| `SELECT 1; DROP TABLE users` | denied, CRITICAL (2 statements) | aborted at gate 2 | nothing |
| `DROP TABLE users` | requires approval, CRITICAL | rejected at gate 4 (auto mode never approves CRITICAL) | nothing |
| `UPDATE users SET active = false WHERE id = 42` | dry-run required, MEDIUM | dry-run, auto-approved, executed | the UPDATE |
| `SELECT id FROM users WHERE id = 1` | allowed, LOW | executed | the SELECT |

### Policy rules

Rules live in a JSON file validated against [schemas/policy.schema.json](schemas/policy.schema.json). From `config/default-policy.json`:

```json
{
  "id": "deny-delete-no-where",
  "description": "Deny DELETE without WHERE clause — too dangerous",
  "match": { "operationType": ["DELETE"], "hasWhereClause": false },
  "action": "deny",
  "riskLevel": "CRITICAL",
  "message": "DELETE without WHERE clause is not allowed. Add a WHERE condition or use TRUNCATE with explicit approval."
}
```

All matching rules apply: risk only escalates, any `deny` wins, and CRITICAL always forces dry-run plus approval.

### Other domains

`SafeExecutor` builds the SQL adapter from `config.database`. To drive another system, pass an object implementing `SafeAdapter` (`domain`, `ping`, `parseIntent`, `sandbox`, `execute`, `close`) as `options.adapter`. The package exports `SQLAdapter`, `CloudAdapter`, `KubernetesAdapter`, `FilesystemAdapter`, `SecretsAdapter` and `GitAdapter`; the non-SQL adapters run their CLI through child processes. Two caveats: the policy schema matches on SQL operation types, so a non-SQL adapter needs a policy written for the intent types it emits, and the config schema still requires a `database` block.

---

## MCP server

The MCP server exposes the domain parsers as analysis tools. It **does not execute anything**: it tells the calling agent whether a command should run.

```bash
npm run build
node dist/bin/safe-executor-mcp.js      # MCP over stdio
```

Register it with Claude Code in `.mcp.json` (absolute path to your checkout):

```json
{
  "mcpServers": {
    "safe-executor": {
      "command": "node",
      "args": ["/path/to/SafeExecutor/dist/bin/safe-executor-mcp.js"]
    }
  }
}
```

| Tool | Returns |
|---|---|
| `safe_execute` | `domain, operation, targets, riskLevel, blocked, reason, segments, policy_decision`. Despite the name, it only classifies. |
| `safe_analyze` | Same, plus `note: "Analysis only — no execution performed"` |
| `safe_policy_check` | `{ allowed, risk, domain, reason }` |

How a command is judged:

- **Shell structure first.** Unquoted `&&`, `||`, `;`, `|`, `&` and newlines split the command; `sudo`, `doas`, `env`, `nohup`, `time`, `exec`, `nice` and `VAR=value` prefixes are peeled off; `sh/bash -c '…'` and `env -S` scripts are expanded; `psql -c` / `mysql -e` payloads go to the SQL parser. Every segment is analyzed and the worst one decides.
- **Fail-closed.** A segment no parser recognizes is `BLOCKED`, as is a parser error, command substitution (`$(…)`, backticks, `<(…)`), or shell nesting deeper than 4 levels.
- **HIGH and CRITICAL are blocked.** LOW and MEDIUM are allowed.
- **The `domain` argument can only add scrutiny.** The auto-detected domain is always evaluated too, so `safe_execute("rm -rf /", domain: "sql")` is still blocked.

Verdicts from `safe_execute`:

| Command | Verdict |
|---|---|
| `sudo rm -rf /` · `cd /tmp && rm -rf /` · `bash -c "rm -rf /"` | BLOCKED, CRITICAL (filesystem) |
| `psql -c "DROP TABLE users"` · `SELECT 1; DROP TABLE users` | BLOCKED, CRITICAL (sql) |
| `python3 -c "import shutil; shutil.rmtree('/')"` · `ls -la` | BLOCKED, HIGH (unrecognized) |
| `git push --force origin main` · `kubectl delete namespace production` · `terraform destroy` | BLOCKED, CRITICAL |
| `docker run --privileged -v /:/host alpine` · `iptables -F` · `redis-cli FLUSHALL` | BLOCKED, CRITICAL |
| `git status` · `kubectl get pods` · `aws s3 ls` · `SELECT id FROM users WHERE id = 1` | ALLOWED, LOW |

Reproduce any line after a build:

```bash
node --input-type=module -e "import { safePolicyCheck } from './dist/mcp-server/tools.js'; console.log(await safePolicyCheck('cd /tmp && rm -rf /'))"
```

### Claude Code plugin: advisory, not enforcement

`plugin/` contains `manifest.json` (points an MCP client at `dist/bin/safe-executor-mcp.js`) and `SKILL.md` (tells the model to call `safe_analyze` before destructive commands and to stop on `BLOCKED`). This is guidance for the model: nothing prevents it from running a command without calling the tool. Enforcement before execution needs a Claude Code `PreToolUse` hook.

---

## Performance

From [BENCHMARK_REPORT.md](BENCHMARK_REPORT.md): a single run on 2026-03-28, Apple M2, against a remote Supabase PostgreSQL, 15 runs per case.

| Path | Cost |
|---|---|
| Refused at the policy gate (e.g. `DELETE` without `WHERE`) | **0.12 ms** mean; no database round-trip after the gate |
| In-process gates (parse + policy + approval + audit) on any path | **~0.30 ms** |
| Allowed `SELECT`, end-to-end vs a direct `pg` query | **+81 ms**, dominated by 3 extra transaction round-trips (BEGIN, SAVEPOINT, COMMIT) at ~90 ms RTT |

The throughput figure in the report (7,273 req/s) measures 20 refusals only, not executed operations. `tests/benchmark.ts` predates the `SafeAdapter` refactor and no longer compiles against the current API; treat these numbers as indicative until it is updated.

---

## Limitations

- **Not on npm.** Install from source as above.
- **MCP analysis is advisory** unless a pre-execution hook enforces it; the plugin alone does not.
- **Fail-closed has a cost.** The MCP tools block every command they do not recognize, including harmless ones (`ls`, `cat`, `npm test`).
- **Parsers are heuristics.** Examples: `aws secretsmanager get-secret-value --secret-id prod/db` is classified LOW and allowed; `kafka-topics.sh --list` is classified HIGH and blocked.
- **Library pipeline is SQL-first.** See [Other domains](#other-domains). `database.allowedTables` / `blockedTables` are accepted by the config schema but not enforced yet.

---

## Project layout

```
src/
├── index.ts                 # SafeExecutor class + public exports
├── core/                    # pipeline.ts, policy-engine.ts, approval-gate.ts, audit.ts
├── config/loader.ts         # JSON Schema validation, ${ENV_VAR} resolution
├── adapters/
│   ├── adapter.interface.ts # SafeAdapter, DatabaseAdapter
│   ├── sql/                 # AST parser, sandbox, executor, PostgreSQL driver
│   └── <domain>/            # parser, sandbox, adapter for cloud, kubernetes, filesystem,
│                            # git, secrets, cicd, network, queue, api
├── mcp-server/              # index.ts (server), tools.ts, auto-detect.ts, command-segments.ts
└── bin/safe-executor-mcp.ts # stdio entry point → dist/bin/safe-executor-mcp.js
config/                      # default-policy.json, policies/<domain>-default-policy.json, example configs
schemas/                     # config, policy and audit JSON Schemas
plugin/                      # manifest.json + SKILL.md
tests/                       # Jest suites (*.test.ts); e2e-neubooks.ts and benchmark.ts need a live database
```

Database-backed scripts read the connection string from `SAFE_EXECUTOR_DATABASE_URL`; no credential is stored in the repository.

---

## License

MIT
