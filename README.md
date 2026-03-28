# SafeExecutor

![Tests](https://img.shields.io/badge/tests-1279%20passing-brightgreen)
![Adapters](https://img.shields.io/badge/adapters-10-blue)
![Policy Rules](https://img.shields.io/badge/policy%20rules-~100-orange)
![Overhead](https://img.shields.io/badge/overhead-0.30ms-green)
![Throughput](https://img.shields.io/badge/throughput-7273%20req%2Fs-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

**A universal safe execution framework for autonomous AI agents.**

SafeExecutor intercepts and evaluates **any** operation before execution — SQL queries, shell commands, cloud infrastructure changes, Kubernetes operations, API calls, CI/CD deployments, secret access, git operations, network configuration, and message queue operations. Every action passes through a 6-gate pipeline before it runs.

> Inspired by [Modragor](https://github.com/sambaleuk/Modragor), a model-driven agent orchestrator.

---

## Why SafeExecutor

AI agents are increasingly capable of taking real-world actions: running SQL, calling APIs, managing infrastructure, pushing code. A single wrong command can drop a production table, flush a Redis cache, or force-push over main. SafeExecutor puts a policy-enforced safety layer between the agent and the world.

```
Agent intent  →  SafeExecutor  →  Safe execution (or rejection with reason)
```

Tested in production against **NeuBooks** (PostgreSQL/Supabase). Benchmarked at **0.30ms** business logic overhead and **7273 req/s** for blocking dangerous commands.

---

## Pipeline

Every operation passes through 6 gates:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     SafeExecutor Pipeline                           │
│                                                                     │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐   │
│  │ 1. Intent    │──▶│ 2. Policy    │──▶│ 3. Sandbox / Dry-Run │   │
│  │    Parser    │   │    Engine    │   │                      │   │
│  └──────────────┘   └──────────────┘   └──────────────────────┘   │
│                                                  │                  │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐   │
│  │ 6. Audit     │◀──│ 5. Execution │◀──│ 4. Approval Gate     │   │
│  │    Trail     │   │  + Rollback  │   │                      │   │
│  └──────────────┘   └──────────────┘   └──────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

| Gate | What it does |
|---|---|
| **Intent Parser** | Parses the raw operation into a structured intent (type, target, risk level) |
| **Policy Engine** | Evaluates ~100 rules across all domains — blocks, warns, or allows |
| **Sandbox / Dry-Run** | Simulates the operation without side effects when possible |
| **Approval Gate** | Routes high-risk operations to a human approval queue |
| **Execution + Rollback** | Executes with rollback hooks for reversible operations |
| **Audit Trail** | Logs every decision with full context for compliance |

---

## 10 Adapters

### 1. SQL
AST-based parser using `node-sql-parser`. Understands query structure, not just patterns.

| Blocks | Allows |
|---|---|
| `DELETE` without `WHERE` | `DELETE FROM orders WHERE id = 42` |
| `DROP TABLE` | `SELECT *` with row limits |
| `TRUNCATE` | `INSERT` with validated columns |

### 2. Cloud (Terraform / AWS / GCP / Azure)

| Blocks | Allows |
|---|---|
| `terraform destroy` without `-target` | Scoped infrastructure changes |
| VPC deletion | Read-only describe/list operations |
| IAM policy modifications | Tagged resource creation |

### 3. Kubernetes

| Blocks | Allows |
|---|---|
| `delete namespace` | Operations on non-prod namespaces |
| Scale to 0 replicas in prod | Dry-run applies |
| `kubectl exec` in prod | `kubectl get` / `kubectl describe` |

### 4. Filesystem
Shell command analysis for destructive patterns.

| Blocks | Allows |
|---|---|
| `rm -rf /` | Scoped file operations |
| `chmod 777` | Permission changes on non-critical paths |
| `dd` to block devices | Safe data operations |

### 5. CI/CD (Docker / GitHub Actions)

| Blocks | Allows |
|---|---|
| `docker run --privileged` | Standard container runs |
| Mount root filesystem | Scoped volume mounts |
| Deploy to prod without image tag | Tagged, reviewed deployments |

### 6. API / HTTP

| Blocks | Allows |
|---|---|
| Credentials in URL | Authenticated requests via headers |
| Bulk DELETE operations | Standard CRUD with pagination |
| Sensitive data in request bodies | Validated payloads |

### 7. Secrets (Vault / AWS SM / SSM / GCP / Azure KV)

| Blocks | Allows |
|---|---|
| Plaintext secrets in operations | Vault path references |
| Export all secrets | Scoped, per-secret reads |
| `kubectl get secret -o yaml` | Managed secret injection |

### 8. Git

| Blocks | Allows |
|---|---|
| `git push --force` to main | Force push to feature branches |
| `git reset --hard` | Safe resets on local branches |
| `filter-branch` on shared refs | Local history rewriting |

### 9. Network (iptables / ufw / routes)

| Blocks | Allows |
|---|---|
| Flush all firewall rules | Scoped rule additions |
| `ufw disable` | Status checks |
| Remove default gateway | Non-critical route changes |

### 10. Message Queue (Kafka / RabbitMQ / Redis / SQS)

| Blocks | Allows |
|---|---|
| Purge queue in prod | Consume with explicit offset |
| `FLUSHALL` (Redis) | Scoped key deletions |
| Delete topic with active consumers | Pause/throttle operations |

---

## Installation

### Option 1 — Claude Code Plugin

Copy the plugin directory into your Claude Code configuration:

```bash
cp -r plugin/ ~/.claude/plugins/safe-executor
```

The plugin adds SafeExecutor as a pre-execution hook for all tool calls inside Claude Code.

### Option 2 — MCP Server

Run as an MCP server that exposes 3 tools to any MCP-compatible client:

```bash
npx safe-executor-mcp
```

**Available MCP tools:**

| Tool | Description |
|---|---|
| `safe_execute` | Execute an operation through the full safety pipeline |
| `safe_analyze` | Analyze an operation and return risk assessment without executing |
| `safe_policy_check` | Check if an operation would be allowed under current policy |

Add to your MCP config:

```json
{
  "mcpServers": {
    "safe-executor": {
      "command": "npx",
      "args": ["safe-executor-mcp"]
    }
  }
}
```

### Option 3 — NPM Package

```bash
npm install safe-executor
```

```typescript
import { SafeExecutor } from 'safe-executor';

const executor = new SafeExecutor({
  adapters: ['sql', 'filesystem', 'git'],
  policy: 'strict',
  audit: true,
});

const result = await executor.execute({
  type: 'sql',
  operation: 'DELETE FROM users',
  context: { environment: 'production' },
});

// result.allowed === false
// result.reason === 'DELETE without WHERE clause is not allowed in production'
```

---

## Quick Start Examples

### Blocking a dangerous SQL query

```typescript
const result = await executor.execute({
  type: 'sql',
  operation: 'TRUNCATE TABLE orders',
  context: { environment: 'production', database: 'neubooks' },
});

console.log(result);
// {
//   allowed: false,
//   risk: 'critical',
//   reason: 'TRUNCATE is not allowed — use DELETE with WHERE or archive pattern',
//   adapter: 'sql',
//   duration: 0.28
// }
```

### Analyzing a Kubernetes operation

```typescript
const analysis = await executor.analyze({
  type: 'kubernetes',
  operation: 'kubectl delete namespace staging',
  context: { cluster: 'prod-eu-west' },
});

console.log(analysis.riskLevel);    // 'high'
console.log(analysis.matchedRules); // ['no-namespace-delete-prod', ...]
```

### Checking policy before acting

```typescript
const check = await executor.policyCheck({
  type: 'git',
  operation: 'git push --force origin main',
});

console.log(check.allowed);   // false
console.log(check.blockedBy); // 'no-force-push-protected-branches'
```

### MCP usage (Claude Code)

```
User:   Delete all test records from the users table in production

Claude: I'll use safe_analyze first to assess the risk.

        [safe_analyze] → risk: critical, blocked: DELETE without WHERE

        This operation is blocked. The SQL adapter requires a WHERE clause
        for all DELETE statements in production. Should I scope it to a
        specific condition?
```

---

## Configuration

### Policy file (`safe-executor.config.json`)

```json
{
  "adapters": {
    "sql": {
      "enabled": true,
      "strictMode": true,
      "allowedEnvironments": ["development", "staging"],
      "rules": {
        "no-delete-without-where": "block",
        "no-drop-table": "block",
        "no-truncate": "block",
        "select-row-limit": "warn"
      }
    },
    "git": {
      "enabled": true,
      "protectedBranches": ["main", "master", "production"],
      "rules": {
        "no-force-push-protected": "block",
        "no-reset-hard-shared": "block"
      }
    },
    "kubernetes": {
      "enabled": true,
      "productionNamespaces": ["prod", "production", "prod-*"],
      "rules": {
        "no-delete-namespace": "block",
        "no-scale-to-zero-prod": "block",
        "no-exec-prod": "require-approval"
      }
    }
  },
  "global": {
    "auditLog": true,
    "auditPath": "./logs/safe-executor-audit.jsonl",
    "approvalWebhook": "https://your-approval-endpoint/approve",
    "defaultRisk": "warn"
  }
}
```

### Rule severity levels

| Level | Behavior |
|---|---|
| `block` | Operation rejected immediately with reason |
| `warn` | Operation proceeds, warning logged to audit trail |
| `require-approval` | Operation queued, waits for human approval via webhook |
| `allow` | Operation proceeds silently |

### Environment-aware policies

Rules can be scoped to environments:

```json
{
  "rules": {
    "no-truncate": {
      "production": "block",
      "staging": "warn",
      "development": "allow"
    }
  }
}
```

---

## Performance

Measured on Apple M-series hardware:

| Metric | Value |
|---|---|
| Business logic overhead | **0.30ms** |
| Throughput (blocking dangerous commands) | **7273 req/s** |
| Test suite | **1,279 tests passing** |
| Policy rules | **~100 across all adapters** |

---

## Architecture

```
src/
├── core/
│   ├── executor.ts          # Main SafeExecutor class
│   ├── pipeline.ts          # 6-gate pipeline orchestration
│   ├── policy-engine.ts     # Rule evaluation engine
│   └── audit.ts             # Audit trail writer
├── adapters/
│   ├── sql/                 # AST-based SQL analysis
│   ├── cloud/               # Terraform/AWS/GCP/Azure
│   ├── kubernetes/          # kubectl/Helm
│   ├── filesystem/          # Shell command analysis
│   ├── cicd/                # Docker/GitHub Actions
│   ├── api/                 # REST/HTTP
│   ├── secrets/             # Vault/AWS SM/SSM/GCP/Azure KV
│   ├── git/                 # Git operations
│   ├── network/             # iptables/ufw/routes
│   └── queue/               # Kafka/RabbitMQ/Redis/SQS
├── mcp/
│   └── server.ts            # MCP server (safe_execute, safe_analyze, safe_policy_check)
└── plugin/
    └── claude-code/         # Claude Code plugin
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-adapter`
3. Add your adapter in `src/adapters/your-domain/`
4. Follow the existing adapter interface:

```typescript
export interface Adapter {
  name: string;
  analyze(operation: Operation, context: Context): Promise<AnalysisResult>;
  execute(operation: Operation, context: Context): Promise<ExecutionResult>;
}
```

5. Add tests — the bar is high (existing suite: 1,279 tests)
6. Open a PR against `main`

### Adding a new policy rule

Rules live in `src/adapters/<domain>/rules/`. Each rule is a function:

```typescript
export const noDeleteWithoutWhere: Rule = {
  id: 'no-delete-without-where',
  description: 'DELETE statements must include a WHERE clause',
  severity: 'block',
  match: (op: ParsedSQL) => op.type === 'delete' && !op.where,
  reason: (op: ParsedSQL) => `DELETE on ${op.table} without WHERE would affect all rows`,
};
```

---

## License

MIT
