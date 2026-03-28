# SafeExecutor Plugin for Claude Code

Policy-enforced safety harness that analyzes and gates dangerous operations before execution. Covers 10 domains: SQL, cloud, Kubernetes, filesystem, CI/CD, API, secrets, git, network, and queues.

## Installation

### Option 1: Claude Code MCP Configuration

Add to your Claude Code settings (`~/.claude/settings.json` or project `.claude/settings.json`):

```json
{
  "mcpServers": {
    "safe-executor": {
      "command": "npx",
      "args": ["safe-executor", "--mcp"]
    }
  }
}
```

### Option 2: Install as Plugin

Copy the `plugin/` directory to your Claude Code plugins location, or reference it directly:

```json
{
  "plugins": [
    {
      "path": "./node_modules/safe-executor/plugin"
    }
  ]
}
```

### Option 3: NPM Package

```bash
npm install safe-executor
```

Then use programmatically:

```typescript
import { createServer } from 'safe-executor/mcp-server';

const server = createServer();
// Connect to your transport...
```

## Available Tools

| Tool | Description |
|------|-------------|
| `safe_execute` | Full pipeline analysis with risk assessment and policy decision |
| `safe_analyze` | Analyze without executing — returns intent, risk, and policy |
| `safe_policy_check` | Quick allow/deny/require_approval check |
| `configure_policy` | Add, remove, or replace policy rules at runtime |

## How It Works

1. **Auto-detection**: Identifies the domain (SQL, cloud, k8s, etc.) from command syntax
2. **Intent parsing**: Extracts structured intent using domain-specific parsers
3. **Risk assessment**: Evaluates risk factors (destructive ops, missing WHERE clauses, etc.)
4. **Policy evaluation**: Checks against configurable rules to determine allow/deny/require_approval
5. **Response**: Returns the decision with full context for the LLM to act on

## Supported Domains

- **SQL**: SELECT, INSERT, UPDATE, DELETE, DROP, TRUNCATE, ALTER, CREATE
- **Cloud**: Terraform, AWS CLI, GCP gcloud, Azure CLI, Pulumi
- **Kubernetes**: kubectl, helm
- **Filesystem**: rm, cp, mv, chmod, chown, mkdir, rmdir, ln, touch, find
- **CI/CD**: GitHub Actions, GitLab CI, Jenkins, CircleCI, ArgoCD
- **API**: curl, wget, HTTP method + URL
- **Secrets**: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager
- **Git**: All git commands
- **Network**: iptables, ufw, ip, route, ssh, nmap, netcat, ping, traceroute
- **Queue**: AWS SQS/SNS, GCP Pub/Sub, RabbitMQ, Celery
