# SafeExecutor MCP Plugin

Safe execution guardrails for autonomous AI agents — powered by [SafeExecutor](https://github.com/sambaleuk/SafeExecutor).

## Install

```bash
npm install -g safe-executor
```

## Add to Claude Code

Add to your `.claude/settings.json`:

```json
{
  "mcpServers": {
    "safe-executor": {
      "command": "safe-executor-mcp"
    }
  }
}
```

Or run the server directly:

```bash
npx safe-executor-mcp
```

## Tools

| Tool | Description |
|------|-------------|
| `safe_execute` | Parse + classify a command, return policy decision |
| `safe_analyze` | Same as `safe_execute` but explicitly analysis-only |
| `safe_policy_check` | Quick allowed/blocked check |

## Supported Domains

`sql` · `git` · `kubernetes` · `cloud` · `cicd` · `secrets` · `network` · `queue` · `api` · `filesystem`

## Example

```bash
# Ask Claude to check a command
safe_analyze "DELETE FROM users WHERE id = 1"
# → { domain: "sql", riskLevel: "high", blocked: true, ... }
```

## License

MIT
