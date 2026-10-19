# SafeExecutor MCP Plugin

Risk classification for commands an AI agent is about to run, exposed as MCP tools by [SafeExecutor](https://github.com/sambaleuk/SafeExecutor).

The tools analyze; they never execute. This directory is guidance for the model (`SKILL.md`) plus a server manifest: it does not stop a command the model decides to run without asking. For enforcement, also install the `PreToolUse` hook (`dist/bin/safe-executor-hook.js`) described in the main README.

## Install

SafeExecutor is not published on npm. Build it from source:

```bash
git clone https://github.com/sambaleuk/SafeExecutor.git
cd SafeExecutor
npm ci
npm run build
```

## Add to Claude Code

In `.mcp.json` (absolute path to your checkout):

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

## Tools

| Tool | Description |
|------|-------------|
| `safe_execute` | Classify a command and return a `BLOCKED` / `ALLOWED` verdict (does not execute) |
| `safe_analyze` | Same as `safe_execute`, marked analysis-only |
| `safe_policy_check` | Quick `{ allowed, risk, domain, reason }` |

## Supported domains

`sql` · `git` · `kubernetes` · `cloud` · `cicd` · `secrets` · `network` · `queue` · `api` · `filesystem`

Commands outside these domains are blocked (fail-closed). Chains and wrappers (`&&`, `;`, `|`, `sudo`, `env`, `bash -c`, `psql -c`) are split and every segment is checked.

## Example

```
safe_policy_check { "command": "cd /tmp && rm -rf /" }
→ { "allowed": false, "risk": "CRITICAL", "domain": "filesystem", ... }

safe_policy_check { "command": "DELETE FROM users" }
→ { "allowed": false, "risk": "CRITICAL", "domain": "sql", ... }
```

## License

MIT
