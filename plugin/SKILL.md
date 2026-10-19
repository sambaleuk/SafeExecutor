# SafeExecutor — Claude Code Skill

## Purpose
SafeExecutor classifies a command's risk before you run it and returns a BLOCKED / ALLOWED verdict. It does not execute anything and cannot stop you: following these rules is what makes it a guardrail. Use these tools before running any destructive or sensitive operation.

## When to use

Before executing ANY of the following, call `safe_analyze` first:
- SQL queries that modify data (`INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `DROP`)
- Shell commands that delete or overwrite files (`rm`, `dd`, `chmod`, `mv`)
- Kubernetes commands that delete or scale resources (`kubectl delete`, `kubectl drain`)
- Cloud CLI commands that destroy infrastructure (`terraform destroy`, `aws s3 rm`)
- Secret access commands (`vault kv get`, `aws secretsmanager get-secret-value`)
- Network commands that modify firewall rules (`iptables`, `ufw`)

## Tools available

### `safe_analyze`
Analyze a command for risk without any execution. Always call this first.

```json
{
  "command": "DELETE FROM users WHERE created_at < '2020-01-01'",
  "domain": "sql"
}
```

Returns: `{ domain, riskLevel, operation, targets, policy_decision, blocked, reason, note }`

### `safe_execute`
Same as `safe_analyze` but signals intent to execute. Use when you need SafeExecutor's policy decision before proceeding.

### `safe_policy_check`
Quick yes/no policy check. Use when you only need to know if an operation is allowed.

## Rules

1. **Never skip the check** — if `blocked: true` or `policy_decision: "BLOCKED"`, do NOT proceed.
2. **Show the analysis to the user** before running any high-risk operation.
3. **Respect the risk levels**: `CRITICAL` and `HIGH` are blocked; `MEDIUM` requires user confirmation; `LOW` can proceed.
4. **Unrecognized commands are blocked** (fail-closed). If a harmless command is blocked only because it is unrecognized (`domain: "unknown"`), ask the user before running it.
5. **Send the whole command line.** Chains and wrappers (`&&`, `;`, `|`, `sudo`, `bash -c`, `psql -c`) are split and every part is checked. The `domain` parameter only adds a parser; it never lowers the verdict.
