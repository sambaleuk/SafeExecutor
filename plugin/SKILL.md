# SafeExecutor — Claude Code Skill

## Purpose
SafeExecutor intercepts dangerous commands before execution and enforces policy-based guardrails. Use these tools before running any destructive or sensitive operation.

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
3. **Respect the risk levels**: `critical` and `high` are blocked by default; `medium` requires user confirmation; `low` and `safe` can proceed automatically.
4. **Domain auto-detection** works for most commands. Override with the `domain` parameter if the auto-detection is wrong.
