# SafeExecutor — Safety Harness for Dangerous Operations

You have access to SafeExecutor, a policy-enforced safety layer for potentially dangerous operations across 10 domains: SQL, cloud infrastructure, Kubernetes, filesystem, CI/CD, API, secrets, git, network, and message queues.

## When to Use SafeExecutor

**ALWAYS** route the following through SafeExecutor before executing:

1. **Shell commands** that modify files: `rm`, `mv`, `chmod`, `chown`, recursive operations
2. **SQL queries** that modify data: `DELETE`, `UPDATE`, `DROP`, `TRUNCATE`, `ALTER`
3. **Cloud commands**: `terraform apply/destroy`, `aws` resource mutations, `gcloud`/`az` destructive operations
4. **Kubernetes commands**: `kubectl delete`, `kubectl apply`, `helm install/upgrade/delete`
5. **CI/CD operations**: pipeline triggers, deployments to staging/production
6. **API calls**: `curl` with POST/PUT/DELETE to external services
7. **Secret management**: vault writes, secret deletions, key rotations
8. **Network operations**: firewall rule changes, route modifications, SSH tunneling

## How to Use

### Pre-check before executing (recommended)

Use `safe_analyze` to understand the risk before running a command:

```
safe_analyze(command: "DELETE FROM users WHERE created_at < '2024-01-01'")
```

This returns risk level, classification, and policy decision without executing.

### Quick policy check

Use `safe_policy_check` for a fast allow/deny answer:

```
safe_policy_check(command: "terraform destroy")
```

### Full pipeline

Use `safe_execute` for the complete analysis:

```
safe_execute(command: "kubectl delete deployment my-app -n production", domain: "kubernetes")
```

The `domain` parameter is optional — SafeExecutor auto-detects the domain from the command.

## Handling Responses

### ALLOWED
Proceed with execution. Note the risk level for context.

### DENIED
**Do NOT execute the command.** Explain to the user:
- What command was blocked
- Why it was blocked (the policy rule and reason)
- Suggest safer alternatives if possible

### REQUIRE_APPROVAL
**Ask the user for explicit confirmation before executing.** Present:
- The risk assessment
- What the command will do
- Why approval is required
- Wait for explicit "yes" or approval before proceeding

### REQUIRE_DRY_RUN
The command needs a dry-run/simulation before execution. If possible, run the command in dry-run mode first and present results to the user.

## Policy Configuration

You can adjust policy rules at runtime using `configure_policy`:

```
configure_policy(action: "add_rule", rule: {
  id: "block-prod-deletes",
  description: "Block all deletes in production tables",
  match: { operationType: ["DELETE"], tablesPattern: ["prod_.*"] },
  action: "deny",
  riskLevel: "CRITICAL",
  message: "Direct deletes on production tables are not allowed"
})
```

## Domain Hints

When the auto-detection might be ambiguous, provide a domain hint:
- `sql` — SQL queries (SELECT, INSERT, UPDATE, DELETE, DDL)
- `cloud` — Terraform, AWS CLI, gcloud, Azure CLI
- `kubernetes` — kubectl, helm
- `filesystem` — Shell commands (rm, cp, mv, chmod)
- `cicd` — GitHub Actions, GitLab CI, Jenkins, CircleCI, ArgoCD
- `api` — curl, HTTP requests
- `secrets` — HashiCorp Vault, AWS Secrets Manager, Azure Key Vault
- `git` — Git operations
- `network` — iptables, ufw, ip, route, ssh, nmap
- `queue` — SQS, SNS, Pub/Sub, RabbitMQ
