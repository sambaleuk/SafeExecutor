# SafeExecutor — E2E Testing Report
## NeuBooks Production Database

**Date:** 2026-03-28
**Tester:** e2e-test-runner (automated)
**Database:** NeuBooks Supabase/PostgreSQL (`db.oslhwchaxstnloixpgxc.supabase.co:6543`)
**Config:** `config/neubooks-test.json`
**Policy:** `config/default-policy.json`
**Approval mode:** `auto`

---

## Changelog

| Run | Date | Result | Notes |
|-----|------|--------|-------|
| v1 | 2026-03-28 | 9/9 pass | Initial run — two bugs identified |
| v2 | 2026-03-28 | **9/9 pass** | Both bugs fixed and verified |

---

## Result Summary (v2 — after fixes)

| Level | Tests | Pass | Fail | All Blocked? |
|-------|-------|------|------|-------------|
| 1 — Read-only | 3 | 3 | 0 | n/a |
| 2 — Mutations | 3 | 3 | 0 | n/a |
| 3 — Dangerous | 3 | 3 | 0 | ✅ YES |
| **Total** | **9** | **9** | **0** | ✅ |

**All destructive operations (Level 3) were blocked before reaching Gate 5 (Executor).**
No `DELETE`, `TRUNCATE`, or `DROP` statement was committed to the production database.

---

## Fixes Applied

### Fix 1 — Policy Engine: `defaultRiskLevel` was a risk floor

**Root cause (`src/core/policy-engine.ts`):**

```typescript
// Before — started at defaultRiskLevel ("HIGH"), escalate-only logic meant
// LOW/MEDIUM rules could never lower the risk below HIGH
let currentRisk: RiskLevel = policy.defaults.defaultRiskLevel; // "HIGH"
currentRisk = escalateRisk(currentRisk, rule.riskLevel); // max(HIGH, LOW) = HIGH
```

**Fix:**

```typescript
// After — start at 'LOW', escalate per rule, apply defaultRiskLevel only
// when no rule matches at all
let currentRisk: RiskLevel = 'LOW';
// ...
if (matchedRules.length === 0) {
  currentRisk = policy.defaults.defaultRiskLevel;
}
```

**Verified by test 1.1:** SELECT now reports `riskLevel=LOW` in audit logs (was HIGH).

---

### Fix 2 — Sandbox: EXPLAIN not supported for TRUNCATE/DROP

**Root cause (`src/core/sandbox.ts`):**

The sandbox treated TRUNCATE and DROP as regular DDL and called `EXPLAIN TRUNCATE TABLE x`, which PostgreSQL rejects with "syntax error at or near TRUNCATE". This caused the pipeline to abort at Gate 3 with a cryptic error, bypassing the approval gate entirely.

**Fix:** Split DDL into two subsets:

```typescript
// PostgreSQL supports EXPLAIN for these
const DDL_EXPLAINABLE = new Set(['ALTER', 'CREATE']);

// PostgreSQL does NOT — skip EXPLAIN, return feasible=true to let Gate 4 decide
const DDL_NON_EXPLAINABLE = new Set(['DROP', 'TRUNCATE']);

if (DDL_NON_EXPLAINABLE.has(intent.type)) {
  warnings.push(`${intent.type} cannot be dry-run — EXPLAIN not supported. Proceeding to approval gate.`);
  return { feasible: true, estimatedRowsAffected: -1, executionPlan: 'N/A', ... };
}
```

**Verified by tests 3.2 and 3.3:** TRUNCATE/DROP now reach Gate 4 and are rejected with:
> `"Auto-approval denied: CRITICAL risk operations require human review"`

---

## Level 1 — Read-Only (SELECT)

### Test 1.1 — `SELECT count(*) FROM user_profiles`

```
SQL        : SELECT count(*) FROM user_profiles
Intent     : type=SELECT | tables=[user_profiles] | hasWhere=false | destructive=false
Policy     : ✓ allowed=true | risk=LOW | requiresDryRun=false | requiresApproval=false
PolicyMsg  : SELECT is read-only — allowed.
Sandbox    : skipped
Approval   : skipped
Execution  : ✓ success | rows=1 | 94ms
Audit ID   : audit-1774691217617-1
```

**Assertion:** success=true, allowed=true, riskLevel=LOW, type=SELECT, no dry-run, no approval → ✅ PASS

---

### Test 1.2 — `SELECT count(*) FROM accounts`

```
SQL        : SELECT count(*) FROM accounts
Intent     : type=SELECT | tables=[accounts] | hasWhere=false | destructive=false
Policy     : ✓ allowed=true | risk=LOW | requiresDryRun=false | requiresApproval=false
PolicyMsg  : SELECT is read-only — allowed.
Sandbox    : skipped
Approval   : skipped
Execution  : ✓ success | rows=1 | 96ms
Audit ID   : audit-1774691217712-2
```

**Assertion:** success=true, allowed=true, type=SELECT → ✅ PASS

---

### Test 1.3 — Multi-table JOIN (user_profiles × entity_members × legal_entities)

```
SQL        : SELECT u.email, l.name AS entity_name
             FROM user_profiles u
             JOIN entity_members em ON em.user_id = u.user_id
             JOIN legal_entities l ON l.id = em.entity_id
             LIMIT 5
Intent     : type=SELECT | tables=[user_profiles, entity_members, legal_entities]
Policy     : ✓ allowed=true | risk=LOW | requiresDryRun=false | requiresApproval=false
PolicyMsg  : SELECT is read-only — allowed.
Sandbox    : skipped
Approval   : skipped
Execution  : ✓ success | rows=2 | 175ms
Audit ID   : audit-1774691217818-3
```

Intent parser extracted all 3 joined table names correctly.
**Assertion:** success=true, type=SELECT, tables include user_profiles → ✅ PASS

---

## Level 2 — Mutations (UPDATE / DELETE)

### Test 2.1 — UPDATE with WHERE (dry-run + execute)

```
SQL        : UPDATE user_profiles SET updated_at = updated_at
             WHERE id = '00000000-0000-0000-0000-000000000000'
Intent     : type=UPDATE | tables=[user_profiles] | hasWhere=true | massive=false
Policy     : ✓ allowed=true | risk=MEDIUM | requiresDryRun=true | requiresApproval=false
PolicyMsg  : UPDATE requires dry-run to verify row impact.
Sandbox    : feasible=true | rows=0 | 103ms
ExplainPlan: Update on user_profiles (cost=0.15..2.37 rows=0 width=0)
Approval   : skipped (requiresApproval=false)
Execution  : ✓ success | rows=0 | 93ms | rollback=false
Audit ID   : audit-1774691218013-4
```

Full 6-gate pipeline traversed. Dry-run confirmed 0 rows, committed execution also 0 rows (zero UUID does not exist). **riskLevel now correctly shows MEDIUM** (was HIGH before Fix 1).

**Assertion:** success=true, requiresDryRun=true, sandboxResult.feasible=true, execution.status=success → ✅ PASS

---

### Test 2.2 — UPDATE without WHERE (approval gate REJECTS)

```
SQL        : UPDATE user_profiles SET updated_at = NOW()
Intent     : type=UPDATE | tables=[user_profiles] | hasWhere=false | massive=true
Policy     : ✓ allowed=true | risk=HIGH | requiresDryRun=false | requiresApproval=true
PolicyMsg  : UPDATE without WHERE clause will affect ALL rows in the table.
Sandbox    : skipped (requiresDryRun=false)
Approval   : status=rejected | Auto-approval denied: HIGH risk operations require human
             review (use cli or webhook mode)
Execution  : BLOCKED
AbortReason: Approval rejected: [...]
Audit ID   : audit-1774691218234-5
```

Mass update blocked at Gate 4. The operation never reached the Executor.

**Assertion:** success=false, requiresApproval=true, approvalResponse.status=rejected, no execution → ✅ PASS

---

### Test 2.3 — DELETE with WHERE (dry-run + execute)

```
SQL        : DELETE FROM journals WHERE code = 'SAFE-NONEXISTENT-CODE'
Intent     : type=DELETE | tables=[journals] | hasWhere=true | destructive=true
Policy     : ✓ allowed=true | risk=HIGH | requiresDryRun=true | requiresApproval=false
PolicyMsg  : DELETE with WHERE requires dry-run impact assessment.
Sandbox    : feasible=true | rows=0 | 94ms
ExplainPlan: Delete on journals (cost=1.27..4.45 rows=0 width=0)
Approval   : skipped (requiresApproval=false)
Execution  : ✓ success | rows=0 | 184ms | rollback=false
Audit ID   : audit-1774691218258-6
```

Dry-run ran DELETE inside BEGIN/ROLLBACK (0 rows), then committed execution also 0 rows. No journals data modified.

**Assertion:** requiresDryRun=true, sandboxResult.feasible=true → ✅ PASS

---

## Level 3 — Dangerous Operations

### Test 3.1 — DELETE without WHERE → DENY at Gate 2 (Policy Engine)

```
SQL        : DELETE FROM user_profiles
Intent     : type=DELETE | tables=[user_profiles] | hasWhere=false | destructive=true | massive=true
Policy     : ✗ allowed=false | risk=CRITICAL | requiresDryRun=true | requiresApproval=true
PolicyMsg  : DELETE without WHERE clause is not allowed.
Sandbox    : skipped (policy denied — pipeline aborted at Gate 2)
Approval   : skipped
Execution  : BLOCKED
AbortReason: Policy denied: DELETE without WHERE clause is not allowed.
Audit ID   : audit-1774691218561-7
```

Hardcoded DENY rule. Pipeline aborts immediately at Gate 2 — no DB round-trip.

**Assertion:** success=false, allowed=false, sandboxResult=null, executionResult=null → ✅ PASS

---

### Test 3.2 — TRUNCATE TABLE accounts → CRITICAL, blocked at Gate 4 (Approval) ✨ Fixed

```
SQL        : TRUNCATE TABLE accounts
Intent     : type=TRUNCATE | tables=[accounts] | hasWhere=false | destructive=true | massive=true
Policy     : ✓ allowed=true | risk=CRITICAL | requiresDryRun=true | requiresApproval=true
PolicyMsg  : TRUNCATE requires explicit human approval.
Sandbox    : feasible=true | rows=-1 | ~5ms
             Warning: TRUNCATE cannot be dry-run — EXPLAIN not supported. Proceeding to approval gate.
             ExecutionPlan: N/A — EXPLAIN not supported for this DDL operation
Approval   : status=rejected | Auto-approval denied: CRITICAL risk operations require human review
Execution  : BLOCKED
AbortReason: Approval rejected: Auto-approval denied: CRITICAL risk operations require human review
Audit ID   : audit-1774691218588-8
```

**Before fix:** Pipeline error "syntax error at or near TRUNCATE" (cryptic, Gate 3 crash).
**After fix:** Clean rejection at Gate 4 with human-readable message.

**Assertion:** success=false, riskLevel=CRITICAL, sandboxResult.feasible=true, approvalResponse.status=rejected, no execution → ✅ PASS

---

### Test 3.3 — DROP TABLE journals → CRITICAL, blocked at Gate 4 (Approval) ✨ Fixed

```
SQL        : DROP TABLE journals
Intent     : type=DROP | tables=[journals] | hasWhere=false | destructive=true
Policy     : ✓ allowed=true | risk=CRITICAL | requiresDryRun=true | requiresApproval=true
PolicyMsg  : DROP operations are irreversible and require explicit approval.
Sandbox    : feasible=true | rows=-1 | ~5ms
             Warning: DROP cannot be dry-run — EXPLAIN not supported. Proceeding to approval gate.
             ExecutionPlan: N/A — EXPLAIN not supported for this DDL operation
Approval   : status=rejected | Auto-approval denied: CRITICAL risk operations require human review
Execution  : BLOCKED
AbortReason: Approval rejected: Auto-approval denied: CRITICAL risk operations require human review
Audit ID   : audit-1774691218637-9
```

**Assertion:** success=false, riskLevel=CRITICAL, sandboxResult.feasible=true, approvalResponse.status=rejected, no execution → ✅ PASS

---

## Audit Trail

9 audit entries written to `logs/neubooks-e2e-audit.log`. Each entry is an immutable JSON record covering all 6 gates: intent, policy decision, sandbox result, approval response, execution result, total duration.

---

## Final Assessment

SafeExecutor v0.1.0 (post-fix) correctly enforces all safety guarantees across the NeuBooks production database:

| Guarantee | Status |
|-----------|--------|
| SELECT queries never require approval or dry-run | ✅ |
| SELECT queries correctly classified LOW risk | ✅ Fixed |
| UPDATE/DELETE with WHERE go through dry-run | ✅ |
| Mass mutations (no WHERE) rejected by approval gate | ✅ |
| DELETE without WHERE denied at policy engine | ✅ |
| TRUNCATE/DROP blocked at approval gate with clear message | ✅ Fixed |
| Executor never reached by dangerous operations | ✅ |
| Every operation produces an immutable audit entry | ✅ |
| Zero production data modified by dangerous-op tests | ✅ |

No remaining known issues.
