import { spawnSync } from 'node:child_process';
import type { SafeAdapter } from '../adapter.interface.js';
import type {
  SafeIntent,
  SandboxResult,
  ExecutionResult,
  SafeExecutorConfig,
  RiskFactor,
  OperationType,
  Target,
  Scope,
} from '../../types/index.js';
import { parseSecretCommand } from './parser.js';
import { detectLeaks } from './leak-detector.js';
import { SecretSandbox } from './sandbox.js';
import type { SecretsAdapterOptions, SecretAction, ParsedSecretCommand } from './types.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function actionToOperationType(action: SecretAction): OperationType {
  switch (action) {
    case 'read':
    case 'list':
      return 'SELECT';
    case 'write':
      return 'INSERT';
    case 'rotate':
      return 'UPDATE';
    case 'delete':
      return 'DELETE';
  }
}

function buildRiskFactors(
  parsed: ParsedSecretCommand,
  leaks: ReturnType<typeof detectLeaks>,
): RiskFactor[] {
  const factors: RiskFactor[] = [];

  if (parsed.hasPlaintextSecret) {
    factors.push({
      code: 'PLAINTEXT_SECRET_IN_COMMAND',
      severity: 'CRITICAL',
      description: 'Secret value detected in plaintext within the command',
    });
  }

  if (leaks.isExfiltration) {
    factors.push({
      code: 'EXFILTRATION_RISK',
      severity: 'CRITICAL',
      description: 'Command pipes output to an external sink (curl, wget, nc, file redirect)',
    });
  }

  if (leaks.hasLeak) {
    factors.push({
      code: 'SECRET_PATTERN_DETECTED',
      severity: 'CRITICAL',
      description: `Known secret value pattern detected: ${leaks.patterns.join(', ')}`,
    });
  }

  if (parsed.isRawOutput && parsed.environment === 'production') {
    factors.push({
      code: 'RAW_OUTPUT_ON_PRODUCTION',
      severity: 'HIGH',
      description: 'Raw secret output requested in production environment',
    });
  }

  if (parsed.isWildcard && parsed.action === 'delete') {
    factors.push({
      code: 'WILDCARD_DELETE',
      severity: 'CRITICAL',
      description: 'Wildcard delete operation targets multiple secrets',
    });
  }

  if (parsed.isWildcard && parsed.environment === 'production') {
    factors.push({
      code: 'WILDCARD_PRODUCTION_ACCESS',
      severity: 'HIGH',
      description: 'Wildcard operation in production environment',
    });
  }

  if (parsed.action === 'delete') {
    factors.push({
      code: 'DESTRUCTIVE_OPERATION',
      severity: 'HIGH',
      description: 'Secret deletion is irreversible',
    });
  }

  if (parsed.action === 'rotate') {
    factors.push({
      code: 'ROTATION_IMPACT',
      severity: 'MEDIUM',
      description: 'Secret rotation may affect all services using this secret',
    });
  }

  if (parsed.action === 'read' && parsed.environment === 'production') {
    factors.push({
      code: 'PRODUCTION_SECRET_READ',
      severity: 'MEDIUM',
      description: 'Reading a production secret',
    });
  }

  return factors;
}

/**
 * Splits a shell command string into [executable, ...args] respecting quoted tokens.
 */
function splitArgs(command: string): string[] {
  const result: string[] = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;

  for (const ch of command) {
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if (ch === ' ' && !inSingle && !inDouble) {
      if (current) {
        result.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }

  if (current) result.push(current);
  return result;
}

// ─── Adapter ──────────────────────────────────────────────────────────────────

/**
 * SecretsAdapter — SafeAdapter implementation for secret management systems.
 *
 * Supports HashiCorp Vault, AWS Secrets Manager, AWS SSM Parameter Store,
 * GCP Secret Manager, Azure Key Vault, Kubernetes secrets, Docker secrets,
 * and environment variables.
 *
 * Enforcement layers applied in sandbox():
 *   1. Leak detection  — aborts if a secret value is embedded in the command
 *   2. Exfiltration    — aborts if the command pipes output externally
 *   3. Path allowlist/blocklist — restricts accessible secret paths
 *   4. Sandbox simulation — wildcard deletes, raw output on production, etc.
 *
 * Live execution (dryRunOnly: false) spawns the command via spawnSync.
 * Default is dryRunOnly: true — validates and audits without executing.
 */
export class SecretsAdapter implements SafeAdapter {
  readonly domain = 'secrets';

  constructor(private readonly options: SecretsAdapterOptions = {}) {}

  async ping(): Promise<void> {
    if (this.options.allowedPaths !== undefined && this.options.blockedPaths !== undefined) {
      for (const allowed of this.options.allowedPaths) {
        if (this.options.blockedPaths.some((b) => b.startsWith(allowed) || allowed.startsWith(b))) {
          throw new Error(
            `SecretsAdapter misconfiguration: path '${allowed}' appears in both allowedPaths and blockedPaths`,
          );
        }
      }
    }
  }

  async parseIntent(raw: string): Promise<SafeIntent> {
    const parsed = parseSecretCommand(raw);
    const leaks = detectLeaks(raw);
    const riskFactors = buildRiskFactors(parsed, leaks);

    const type = actionToOperationType(parsed.action);
    const scope: Scope = parsed.isWildcard ? 'all' : 'single';
    const target: Target = {
      name: parsed.secretPath || '(none)',
      type: 'secret',
      affectedResources: parsed.secretPath ? [parsed.secretPath] : [],
    };

    return {
      domain: 'secrets',
      type,
      raw,
      target,
      scope,
      riskFactors,
      ast: parsed,
      // backward-compat fields
      tables: parsed.secretPath ? [parsed.secretPath] : [],
      hasWhereClause: !parsed.isWildcard,
      estimatedRowsAffected: null,
      isDestructive: parsed.action === 'delete',
      isMassive: parsed.isWildcard,
      metadata: {
        tool: parsed.tool,
        action: parsed.action,
        environment: parsed.environment,
      },
    };
  }

  async sandbox(intent: SafeIntent): Promise<SandboxResult> {
    const start = Date.now();
    const parsed = intent.ast as ParsedSecretCommand;

    // ── DENY: critical risk factors ────────────────────────────────────────
    const criticalRisks = intent.riskFactors.filter((r) => r.severity === 'CRITICAL');
    if (criticalRisks.length > 0) {
      const reasons = criticalRisks.map((r) => r.description).join('; ');
      return {
        feasible: false,
        estimatedRowsAffected: 0,
        executionPlan: `DENIED: ${reasons}`,
        warnings: criticalRisks.map((r) => r.description),
        durationMs: Date.now() - start,
      };
    }

    // ── Blocklist check ────────────────────────────────────────────────────
    if (
      parsed.secretPath &&
      this.options.blockedPaths?.some((b) => parsed.secretPath.startsWith(b))
    ) {
      return {
        feasible: false,
        estimatedRowsAffected: 0,
        executionPlan: `DENIED: Secret path '${parsed.secretPath}' is in the blocked paths list.`,
        warnings: [`Path '${parsed.secretPath}' is blocked`],
        durationMs: Date.now() - start,
      };
    }

    // ── Allowlist check ────────────────────────────────────────────────────
    if (
      parsed.secretPath &&
      this.options.allowedPaths !== undefined &&
      this.options.allowedPaths.length > 0
    ) {
      const isAllowed = this.options.allowedPaths.some((a) => parsed.secretPath.startsWith(a));
      if (!isAllowed) {
        return {
          feasible: false,
          estimatedRowsAffected: 0,
          executionPlan: `DENIED: Secret path '${parsed.secretPath}' is not in the allowed paths list.`,
          warnings: [`Path '${parsed.secretPath}' not in allowlist`],
          durationMs: Date.now() - start,
        };
      }
    }

    // ── Sandbox simulation ─────────────────────────────────────────────────
    const secretSandbox = new SecretSandbox(this.options);
    const outcome = secretSandbox.simulate(parsed);

    return {
      feasible: outcome.feasible,
      estimatedRowsAffected: outcome.feasible ? 1 : 0,
      executionPlan: outcome.plan,
      warnings: outcome.validationErrors,
      durationMs: Date.now() - start,
    };
  }

  async execute(
    intent: SafeIntent,
    _config: SafeExecutorConfig,
    _estimatedRows: number | null,
  ): Promise<ExecutionResult> {
    const start = Date.now();
    const parsed = intent.ast as ParsedSecretCommand;
    const leaks = detectLeaks(intent.raw);

    // Final safety gate — never execute if leaks or exfiltration are detected
    if (parsed.hasPlaintextSecret) {
      throw new Error('Execution blocked: secret value detected in plaintext within the command');
    }
    if (leaks.isExfiltration) {
      throw new Error('Execution blocked: exfiltration pattern detected in command');
    }
    if (leaks.hasLeak) {
      throw new Error(
        `Execution blocked: secret value pattern detected (${leaks.patterns.join(', ')})`,
      );
    }

    // Dry-run mode: simulate success without executing
    if (this.options.dryRunOnly !== false) {
      return {
        status: 'dry_run',
        rowsAffected: 1,
        durationMs: Date.now() - start,
        savepointUsed: false,
        rolledBack: false,
      };
    }

    // Live mode: spawn the command
    const parts = splitArgs(intent.raw);
    const executable = parts[0];
    if (!executable) {
      throw new Error('Execution blocked: empty command after parsing');
    }

    const result = spawnSync(executable, parts.slice(1), {
      encoding: 'utf-8',
      timeout: 30_000,
      shell: false, // never use shell — prevents injection
    });

    if (result.error) {
      return {
        status: 'failed',
        rowsAffected: 0,
        durationMs: Date.now() - start,
        savepointUsed: false,
        rolledBack: false,
        error: `Command spawn failed: ${result.error.message}. Is '${executable}' installed and in PATH?`,
      };
    }

    if (result.status !== 0) {
      const stderr = result.stderr?.trim() ?? '';
      const exitInfo =
        result.status !== null ? `exit ${result.status}` : `signal ${result.signal ?? 'unknown'}`;
      return {
        status: 'failed',
        rowsAffected: 0,
        durationMs: Date.now() - start,
        savepointUsed: false,
        rolledBack: false,
        error: `Command failed (${exitInfo})${stderr ? `: ${stderr}` : ''}`,
      };
    }

    return {
      status: 'success',
      rowsAffected: 1,
      durationMs: Date.now() - start,
      savepointUsed: false,
      rolledBack: false,
    };
  }

  async close(): Promise<void> {}
}
