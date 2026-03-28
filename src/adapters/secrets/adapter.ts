import { spawnSync } from 'node:child_process';
import type { DatabaseAdapter, DryRunResult, ExecuteResult } from '../adapter.interface.js';
import { parseSecretCommand } from './parser.js';
import { detectLeaks } from './leak-detector.js';
import { SecretSandbox } from './sandbox.js';
import type { SecretsAdapterOptions } from './types.js';

/**
 * Secrets Adapter
 *
 * Implements the DatabaseAdapter interface for secret management systems:
 *   - HashiCorp Vault
 *   - AWS Secrets Manager
 *   - AWS SSM Parameter Store
 *   - GCP Secret Manager
 *   - Azure Key Vault
 *   - Kubernetes Secrets
 *   - Docker Secrets
 *   - Environment variables / .env files
 *
 * The "SQL" passed to each method is a raw secret management command string.
 *
 * Enforcement layers (applied in runInDryRunTransaction and execute):
 *   1. Leak detection — aborts if a secret value is embedded in the command
 *   2. Exfiltration detection — aborts if the command pipes output externally
 *   3. Path allowlist/blocklist — restricts which secret paths are accessible
 *   4. Sandbox simulation — checks for wildcard deletes, raw output on production, etc.
 *
 * Live execution (dryRunOnly: false) spawns the command via child_process.spawnSync.
 * Default mode is dryRunOnly: true — validates and audits without executing.
 */

// ─── Arg Splitter ─────────────────────────────────────────────────────────────

/**
 * Splits a shell command string into [executable, ...args] respecting quoted tokens.
 * Does not handle escape sequences beyond basic quote toggling.
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

export class SecretsAdapter implements DatabaseAdapter {
  readonly name = 'secrets';

  private pendingCommands: string[] = [];
  private readonly savepoints: Map<string, number> = new Map();

  constructor(private readonly options: SecretsAdapterOptions = {}) {}

  /**
   * Validates the adapter configuration.
   * In live mode, also verifies the command is parseable before any operation.
   */
  async ping(): Promise<void> {
    if (
      this.options.allowedPaths !== undefined &&
      this.options.blockedPaths !== undefined
    ) {
      // Catch misconfiguration: a path can't be both allowed and blocked
      for (const allowed of this.options.allowedPaths) {
        if (this.options.blockedPaths.some((b) => b.startsWith(allowed) || allowed.startsWith(b))) {
          throw new Error(
            `SecretsAdapter misconfiguration: path '${allowed}' appears in both allowedPaths and blockedPaths`,
          );
        }
      }
    }
  }

  /**
   * Returns a structural analysis of the secret command without leak detection.
   * Called by the sandbox layer for query planning.
   */
  async explainQuery(command: string): Promise<string> {
    const parsed = parseSecretCommand(command);

    return [
      `Tool:        ${parsed.tool}`,
      `Action:      ${parsed.action}`,
      `Path:        ${parsed.secretPath || '(none)'}`,
      `Environment: ${parsed.environment}`,
      `Wildcard:    ${parsed.isWildcard}`,
      `Raw output:  ${parsed.isRawOutput}`,
      parsed.version ? `Version:     ${parsed.version}` : '',
    ]
      .filter(Boolean)
      .join('\n');
  }

  /**
   * Returns a full analysis including leak detection and sandbox simulation.
   * Called by the sandbox layer for SELECT-equivalent operations.
   */
  async explainAnalyzeQuery(command: string): Promise<string> {
    const plan = await this.explainQuery(command);
    const leaks = detectLeaks(command);
    const parsed = parseSecretCommand(command);
    const sandbox = new SecretSandbox(this.options);
    const outcome = sandbox.simulate(parsed);

    const leakSection =
      leaks.hasLeak || leaks.isExfiltration
        ? [
            '',
            '── Leak Detection ──',
            leaks.hasLeak ? `Patterns found: ${leaks.patterns.join(', ')}` : '',
            leaks.isExfiltration ? 'EXFILTRATION RISK: command pipes output to an external sink' : '',
            `Masked command: ${leaks.masked}`,
          ]
            .filter(Boolean)
            .join('\n')
        : '\nNo leak patterns detected.';

    const sandboxSection = [
      '',
      '── Sandbox Simulation ──',
      `Feasible: ${outcome.feasible}`,
      outcome.plan,
      outcome.validationErrors.length > 0
        ? `Warnings: ${outcome.validationErrors.join('; ')}`
        : '',
    ]
      .filter(Boolean)
      .join('\n');

    return plan + leakSection + sandboxSection;
  }

  /**
   * Simulates the secret operation without executing it.
   * Returns feasible:false for DENY cases (leaks, exfiltration, blocklist, wildcard delete, etc.).
   * Called by the pipeline sandbox layer when requiresDryRun is true.
   */
  async runInDryRunTransaction(command: string): Promise<DryRunResult> {
    const start = Date.now();
    const parsed = parseSecretCommand(command);
    const leaks = detectLeaks(command);

    // ── Hard DENY: plaintext secret embedded in command ────────────────────
    if (parsed.hasPlaintextSecret) {
      return {
        feasible: false,
        rowsAffected: 0,
        plan: [
          'DENIED: Secret value detected in plaintext within the command.',
          'Use file references (@file), environment variable injection, or a secrets manager SDK instead.',
          `Masked command: ${leaks.masked}`,
        ].join('\n'),
      };
    }

    // ── Hard DENY: exfiltration attempt ────────────────────────────────────
    if (leaks.isExfiltration) {
      return {
        feasible: false,
        rowsAffected: 0,
        plan: [
          'DENIED: Potential secret exfiltration detected.',
          'Piping secret output to curl, wget, nc, or redirecting to files is not permitted.',
          `Masked command: ${leaks.masked}`,
        ].join('\n'),
      };
    }

    // ── Hard DENY: known secret value in command ───────────────────────────
    if (leaks.hasLeak) {
      return {
        feasible: false,
        rowsAffected: 0,
        plan: [
          `DENIED: Secret value pattern detected (${leaks.patterns.join(', ')}).`,
          'Remove the secret value from the command. Use file or environment variable references.',
          `Masked command: ${leaks.masked}`,
        ].join('\n'),
      };
    }

    // ── Blocklist check ────────────────────────────────────────────────────
    if (
      parsed.secretPath &&
      this.options.blockedPaths?.some((b) => parsed.secretPath.startsWith(b))
    ) {
      return {
        feasible: false,
        rowsAffected: 0,
        plan: `DENIED: Secret path '${parsed.secretPath}' is in the blocked paths list.`,
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
          rowsAffected: 0,
          plan: `DENIED: Secret path '${parsed.secretPath}' is not in the allowed paths list.`,
        };
      }
    }

    // ── Sandbox simulation ─────────────────────────────────────────────────
    const sandbox = new SecretSandbox(this.options);
    const outcome = sandbox.simulate(parsed);
    const durationMs = Date.now() - start;

    return {
      feasible: outcome.feasible,
      rowsAffected: outcome.feasible ? 1 : 0,
      plan: `${outcome.plan}\n[dry-run completed in ${durationMs}ms]`,
    };
  }

  /**
   * Begins tracking a batch of operations.
   * Secret operations are atomic, so this is a tracking mechanism only.
   */
  async beginTransaction(): Promise<void> {
    this.pendingCommands = [];
    this.savepoints.clear();
  }

  /**
   * Records a checkpoint within the current operation batch.
   */
  async setSavepoint(name: string): Promise<void> {
    this.savepoints.set(name, this.pendingCommands.length);
  }

  /**
   * Discards operations recorded after the named checkpoint.
   * Note: already-executed secret operations cannot be undone by this call.
   */
  async rollbackToSavepoint(name: string): Promise<void> {
    const idx = this.savepoints.get(name);
    if (idx !== undefined) {
      this.pendingCommands = this.pendingCommands.slice(0, idx);
      // Remove all savepoints created after this one
      for (const [k, v] of this.savepoints) {
        if (v > idx) this.savepoints.delete(k);
      }
    }
  }

  /**
   * Clears the operation tracking state.
   */
  async commitTransaction(): Promise<void> {
    this.pendingCommands = [];
    this.savepoints.clear();
  }

  /**
   * Clears the operation tracking state (best-effort — already-executed operations are not reversed).
   */
  async rollbackTransaction(): Promise<void> {
    this.pendingCommands = [];
    this.savepoints.clear();
  }

  /**
   * Executes the secret management command.
   *
   * In dryRunOnly mode (default): validates, records, and returns simulated success.
   * In live mode (dryRunOnly: false): spawns the command via child_process.spawnSync.
   *
   * Always blocks if leaks or exfiltration patterns are detected.
   */
  async execute(command: string): Promise<ExecuteResult> {
    const parsed = parseSecretCommand(command);
    const leaks = detectLeaks(command);

    // Final safety gate — never execute if leaks or exfiltration are detected
    if (parsed.hasPlaintextSecret) {
      throw new Error(
        'Execution blocked: secret value detected in plaintext within the command',
      );
    }
    if (leaks.isExfiltration) {
      throw new Error('Execution blocked: exfiltration pattern detected in command');
    }
    if (leaks.hasLeak) {
      throw new Error(
        `Execution blocked: secret value pattern detected (${leaks.patterns.join(', ')})`,
      );
    }

    // Record the operation for audit trail
    this.pendingCommands.push(command);

    // Dry-run mode: simulate success without executing
    if (this.options.dryRunOnly !== false) {
      return { rowsAffected: 1 };
    }

    // Live mode: spawn the command
    const parts = splitArgs(command);
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
      throw new Error(
        `Command spawn failed: ${result.error.message}. Is '${executable}' installed and in PATH?`,
      );
    }

    const exitInfo =
      result.status !== null ? `exit ${result.status}` : `signal ${result.signal ?? 'unknown'}`;

    if (result.status !== 0) {
      const stderr = result.stderr?.trim() ?? '';
      throw new Error(
        `Command failed (${exitInfo})${stderr ? `: ${stderr}` : ''}`,
      );
    }

    return { rowsAffected: 1 };
  }

  async close(): Promise<void> {
    this.pendingCommands = [];
    this.savepoints.clear();
  }
}
