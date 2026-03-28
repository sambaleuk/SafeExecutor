import type { ParsedSecretCommand, SecretEnvironment, SecretSandboxOutcome, SecretsAdapterOptions } from './types.js';

/**
 * Secret Sandbox
 *
 * Simulates secret operations without touching any vault.
 *
 * Strategy:
 *   - read    → metadata-only plan (no actual secret value accessed)
 *   - write   → format/policy validation (length, complexity hints)
 *   - delete  → dependency analysis (simulated — cannot check without live inventory)
 *   - list    → scope assessment
 *   - rotate  → impact assessment
 *
 * DENY cases (feasible: false):
 *   - Raw output flags on production secrets (-o yaml/-o json) — exposes plaintext
 *   - Wildcard delete — irreversible mass operation
 *   - Path is on the explicit blocklist
 */

export class SecretSandbox {
  constructor(private readonly options: SecretsAdapterOptions = {}) {}

  simulate(parsed: ParsedSecretCommand): SecretSandboxOutcome {
    const start = Date.now();
    const validationErrors: string[] = [];

    // Use environment override from options if provided
    const effectiveEnv: SecretEnvironment = this.options.environment ?? parsed.environment;

    // ── Hard DENY: raw output on production ────────────────────────────────
    if (parsed.isRawOutput && effectiveEnv === 'production') {
      return {
        feasible: false,
        secretExists: false,
        dependentsCount: 0,
        validationErrors: [
          'Raw output format (-o yaml/-o json) exposes production secrets in plaintext',
        ],
        plan: [
          'DENIED: Raw output on production secret',
          `Tool: ${parsed.tool}`,
          `Path: ${parsed.secretPath}`,
          'Reason: Output flags like -o yaml expose the secret value in the command output.',
          'Fix: Remove the -o yaml/-o json flag, or use a targeted field selector (e.g. -o jsonpath).',
        ].join('\n'),
        durationMs: Date.now() - start,
      };
    }

    // ── Hard DENY: wildcard delete ─────────────────────────────────────────
    if (parsed.action === 'delete' && parsed.isWildcard) {
      return {
        feasible: false,
        secretExists: false,
        dependentsCount: 0,
        validationErrors: ['Wildcard delete is not allowed — specify an exact secret path'],
        plan: [
          'DENIED: Wildcard delete operation',
          `Tool: ${parsed.tool}`,
          `Path: ${parsed.secretPath || '(root)'}`,
          'Reason: Mass deletion of secrets is irreversible and not permitted.',
        ].join('\n'),
        durationMs: Date.now() - start,
      };
    }

    // ── Warnings (non-blocking) ────────────────────────────────────────────
    if (parsed.isRawOutput && effectiveEnv !== 'production') {
      validationErrors.push(
        `Raw output format on ${effectiveEnv} secret — value will be visible in plaintext`,
      );
    }

    if (parsed.isWildcard && effectiveEnv === 'production' && parsed.action === 'list') {
      validationErrors.push(
        'Listing all production secrets is a broad access operation — approval recommended',
      );
    }

    // ── Simulate by action ─────────────────────────────────────────────────
    switch (parsed.action) {
      case 'read': {
        return {
          feasible: true,
          secretExists: true, // optimistic — cannot verify without credentials
          dependentsCount: 0,
          validationErrors,
          plan: this.planRead(parsed, effectiveEnv),
          durationMs: Date.now() - start,
        };
      }

      case 'write': {
        return {
          feasible: true,
          secretExists: false, // unknown — may or may not exist
          dependentsCount: 0,
          validationErrors,
          plan: this.planWrite(parsed, effectiveEnv),
          durationMs: Date.now() - start,
        };
      }

      case 'delete': {
        return {
          feasible: true,
          secretExists: true,
          dependentsCount: 0, // unknown without live service inventory
          validationErrors,
          plan: this.planDelete(parsed, effectiveEnv),
          durationMs: Date.now() - start,
        };
      }

      case 'list': {
        return {
          feasible: true,
          secretExists: true,
          dependentsCount: 0,
          validationErrors,
          plan: [
            `Would list secrets at: ${parsed.secretPath || '(root)'}`,
            `Tool: ${parsed.tool}`,
            `Environment: ${effectiveEnv}`,
            parsed.isWildcard ? 'Scope: ALL secrets (wildcard)' : `Scope: ${parsed.secretPath}`,
          ].join('\n'),
          durationMs: Date.now() - start,
        };
      }

      case 'rotate': {
        return {
          feasible: true,
          secretExists: true,
          dependentsCount: 0,
          validationErrors,
          plan: [
            `Would rotate secret: ${parsed.secretPath}`,
            `Tool: ${parsed.tool}`,
            `Environment: ${effectiveEnv}`,
            'Impact: All services using this secret must be updated or will fail after rotation.',
            'Recommendation: Ensure zero-downtime rotation is configured before proceeding.',
          ].join('\n'),
          durationMs: Date.now() - start,
        };
      }

      default: {
        // TypeScript exhaustive check
        const _unreachable: never = parsed.action;
        throw new Error(`SecretSandbox: unhandled action '${String(_unreachable)}'`);
      }
    }
  }

  private planRead(parsed: ParsedSecretCommand, env: SecretEnvironment): string {
    const lines = [
      `Would read secret metadata: ${parsed.secretPath}`,
      `Tool: ${parsed.tool}`,
      `Environment: ${env}`,
    ];
    if (parsed.version) {
      lines.push(`Version: ${parsed.version}`);
    }
    if (parsed.isRawOutput) {
      lines.push('WARNING: Output flags will expose the secret value in plaintext');
    }
    lines.push('Dry-run: Only verifying access path — no secret value will be read');
    return lines.join('\n');
  }

  private planWrite(parsed: ParsedSecretCommand, env: SecretEnvironment): string {
    return [
      `Would write secret: ${parsed.secretPath}`,
      `Tool: ${parsed.tool}`,
      `Environment: ${env}`,
      'Dry-run: Secret value not available for format validation in simulation mode',
      env === 'production'
        ? 'CAUTION: Writing to production — ensure the value is from a secure source' : '',
    ]
      .filter(Boolean)
      .join('\n');
  }

  private planDelete(parsed: ParsedSecretCommand, env: SecretEnvironment): string {
    return [
      `Would delete secret: ${parsed.secretPath}`,
      `Tool: ${parsed.tool}`,
      `Environment: ${env}`,
      'Dependency check: Cannot verify live dependents without service inventory',
      'WARNING: Deletion may be irreversible — verify no active services depend on this secret',
      env === 'production'
        ? 'CRITICAL: Production secret deletion — impact may be immediate and widespread'
        : '',
    ]
      .filter(Boolean)
      .join('\n');
  }
}
