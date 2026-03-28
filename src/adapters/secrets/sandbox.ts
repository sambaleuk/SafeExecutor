import type { SimulationResult } from '../../core/types.js';
import type { ParsedSecretCommand, ValidationResult } from './types.js';
import { detectLeaks } from './leak-detector.js';

function buildSummary(
  parsed: ParsedSecretCommand,
  warnings: string[],
  validations: ValidationResult[],
): string {
  const lines: string[] = [
    '[DRY-RUN] Secrets Command Preview',
    `Tool       : ${parsed.tool}`,
    `Action     : ${parsed.action}`,
    `Scope      : ${parsed.scope}`,
  ];
  if (parsed.secretPath) lines.push(`Secret     : ${parsed.secretPath}`);
  if (parsed.namespace) lines.push(`Namespace  : ${parsed.namespace}`);
  if (Object.keys(parsed.parameters).length > 0) {
    lines.push(`Parameters : ${JSON.stringify(parsed.parameters)}`);
  }
  if (warnings.length > 0) {
    lines.push('');
    lines.push('Warnings:');
    for (const w of warnings) lines.push(`  ⚠  ${w}`);
  }
  if (validations.length > 0) {
    lines.push('');
    lines.push('Validations:');
    for (const v of validations) {
      lines.push(`  ${v.passed ? '✓' : '✗'}  ${v.check}: ${v.message}`);
    }
  }
  return lines.join('\n');
}

/**
 * Secrets sandbox — static validation without executing the command.
 *
 * Returns a SimulationResult compatible with SafeAdapter<TIntent>.sandbox().
 * DENY patterns (force-delete, purge, wildcard-delete) set feasible=false.
 * Warnings (production targets, value exposure) are surfaced for the approval gate.
 */
export async function simulateSecretCommand(parsed: ParsedSecretCommand): Promise<SimulationResult> {
  const start = Date.now();
  const warnings: string[] = [];
  const validations: ValidationResult[] = [];

  // ── DENY patterns — hard stop ──────────────────────────────────────────────
  for (const dp of parsed.dangerousPatterns) {
    if (dp.severity === 'DENY') {
      const msg = `DENIED: ${dp.description}`;
      return {
        feasible: false,
        resourcesImpacted: 0,
        summary: msg,
        warnings: [`Dangerous pattern '${dp.pattern}': ${dp.description}`],
        durationMs: Date.now() - start,
      };
    }
  }

  // ── Production delete without approval — hard stop ─────────────────────────
  if (parsed.action === 'delete' && parsed.isProduction) {
    const msg = 'DENIED: Cannot delete production secrets without explicit approval workflow';
    return {
      feasible: false,
      resourcesImpacted: 0,
      summary: msg,
      warnings: [msg],
      durationMs: Date.now() - start,
    };
  }

  // ── Leak detection in command itself ───────────────────────────────────────
  const leakResult = detectLeaks(parsed.raw);
  if (leakResult.hasLeaks) {
    warnings.push(
      `Command contains ${leakResult.leaks.length} potential secret(s) in plaintext — ` +
      `types: ${leakResult.leaks.map(l => l.type).join(', ')}`
    );
    validations.push({
      check: 'leak-detection',
      passed: false,
      message: 'Secret values detected in command text — use references, not inline values',
    });
  }

  // ── Value exposure check ──────────────────────────────────────────────────
  if (parsed.exposesValue) {
    warnings.push('This command will expose a secret value in stdout');
    validations.push({
      check: 'value-exposure',
      passed: false,
      message: 'Secret value will be printed to stdout — ensure output is not logged',
    });
  }

  // ── Production target ─────────────────────────────────────────────────────
  if (parsed.isProduction) {
    warnings.push('Targeting PRODUCTION secrets — elevated risk');
    validations.push({
      check: 'production-target',
      passed: false,
      message: 'Production secret operations require explicit approval',
    });
  }

  // ── Overwrite check ───────────────────────────────────────────────────────
  if (parsed.isOverwrite) {
    warnings.push('This command will overwrite an existing secret value');
    validations.push({
      check: 'overwrite',
      passed: false,
      message: 'Secret overwrite detected — ensure previous version is backed up',
    });
  }

  // ── Force flag ────────────────────────────────────────────────────────────
  if (parsed.isForce) {
    warnings.push('Force flag detected — safety confirmations bypassed');
    validations.push({
      check: 'force-flag',
      passed: false,
      message: '--force bypasses safety prompts',
    });
  }

  // ── Destructive action ────────────────────────────────────────────────────
  if (parsed.isDestructive) {
    warnings.push(`Destructive action '${parsed.action}' — may cause data loss`);
    validations.push({
      check: 'destructive-action',
      passed: false,
      message: `Action '${parsed.action}' can permanently remove secrets`,
    });
  }

  // ── Safe actions ──────────────────────────────────────────────────────────
  if (parsed.action === 'list') {
    validations.push({
      check: 'safe-action',
      passed: true,
      message: "Action 'list' is non-destructive — lists secret names only",
    });
  }

  if (parsed.action === 'read' && !parsed.isProduction) {
    validations.push({
      check: 'read-non-prod',
      passed: true,
      message: 'Reading non-production secret — lower risk',
    });
  }

  const summary = buildSummary(parsed, warnings, validations);

  return {
    feasible: true,
    resourcesImpacted: parsed.scope === 'single' ? 1 : -1,
    summary,
    warnings,
    durationMs: Date.now() - start,
  };
}
