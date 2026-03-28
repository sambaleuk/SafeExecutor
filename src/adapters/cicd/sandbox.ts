import type { SimulationResult } from '../../core/types.js';
import type { ParsedCicdCommand, ValidationResult } from './types.js';

function buildSummary(
  parsed: ParsedCicdCommand,
  warnings: string[],
  validations: ValidationResult[],
): string {
  const lines: string[] = [
    '[DRY-RUN] CI/CD Command Preview',
    `Tool       : ${parsed.tool}`,
    `Action     : ${parsed.action}`,
    `Environment: ${parsed.environment}`,
  ];
  if (parsed.imageTag) lines.push(`Image      : ${parsed.imageTag}`);
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
 * CI/CD sandbox — static validation without executing the command.
 *
 * Returns a SimulationResult compatible with SafeAdapter<TIntent>.sandbox().
 * Only hard-DENY patterns (root mount, latest-to-prod) set feasible=false.
 * Warnings (production targets, force flags, public registry) are surfaced
 * but leave feasibility to the approval gate.
 */
export async function simulateCicdCommand(parsed: ParsedCicdCommand): Promise<SimulationResult> {
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

  // ── Production deploy without version tag — hard stop ─────────────────────
  if (
    parsed.action === 'deploy' &&
    parsed.environment === 'production' &&
    !parsed.hasSpecificTag
  ) {
    const msg = "DENIED: Cannot deploy 'latest' to production — specify an explicit version tag";
    return {
      feasible: false,
      resourcesImpacted: 0,
      summary: msg,
      warnings: [msg],
      durationMs: Date.now() - start,
    };
  }

  // ── Docker image tag pinning (non-build actions) ───────────────────────────
  if (parsed.tool === 'docker' && parsed.action !== 'build') {
    const pinned = parsed.hasSpecificTag;
    validations.push({
      check: 'image-tag-pinning',
      passed: pinned,
      message: pinned
        ? `Version-pinned image: ${parsed.imageTag ?? 'unknown'}`
        : "Image uses implicit 'latest' — no version pinning",
    });
    if (!pinned) warnings.push("Using 'latest' tag is dangerous — pin to an explicit version");
  }

  // ── Production target ──────────────────────────────────────────────────────
  if (parsed.environment === 'production') {
    warnings.push('Targeting PRODUCTION environment — human approval required');
    validations.push({
      check: 'production-target',
      passed: false,
      message: 'Production deployments require explicit approval and green CI',
    });
  }

  // ── Force deployment ───────────────────────────────────────────────────────
  if (parsed.isForceDeployment) {
    warnings.push('Force flag detected — CI safety gates are being bypassed');
    validations.push({
      check: 'force-deployment',
      passed: false,
      message: '--force / --skip-checks bypasses pipeline validation',
    });
  }

  // ── Privileged container ───────────────────────────────────────────────────
  if (parsed.isPrivileged) {
    warnings.push('--privileged grants the container full host access');
    validations.push({
      check: 'privileged-container',
      passed: false,
      message: '--privileged can break container isolation',
    });
  }

  // ── Public registry push ───────────────────────────────────────────────────
  if (parsed.action === 'push' && parsed.isPublicRegistry) {
    warnings.push(
      `Pushing to public registry (${parsed.registry ?? 'docker.io'}) — image will be world-readable`,
    );
    validations.push({
      check: 'public-registry-push',
      passed: false,
      message: `Target registry is public: ${parsed.registry ?? 'docker.io'}`,
    });
  }

  // ── Staging / preview — informational ─────────────────────────────────────
  if (parsed.environment === 'staging' || parsed.environment === 'preview') {
    validations.push({
      check: 'non-prod-target',
      passed: true,
      message: `Targeting ${parsed.environment} — lower risk deployment`,
    });
  }

  // ── Build / test / lint — always safe ─────────────────────────────────────
  if (parsed.action === 'build' || parsed.action === 'test' || parsed.action === 'lint') {
    validations.push({
      check: 'safe-action',
      passed: true,
      message: `Action '${parsed.action}' is non-destructive`,
    });
  }

  const summary = buildSummary(parsed, warnings, validations);

  return {
    feasible: true,
    resourcesImpacted: -1, // unknown for CI/CD operations
    summary,
    warnings,
    durationMs: Date.now() - start,
  };
}
