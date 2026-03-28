import type { ParsedCicdCommand, CicdSandboxResult, ValidationResult } from './types.js';

function makeResult(
  feasible: boolean,
  preview: string,
  warnings: string[],
  validations: ValidationResult[],
  durationMs: number,
): CicdSandboxResult {
  return { feasible, preview, warnings, validations, durationMs };
}

function buildPreview(
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
 * CI/CD sandbox layer.
 *
 * Performs static validation without executing the command:
 * - Rejects DENY-severity dangerous patterns immediately
 * - Flags missing version pins, force flags, privileged containers
 * - Warns about production targets and public registry pushes
 */
export async function runCicdSandbox(parsed: ParsedCicdCommand): Promise<CicdSandboxResult> {
  const start = Date.now();
  const warnings: string[] = [];
  const validations: ValidationResult[] = [];

  // ── DENY patterns — hard stop ──────────────────────────────────────────────
  for (const dp of parsed.dangerousPatterns) {
    if (dp.severity === 'DENY') {
      const msg = `DENIED: ${dp.description}`;
      return makeResult(false, msg, [`Dangerous pattern '${dp.pattern}': ${dp.description}`], [
        { check: dp.pattern, passed: false, message: dp.description },
      ], Date.now() - start);
    }
  }

  // ── Docker image tag pinning ───────────────────────────────────────────────
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

  // ── Production deploy without specific tag — hard stop ────────────────────
  if (
    parsed.action === 'deploy' &&
    parsed.environment === 'production' &&
    !parsed.hasSpecificTag
  ) {
    const msg = "DENIED: Cannot deploy 'latest' to production — specify an explicit version tag";
    validations.push({ check: 'prod-tag-pinning', passed: false, message: msg });
    return makeResult(
      false,
      msg,
      [...warnings, msg],
      validations,
      Date.now() - start,
    );
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

  // ── Staging / preview deploys — informational ──────────────────────────────
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

  // Sandbox feasibility: only hard DENY cases (dangerous mount, latest to prod) make this false.
  // Production warnings and approval requirements are surfaced as warnings but remain feasible —
  // it is the approval gate's job to gate production, not the sandbox.
  const feasible = true;

  const preview = buildPreview(parsed, warnings, validations);

  return makeResult(feasible, preview, warnings, validations, Date.now() - start);
}
