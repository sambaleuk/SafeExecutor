import { spawnSync } from 'child_process';
import type { CloudIntent } from './types.js';
import type { SimulationResult } from '../../core/types.js';

// AWS services that natively support --dry-run
const AWS_DRY_RUN_SERVICES = new Set(['ec2', 'ebs', 'ecs']);

/**
 * Parse the human-readable summary line from `terraform plan` output.
 * Handles: "Plan: 2 to add, 1 to change, 0 to destroy."
 */
function parseTerraformPlanOutput(output: string): {
  add: number;
  change: number;
  destroy: number;
} {
  const match = output.match(
    /Plan:\s*(\d+)\s*to add,\s*(\d+)\s*to change,\s*(\d+)\s*to destroy/,
  );
  if (match) {
    return {
      add: parseInt(match[1], 10),
      change: parseInt(match[2], 10),
      destroy: parseInt(match[3], 10),
    };
  }
  // "No changes" case
  if (/No changes/.test(output)) {
    return { add: 0, change: 0, destroy: 0 };
  }
  return { add: 0, change: 0, destroy: 0 };
}

// ─── Provider sandboxes ───────────────────────────────────────────────────────

function simulateTerraform(
  intent: CloudIntent,
  start: number,
  warnings: string[],
): SimulationResult {
  const { action, flags } = intent.command;

  if (intent.affectsAll) {
    warnings.push(
      'terraform destroy without -target will destroy ALL managed resources. ' +
      'Use -target=<resource_type.resource_name> to limit scope.',
    );
  }

  // For destroy: can only estimate via terraform plan -destroy; skip live call here
  if (action === 'destroy') {
    warnings.push('Destructive operation: all targeted resources will be permanently removed.');
    return {
      feasible: true,
      resourcesImpacted: -1,
      summary: 'terraform destroy — run `terraform plan -destroy` to preview impact',
      warnings,
      durationMs: Date.now() - start,
    };
  }

  if (action === 'plan' || action === 'apply') {
    const targetArgs = flags['target'] ? [`-target=${String(flags['target'])}`] : [];
    const result = spawnSync('terraform', ['plan', '-no-color', ...targetArgs], {
      timeout: 60_000,
      encoding: 'utf8',
    });

    if (result.error || result.status !== 0) {
      const msg = result.error?.message ?? result.stderr ?? 'terraform plan failed';
      warnings.push(`Could not run terraform plan: ${msg}`);
      return {
        feasible: true,
        resourcesImpacted: -1,
        summary: 'terraform plan could not be executed — proceeding with caution',
        warnings,
        durationMs: Date.now() - start,
      };
    }

    const output = result.stdout ?? '';
    const counts = parseTerraformPlanOutput(output);
    const total = counts.add + counts.change + counts.destroy;

    if (counts.destroy > 0) {
      warnings.push(`terraform plan will destroy ${counts.destroy} resource(s)`);
    }

    return {
      feasible: true,
      resourcesImpacted: total,
      summary: `Plan: ${counts.add} to add, ${counts.change} to change, ${counts.destroy} to destroy`,
      warnings,
      durationMs: Date.now() - start,
    };
  }

  // state rm/mv, import, taint, etc.
  return {
    feasible: true,
    resourcesImpacted: intent.command.resources.length || 1,
    summary: `terraform ${action} — state operation affecting ${intent.command.resources.length || 1} resource(s)`,
    warnings,
    durationMs: Date.now() - start,
  };
}

function simulateAws(
  intent: CloudIntent,
  start: number,
  warnings: string[],
): SimulationResult {
  const { service, action, resources } = intent.command;

  if (intent.isDestructive) {
    const targets = resources.join(', ') || 'the specified resource(s)';
    warnings.push(`Destructive AWS operation: ${service} ${action} will permanently affect ${targets}`);
  }

  if (AWS_DRY_RUN_SERVICES.has(service)) {
    // Run with --dry-run appended
    const tokens = intent.raw.trim().split(/\s+/).slice(1); // drop 'aws'
    tokens.push('--dry-run');

    const result = spawnSync('aws', tokens, {
      timeout: 30_000,
      encoding: 'utf8',
    });

    const stdout = result.stdout ?? '';
    const stderr = result.stderr ?? '';

    // AWS signals dry-run success via a specific error code
    const isDryRunSuccess =
      result.status === 0 ||
      stderr.includes('DryRunOperation') ||
      stderr.includes('Request would have succeeded');

    if (!isDryRunSuccess && !result.error) {
      warnings.push(`AWS dry-run check failed: ${(stderr || stdout).slice(0, 200)}`);
      return {
        feasible: false,
        resourcesImpacted: 0,
        summary: `AWS ${service} ${action}: dry-run failed — check permissions or resource existence`,
        warnings,
        durationMs: Date.now() - start,
      };
    }

    return {
      feasible: true,
      resourcesImpacted: resources.length || 1,
      summary: `AWS ${service} ${action}: dry-run succeeded`,
      warnings,
      durationMs: Date.now() - start,
    };
  }

  // For services without --dry-run: describe-based estimate
  const count = resources.length || 1;
  return {
    feasible: true,
    resourcesImpacted: count,
    summary: `AWS ${service} ${action}: will affect ~${count} resource(s) — no dry-run available for this service`,
    warnings,
    durationMs: Date.now() - start,
  };
}

function simulateDescribe(
  intent: CloudIntent,
  start: number,
  warnings: string[],
): SimulationResult {
  const { provider, service, action, resources } = intent.command;

  if (intent.isDestructive) {
    warnings.push(
      `Destructive operation: ${provider} ${service} ${action} will permanently remove resources`,
    );
  }

  if (intent.affectsAll) {
    warnings.push('No specific target provided — operation may affect all resources of this type');
  }

  const count = resources.length || 1;
  return {
    feasible: true,
    resourcesImpacted: count,
    summary: `${provider} ${service} ${action}: will affect approximately ${count} resource(s)`,
    warnings,
    durationMs: Date.now() - start,
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function simulateCloudCommand(intent: CloudIntent): Promise<SimulationResult> {
  const start = Date.now();
  const warnings: string[] = [];

  switch (intent.command.provider) {
    case 'terraform': return simulateTerraform(intent, start, warnings);
    case 'aws':       return simulateAws(intent, start, warnings);
    case 'gcloud':
    case 'az':        return simulateDescribe(intent, start, warnings);
  }
}
