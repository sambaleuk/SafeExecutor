import { spawnSync } from 'child_process';
import type { SafeAdapter, SimulationResult, AdapterExecutionResult } from '../../core/types.js';
import type { CloudIntent, CloudSnapshot } from './types.js';
import { buildCloudIntent } from './parser.js';
import { simulateCloudCommand } from './sandbox.js';

/**
 * Cloud Infrastructure Adapter
 *
 * Implements SafeAdapter for cloud infrastructure CLIs:
 *   - Terraform (plan, apply, destroy, state, import)
 *   - AWS CLI   (ec2, rds, s3, iam, lambda, cloudformation)
 *   - GCP gcloud (compute, sql, storage, iam)
 *   - Azure CLI  (vm, sql, storage, ad)
 *
 * Rollback strategy:
 *   - terraform apply → terraform destroy -target=<resources> -auto-approve
 *   - All other providers → not automatable; throws with snapshot reference
 *
 * Security note: execute() runs the raw command using spawnSync with the
 * argument list from the parsed CloudCommand (not via shell), preventing
 * injection attacks from intermediate processing.
 */
export class CloudAdapter implements SafeAdapter<CloudIntent, CloudSnapshot> {
  readonly name = 'cloud';

  parseIntent(raw: string): CloudIntent {
    return buildCloudIntent(raw);
  }

  async sandbox(intent: CloudIntent): Promise<SimulationResult> {
    return simulateCloudCommand(intent);
  }

  async execute(intent: CloudIntent): Promise<AdapterExecutionResult> {
    const start = Date.now();
    const { provider, service, action, resources, flags } = intent.command;

    // Build the argv list from the parsed command (avoids shell injection)
    const [cli, ...args] = buildArgv(provider, service, action, resources, flags);

    const result = spawnSync(cli, args, {
      timeout: 300_000,
      encoding: 'utf8',
    });

    const durationMs = Date.now() - start;

    if (result.error) {
      return {
        success: false,
        output: '',
        resourcesAffected: 0,
        durationMs,
        error: result.error.message,
      };
    }

    const output = [result.stdout, result.stderr]
      .filter(Boolean)
      .join('\n')
      .trim();

    if (result.status !== 0) {
      return {
        success: false,
        output,
        resourcesAffected: 0,
        durationMs,
        error: `Process exited with code ${result.status}`,
      };
    }

    return {
      success: true,
      output,
      resourcesAffected: resources.length || 1,
      durationMs,
    };
  }

  async rollback(intent: CloudIntent, snapshot: CloudSnapshot): Promise<void> {
    const { provider, action, resources } = intent.command;

    if (provider === 'terraform' && action === 'apply') {
      // Reverse a terraform apply by destroying only the targeted resources
      const targetArgs = resources.map((r) => `-target=${r}`);
      const destroyArgs = ['destroy', '-auto-approve', ...targetArgs];

      const result = spawnSync('terraform', destroyArgs, {
        timeout: 300_000,
        encoding: 'utf8',
      });

      if (result.status !== 0) {
        throw new Error(
          `Terraform rollback failed (exit ${result.status}): ${result.stderr ?? result.stdout}`,
        );
      }
      return;
    }

    // Cloud resource deletions are generally irreversible without a backup/restore flow.
    // Surface the snapshot timestamp so operators know when to look.
    throw new Error(
      `Automatic rollback is not supported for ${provider} ${action}. ` +
      `A resource snapshot was captured at ${snapshot.timestamp.toISOString()} ` +
      `(id: ${snapshot.commandId}). Manual intervention is required.`,
    );
  }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Reconstruct the CLI argv from structured command parts.
 * Using the parsed structure (rather than splitting intent.raw) ensures
 * we never accidentally re-introduce injected tokens.
 */
function buildArgv(
  provider: string,
  service: string,
  action: string,
  resources: string[],
  flags: Record<string, string | boolean>,
): string[] {
  const args: string[] = [provider];

  if (provider === 'terraform') {
    // terraform plan / apply / destroy / state rm ...
    if (service === 'state') {
      args.push('state', action);
    } else {
      args.push(action);
    }
  } else if (provider === 'gcloud') {
    // gcloud compute instances delete ...  → service = 'compute:instances'
    args.push(...service.split(':'), action);
  } else {
    // aws <service> <action> or az <service> <action>
    args.push(service, action);
  }

  // Positional resources
  args.push(...resources);

  // Named flags
  for (const [key, value] of Object.entries(flags)) {
    if (value === true) {
      args.push(`--${key}`);
    } else if (value !== false) {
      args.push(`--${key}`, String(value));
    }
  }

  return args;
}
