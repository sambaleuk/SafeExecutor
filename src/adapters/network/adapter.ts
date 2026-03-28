import { spawnSync } from 'child_process';
import type { SafeAdapter, SimulationResult, AdapterExecutionResult } from '../../core/types.js';
import type {
  NetworkPolicy,
  NetworkPolicyDecision,
  NetworkPolicyRule,
  NetworkSnapshot,
  ParsedNetworkCommand,
} from './types.js';
import type { RiskLevel } from '../../types/index.js';
import { parseNetworkCommand } from './parser.js';
import { simulateNetworkCommand } from './sandbox.js';

// ─── Policy Evaluator ─────────────────────────────────────────────────────────

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function escalateRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

function matchesRule(intent: ParsedNetworkCommand, rule: NetworkPolicyRule): boolean {
  const m = rule.match;
  if (m.tools && !m.tools.includes(intent.tool)) return false;
  if (m.actions && !m.actions.includes(intent.action)) return false;
  if (m.isFirewallModification !== undefined && intent.isFirewallModification !== m.isFirewallModification) return false;
  if (m.isFirewallDisable !== undefined && intent.isFirewallDisable !== m.isFirewallDisable) return false;
  if (m.isInterfaceDown !== undefined && intent.isInterfaceDown !== m.isInterfaceDown) return false;
  if (m.isDefaultRouteRemoval !== undefined && intent.isDefaultRouteRemoval !== m.isDefaultRouteRemoval) return false;
  if (m.isTunnel !== undefined && intent.isTunnel !== m.isTunnel) return false;
  if (m.isScan !== undefined && intent.isScan !== m.isScan) return false;
  if (m.interface !== undefined && intent.interface !== m.interface) return false;
  return true;
}

export function evaluateNetworkPolicy(
  intent: ParsedNetworkCommand,
  policy: NetworkPolicy,
): NetworkPolicyDecision {
  const matchedRules: NetworkPolicyRule[] = [];
  let allowed = true;
  let requiresDryRun = false;
  let requiresApproval = false;
  let currentRisk: RiskLevel = 'LOW';
  const messages: string[] = [];

  for (const rule of policy.rules) {
    if (!matchesRule(intent, rule)) continue;
    matchedRules.push(rule);
    currentRisk = escalateRisk(currentRisk, rule.riskLevel);

    switch (rule.action) {
      case 'deny':
        allowed = false;
        messages.push(rule.message ?? `Denied by rule: ${rule.id}`);
        break;
      case 'require_approval':
        requiresApproval = true;
        messages.push(rule.message ?? `Approval required: ${rule.id}`);
        break;
      case 'require_dry_run':
        requiresDryRun = true;
        messages.push(rule.message ?? `Dry-run required: ${rule.id}`);
        break;
      case 'allow':
        messages.push(rule.message ?? `Allowed: ${rule.id}`);
        break;
    }
  }

  if (matchedRules.length === 0) {
    currentRisk = policy.defaults.defaultRiskLevel;
    if (!policy.defaults.allowUnknown) {
      allowed = false;
      messages.push('No matching rule found and allowUnknown is false');
    } else {
      messages.push('No matching rule — default: allowed');
    }
  }

  // CRITICAL risk always forces dry-run + approval
  if (currentRisk === 'CRITICAL') {
    requiresDryRun = true;
    requiresApproval = true;
  }

  return {
    allowed,
    riskLevel: currentRisk,
    requiresDryRun,
    requiresApproval,
    matchedRules,
    message: messages.join('; '),
  };
}

// ─── Argv Builder ─────────────────────────────────────────────────────────────

/**
 * Build a safe argv from the parsed command, avoiding shell injection.
 * Strips shell metacharacters that have no place in single-command execution.
 */
function buildArgv(intent: ParsedNetworkCommand): string[] {
  const sanitized = intent.raw.replace(/[;&|`$]/g, '');
  return sanitized.split(/\s+/).filter(Boolean);
}

// ─── Adapter ──────────────────────────────────────────────────────────────────

/**
 * NetworkAdapter — SafeAdapter<ParsedNetworkCommand, NetworkSnapshot>
 *
 * Implements the 4-method gate interface for network configuration commands:
 *   parseIntent  → classify the raw command (iptables, ufw, ip, route, ssh, nmap, …)
 *   sandbox      → show current state before change; static analysis + deny checks
 *   execute      → run the command via spawnSync (no shell)
 *   rollback     → restore from pre-state snapshot (where supported)
 *
 * Security note: execute() uses spawnSync with shell:false to prevent injection.
 * Commands that pass DENY patterns never reach execute().
 */
export class NetworkAdapter implements SafeAdapter<ParsedNetworkCommand, NetworkSnapshot> {
  readonly name = 'network';

  parseIntent(raw: string): ParsedNetworkCommand {
    return parseNetworkCommand(raw);
  }

  async sandbox(intent: ParsedNetworkCommand): Promise<SimulationResult> {
    return simulateNetworkCommand(intent);
  }

  async execute(intent: ParsedNetworkCommand): Promise<AdapterExecutionResult> {
    const start = Date.now();
    const argv = buildArgv(intent);
    const [cli, ...args] = argv;

    if (!cli) {
      return {
        success: false,
        output: '',
        resourcesAffected: 0,
        durationMs: Date.now() - start,
        error: 'Empty command after sanitization',
      };
    }

    const result = spawnSync(cli, args, {
      timeout: 30_000,
      encoding: 'utf8',
      shell: false,
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
      resourcesAffected: 1,
      durationMs,
    };
  }

  async rollback(intent: ParsedNetworkCommand, snapshot: NetworkSnapshot): Promise<void> {
    const { tool } = intent;

    // For iptables: restore rules from pre-state using iptables-restore
    if (tool === 'iptables' && snapshot.preState) {
      const result = spawnSync('iptables-restore', [], {
        input: snapshot.preState,
        timeout: 10_000,
        encoding: 'utf8',
      });

      if (result.status !== 0) {
        throw new Error(
          `iptables-restore failed (exit ${result.status}): ${result.stderr ?? result.stdout}. ` +
          `Manual restoration required using snapshot from ${snapshot.timestamp.toISOString()}.`,
        );
      }
      return;
    }

    // For ip route / route: manual restoration is required
    throw new Error(
      `Automatic rollback is not supported for ${tool} commands. ` +
      `Pre-execution state was captured at ${snapshot.timestamp.toISOString()} ` +
      `(id: ${snapshot.commandId}). ` +
      `Pre-state:\n${snapshot.preState || '(not captured)'}`,
    );
  }
}
