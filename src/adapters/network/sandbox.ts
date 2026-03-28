import { spawnSync } from 'child_process';
import type { SimulationResult } from '../../core/types.js';
import type { ParsedNetworkCommand } from './types.js';

// ─── Pre-state capture ────────────────────────────────────────────────────────

/**
 * Capture current state before a modification so the user can see what will change.
 * Returns an empty string if the capture command fails (non-fatal).
 */
function capturePreState(intent: ParsedNetworkCommand): string {
  const { tool } = intent;

  let captureCmd: string[] | null = null;

  switch (tool) {
    case 'iptables':
      captureCmd = ['iptables', '-L', '-n', '--line-numbers'];
      break;
    case 'ufw':
      captureCmd = ['ufw', 'status', 'verbose'];
      break;
    case 'firewalld':
      captureCmd = ['firewall-cmd', '--list-all'];
      break;
    case 'ip':
      if (/route/.test(intent.raw)) {
        captureCmd = ['ip', 'route', 'show'];
      } else if (/link/.test(intent.raw)) {
        captureCmd = ['ip', 'link', 'show'];
      } else if (/addr/.test(intent.raw)) {
        captureCmd = ['ip', 'addr', 'show'];
      }
      break;
    case 'route':
      captureCmd = ['ip', 'route', 'show'];
      break;
    default:
      break;
  }

  if (!captureCmd) return '';

  const result = spawnSync(captureCmd[0], captureCmd.slice(1), {
    timeout: 5_000,
    encoding: 'utf8',
  });

  if (result.error || result.status !== 0) return '';
  return (result.stdout ?? '').trim();
}

// ─── Dry-run check helpers ────────────────────────────────────────────────────

/**
 * For iptables: use --check to verify a rule would succeed.
 * Only meaningful for -A (append) operations — we convert to --check first.
 */
function dryRunIptables(intent: ParsedNetworkCommand): { ok: boolean; output: string } {
  // Only attempt --check on append operations (not flush/delete)
  if (!/-[AIC]\b/.test(intent.raw)) {
    return { ok: true, output: '' };
  }

  const checkCmd = intent.raw.replace(/-A\b/, '--check').replace(/-I\b/, '--check');
  const tokens = checkCmd.trim().split(/\s+/);

  const result = spawnSync(tokens[0], tokens.slice(1), {
    timeout: 5_000,
    encoding: 'utf8',
  });

  // Exit 0 = rule exists (can be appended), exit 1 = rule does not exist (append will create it)
  // Both are acceptable for an append operation
  if (result.error) {
    return { ok: true, output: 'iptables --check not available; skipping pre-check' };
  }

  const output = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
  return { ok: true, output };
}

// ─── Build dry-run summary ────────────────────────────────────────────────────

function buildSummary(
  intent: ParsedNetworkCommand,
  preState: string,
  warnings: string[],
): string {
  const lines: string[] = [
    '[DRY-RUN] Network Command Preview',
    `Tool      : ${intent.tool}`,
    `Action    : ${intent.action}`,
    `Risk      : ${intent.riskLevel}`,
  ];

  if (intent.interface) lines.push(`Interface : ${intent.interface}`);
  if (intent.targetHost) lines.push(`Target    : ${intent.targetHost}`);
  if (intent.chain) lines.push(`Chain     : ${intent.chain}`);

  if (preState) {
    lines.push('');
    lines.push('Current State (before change):');
    // Truncate to avoid overwhelming output
    const stateLines = preState.split('\n').slice(0, 20);
    for (const l of stateLines) lines.push(`  ${l}`);
    if (preState.split('\n').length > 20) lines.push('  … (truncated)');
  }

  if (warnings.length > 0) {
    lines.push('');
    lines.push('Warnings:');
    for (const w of warnings) lines.push(`  ⚠  ${w}`);
  }

  return lines.join('\n');
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function simulateNetworkCommand(
  intent: ParsedNetworkCommand,
): Promise<SimulationResult> {
  const start = Date.now();
  const warnings: string[] = [];

  // ── DENY patterns — hard stop ──────────────────────────────────────────────
  for (const dp of intent.dangerousPatterns) {
    if (dp.severity === 'DENY') {
      return {
        feasible: false,
        resourcesImpacted: 0,
        summary: `DENIED: ${dp.description}`,
        warnings: [`Dangerous pattern '${dp.pattern}': ${dp.description}`],
        durationMs: Date.now() - start,
      };
    }
  }

  // ── Collect warnings from dangerous patterns ───────────────────────────────
  for (const dp of intent.dangerousPatterns) {
    if (dp.severity === 'CRITICAL' || dp.severity === 'HIGH') {
      warnings.push(`${dp.severity}: ${dp.description}`);
    }
  }

  // ── Firewall disable — strong warning ─────────────────────────────────────
  if (intent.isFirewallDisable) {
    warnings.push('This command will disable or flush ALL firewall rules — system will be unprotected');
  }

  // ── Interface down ─────────────────────────────────────────────────────────
  if (intent.isInterfaceDown) {
    const iface = intent.interface ?? 'unknown';
    warnings.push(`This command will bring interface '${iface}' down — all traffic through this interface will be interrupted`);
  }

  // ── Default route removal ──────────────────────────────────────────────────
  if (intent.isDefaultRouteRemoval) {
    warnings.push('This command will remove the default route — outbound internet access will be lost');
  }

  // ── Tunnel warning ─────────────────────────────────────────────────────────
  if (intent.isTunnel) {
    const host = intent.targetHost ?? 'unknown host';
    warnings.push(`SSH tunnel will forward traffic to '${host}' — ensure this host is trusted`);
  }

  // ── Scan warning ──────────────────────────────────────────────────────────
  if (intent.isScan && intent.tool === 'nmap') {
    const target = intent.targetHost ?? 'target';
    warnings.push(`nmap scan of '${target}' may have legal implications — ensure you have explicit authorization`);
  }

  // ── Capture current state for modifying operations ─────────────────────────
  let preState = '';
  if (intent.isFirewallModification || intent.isInterfaceDown || intent.isDefaultRouteRemoval) {
    preState = capturePreState(intent);
  }

  // ── iptables dry-run check ─────────────────────────────────────────────────
  if (intent.tool === 'iptables' && intent.action === 'configure') {
    const check = dryRunIptables(intent);
    if (check.output) {
      warnings.push(`iptables pre-check: ${check.output}`);
    }
  }

  const summary = buildSummary(intent, preState, warnings);

  return {
    feasible: true,
    resourcesImpacted: 1,
    summary,
    warnings,
    durationMs: Date.now() - start,
  };
}
