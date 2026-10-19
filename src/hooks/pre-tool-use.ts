/**
 * Claude Code PreToolUse hook for the Bash tool.
 *
 * The MCP tools only advise: the model decides whether to call them. This
 * hook runs on every Bash call before execution, so the verdict no longer
 * depends on the model. It can only tighten permissions:
 *
 *   - CRITICAL                      → "deny" (the command does not run)
 *   - any other blocked verdict     → "ask"  (HIGH risk, unrecognized or
 *                                             unanalyzable: a human decides)
 *   - allowed                       → no output, the normal permission
 *                                     flow applies (never "allow")
 *
 * Malformed input or an internal error yields "deny" (fail-closed).
 */

import { analyzeShellCommand } from '../mcp-server/tools.js';
import type { RiskLevel } from '../types/index.js';

export interface PreToolUseOutput {
  hookSpecificOutput: {
    hookEventName: 'PreToolUse';
    permissionDecision: 'deny' | 'ask';
    permissionDecisionReason: string;
  };
}

interface HookInput {
  tool_name?: unknown;
  tool_input?: { command?: unknown };
}

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function output(permissionDecision: 'deny' | 'ask', reason: string): PreToolUseOutput {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision,
      permissionDecisionReason: `SafeExecutor: ${reason}`,
    },
  };
}

/**
 * Maps the hook's stdin payload to a PreToolUse decision, or null to defer
 * to Claude Code's normal permission flow.
 */
export async function preToolUseResponse(rawInput: string): Promise<PreToolUseOutput | null> {
  try {
    const input = JSON.parse(rawInput) as HookInput;
    if (input.tool_name !== 'Bash') return null;

    const command = input.tool_input?.command;
    if (typeof command !== 'string') {
      return output('deny', 'Bash call without a command string — refusing to guess');
    }

    const result = await analyzeShellCommand(command);
    if (!result.blocked) return null;

    const flagged = result.segments
      .filter((s) => s.blocked)
      .sort((a, b) => RISK_ORDER.indexOf(b.riskLevel) - RISK_ORDER.indexOf(a.riskLevel))
      .map((s) => `\`${s.command}\` (${s.domain}, ${s.riskLevel})${s.reason ? `: ${s.reason}` : ''}`);
    const detail = flagged.length > 0 ? flagged.join('; ') : `${result.domain}, ${result.riskLevel}`;

    return result.riskLevel === 'CRITICAL'
      ? output('deny', `blocked — ${detail}`)
      : output('ask', `needs confirmation — ${detail}`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return output('deny', `hook failed, refusing by default: ${message}`);
  }
}
