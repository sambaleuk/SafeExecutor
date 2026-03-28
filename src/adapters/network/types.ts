import type { RiskLevel } from '../../types/index.js';

// ─── Network Tools ────────────────────────────────────────────────────────────

export type NetworkTool =
  | 'iptables'
  | 'ufw'
  | 'firewalld'
  | 'route'
  | 'ip'
  | 'dig'
  | 'nslookup'
  | 'netstat'
  | 'ss'
  | 'curl'
  | 'nmap'
  | 'tcpdump'
  | 'nc'
  | 'ssh-config'
  | 'ping'
  | 'traceroute'
  | 'host'
  | 'whois'
  | 'ssh'
  | 'scp'
  | 'rsync'
  | 'unknown';

// ─── Network Actions ──────────────────────────────────────────────────────────

export type NetworkAction =
  | 'configure'
  | 'delete'
  | 'scan'
  | 'tunnel'
  | 'redirect'
  | 'query'
  | 'monitor'
  | 'transfer'
  | 'unknown';

// ─── Dangerous Pattern ────────────────────────────────────────────────────────

export interface NetworkDangerousPattern {
  pattern: string;
  description: string;
  severity: 'HIGH' | 'CRITICAL' | 'DENY';
}

// ─── Parsed Network Command ───────────────────────────────────────────────────

/**
 * Parsed network command intent — TIntent for SafeAdapter<ParsedNetworkCommand, NetworkSnapshot>.
 */
export interface ParsedNetworkCommand {
  raw: string;
  tool: NetworkTool;
  action: NetworkAction;
  riskLevel: RiskLevel;
  isDestructive: boolean;
  /** True when the command modifies firewall rules */
  isFirewallModification: boolean;
  /** True when the command flushes/disables firewall entirely */
  isFirewallDisable: boolean;
  /** True when the command sets a network interface down */
  isInterfaceDown: boolean;
  /** True when the command removes the default route */
  isDefaultRouteRemoval: boolean;
  /** True when the command creates a tunnel (ssh -L/-R/-D) */
  isTunnel: boolean;
  /** True when the command performs a network scan */
  isScan: boolean;
  /** The network interface targeted (e.g. 'eth0', 'lo', 'ens3') */
  interface?: string;
  /** The target host or IP address */
  targetHost?: string;
  /** The chain targeted (INPUT, OUTPUT, FORWARD) for iptables */
  chain?: string;
  /** Named flags */
  flags: Record<string, string | boolean>;
  /** Detected dangerous patterns */
  dangerousPatterns: NetworkDangerousPattern[];
  metadata: Record<string, unknown>;
}

// ─── Snapshot ─────────────────────────────────────────────────────────────────

/**
 * State snapshot captured before execution — used by rollback().
 */
export interface NetworkSnapshot {
  commandId: string;
  timestamp: Date;
  /** Output of `iptables -L -n` or `ip route show` captured before change */
  preState: string;
  /** The tool that was used */
  tool: NetworkTool;
}

// ─── Policy types ─────────────────────────────────────────────────────────────

export interface NetworkRuleMatch {
  tools?: NetworkTool[];
  actions?: NetworkAction[];
  isFirewallModification?: boolean;
  isFirewallDisable?: boolean;
  isInterfaceDown?: boolean;
  isDefaultRouteRemoval?: boolean;
  isTunnel?: boolean;
  isScan?: boolean;
  interface?: string;
}

export interface NetworkPolicyRule {
  id: string;
  description: string;
  match: NetworkRuleMatch;
  action: 'allow' | 'deny' | 'require_approval' | 'require_dry_run';
  riskLevel: RiskLevel;
  message?: string;
}

export interface NetworkPolicy {
  version: string;
  rules: NetworkPolicyRule[];
  defaults: {
    allowUnknown: boolean;
    defaultRiskLevel: RiskLevel;
  };
}

export interface NetworkPolicyDecision {
  allowed: boolean;
  riskLevel: RiskLevel;
  requiresDryRun: boolean;
  requiresApproval: boolean;
  matchedRules: NetworkPolicyRule[];
  message: string;
}
