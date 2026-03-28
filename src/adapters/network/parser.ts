import type {
  ParsedNetworkCommand,
  NetworkTool,
  NetworkAction,
  NetworkDangerousPattern,
} from './types.js';
import type { RiskLevel } from '../../types/index.js';

const RISK_ORDER: RiskLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function escalateRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

// ─── Tool Detection ────────────────────────────────────────────────────────────

function detectTool(command: string): NetworkTool {
  const cmd = command.trim();
  const first = cmd.split(/\s+/)[0].toLowerCase();

  // ip6tables maps to iptables (same semantic, just IPv6)
  if (first === 'ip6tables') return 'iptables';

  switch (first) {
    case 'iptables': return 'iptables';
    case 'ufw':       return 'ufw';
    case 'firewall-cmd': return 'firewalld';
    case 'route':     return 'route';
    case 'ip':        return 'ip';
    case 'dig':       return 'dig';
    case 'nslookup':  return 'nslookup';
    case 'netstat':   return 'netstat';
    case 'ss':        return 'ss';
    case 'curl':      return 'curl';
    case 'nmap':      return 'nmap';
    case 'tcpdump':   return 'tcpdump';
    case 'nc':
    case 'netcat':    return 'nc';
    case 'ping':      return 'ping';
    case 'traceroute':
    case 'tracepath': return 'traceroute';
    case 'host':      return 'host';
    case 'whois':     return 'whois';
    case 'ssh':       return 'ssh';
    case 'scp':       return 'scp';
    case 'rsync':     return 'rsync';
    default:
      // ssh-config detection via file manipulation
      if (/ssh.*config/i.test(cmd)) return 'ssh-config';
      return 'unknown';
  }
}

// ─── Flag Parsing ─────────────────────────────────────────────────────────────

function parseFlags(tokens: string[]): Record<string, string | boolean> {
  const flags: Record<string, string | boolean> = {};
  let i = 0;
  while (i < tokens.length) {
    const token = tokens[i];
    if (token.startsWith('-')) {
      const key = token.replace(/^-+/, '');
      if (key.includes('=')) {
        const eqIdx = key.indexOf('=');
        flags[key.slice(0, eqIdx)] = key.slice(eqIdx + 1);
        i++;
      } else {
        const next = tokens[i + 1];
        if (next !== undefined && !next.startsWith('-')) {
          flags[key] = next;
          i += 2;
        } else {
          flags[key] = true;
          i++;
        }
      }
    } else {
      i++;
    }
  }
  return flags;
}

// ─── Action Classification ────────────────────────────────────────────────────

function detectAction(command: string, tool: NetworkTool): NetworkAction {
  const cmd = command.toLowerCase();

  switch (tool) {
    case 'iptables':
      if (/-[AIC]\b/.test(cmd) || /--append|--insert/.test(cmd)) return 'configure';
      if (/-[DFX]\b/.test(cmd) || /--delete|--flush|--zero/.test(cmd)) return 'delete';
      if (/-[LP]\b/.test(cmd) || /--list|--policy/.test(cmd)) return 'query';
      return 'configure';

    case 'ufw':
      if (/\ballow\b|\bdeny\b|\breject\b|\blimit\b/.test(cmd)) return 'configure';
      if (/\bdelete\b/.test(cmd)) return 'delete';
      if (/\bdisable\b|\benable\b|\breset\b/.test(cmd)) return 'configure';
      if (/\bstatus\b/.test(cmd)) return 'query';
      return 'configure';

    case 'firewalld':
      if (/--add/.test(cmd)) return 'configure';
      if (/--remove/.test(cmd)) return 'delete';
      if (/--list|--query/.test(cmd)) return 'query';
      return 'configure';

    case 'route':
      if (/\badd\b/.test(cmd)) return 'configure';
      if (/\bdel\b|\bdelete\b/.test(cmd)) return 'delete';
      return 'query';

    case 'ip':
      if (/route\s+add|addr\s+add|link\s+add/.test(cmd)) return 'configure';
      if (/route\s+del|addr\s+del|link\s+del/.test(cmd)) return 'delete';
      if (/link\s+set/.test(cmd)) return 'configure';
      if (/route\s+show|addr\s+show|link\s+show/.test(cmd)) return 'query';
      return 'query';

    case 'ssh':
      if (/-[LRD]\b/.test(cmd)) return 'tunnel';
      return 'transfer';

    case 'scp':
    case 'rsync':
      return 'transfer';

    case 'nmap':
      return 'scan';

    case 'tcpdump':
      return 'monitor';

    case 'nc':
      if (/-l\b/.test(cmd)) return 'configure'; // listening mode
      return 'tunnel';

    case 'curl':
      if (/-X\s+POST|-X\s+PUT|-X\s+DELETE|--data|--upload-file/.test(cmd)) return 'configure';
      return 'query';

    case 'dig':
    case 'nslookup':
    case 'host':
    case 'whois':
    case 'ping':
    case 'traceroute':
    case 'netstat':
    case 'ss':
      return 'query';

    default:
      return 'unknown';
  }
}

// ─── Interface Extraction ─────────────────────────────────────────────────────

function extractInterface(command: string, tool: NetworkTool): string | undefined {
  // ip link set <iface> down/up
  if (tool === 'ip') {
    const m = command.match(/link\s+set\s+([\w@.-]+)/);
    if (m) return m[1];
    const m2 = command.match(/-i\s+([\w@.-]+)/);
    if (m2) return m2[1];
  }
  // iptables -i <iface>
  const m = command.match(/(?:-i|-o)\s+([\w@.-]+)/);
  if (m) return m[1];
  // tcpdump -i <iface>
  const m2 = command.match(/-i\s+([\w@.-]+)/);
  if (m2) return m2[1];
  return undefined;
}

// ─── Target Host Extraction ───────────────────────────────────────────────────

function extractTargetHost(command: string, tool: NetworkTool): string | undefined {
  const tokens = command.trim().split(/\s+/);

  switch (tool) {
    case 'dig':
    case 'nslookup':
    case 'host':
    case 'whois':
    case 'ping':
    case 'traceroute':
    case 'nmap':
      // Last non-flag argument is typically the host
      for (let i = tokens.length - 1; i >= 1; i--) {
        if (!tokens[i].startsWith('-')) return tokens[i];
      }
      break;

    case 'curl': {
      // Find URL: could be positional or after --url
      const urlMatch = command.match(/--url\s+(\S+)/) ?? command.match(/https?:\/\/\S+/);
      if (urlMatch) return urlMatch[1];
      break;
    }

    case 'ssh':
    case 'scp': {
      // ssh [opts] user@host or host
      const m = command.match(/(?:@|ssh\s+(?:-\S+\s+)*)([\w.-]+)/);
      if (m) return m[1];
      break;
    }

    case 'nc': {
      // nc [opts] host port
      const args = tokens.slice(1).filter(t => !t.startsWith('-'));
      if (args[0]) return args[0];
      break;
    }

    default:
      break;
  }
  return undefined;
}

// ─── Chain Extraction (iptables) ──────────────────────────────────────────────

function extractChain(command: string): string | undefined {
  // iptables -A INPUT / -F OUTPUT / etc.
  const m = command.match(/(?:-[ADIFLPZNXE]|--(append|delete|insert|flush|list|policy|zero|new-chain|delete-chain|rename-chain))\s+(INPUT|OUTPUT|FORWARD|PREROUTING|POSTROUTING)/i);
  if (m) return m[2].toUpperCase();
  // iptables -F (no chain = all chains)
  if (/-F\b/.test(command) && !/INPUT|OUTPUT|FORWARD/.test(command.toUpperCase())) return undefined;
  return undefined;
}

// ─── Dangerous Pattern Detection ─────────────────────────────────────────────

const DANGEROUS_PATTERNS: Array<{
  regex: RegExp;
  pattern: string;
  description: string;
  severity: NetworkDangerousPattern['severity'];
}> = [
  // DENY patterns
  {
    regex: /iptables\s+.*-F\s+(INPUT|PREROUTING)\b/i,
    pattern: 'iptables-flush-input',
    description: 'Flushing INPUT chain removes all firewall rules — locks you out of the system',
    severity: 'DENY',
  },
  {
    regex: /ip\s+link\s+set\s+lo\s+down/i,
    pattern: 'loopback-down',
    description: 'Disabling loopback interface (lo) breaks local services and DNS resolution',
    severity: 'DENY',
  },
  {
    regex: /^route\s+del\s+default\b/i,
    pattern: 'route-del-default',
    description: 'Removing the default route cuts off all outbound network access',
    severity: 'DENY',
  },
  {
    regex: /ip\s+route\s+del\s+default\b/i,
    pattern: 'ip-route-del-default',
    description: 'Removing the default route cuts off all outbound network access',
    severity: 'DENY',
  },

  // CRITICAL patterns
  {
    regex: /iptables\s+.*-F\b(?!\s+(OUTPUT|FORWARD))/i,
    pattern: 'iptables-flush-all',
    description: 'Flushing all iptables rules removes all firewall protection',
    severity: 'CRITICAL',
  },
  {
    regex: /ufw\s+disable\b/i,
    pattern: 'ufw-disable',
    description: 'Disabling UFW removes all firewall protection',
    severity: 'CRITICAL',
  },
  {
    regex: /ufw\s+reset\b/i,
    pattern: 'ufw-reset',
    description: 'Resetting UFW removes all custom rules',
    severity: 'CRITICAL',
  },

  // HIGH patterns
  {
    regex: /iptables\s+.*-[AIC]\b/i,
    pattern: 'iptables-rule-add',
    description: 'Adding iptables rule modifies firewall security policy',
    severity: 'HIGH',
  },
  {
    regex: /ip\s+link\s+set\s+\S+\s+down\b/i,
    pattern: 'interface-down',
    description: 'Setting a network interface down disrupts connectivity',
    severity: 'HIGH',
  },
  {
    regex: /ssh\s+.*-[LRD]\s+/i,
    pattern: 'ssh-tunnel',
    description: 'SSH tunnel opens a persistent forwarding channel to an external host',
    severity: 'HIGH',
  },
  {
    regex: /nmap\b/i,
    pattern: 'nmap-scan',
    description: 'Network scanning has legal implications and may trigger security alerts',
    severity: 'HIGH',
  },
  {
    regex: /ip\s+route\s+add\b/i,
    pattern: 'route-add',
    description: 'Adding a route can redirect traffic and affect network connectivity',
    severity: 'HIGH',
  },
  {
    regex: /ip\s+route\s+del\b(?!.*default)/i,
    pattern: 'route-delete',
    description: 'Deleting a route can disrupt network connectivity',
    severity: 'HIGH',
  },
  {
    regex: /ufw\s+(allow|deny|reject)\b/i,
    pattern: 'ufw-rule-modify',
    description: 'Modifying UFW allow/deny rules changes firewall security policy',
    severity: 'HIGH',
  },
];

function detectDangerousPatterns(command: string): NetworkDangerousPattern[] {
  const results: NetworkDangerousPattern[] = [];
  const seen = new Set<string>();

  for (const dp of DANGEROUS_PATTERNS) {
    if (dp.regex.test(command) && !seen.has(dp.pattern)) {
      seen.add(dp.pattern);
      results.push({ pattern: dp.pattern, description: dp.description, severity: dp.severity });
    }
  }

  return results;
}

// ─── Risk Classification ──────────────────────────────────────────────────────

/**
 * Risk levels by tool/action, matching the spec:
 * LOW:      dig, nslookup, ping, traceroute, netstat, ss, ip addr show, host, whois
 * MEDIUM:   curl (POST/PUT/DELETE), ssh, scp, rsync, ip route show
 * HIGH:     iptables -A, ufw allow/deny, ip route add/del, ssh tunnels, nmap
 * CRITICAL: iptables -F, ufw disable, ip link set down, route del default
 * DENY:     iptables -F INPUT, ip link set lo down
 */
function classifyRisk(
  tool: NetworkTool,
  action: NetworkAction,
  command: string,
  dangerousPatterns: NetworkDangerousPattern[],
): RiskLevel {
  let risk: RiskLevel = 'LOW';

  // Base risk by tool
  switch (tool) {
    case 'dig':
    case 'nslookup':
    case 'host':
    case 'whois':
    case 'ping':
    case 'traceroute':
    case 'netstat':
    case 'ss':
      risk = 'LOW';
      break;

    case 'curl':
      if (/(-X\s+(POST|PUT|DELETE|PATCH)|--data|--upload-file)/i.test(command)) {
        risk = 'MEDIUM';
      } else {
        risk = 'LOW';
      }
      break;

    case 'ssh':
      risk = 'MEDIUM';
      if (/-[LRD]\b/.test(command)) risk = 'HIGH'; // tunnels
      break;

    case 'scp':
    case 'rsync':
      risk = 'MEDIUM';
      break;

    case 'ip':
      if (/addr\s+show|link\s+show|route\s+show/.test(command)) {
        risk = 'LOW';
      } else if (/route\s+show/.test(command)) {
        risk = 'MEDIUM';
      } else if (/route\s+add|route\s+del/.test(command)) {
        risk = 'HIGH';
      } else if (/link\s+set\s+\S+\s+down/.test(command)) {
        risk = 'CRITICAL';
      } else {
        risk = 'MEDIUM';
      }
      break;

    case 'route':
      if (/\bdel\b/.test(command)) risk = 'CRITICAL';
      else if (/\badd\b/.test(command)) risk = 'HIGH';
      else risk = 'MEDIUM';
      break;

    case 'iptables':
      if (/-F\b/.test(command)) risk = 'CRITICAL';
      else if (/-[AIC]\b/.test(command)) risk = 'HIGH';
      else if (/-[DX]\b/.test(command)) risk = 'HIGH';
      else risk = 'MEDIUM';
      break;

    case 'ufw':
      if (/\bdisable\b|\breset\b/.test(command)) risk = 'CRITICAL';
      else if (/\ballow\b|\bdeny\b|\breject\b/.test(command)) risk = 'HIGH';
      else risk = 'MEDIUM';
      break;

    case 'firewalld':
      if (/--remove/.test(command)) risk = 'HIGH';
      else if (/--add/.test(command)) risk = 'HIGH';
      else risk = 'MEDIUM';
      break;

    case 'nmap':
      risk = 'HIGH';
      break;

    case 'tcpdump':
      risk = 'MEDIUM';
      break;

    case 'nc':
      risk = 'MEDIUM';
      break;

    case 'ssh-config':
      risk = 'MEDIUM';
      break;

    default:
      risk = 'MEDIUM';
  }

  // Dangerous pattern escalation
  for (const dp of dangerousPatterns) {
    if (dp.severity === 'DENY' || dp.severity === 'CRITICAL') {
      risk = escalateRisk(risk, 'CRITICAL');
    } else if (dp.severity === 'HIGH') {
      risk = escalateRisk(risk, 'HIGH');
    }
  }

  // action-level: query is never more than LOW for read-only tools
  if (action === 'query' && (tool === 'dig' || tool === 'nslookup' || tool === 'host' || tool === 'whois' || tool === 'ping' || tool === 'traceroute' || tool === 'netstat' || tool === 'ss')) {
    risk = 'LOW';
  }

  return risk;
}

// ─── Main Parser ──────────────────────────────────────────────────────────────

export function parseNetworkCommand(raw: string): ParsedNetworkCommand {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('Empty command');

  const tokens = trimmed.split(/\s+/);
  const tool = detectTool(trimmed);
  const action = detectAction(trimmed, tool);
  const iface = extractInterface(trimmed, tool);
  const targetHost = extractTargetHost(trimmed, tool);
  const chain = extractChain(trimmed);
  const flags = parseFlags(tokens.slice(1));
  const dangerousPatterns = detectDangerousPatterns(trimmed);
  const riskLevel = classifyRisk(tool, action, trimmed, dangerousPatterns);

  const isFirewallModification =
    (tool === 'iptables' && /-[AICDXFP]\b/.test(trimmed)) ||
    (tool === 'ufw' && /\b(allow|deny|reject|delete|limit)\b/.test(trimmed)) ||
    (tool === 'firewalld' && /--(?:add|remove)-(?:port|service|rule)/.test(trimmed));

  const isFirewallDisable =
    (tool === 'iptables' && /-F\b/.test(trimmed)) ||
    (tool === 'ufw' && /\bdisable\b/.test(trimmed)) ||
    (tool === 'ufw' && /\breset\b/.test(trimmed));

  const isInterfaceDown =
    (tool === 'ip' && /link\s+set\s+\S+\s+down\b/.test(trimmed));

  const isDefaultRouteRemoval =
    (tool === 'route' && /\bdel\b.*\bdefault\b/.test(trimmed)) ||
    (tool === 'ip' && /route\s+del.*\bdefault\b/.test(trimmed));

  const isTunnel =
    (tool === 'ssh' && /-[LRD]\b/.test(trimmed)) ||
    (tool === 'nc' && !/-l\b/.test(trimmed));

  const isScan = tool === 'nmap' || tool === 'tcpdump';

  const isDestructive =
    isFirewallDisable ||
    isInterfaceDown ||
    isDefaultRouteRemoval ||
    dangerousPatterns.some(dp => dp.severity === 'DENY' || dp.severity === 'CRITICAL');

  return {
    raw: trimmed,
    tool,
    action,
    riskLevel,
    isDestructive,
    isFirewallModification,
    isFirewallDisable,
    isInterfaceDown,
    isDefaultRouteRemoval,
    isTunnel,
    isScan,
    interface: iface,
    targetHost,
    chain,
    flags,
    dangerousPatterns,
    metadata: {},
  };
}
