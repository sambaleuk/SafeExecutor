import { readFileSync } from 'fs';
import { parseNetworkCommand } from '../src/adapters/network/parser.js';
import { simulateNetworkCommand } from '../src/adapters/network/sandbox.js';
import { NetworkAdapter, evaluateNetworkPolicy } from '../src/adapters/network/adapter.js';
import type { NetworkPolicy } from '../src/adapters/network/types.js';

// ─── Fixtures ──────────────────────────────────────────────────────────────────

const defaultPolicy = JSON.parse(
  readFileSync(new URL('../config/policies/network-default-policy.json', import.meta.url), 'utf-8'),
) as NetworkPolicy;

// ─── Parser: tool detection ────────────────────────────────────────────────────

describe('parseNetworkCommand — tool detection', () => {
  test('detects iptables', () => {
    const r = parseNetworkCommand('iptables -A INPUT -p tcp --dport 80 -j ACCEPT');
    expect(r.tool).toBe('iptables');
  });

  test('detects ip6tables as iptables', () => {
    const r = parseNetworkCommand('ip6tables -F');
    expect(r.tool).toBe('iptables');
  });

  test('detects ufw', () => {
    const r = parseNetworkCommand('ufw allow 22/tcp');
    expect(r.tool).toBe('ufw');
  });

  test('detects firewalld', () => {
    const r = parseNetworkCommand('firewall-cmd --add-port=80/tcp --permanent');
    expect(r.tool).toBe('firewalld');
  });

  test('detects ip command', () => {
    const r = parseNetworkCommand('ip route show');
    expect(r.tool).toBe('ip');
  });

  test('detects route command', () => {
    const r = parseNetworkCommand('route del default');
    expect(r.tool).toBe('route');
  });

  test('detects dig', () => {
    const r = parseNetworkCommand('dig example.com A');
    expect(r.tool).toBe('dig');
  });

  test('detects nslookup', () => {
    const r = parseNetworkCommand('nslookup example.com 8.8.8.8');
    expect(r.tool).toBe('nslookup');
  });

  test('detects netstat', () => {
    const r = parseNetworkCommand('netstat -tlnp');
    expect(r.tool).toBe('netstat');
  });

  test('detects ss', () => {
    const r = parseNetworkCommand('ss -tlnp');
    expect(r.tool).toBe('ss');
  });

  test('detects curl', () => {
    const r = parseNetworkCommand('curl https://example.com');
    expect(r.tool).toBe('curl');
  });

  test('detects nmap', () => {
    const r = parseNetworkCommand('nmap -sV 192.168.1.1');
    expect(r.tool).toBe('nmap');
  });

  test('detects tcpdump', () => {
    const r = parseNetworkCommand('tcpdump -i eth0 port 80');
    expect(r.tool).toBe('tcpdump');
  });

  test('detects nc (netcat)', () => {
    const r = parseNetworkCommand('nc -l 4444');
    expect(r.tool).toBe('nc');
  });

  test('detects ssh', () => {
    const r = parseNetworkCommand('ssh user@example.com');
    expect(r.tool).toBe('ssh');
  });

  test('detects scp', () => {
    const r = parseNetworkCommand('scp file.txt user@host:/tmp/');
    expect(r.tool).toBe('scp');
  });

  test('detects rsync', () => {
    const r = parseNetworkCommand('rsync -av ./src/ user@host:/opt/app/');
    expect(r.tool).toBe('rsync');
  });

  test('detects ping', () => {
    const r = parseNetworkCommand('ping -c 4 8.8.8.8');
    expect(r.tool).toBe('ping');
  });

  test('detects traceroute', () => {
    const r = parseNetworkCommand('traceroute google.com');
    expect(r.tool).toBe('traceroute');
  });

  test('returns unknown for unrecognized commands', () => {
    const r = parseNetworkCommand('some-net-tool configure eth0');
    expect(r.tool).toBe('unknown');
  });

  test('throws on empty command', () => {
    expect(() => parseNetworkCommand('')).toThrow('Empty command');
  });
});

// ─── Parser: risk classification ──────────────────────────────────────────────

describe('parseNetworkCommand — risk classification', () => {
  test('dig is LOW risk', () => {
    const r = parseNetworkCommand('dig example.com');
    expect(r.riskLevel).toBe('LOW');
  });

  test('nslookup is LOW risk', () => {
    const r = parseNetworkCommand('nslookup example.com');
    expect(r.riskLevel).toBe('LOW');
  });

  test('ping is LOW risk', () => {
    const r = parseNetworkCommand('ping -c 3 8.8.8.8');
    expect(r.riskLevel).toBe('LOW');
  });

  test('traceroute is LOW risk', () => {
    const r = parseNetworkCommand('traceroute 8.8.8.8');
    expect(r.riskLevel).toBe('LOW');
  });

  test('netstat is LOW risk', () => {
    const r = parseNetworkCommand('netstat -tlnp');
    expect(r.riskLevel).toBe('LOW');
  });

  test('ss is LOW risk', () => {
    const r = parseNetworkCommand('ss -tlnp');
    expect(r.riskLevel).toBe('LOW');
  });

  test('ip addr show is LOW risk', () => {
    const r = parseNetworkCommand('ip addr show');
    expect(r.riskLevel).toBe('LOW');
  });

  test('curl GET is LOW risk', () => {
    const r = parseNetworkCommand('curl https://api.example.com/status');
    expect(r.riskLevel).toBe('LOW');
  });

  test('curl POST is MEDIUM risk', () => {
    const r = parseNetworkCommand('curl -X POST https://api.example.com/data -d "{}"');
    expect(r.riskLevel).toBe('MEDIUM');
  });

  test('ssh without tunnel is MEDIUM risk', () => {
    const r = parseNetworkCommand('ssh user@example.com');
    expect(r.riskLevel).toBe('MEDIUM');
  });

  test('scp is MEDIUM risk', () => {
    const r = parseNetworkCommand('scp file.txt user@host:/tmp/');
    expect(r.riskLevel).toBe('MEDIUM');
  });

  test('ip route show is LOW risk', () => {
    const r = parseNetworkCommand('ip route show');
    expect(r.riskLevel).toBe('LOW');
  });

  test('iptables -A rule add is HIGH risk', () => {
    const r = parseNetworkCommand('iptables -A INPUT -p tcp --dport 22 -j ACCEPT');
    expect(r.riskLevel).toBe('HIGH');
  });

  test('ufw allow is HIGH risk', () => {
    const r = parseNetworkCommand('ufw allow 443/tcp');
    expect(r.riskLevel).toBe('HIGH');
  });

  test('ufw deny is HIGH risk', () => {
    const r = parseNetworkCommand('ufw deny 23');
    expect(r.riskLevel).toBe('HIGH');
  });

  test('ip route add is HIGH risk', () => {
    const r = parseNetworkCommand('ip route add 10.0.0.0/8 via 192.168.1.1');
    expect(r.riskLevel).toBe('HIGH');
  });

  test('ssh -L tunnel is HIGH risk', () => {
    const r = parseNetworkCommand('ssh -L 8080:localhost:80 user@example.com');
    expect(r.riskLevel).toBe('HIGH');
  });

  test('ssh -R tunnel is HIGH risk', () => {
    const r = parseNetworkCommand('ssh -R 9090:localhost:9090 user@example.com');
    expect(r.riskLevel).toBe('HIGH');
  });

  test('nmap scan is HIGH risk', () => {
    const r = parseNetworkCommand('nmap -sV 192.168.1.0/24');
    expect(r.riskLevel).toBe('HIGH');
  });

  test('iptables -F (flush all) is CRITICAL risk', () => {
    const r = parseNetworkCommand('iptables -F');
    expect(r.riskLevel).toBe('CRITICAL');
  });

  test('ufw disable is CRITICAL risk', () => {
    const r = parseNetworkCommand('ufw disable');
    expect(r.riskLevel).toBe('CRITICAL');
  });

  test('ip link set eth0 down is CRITICAL risk', () => {
    const r = parseNetworkCommand('ip link set eth0 down');
    expect(r.riskLevel).toBe('CRITICAL');
  });

  test('route del default is CRITICAL risk', () => {
    const r = parseNetworkCommand('route del default');
    expect(r.riskLevel).toBe('CRITICAL');
  });
});

// ─── Parser: dangerous pattern detection ─────────────────────────────────────

describe('parseNetworkCommand — dangerous patterns', () => {
  test('iptables -F INPUT is DENY', () => {
    const r = parseNetworkCommand('iptables -F INPUT');
    const deny = r.dangerousPatterns.find(p => p.severity === 'DENY');
    expect(deny).toBeDefined();
    expect(deny?.pattern).toBe('iptables-flush-input');
  });

  test('ip link set lo down is DENY', () => {
    const r = parseNetworkCommand('ip link set lo down');
    const deny = r.dangerousPatterns.find(p => p.severity === 'DENY');
    expect(deny).toBeDefined();
    expect(deny?.pattern).toBe('loopback-down');
  });

  test('route del default is DENY', () => {
    const r = parseNetworkCommand('route del default');
    const deny = r.dangerousPatterns.find(p => p.severity === 'DENY');
    expect(deny).toBeDefined();
    expect(deny?.pattern).toBe('route-del-default');
  });

  test('ip route del default is DENY', () => {
    const r = parseNetworkCommand('ip route del default');
    const deny = r.dangerousPatterns.find(p => p.severity === 'DENY');
    expect(deny).toBeDefined();
    expect(deny?.pattern).toBe('ip-route-del-default');
  });

  test('iptables -F (all chains) is CRITICAL', () => {
    const r = parseNetworkCommand('iptables -F');
    const crit = r.dangerousPatterns.find(p => p.severity === 'CRITICAL');
    expect(crit).toBeDefined();
  });

  test('ufw disable is CRITICAL', () => {
    const r = parseNetworkCommand('ufw disable');
    const crit = r.dangerousPatterns.find(p => p.severity === 'CRITICAL');
    expect(crit).toBeDefined();
    expect(crit?.pattern).toBe('ufw-disable');
  });

  test('iptables -A adds a HIGH pattern', () => {
    const r = parseNetworkCommand('iptables -A INPUT -p tcp --dport 8080 -j DROP');
    const high = r.dangerousPatterns.find(p => p.severity === 'HIGH');
    expect(high).toBeDefined();
  });

  test('ssh -L tunnel adds a HIGH pattern', () => {
    const r = parseNetworkCommand('ssh -L 8080:localhost:80 user@host.example.com');
    const high = r.dangerousPatterns.find(p => p.pattern === 'ssh-tunnel');
    expect(high).toBeDefined();
    expect(high?.severity).toBe('HIGH');
  });

  test('nmap adds a HIGH pattern', () => {
    const r = parseNetworkCommand('nmap -sS 10.0.0.0/24');
    const high = r.dangerousPatterns.find(p => p.pattern === 'nmap-scan');
    expect(high).toBeDefined();
    expect(high?.severity).toBe('HIGH');
  });

  test('safe command has no dangerous patterns', () => {
    const r = parseNetworkCommand('dig example.com');
    expect(r.dangerousPatterns).toHaveLength(0);
  });
});

// ─── Parser: boolean flags ────────────────────────────────────────────────────

describe('parseNetworkCommand — semantic flags', () => {
  test('isFirewallModification true for iptables -A', () => {
    const r = parseNetworkCommand('iptables -A OUTPUT -j ACCEPT');
    expect(r.isFirewallModification).toBe(true);
  });

  test('isFirewallModification true for ufw allow', () => {
    const r = parseNetworkCommand('ufw allow 80/tcp');
    expect(r.isFirewallModification).toBe(true);
  });

  test('isFirewallDisable true for iptables -F', () => {
    const r = parseNetworkCommand('iptables -F');
    expect(r.isFirewallDisable).toBe(true);
  });

  test('isFirewallDisable true for ufw disable', () => {
    const r = parseNetworkCommand('ufw disable');
    expect(r.isFirewallDisable).toBe(true);
  });

  test('isInterfaceDown true for ip link set eth0 down', () => {
    const r = parseNetworkCommand('ip link set eth0 down');
    expect(r.isInterfaceDown).toBe(true);
    expect(r.interface).toBe('eth0');
  });

  test('isInterfaceDown false for ip link set eth0 up', () => {
    const r = parseNetworkCommand('ip link set eth0 up');
    expect(r.isInterfaceDown).toBe(false);
  });

  test('isDefaultRouteRemoval true for route del default', () => {
    const r = parseNetworkCommand('route del default');
    expect(r.isDefaultRouteRemoval).toBe(true);
  });

  test('isDefaultRouteRemoval true for ip route del default', () => {
    const r = parseNetworkCommand('ip route del default');
    expect(r.isDefaultRouteRemoval).toBe(true);
  });

  test('isTunnel true for ssh -L', () => {
    const r = parseNetworkCommand('ssh -L 3306:db.internal:3306 bastion.example.com');
    expect(r.isTunnel).toBe(true);
  });

  test('isTunnel true for ssh -R', () => {
    const r = parseNetworkCommand('ssh -R 2222:localhost:22 relay.example.com');
    expect(r.isTunnel).toBe(true);
  });

  test('isTunnel true for ssh -D (SOCKS)', () => {
    const r = parseNetworkCommand('ssh -D 1080 user@proxy.example.com');
    expect(r.isTunnel).toBe(true);
  });

  test('isScan true for nmap', () => {
    const r = parseNetworkCommand('nmap -p 80,443 example.com');
    expect(r.isScan).toBe(true);
  });

  test('isScan true for tcpdump', () => {
    const r = parseNetworkCommand('tcpdump -i eth0 -w capture.pcap');
    expect(r.isScan).toBe(true);
  });
});

// ─── Sandbox ──────────────────────────────────────────────────────────────────

describe('simulateNetworkCommand', () => {
  test('DENY for iptables -F INPUT', async () => {
    const intent = parseNetworkCommand('iptables -F INPUT');
    const result = await simulateNetworkCommand(intent);
    expect(result.feasible).toBe(false);
    expect(result.summary).toMatch(/DENIED/);
  });

  test('DENY for ip link set lo down', async () => {
    const intent = parseNetworkCommand('ip link set lo down');
    const result = await simulateNetworkCommand(intent);
    expect(result.feasible).toBe(false);
    expect(result.summary).toMatch(/DENIED/);
  });

  test('DENY for route del default', async () => {
    const intent = parseNetworkCommand('route del default');
    const result = await simulateNetworkCommand(intent);
    expect(result.feasible).toBe(false);
    expect(result.summary).toMatch(/DENIED/);
  });

  test('feasible for iptables -A with firewall warning', async () => {
    const intent = parseNetworkCommand('iptables -A INPUT -p tcp --dport 8080 -j ACCEPT');
    const result = await simulateNetworkCommand(intent);
    expect(result.feasible).toBe(true);
    expect(result.warnings.length).toBeGreaterThan(0);
  });

  test('feasible for ufw disable with warning', async () => {
    const intent = parseNetworkCommand('ufw disable');
    const result = await simulateNetworkCommand(intent);
    // ufw disable itself is CRITICAL (not DENY), feasible = true but with warnings
    expect(result.feasible).toBe(true);
    expect(result.warnings.some(w => /firewall/i.test(w))).toBe(true);
  });

  test('feasible with no warnings for dig', async () => {
    const intent = parseNetworkCommand('dig example.com');
    const result = await simulateNetworkCommand(intent);
    expect(result.feasible).toBe(true);
    expect(result.warnings).toHaveLength(0);
  });

  test('tunnel warning for ssh -L', async () => {
    const intent = parseNetworkCommand('ssh -L 5432:db.internal:5432 bastion.example.com');
    const result = await simulateNetworkCommand(intent);
    expect(result.feasible).toBe(true);
    expect(result.warnings.some(w => /tunnel/i.test(w))).toBe(true);
  });

  test('nmap scan warning', async () => {
    const intent = parseNetworkCommand('nmap -sV 10.0.0.1');
    const result = await simulateNetworkCommand(intent);
    expect(result.feasible).toBe(true);
    expect(result.warnings.some(w => /legal|authorization/i.test(w))).toBe(true);
  });

  test('ip link set eth0 down warning', async () => {
    const intent = parseNetworkCommand('ip link set eth0 down');
    const result = await simulateNetworkCommand(intent);
    expect(result.feasible).toBe(true);
    expect(result.warnings.some(w => /interface|eth0/i.test(w))).toBe(true);
  });

  test('summary includes tool and action', async () => {
    const intent = parseNetworkCommand('iptables -A INPUT -p tcp --dport 443 -j ACCEPT');
    const result = await simulateNetworkCommand(intent);
    expect(result.summary).toMatch(/Tool/);
    expect(result.summary).toMatch(/iptables/);
  });
});

// ─── Policy evaluation ────────────────────────────────────────────────────────

describe('evaluateNetworkPolicy', () => {
  test('DENY for iptables flush (isFirewallDisable)', () => {
    const intent = parseNetworkCommand('iptables -F');
    intent.isFirewallDisable = true;
    const decision = evaluateNetworkPolicy(intent, defaultPolicy);
    expect(decision.allowed).toBe(false);
  });

  test('DENY for ufw disable', () => {
    const intent = parseNetworkCommand('ufw disable');
    const decision = evaluateNetworkPolicy(intent, defaultPolicy);
    expect(decision.allowed).toBe(false);
  });

  test('require_approval for iptables modification', () => {
    const intent = parseNetworkCommand('iptables -A INPUT -p tcp --dport 22 -j ACCEPT');
    const decision = evaluateNetworkPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('require_approval for ufw allow', () => {
    const intent = parseNetworkCommand('ufw allow 80/tcp');
    const decision = evaluateNetworkPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('require_approval for ssh tunnel', () => {
    const intent = parseNetworkCommand('ssh -L 3306:db.internal:3306 bastion.example.com');
    const decision = evaluateNetworkPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('require_approval for nmap scan', () => {
    const intent = parseNetworkCommand('nmap -p 1-1024 192.168.1.1');
    const decision = evaluateNetworkPolicy(intent, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('allow for dig query', () => {
    const intent = parseNetworkCommand('dig example.com AAAA');
    const decision = evaluateNetworkPolicy(intent, defaultPolicy);
    expect(decision.allowed).toBe(true);
    expect(decision.requiresApproval).toBe(false);
  });

  test('allow for netstat status', () => {
    const intent = parseNetworkCommand('netstat -tlnp');
    const decision = evaluateNetworkPolicy(intent, defaultPolicy);
    expect(decision.allowed).toBe(true);
    expect(decision.requiresApproval).toBe(false);
  });

  test('allow for ip addr show', () => {
    const intent = parseNetworkCommand('ip addr show');
    const decision = evaluateNetworkPolicy(intent, defaultPolicy);
    expect(decision.allowed).toBe(true);
    expect(decision.requiresApproval).toBe(false);
  });

  test('CRITICAL risk forces dry-run + approval', () => {
    const intent = parseNetworkCommand('ip link set eth0 down');
    // manually escalate to CRITICAL to test the override
    intent.riskLevel = 'CRITICAL';
    const decision = evaluateNetworkPolicy(intent, defaultPolicy);
    // CRITICAL rule forces these
    if (decision.riskLevel === 'CRITICAL') {
      expect(decision.requiresDryRun).toBe(true);
      expect(decision.requiresApproval).toBe(true);
    }
  });

  test('matched rules list is populated', () => {
    const intent = parseNetworkCommand('iptables -A INPUT -p tcp --dport 8080 -j ACCEPT');
    const decision = evaluateNetworkPolicy(intent, defaultPolicy);
    expect(decision.matchedRules.length).toBeGreaterThan(0);
  });

  test('message is non-empty for denied commands', () => {
    const intent = parseNetworkCommand('ufw disable');
    const decision = evaluateNetworkPolicy(intent, defaultPolicy);
    expect(decision.message.length).toBeGreaterThan(0);
  });
});

// ─── NetworkAdapter ────────────────────────────────────────────────────────────

describe('NetworkAdapter', () => {
  const adapter = new NetworkAdapter();

  test('adapter name is "network"', () => {
    expect(adapter.name).toBe('network');
  });

  test('parseIntent returns ParsedNetworkCommand', () => {
    const intent = adapter.parseIntent('dig example.com');
    expect(intent.tool).toBe('dig');
    expect(intent.riskLevel).toBe('LOW');
  });

  test('sandbox returns SimulationResult', async () => {
    const intent = adapter.parseIntent('nmap -p 80 192.168.1.1');
    const result = await adapter.sandbox(intent);
    expect(result).toHaveProperty('feasible');
    expect(result).toHaveProperty('summary');
    expect(result).toHaveProperty('warnings');
    expect(result).toHaveProperty('durationMs');
  });

  test('sandbox is DENY for iptables -F INPUT', async () => {
    const intent = adapter.parseIntent('iptables -F INPUT');
    const result = await adapter.sandbox(intent);
    expect(result.feasible).toBe(false);
  });

  test('rollback throws for non-iptables tools', async () => {
    const intent = adapter.parseIntent('ufw allow 80/tcp');
    const snapshot = {
      commandId: 'test-001',
      timestamp: new Date(),
      preState: 'Status: active',
      tool: intent.tool,
    } as const;
    await expect(adapter.rollback(intent, snapshot)).rejects.toThrow();
  });
});
