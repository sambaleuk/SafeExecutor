/**
 * E2E Security Tests — All dangerous patterns must be blocked.
 * Uses detectDomain + the appropriate parser to verify risk >= HIGH or blocked.
 */

import { detectDomain } from '../src/mcp-server/auto-detect.js';
import { parseIntent as parseSql } from '../src/adapters/sql/parser.js';
import { parseIntent as parseFilesystem } from '../src/adapters/filesystem/parser.js';
import { buildCloudIntent } from '../src/adapters/cloud/parser.js';
import { parseKubeCommand } from '../src/adapters/kubernetes/parser.js';
import { parseCicdCommand } from '../src/adapters/cicd/parser.js';
import { parseHttpRequest } from '../src/adapters/api/parser.js';
import { parseSecretCommand } from '../src/adapters/secrets/parser.js';
import { parseNetworkCommand } from '../src/adapters/network/parser.js';
import { parseGitCommand } from '../src/adapters/git/parser.js';
import { parseQueueCommand } from '../src/adapters/queue/parser.js';

const HIGH_RISK = new Set(['HIGH', 'CRITICAL']);

async function getRiskLevel(command: string): Promise<string> {
  const domain = detectDomain(command);
  switch (domain) {
    case 'sql': {
      const i = await parseSql(command);
      return i.riskLevel;
    }
    case 'filesystem': {
      const i = parseFilesystem(command);
      return i.riskLevel;
    }
    case 'cloud': {
      const i = buildCloudIntent(command);
      return i.riskLevel;
    }
    case 'kubernetes': {
      const kube = parseKubeCommand(command);
      return kube.riskLevel;
    }
    case 'cicd': {
      const i = parseCicdCommand(command);
      return i.riskLevel;
    }
    case 'api': {
      const i = parseHttpRequest(command);
      return i.riskLevel;
    }
    case 'secrets': {
      const i = parseSecretCommand(command);
      return i.riskLevel;
    }
    case 'network': {
      const i = parseNetworkCommand(command);
      return i.riskLevel;
    }
    case 'git': {
      const i = parseGitCommand(command);
      return i.riskLevel;
    }
    case 'queue': {
      const i = parseQueueCommand(command);
      return i.riskLevel;
    }
    default:
      return 'unknown';
  }
}

// ─── MUST_BLOCK list ──────────────────────────────────────────────────────────

const MUST_BLOCK: [string, string][] = [
  // Filesystem
  ['rm -rf /', 'filesystem'],
  ['rm -rf /etc', 'filesystem'],
  ['rm -rf /usr', 'filesystem'],
  ['chmod 777 /etc/passwd', 'filesystem'],
  ['chmod 777 /etc/shadow', 'filesystem'],

  // SQL
  ['DELETE FROM users', 'sql'],
  ['DROP TABLE users', 'sql'],
  ['TRUNCATE TABLE orders', 'sql'],
  ['DROP DATABASE production', 'sql'],

  // Git
  ['git push --force origin main', 'git'],
  ['git reset --hard HEAD~50', 'git'],
  ['git push --force-with-lease origin master', 'git'],

  // Kubernetes
  ['kubectl delete namespace production', 'kubernetes'],
  ['kubectl delete pods --all -n default', 'kubernetes'],
  ['kubectl delete namespace kube-system', 'kubernetes'],

  // Cloud
  ['terraform destroy', 'cloud'],
  ['aws ec2 terminate-instances --instance-ids i-1234567890', 'cloud'],
  ['gcloud projects delete my-production-project', 'cloud'],

  // Network
  ['iptables -F INPUT', 'network'],
  ['iptables -F', 'network'],
  ['ufw --force reset', 'network'],

  // Queue
  ['redis-cli FLUSHALL', 'queue'],
  ['redis-cli FLUSHDB', 'queue'],
  ['kafka-topics --delete --topic production-events --bootstrap-server localhost:9092', 'queue'],

  // Secrets
  ['vault kv delete secret/production/db', 'secrets'],
  ['aws secretsmanager delete-secret --secret-id prod/api-key', 'secrets'],

  // CI/CD
  ['docker system prune -af', 'cicd'],
  ['docker rm -f production-api', 'cicd'],
];

describe('Security E2E — All dangerous commands must be HIGH/CRITICAL', () => {
  test.each(MUST_BLOCK)('blocks dangerous: %s (domain: %s)', async (cmd) => {
    const risk = await getRiskLevel(cmd);
    expect(HIGH_RISK.has(risk)).toBe(true);
  });
});

// ─── Domain detection for dangerous commands ──────────────────────────────────

describe('Security E2E — Domain detection for dangerous commands', () => {
  test('rm -rf / → filesystem', () => {
    expect(detectDomain('rm -rf /')).toBe('filesystem');
  });

  test('DELETE FROM users → sql', () => {
    expect(detectDomain('DELETE FROM users')).toBe('sql');
  });

  test('git push --force origin main → git', () => {
    expect(detectDomain('git push --force origin main')).toBe('git');
  });

  test('kubectl delete namespace production → kubernetes', () => {
    expect(detectDomain('kubectl delete namespace production')).toBe('kubernetes');
  });

  test('terraform destroy → cloud', () => {
    expect(detectDomain('terraform destroy')).toBe('cloud');
  });

  test('iptables -F INPUT → network', () => {
    expect(detectDomain('iptables -F INPUT')).toBe('network');
  });

  test('redis-cli FLUSHALL → queue', () => {
    expect(detectDomain('redis-cli FLUSHALL')).toBe('queue');
  });

  test('DROP TABLE users → sql', () => {
    expect(detectDomain('DROP TABLE users')).toBe('sql');
  });

  test('vault kv delete → secrets', () => {
    expect(detectDomain('vault kv delete secret/prod')).toBe('secrets');
  });

  test('docker system prune → cicd', () => {
    expect(detectDomain('docker system prune -af')).toBe('cicd');
  });
});

// ─── Safe commands must NOT be blocked ────────────────────────────────────────

const SAFE_COMMANDS: [string, string][] = [
  ['SELECT id FROM users WHERE id = 1', 'sql'],
  ['cp /tmp/a.txt /tmp/b.txt', 'filesystem'],
  ['terraform plan', 'cloud'],
  ['kubectl get pods', 'kubernetes'],
  ['docker build -t myapp .', 'cicd'],
  ['GET /api/health', 'api'],
  ['vault kv list secret/', 'secrets'],
  ['ip addr show', 'network'],
  ['git status', 'git'],
  ['kafka-topics --list --bootstrap-server localhost:9092', 'queue'],
];

describe('Security E2E — Safe commands must NOT be blocked', () => {
  test.each(SAFE_COMMANDS)('allows safe: %s', async (cmd) => {
    const risk = await getRiskLevel(cmd);
    expect(HIGH_RISK.has(risk)).toBe(false);
  });
});
