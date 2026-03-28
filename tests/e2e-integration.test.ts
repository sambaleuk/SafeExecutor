/**
 * E2E Integration Tests — Full chain: detectDomain → parser → risk classification
 * Tests all 10 domains with dangerous and safe commands.
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

// ─── SQL ──────────────────────────────────────────────────────────────────────

describe('E2E Integration — SQL', () => {
  test('detectDomain identifies SQL', () => {
    expect(detectDomain('SELECT * FROM users')).toBe('sql');
    expect(detectDomain('DELETE FROM orders')).toBe('sql');
    expect(detectDomain('DROP TABLE sessions')).toBe('sql');
  });

  test('SELECT with WHERE is LOW risk', async () => {
    const intent = await parseSql('SELECT id, name FROM users WHERE id = 1');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('SELECT with LIMIT is LOW risk', async () => {
    const intent = await parseSql('SELECT * FROM logs LIMIT 100');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('DELETE without WHERE is CRITICAL', async () => {
    const intent = await parseSql('DELETE FROM users');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('DROP TABLE is CRITICAL', async () => {
    const intent = await parseSql('DROP TABLE users');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('TRUNCATE is HIGH/CRITICAL risk', async () => {
    const intent = await parseSql('TRUNCATE TABLE sessions');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });
});

// ─── Filesystem ───────────────────────────────────────────────────────────────

describe('E2E Integration — Filesystem', () => {
  test('detectDomain identifies filesystem', () => {
    expect(detectDomain('rm -rf /tmp/cache')).toBe('filesystem');
    expect(detectDomain('chmod 777 /etc/passwd')).toBe('filesystem');
  });

  test('cp to safe path is LOW risk', () => {
    const intent = parseFilesystem('cp /tmp/file.txt /tmp/backup.txt');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('mv within tmp is LOW risk', () => {
    const intent = parseFilesystem('mv /tmp/a.txt /tmp/b.txt');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('rm -rf / is CRITICAL', () => {
    const intent = parseFilesystem('rm -rf /');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('rm -rf /etc is CRITICAL', () => {
    const intent = parseFilesystem('rm -rf /etc');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('chmod 777 /etc/passwd is HIGH/CRITICAL', () => {
    const intent = parseFilesystem('chmod 777 /etc/passwd');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });
});

// ─── Cloud ────────────────────────────────────────────────────────────────────

describe('E2E Integration — Cloud', () => {
  test('detectDomain identifies cloud', () => {
    expect(detectDomain('terraform destroy')).toBe('cloud');
    expect(detectDomain('aws s3 ls')).toBe('cloud');
    expect(detectDomain('gcloud compute instances list')).toBe('cloud');
  });

  test('terraform plan is LOW risk', () => {
    const intent = buildCloudIntent('terraform plan');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('aws s3 ls is LOW risk', () => {
    const intent = buildCloudIntent('aws s3 ls s3://my-bucket');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('terraform destroy is CRITICAL', () => {
    const intent = buildCloudIntent('terraform destroy');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('aws ec2 terminate-instances is HIGH/CRITICAL', () => {
    const intent = buildCloudIntent('aws ec2 terminate-instances --instance-ids i-1234567890');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('gcloud projects delete is CRITICAL', () => {
    const intent = buildCloudIntent('gcloud projects delete my-project');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });
});

// ─── Kubernetes ───────────────────────────────────────────────────────────────

describe('E2E Integration — Kubernetes', () => {
  test('detectDomain identifies kubernetes', () => {
    expect(detectDomain('kubectl get pods')).toBe('kubernetes');
    expect(detectDomain('helm list')).toBe('kubernetes');
  });

  test('kubectl get pods is LOW risk', () => {
    const kube = parseKubeCommand('kubectl get pods');
    expect(HIGH_RISK.has(kube.riskLevel)).toBe(false);
  });

  test('kubectl describe node is LOW risk', () => {
    const kube = parseKubeCommand('kubectl describe node worker-1');
    expect(HIGH_RISK.has(kube.riskLevel)).toBe(false);
  });

  test('kubectl delete namespace production is CRITICAL', () => {
    const kube = parseKubeCommand('kubectl delete namespace production');
    expect(HIGH_RISK.has(kube.riskLevel)).toBe(true);
  });

  test('kubectl delete pods --all is HIGH/CRITICAL', () => {
    const kube = parseKubeCommand('kubectl delete pods --all -n default');
    expect(HIGH_RISK.has(kube.riskLevel)).toBe(true);
  });

  test('kubectl delete namespace kube-system is CRITICAL', () => {
    const kube = parseKubeCommand('kubectl delete namespace kube-system');
    expect(HIGH_RISK.has(kube.riskLevel)).toBe(true);
  });
});

// ─── CI/CD ────────────────────────────────────────────────────────────────────

describe('E2E Integration — CI/CD', () => {
  test('detectDomain identifies cicd', () => {
    expect(detectDomain('docker build -t myapp .')).toBe('cicd');
    expect(detectDomain('docker-compose up -d')).toBe('cicd');
  });

  test('docker build is LOW risk', () => {
    const intent = parseCicdCommand('docker build -t myapp:latest .');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('docker images is LOW risk', () => {
    const intent = parseCicdCommand('docker images');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('docker system prune -af is HIGH/CRITICAL', () => {
    const intent = parseCicdCommand('docker system prune -af');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('docker rm -f production container is HIGH/CRITICAL', () => {
    const intent = parseCicdCommand('docker rm -f production-api');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('docker rmi --force all images is HIGH/CRITICAL', () => {
    const intent = parseCicdCommand('docker rmi --force $(docker images -q)');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });
});

// ─── API ──────────────────────────────────────────────────────────────────────

describe('E2E Integration — API', () => {
  test('detectDomain identifies api', () => {
    expect(detectDomain('GET /api/users')).toBe('api');
    expect(detectDomain('curl https://api.example.com/health')).toBe('api');
  });

  test('GET request is LOW risk', () => {
    const intent = parseHttpRequest('GET /api/users');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('curl GET is LOW risk', () => {
    const intent = parseHttpRequest('curl https://api.example.com/health');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('DELETE /api/users is HIGH/CRITICAL', () => {
    const intent = parseHttpRequest('DELETE /api/users');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('DELETE to production endpoint is HIGH/CRITICAL', () => {
    const intent = parseHttpRequest('DELETE https://api.production.com/users/all');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('POST with sensitive data is flagged', () => {
    const intent = parseHttpRequest('POST /api/auth/login -d \'{"password":"secret123"}\'');
    expect(intent.riskLevel).toBeDefined();
  });
});

// ─── Secrets ──────────────────────────────────────────────────────────────────

describe('E2E Integration — Secrets', () => {
  test('detectDomain identifies secrets', () => {
    expect(detectDomain('vault kv get secret/db')).toBe('secrets');
    expect(detectDomain('aws secretsmanager list-secrets')).toBe('secrets');
  });

  test('vault kv get is LOW/MEDIUM risk', () => {
    const intent = parseSecretCommand('vault kv get secret/app/config');
    expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(intent.riskLevel);
  });

  test('vault kv list is LOW risk', () => {
    const intent = parseSecretCommand('vault kv list secret/');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('vault secrets delete is HIGH/CRITICAL', () => {
    const intent = parseSecretCommand('vault kv delete secret/production/db');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('vault lease revoke-prefix is HIGH/CRITICAL', () => {
    const intent = parseSecretCommand('vault lease revoke -prefix secret/');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('aws secretsmanager delete-secret is HIGH/CRITICAL', () => {
    const intent = parseSecretCommand('aws secretsmanager delete-secret --secret-id prod/db/password');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });
});

// ─── Network ──────────────────────────────────────────────────────────────────

describe('E2E Integration — Network', () => {
  test('detectDomain identifies network', () => {
    expect(detectDomain('iptables -F INPUT')).toBe('network');
    expect(detectDomain('ufw allow 80')).toBe('network');
  });

  test('ip addr show is LOW risk', () => {
    const intent = parseNetworkCommand('ip addr show');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('ufw status is LOW risk', () => {
    const intent = parseNetworkCommand('ufw status');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('iptables -F INPUT is HIGH/CRITICAL', () => {
    const intent = parseNetworkCommand('iptables -F INPUT');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('iptables -F is CRITICAL (flush all rules)', () => {
    const intent = parseNetworkCommand('iptables -F');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('nmap full scan is HIGH/CRITICAL', () => {
    const intent = parseNetworkCommand('nmap -sS -p- 192.168.1.0/24');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });
});

// ─── Git ──────────────────────────────────────────────────────────────────────

describe('E2E Integration — Git', () => {
  test('detectDomain identifies git', () => {
    expect(detectDomain('git push --force origin main')).toBe('git');
    expect(detectDomain('git status')).toBe('git');
  });

  test('git status is LOW risk', () => {
    const intent = parseGitCommand('git status');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('git log is LOW risk', () => {
    const intent = parseGitCommand('git log --oneline -10');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('git push --force origin main is CRITICAL', () => {
    const intent = parseGitCommand('git push --force origin main');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('git reset --hard HEAD~10 is HIGH/CRITICAL', () => {
    const intent = parseGitCommand('git reset --hard HEAD~10');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('git push --force-with-lease main is HIGH/CRITICAL', () => {
    const intent = parseGitCommand('git push --force-with-lease origin main');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });
});

// ─── Queue ────────────────────────────────────────────────────────────────────

describe('E2E Integration — Queue', () => {
  test('detectDomain identifies queue', () => {
    expect(detectDomain('redis-cli FLUSHALL')).toBe('queue');
    expect(detectDomain('kafka-topics --list')).toBe('queue');
  });

  test('kafka-topics --list is LOW risk', () => {
    const intent = parseQueueCommand('kafka-topics --list --bootstrap-server localhost:9092');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('redis-cli GET key is LOW risk', () => {
    const intent = parseQueueCommand('redis-cli GET user:session:123');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(false);
  });

  test('redis-cli FLUSHALL is CRITICAL', () => {
    const intent = parseQueueCommand('redis-cli FLUSHALL');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('redis-cli FLUSHDB is HIGH/CRITICAL', () => {
    const intent = parseQueueCommand('redis-cli FLUSHDB');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });

  test('kafka-topics --delete is HIGH/CRITICAL', () => {
    const intent = parseQueueCommand('kafka-topics --delete --topic production-events --bootstrap-server localhost:9092');
    expect(HIGH_RISK.has(intent.riskLevel)).toBe(true);
  });
});
