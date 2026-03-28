/**
 * E2E Performance Benchmarks for SafeExecutor
 *
 * Measures parse time, auto-detect time, policy evaluation, and full pipeline
 * throughput across all 10 supported domains.
 */

import { jest, describe, it, expect, beforeAll } from '@jest/globals';
import { detectDomain } from '../src/mcp-server/auto-detect.js';
import { safeExecute } from '../src/mcp-server/tools.js';
import { parseIntent as parseSqlIntent } from '../src/adapters/sql/parser.js'; // async
import { parseIntent as parseFilesystemIntent } from '../src/adapters/filesystem/parser.js'; // sync
import { buildCloudIntent } from '../src/adapters/cloud/parser.js'; // sync
import { parseKubeCommand, toSafeIntent } from '../src/adapters/kubernetes/parser.js'; // sync
import { parseCicdCommand } from '../src/adapters/cicd/parser.js'; // sync
import { parseHttpRequest } from '../src/adapters/api/parser.js'; // sync
import { parseSecretCommand } from '../src/adapters/secrets/parser.js'; // sync
import { parseNetworkCommand } from '../src/adapters/network/parser.js'; // sync
import { parseGitCommand } from '../src/adapters/git/parser.js'; // sync
import { parseQueueCommand } from '../src/adapters/queue/parser.js'; // sync

import { evaluatePolicy } from '../src/core/policy-engine.js';
import type { SafeIntent, Policy } from '../src/types/index.js';
import { readFileSync } from 'node:fs';

beforeAll(() => {
  jest.setTimeout(30000);
});

// ─── Helpers ────────────────────────────────────────────────────────────────

function percentile(sorted: number[], p: number): number {
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
}

/**
 * Run a synchronous function `iterations` times and return timing stats.
 */
function benchmarkSync(fn: () => void, iterations: number) {
  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    fn();
    times.push(performance.now() - start);
  }
  times.sort((a, b) => a - b);
  const total = times.reduce((s, t) => s + t, 0);
  return {
    avg: total / iterations,
    p99: percentile(times, 99),
    total,
    times,
  };
}

/**
 * Run an async function `iterations` times sequentially and return timing stats.
 */
async function benchmarkAsync(fn: () => Promise<void>, iterations: number) {
  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    await fn();
    times.push(performance.now() - start);
  }
  times.sort((a, b) => a - b);
  const total = times.reduce((s, t) => s + t, 0);
  return {
    avg: total / iterations,
    p99: percentile(times, 99),
    total,
    times,
  };
}

// ─── 1. Parse Time Per Domain ───────────────────────────────────────────────

describe('Parse Time Per Domain', () => {
  const ITERATIONS = 100;
  const MAX_AVG_MS = 5;
  const MAX_P99_MS = 10;

  it('SQL parser: complex JOIN query', async () => {
    const cmd = 'SELECT u.id, u.name FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = true';
    const stats = await benchmarkAsync(async () => {
      await parseSqlIntent(cmd);
    }, ITERATIONS);
    console.log(`SQL parser — avg: ${stats.avg.toFixed(3)}ms, p99: ${stats.p99.toFixed(3)}ms`);
    expect(stats.avg).toBeLessThan(MAX_AVG_MS);
    expect(stats.p99).toBeLessThan(MAX_P99_MS);
  });

  it('Filesystem parser: rm -rf with flags', () => {
    const cmd = 'rm -rf /home/user/old-data --verbose';
    const stats = benchmarkSync(() => {
      parseFilesystemIntent(cmd);
    }, ITERATIONS);
    console.log(`Filesystem parser — avg: ${stats.avg.toFixed(3)}ms, p99: ${stats.p99.toFixed(3)}ms`);
    expect(stats.avg).toBeLessThan(MAX_AVG_MS);
    expect(stats.p99).toBeLessThan(MAX_P99_MS);
  });

  it('Cloud parser: aws ec2 describe-instances with filters', () => {
    const cmd = 'aws ec2 describe-instances --filters Name=tag:Env,Values=prod';
    const stats = benchmarkSync(() => {
      buildCloudIntent(cmd);
    }, ITERATIONS);
    console.log(`Cloud parser — avg: ${stats.avg.toFixed(3)}ms, p99: ${stats.p99.toFixed(3)}ms`);
    expect(stats.avg).toBeLessThan(MAX_AVG_MS);
    expect(stats.p99).toBeLessThan(MAX_P99_MS);
  });

  it('Kubernetes parser: kubectl get pods with namespace and selector', () => {
    const cmd = 'kubectl get pods -n production --selector=app=web -o wide';
    const stats = benchmarkSync(() => {
      const kube = parseKubeCommand(cmd);
      toSafeIntent(kube);
    }, ITERATIONS);
    console.log(`Kubernetes parser — avg: ${stats.avg.toFixed(3)}ms, p99: ${stats.p99.toFixed(3)}ms`);
    expect(stats.avg).toBeLessThan(MAX_AVG_MS);
    expect(stats.p99).toBeLessThan(MAX_P99_MS);
  });

  it('CI/CD parser: docker build with build-arg', () => {
    const cmd = 'docker build -t myregistry.io/app:v2.3.1 --build-arg NODE_ENV=production .';
    const stats = benchmarkSync(() => {
      parseCicdCommand(cmd);
    }, ITERATIONS);
    console.log(`CI/CD parser — avg: ${stats.avg.toFixed(3)}ms, p99: ${stats.p99.toFixed(3)}ms`);
    expect(stats.avg).toBeLessThan(MAX_AVG_MS);
    expect(stats.p99).toBeLessThan(MAX_P99_MS);
  });

  it('API parser: curl POST with auth and body', () => {
    const cmd = "curl -X POST https://api.stripe.com/v1/charges -H 'Authorization: Bearer sk_test_xxx' -d '{\"amount\": 2000}'";
    const stats = benchmarkSync(() => {
      parseHttpRequest(cmd);
    }, ITERATIONS);
    console.log(`API parser — avg: ${stats.avg.toFixed(3)}ms, p99: ${stats.p99.toFixed(3)}ms`);
    expect(stats.avg).toBeLessThan(MAX_AVG_MS);
    expect(stats.p99).toBeLessThan(MAX_P99_MS);
  });

  it('Secrets parser: vault read with format flag', () => {
    const cmd = 'vault read secret/data/prod/database -format=json';
    const stats = benchmarkSync(() => {
      parseSecretCommand(cmd);
    }, ITERATIONS);
    console.log(`Secrets parser — avg: ${stats.avg.toFixed(3)}ms, p99: ${stats.p99.toFixed(3)}ms`);
    expect(stats.avg).toBeLessThan(MAX_AVG_MS);
    expect(stats.p99).toBeLessThan(MAX_P99_MS);
  });

  it('Network parser: iptables rule addition', () => {
    const cmd = 'iptables -A INPUT -p tcp --dport 443 -j ACCEPT';
    const stats = benchmarkSync(() => {
      parseNetworkCommand(cmd);
    }, ITERATIONS);
    console.log(`Network parser — avg: ${stats.avg.toFixed(3)}ms, p99: ${stats.p99.toFixed(3)}ms`);
    expect(stats.avg).toBeLessThan(MAX_AVG_MS);
    expect(stats.p99).toBeLessThan(MAX_P99_MS);
  });

  it('Git parser: force push with lease', () => {
    const cmd = 'git push --force-with-lease origin feature/my-branch';
    const stats = benchmarkSync(() => {
      parseGitCommand(cmd);
    }, ITERATIONS);
    console.log(`Git parser — avg: ${stats.avg.toFixed(3)}ms, p99: ${stats.p99.toFixed(3)}ms`);
    expect(stats.avg).toBeLessThan(MAX_AVG_MS);
    expect(stats.p99).toBeLessThan(MAX_P99_MS);
  });

  it('Queue parser: kafka-topics create with options', () => {
    const cmd = 'kafka-topics --create --topic my-events --partitions 3 --replication-factor 2 --bootstrap-server localhost:9092';
    const stats = benchmarkSync(() => {
      parseQueueCommand(cmd);
    }, ITERATIONS);
    console.log(`Queue parser — avg: ${stats.avg.toFixed(3)}ms, p99: ${stats.p99.toFixed(3)}ms`);
    expect(stats.avg).toBeLessThan(MAX_AVG_MS);
    expect(stats.p99).toBeLessThan(MAX_P99_MS);
  });
});

// ─── 2. Auto-Detect Time ────────────────────────────────────────────────────

describe('Auto-Detect Time', () => {
  const DOMAIN_COMMANDS: Record<string, string> = {
    sql: 'SELECT * FROM users WHERE id = 1',
    filesystem: 'rm -rf /tmp/old-data',
    cloud: 'terraform plan',
    kubernetes: 'kubectl get pods -n production',
    cicd: 'docker build -t app:v1 .',
    api: 'GET https://api.example.com/users',
    secrets: 'vault read secret/data/db',
    network: 'iptables -A INPUT -p tcp --dport 80 -j ACCEPT',
    git: 'git push origin main',
    queue: 'redis-cli GET mykey',
  };

  it('should detect 1000 domains (100 per pattern) in under 100ms total', () => {
    const domains = Object.keys(DOMAIN_COMMANDS);
    const ITERATIONS_PER_DOMAIN = 100;
    const totalIterations = domains.length * ITERATIONS_PER_DOMAIN;

    const start = performance.now();
    for (let i = 0; i < ITERATIONS_PER_DOMAIN; i++) {
      for (const domain of domains) {
        const result = detectDomain(DOMAIN_COMMANDS[domain]);
        expect(result).toBe(domain);
      }
    }
    const totalMs = performance.now() - start;
    const avgPerDetection = totalMs / totalIterations;

    console.log(`Auto-detect — total: ${totalMs.toFixed(3)}ms, avg: ${avgPerDetection.toFixed(4)}ms (${totalIterations} detections)`);
    expect(totalMs).toBeLessThan(100);
    expect(avgPerDetection).toBeLessThan(0.1);
  });
});

// ─── 3. Policy Evaluation Time ──────────────────────────────────────────────

describe('Policy Evaluation Time', () => {
  let policy: Policy;

  beforeAll(() => {
    const raw = readFileSync(
      new URL('../config/default-policy.json', import.meta.url),
      'utf-8',
    );
    policy = JSON.parse(raw) as Policy;
  });

  it('should evaluate policy 1000 times in under 1ms average', () => {
    const intent: SafeIntent = {
      domain: 'sql',
      type: 'SELECT',
      raw: 'SELECT * FROM users WHERE id = 1',
      target: {
        name: 'users',
        type: 'table',
        affectedResources: ['users'],
      },
      scope: 'single',
      riskFactors: [],
      tables: ['users'],
      hasWhereClause: true,
      estimatedRowsAffected: null,
      isDestructive: false,
      isMassive: false,
      metadata: {},
    };

    const ITERATIONS = 1000;
    const stats = benchmarkSync(() => {
      evaluatePolicy(intent, policy);
    }, ITERATIONS);

    console.log(`Policy evaluation — avg: ${stats.avg.toFixed(4)}ms, p99: ${stats.p99.toFixed(4)}ms`);
    expect(stats.avg).toBeLessThan(1);
  });
});

// ─── 4. Full Pipeline Throughput — 100 Mixed Commands ───────────────────────

describe('Full Pipeline Throughput — 100 Mixed Commands', () => {
  const MIXED_COMMANDS = [
    // SQL (10)
    'SELECT * FROM users',
    'INSERT INTO logs (msg) VALUES (\'test\')',
    'UPDATE users SET active = false WHERE id = 1',
    'DELETE FROM sessions WHERE expired = true',
    'DROP TABLE temp_data',
    'CREATE TABLE test (id INT)',
    'ALTER TABLE users ADD COLUMN phone TEXT',
    'TRUNCATE TABLE old_logs',
    'SELECT COUNT(*) FROM orders WHERE status = \'pending\'',
    'SELECT 1',
    // Filesystem (10)
    'rm -rf /tmp/old-data',
    'chmod 755 /usr/local/bin/app',
    'cp -r /src /dst',
    'mv /tmp/upload /data/files',
    'find /var/log -name "*.log"',
    'dd if=/dev/zero of=/tmp/test bs=1M count=10',
    'chown user:group /opt/app',
    'rm file.txt',
    'cp a.txt b.txt',
    'mv old.txt new.txt',
    // Cloud (10)
    'terraform plan',
    'terraform destroy -target=aws_instance.web',
    'aws s3 ls',
    'aws ec2 describe-instances',
    'aws ec2 terminate-instances --instance-ids i-123',
    'gcloud compute instances list',
    'gcloud compute instances delete my-vm --zone us-east1',
    'az vm list',
    'az vm delete --name myvm',
    'terraform apply -auto-approve',
    // Kubernetes (10)
    'kubectl get pods',
    'kubectl get pods -n production',
    'kubectl delete pod my-pod',
    'kubectl delete namespace staging',
    'kubectl scale deployment web --replicas=3',
    'kubectl scale deployment web --replicas=0',
    'kubectl apply -f deployment.yaml',
    'helm install my-release chart/',
    'helm uninstall my-release',
    'kubectl exec -it my-pod -- /bin/sh',
    // CI/CD (10)
    'docker build -t app:v1 .',
    'docker push app:v1',
    'docker run --privileged alpine',
    'docker-compose up -d',
    'docker-compose down',
    'docker build -t ghcr.io/org/app:latest .',
    'docker push ghcr.io/org/app:latest',
    'docker run -v /:/host alpine',
    'gh workflow run deploy.yml',
    'docker pull nginx:latest',
    // API (10)
    'GET https://api.example.com/users',
    'POST https://api.example.com/users',
    'DELETE https://api.example.com/users/123',
    'PUT https://api.example.com/users/123',
    'curl https://api.example.com/health',
    'curl -X POST https://api.stripe.com/v1/charges -d \'{"amount":100}\'',
    'PATCH https://api.example.com/users/123',
    'GET https://api.example.com/admin/settings',
    'POST https://api.example.com/batch/import',
    'DELETE https://api.example.com/admin/users/1',
    // Secrets (10)
    'vault read secret/data/db',
    'vault write secret/data/db password=new',
    'vault delete secret/data/old',
    'vault list secret/data/',
    'aws secretsmanager get-secret-value --secret-id prod/db',
    'aws secretsmanager delete-secret --secret-id old/key',
    'kubectl get secret my-secret -o yaml',
    'az keyvault secret show --name dbpass --vault-name myvault',
    'export DB_PASSWORD=secret123',
    'aws ssm get-parameter --name /prod/key',
    // Network (10)
    'iptables -A INPUT -p tcp --dport 80 -j ACCEPT',
    'iptables -F INPUT',
    'ufw allow 443',
    'ufw disable',
    'ip addr show',
    'ip link set eth0 down',
    'nmap -sV 192.168.1.0/24',
    'ip route add 10.0.0.0/8 via 192.168.1.1',
    'ufw deny 22',
    'iptables -L',
    // Git (10) - Note: git domain returns 'no parser available' from tools.ts
    'git status',
    'git push origin main',
    'git push --force origin main',
    'git reset --hard HEAD~1',
    'git commit -m "fix"',
    'git branch -D old-branch',
    'git rebase -i HEAD~3',
    'git stash',
    'git log --oneline',
    'git diff HEAD~1',
    // Queue (10) - Note: queue domain returns 'no parser available' from tools.ts
    'redis-cli GET mykey',
    'redis-cli FLUSHALL',
    'kafka-topics --list --bootstrap-server localhost:9092',
    'kafka-topics --delete --topic test --bootstrap-server localhost:9092',
    'rabbitmqctl list_queues',
    'rabbitmqctl purge_queue my-queue',
    'aws sqs send-message --queue-url https://sqs.us-east-1.amazonaws.com/123/q --message-body test',
    'aws sns publish --topic-arn arn:aws:sns:us-east-1:123:T --message hello',
    'gcloud pubsub topics list',
    'gcloud pubsub topics delete my-topic',
  ];

  it('should process 100 mixed commands within 5000ms total', async () => {
    const times: number[] = [];

    const totalStart = performance.now();
    for (const cmd of MIXED_COMMANDS) {
      const start = performance.now();
      await safeExecute(cmd);
      times.push(performance.now() - start);
    }
    const totalMs = performance.now() - totalStart;
    const avgMs = totalMs / MIXED_COMMANDS.length;

    console.log(`Full pipeline — total: ${totalMs.toFixed(1)}ms, avg: ${avgMs.toFixed(2)}ms, commands: ${MIXED_COMMANDS.length}`);
    expect(totalMs).toBeLessThan(5000);
    expect(avgMs).toBeLessThan(50);
  });
});

// ─── 5. No Domain Significantly Slower ──────────────────────────────────────

describe('No Domain Significantly Slower', () => {
  const DOMAIN_COMMANDS: Record<string, string[]> = {
    sql: [
      'SELECT * FROM users',
      'INSERT INTO logs (msg) VALUES (\'test\')',
      'UPDATE users SET active = false WHERE id = 1',
      'DELETE FROM sessions WHERE expired = true',
      'DROP TABLE temp_data',
      'CREATE TABLE test (id INT)',
      'ALTER TABLE users ADD COLUMN phone TEXT',
      'TRUNCATE TABLE old_logs',
      'SELECT COUNT(*) FROM orders WHERE status = \'pending\'',
      'SELECT 1',
    ],
    filesystem: [
      'rm -rf /tmp/old-data',
      'chmod 755 /usr/local/bin/app',
      'cp -r /src /dst',
      'mv /tmp/upload /data/files',
      'find /var/log -name "*.log"',
      'dd if=/dev/zero of=/tmp/test bs=1M count=10',
      'chown user:group /opt/app',
      'rm file.txt',
      'cp a.txt b.txt',
      'mv old.txt new.txt',
    ],
    cloud: [
      'terraform plan',
      'terraform destroy -target=aws_instance.web',
      'aws s3 ls',
      'aws ec2 describe-instances',
      'aws ec2 terminate-instances --instance-ids i-123',
      'gcloud compute instances list',
      'gcloud compute instances delete my-vm --zone us-east1',
      'az vm list',
      'az vm delete --name myvm',
      'terraform apply -auto-approve',
    ],
    kubernetes: [
      'kubectl get pods',
      'kubectl get pods -n production',
      'kubectl delete pod my-pod',
      'kubectl delete namespace staging',
      'kubectl scale deployment web --replicas=3',
      'kubectl scale deployment web --replicas=0',
      'kubectl apply -f deployment.yaml',
      'helm install my-release chart/',
      'helm uninstall my-release',
      'kubectl exec -it my-pod -- /bin/sh',
    ],
    cicd: [
      'docker build -t app:v1 .',
      'docker push app:v1',
      'docker run --privileged alpine',
      'docker-compose up -d',
      'docker-compose down',
      'docker build -t ghcr.io/org/app:latest .',
      'docker push ghcr.io/org/app:latest',
      'docker run -v /:/host alpine',
      'gh workflow run deploy.yml',
      'docker pull nginx:latest',
    ],
    api: [
      'GET https://api.example.com/users',
      'POST https://api.example.com/users',
      'DELETE https://api.example.com/users/123',
      'PUT https://api.example.com/users/123',
      'curl https://api.example.com/health',
      'curl -X POST https://api.stripe.com/v1/charges -d \'{"amount":100}\'',
      'PATCH https://api.example.com/users/123',
      'GET https://api.example.com/admin/settings',
      'POST https://api.example.com/batch/import',
      'DELETE https://api.example.com/admin/users/1',
    ],
    secrets: [
      'vault read secret/data/db',
      'vault write secret/data/db password=new',
      'vault delete secret/data/old',
      'vault list secret/data/',
      'aws secretsmanager get-secret-value --secret-id prod/db',
      'aws secretsmanager delete-secret --secret-id old/key',
      'kubectl get secret my-secret -o yaml',
      'az keyvault secret show --name dbpass --vault-name myvault',
      'export DB_PASSWORD=secret123',
      'aws ssm get-parameter --name /prod/key',
    ],
    network: [
      'iptables -A INPUT -p tcp --dport 80 -j ACCEPT',
      'iptables -F INPUT',
      'ufw allow 443',
      'ufw disable',
      'ip addr show',
      'ip link set eth0 down',
      'nmap -sV 192.168.1.0/24',
      'ip route add 10.0.0.0/8 via 192.168.1.1',
      'ufw deny 22',
      'iptables -L',
    ],
  };

  // Exclude git and queue — they use the no-parser default path
  const EXCLUDED_DOMAINS = ['git', 'queue'];

  it('no domain average should exceed 10x another domain average', async () => {
    const domainAverages: Record<string, number> = {};

    for (const [domain, commands] of Object.entries(DOMAIN_COMMANDS)) {
      if (EXCLUDED_DOMAINS.includes(domain)) continue;

      const times: number[] = [];
      for (const cmd of commands) {
        const start = performance.now();
        await safeExecute(cmd);
        times.push(performance.now() - start);
      }
      const avg = times.reduce((s, t) => s + t, 0) / times.length;
      domainAverages[domain] = avg;
    }

    const domains = Object.keys(domainAverages);
    const averages = Object.values(domainAverages);
    const minAvg = Math.min(...averages);
    const maxAvg = Math.max(...averages);

    console.log('Domain averages (ms):');
    for (const [domain, avg] of Object.entries(domainAverages)) {
      console.log(`  ${domain.padEnd(12)} ${avg.toFixed(3)}ms`);
    }
    console.log(`  Ratio max/min: ${(maxAvg / minAvg).toFixed(1)}x`);

    // No domain should be more than 10x slower than the fastest
    for (const domain of domains) {
      expect(domainAverages[domain]).toBeLessThan(minAvg * 10);
    }
  });
});
