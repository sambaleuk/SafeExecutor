/**
 * E2E Pipeline Tests for SafeExecutor MCP Tool Functions
 *
 * Tests the full pipeline: auto-detect -> parse -> risk classification
 * through the three exported tool functions: safeExecute, safeAnalyze, safePolicyCheck.
 *
 * All tests verify actual runtime behavior after tools.ts property-name fixes:
 * - All domains now return correct operation, riskLevel, blocked, and targets fields.
 * - Blocking is functional: dangerous commands are blocked (blocked=true, policy_decision='BLOCKED').
 * - aws secretsmanager / aws ssm / az keyvault route to 'secrets' (not 'cloud').
 */

import { safeExecute, safeAnalyze, safePolicyCheck } from '../src/mcp-server/tools.js';

// ─────────────────────────────────────────────────────────────────────────────
// 1. Domain Routing
// ─────────────────────────────────────────────────────────────────────────────

describe('Domain Routing', () => {
  test.each<[string, string]>([
    // SQL
    ['SELECT * FROM users', 'sql'],
    ['INSERT INTO orders VALUES (1, "item", 9.99)', 'sql'],
    ['UPDATE users SET active = false WHERE id = 5', 'sql'],
    ['DELETE FROM sessions WHERE expired = true', 'sql'],
    ['CREATE TABLE logs (id SERIAL)', 'sql'],
    ['ALTER TABLE users ADD COLUMN email TEXT', 'sql'],
    ['DROP TABLE temp_data', 'sql'],
    ['TRUNCATE TABLE cache', 'sql'],

    // Filesystem
    ['rm -rf /tmp/old', 'filesystem'],
    ['chmod 755 /var/www', 'filesystem'],
    ['chown root:root /etc/config', 'filesystem'],
    ['dd if=/dev/zero of=/tmp/test bs=1M count=1', 'filesystem'],
    ['find /tmp -name "*.log"', 'filesystem'],
    ['mv /tmp/a /tmp/b', 'filesystem'],
    ['cp file1.txt file2.txt', 'filesystem'],

    // Cloud
    ['terraform plan', 'cloud'],
    ['terraform destroy -auto-approve', 'cloud'],
    ['aws s3 ls', 'cloud'],
    ['gcloud compute instances list', 'cloud'],
    ['az vm delete --name myVM', 'cloud'],

    // Kubernetes
    ['kubectl get pods', 'kubernetes'],
    ['kubectl apply -f deployment.yaml', 'kubernetes'],
    ['kubectl delete namespace staging', 'kubernetes'],
    ['helm install my-release chart/', 'kubernetes'],
    ['helm uninstall my-release', 'kubernetes'],

    // CI/CD
    ['docker build -t myapp .', 'cicd'],
    ['docker run -d nginx', 'cicd'],
    ['docker-compose up -d', 'cicd'],
    ['gh workflow run deploy.yml', 'cicd'],

    // API
    ['GET https://example.com/api/v1/users', 'api'],
    ['POST https://api.stripe.com/v1/charges', 'api'],
    // NOTE: 'DELETE https://...' matches SQL regex before API check
    ['DELETE https://example.com/users/123', 'sql'],
    ['curl -X GET https://example.com/health', 'api'],
    ['https://example.com/resource', 'api'],

    // Secrets
    ['vault read secret/data/prod/db', 'secrets'],
    ['aws secretsmanager get-secret-value --secret-id prod/api-key', 'secrets'],
    ['aws ssm get-parameter --name /prod/db-password', 'secrets'],
    ['az keyvault secret show --name api-key', 'secrets'],

    // Network
    ['iptables -L', 'network'],
    ['ufw status', 'network'],
    ['ip addr show', 'network'],
    ['nmap 192.168.1.1', 'network'],

    // Git
    ['git commit -m "fix: resolve race condition"', 'git'],
    ['git push origin main', 'git'],

    // Queue
    ['kafka-topics --list', 'queue'],
    ['redis-cli KEYS *', 'queue'],

    // Unknown
    ['echo hello world', 'unknown'],
    ['ls -la /tmp', 'unknown'],
    ['ping google.com', 'unknown'],
  ])('"%s" routes to domain="%s"', async (command, expectedDomain) => {
    const result = await safeExecute(command);
    expect(result.domain).toBe(expectedDomain);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Blocking Behavior for Dangerous Commands
// ─────────────────────────────────────────────────────────────────────────────

describe('Blocking behavior for dangerous commands', () => {
  describe('SQL destructive commands ARE blocked', () => {
    test('DELETE FROM users (no WHERE) -> blocked=true', async () => {
      const result = await safeExecute('DELETE FROM users');
      expect(result.domain).toBe('sql');
      expect(result.riskLevel).toMatch(/^(HIGH|CRITICAL)$/);
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });

    test('DROP TABLE production_data -> blocked=true', async () => {
      const result = await safeExecute('DROP TABLE production_data');
      expect(result.domain).toBe('sql');
      expect(result.riskLevel).toMatch(/^(HIGH|CRITICAL)$/);
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });

    test('TRUNCATE TABLE users -> blocked=true', async () => {
      const result = await safeExecute('TRUNCATE TABLE users');
      expect(result.domain).toBe('sql');
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });
  });

  describe('Filesystem destructive commands ARE blocked', () => {
    test('rm -rf / -> blocked=true', async () => {
      const result = await safeExecute('rm -rf /');
      expect(result.domain).toBe('filesystem');
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });

    test('rm -rf /etc -> blocked=true', async () => {
      const result = await safeExecute('rm -rf /etc');
      expect(result.domain).toBe('filesystem');
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });

    test('dd if=/dev/zero of=/dev/sda -> blocked=true', async () => {
      const result = await safeExecute('dd if=/dev/zero of=/dev/sda');
      expect(result.domain).toBe('filesystem');
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });
  });

  describe('Cloud destructive commands ARE blocked', () => {
    test('terraform destroy -> blocked=true', async () => {
      const result = await safeExecute('terraform destroy');
      expect(result.domain).toBe('cloud');
      expect(result.riskLevel).toMatch(/^(HIGH|CRITICAL)$/);
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });

    test('aws ec2 terminate-instances -> blocked=true', async () => {
      const result = await safeExecute('aws ec2 terminate-instances --instance-ids i-1234');
      expect(result.domain).toBe('cloud');
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });
  });

  describe('Kubernetes destructive commands ARE blocked', () => {
    test('kubectl delete namespace kube-system -> blocked=true', async () => {
      const result = await safeExecute('kubectl delete namespace kube-system');
      expect(result.domain).toBe('kubernetes');
      expect(result.riskLevel).toMatch(/^(HIGH|CRITICAL)$/);
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });

    test('helm uninstall my-release -> blocked=true', async () => {
      const result = await safeExecute('helm uninstall my-release');
      expect(result.domain).toBe('kubernetes');
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });
  });

  describe('Network destructive commands ARE blocked', () => {
    test('iptables -F INPUT -> blocked=true', async () => {
      const result = await safeExecute('iptables -F INPUT');
      expect(result.domain).toBe('network');
      expect(result.riskLevel).toMatch(/^(HIGH|CRITICAL)$/);
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });

    test('ip link set eth0 down -> blocked=true', async () => {
      const result = await safeExecute('ip link set eth0 down');
      expect(result.domain).toBe('network');
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });

    test('ufw disable -> blocked=true', async () => {
      const result = await safeExecute('ufw disable');
      expect(result.domain).toBe('network');
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });
  });

  describe('CICD dangerous commands ARE blocked', () => {
    test('docker run --privileged -> blocked=true', async () => {
      const result = await safeExecute('docker run --privileged -v /:/host alpine');
      expect(result.domain).toBe('cicd');
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });
  });

  describe('API destructive commands ARE blocked', () => {
    test('curl -X DELETE to admin endpoint -> blocked=true', async () => {
      const result = await safeExecute('curl -X DELETE https://api.example.com/admin/users/123');
      expect(result.domain).toBe('api');
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });

    test('DELETE keyword routes to SQL, not API (regex precedence)', async () => {
      // 'DELETE https://...' matches SQL_KEYWORDS regex before HTTP_METHOD check
      const result = await safeExecute('DELETE https://api.example.com/admin/users/123');
      expect(result.domain).toBe('sql');
    });
  });

  describe('Secrets destructive commands ARE blocked', () => {
    test('vault delete secret -> blocked=true', async () => {
      const result = await safeExecute('vault delete secret/prod/api-key');
      expect(result.domain).toBe('secrets');
      expect(result.blocked).toBe(true);
      expect(result.policy_decision).toBe('BLOCKED');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Low-Risk Commands Pass Through
// ─────────────────────────────────────────────────────────────────────────────

describe('Low-risk commands pass through', () => {
  test('SQL SELECT -> not blocked, domain=sql', async () => {
    const result = await safeExecute('SELECT * FROM users');
    expect(result.domain).toBe('sql');
    expect(result.blocked).toBe(false);
    expect(result.policy_decision).toBe('ALLOWED');
  });

  test('find /tmp -name "*.log" -> domain=filesystem, not blocked', async () => {
    const result = await safeExecute('find /tmp -name "*.log"');
    expect(result.domain).toBe('filesystem');
    expect(result.operation).toBe('FIND');
    expect(result.riskLevel).toBe('LOW');
    expect(result.policy_decision).toBe('ALLOWED');
  });

  test('cp file1 file2 -> domain=filesystem, not blocked', async () => {
    const result = await safeExecute('cp file1 file2');
    expect(result.domain).toBe('filesystem');
    expect(result.operation).toBe('CP');
    expect(result.policy_decision).toBe('ALLOWED');
  });

  test('terraform plan -> domain=cloud, not blocked', async () => {
    const result = await safeExecute('terraform plan');
    expect(result.domain).toBe('cloud');
    expect(result.riskLevel).toBe('LOW');
    expect(result.blocked).toBe(false);
    expect(result.policy_decision).toBe('ALLOWED');
  });

  test('aws s3 ls -> domain=cloud, not blocked', async () => {
    const result = await safeExecute('aws s3 ls');
    expect(result.domain).toBe('cloud');
    expect(result.blocked).toBe(false);
    expect(result.policy_decision).toBe('ALLOWED');
  });

  test('GET https://example.com/health -> domain=api, not blocked', async () => {
    const result = await safeExecute('GET https://example.com/health');
    expect(result.domain).toBe('api');
    expect(result.operation).toBe('GET');
    expect(result.riskLevel).toBe('LOW');
    expect(result.blocked).toBe(false);
    expect(result.policy_decision).toBe('ALLOWED');
  });

  test('kubectl get pods -> domain=kubernetes, not blocked', async () => {
    const result = await safeExecute('kubectl get pods');
    expect(result.domain).toBe('kubernetes');
    expect(result.blocked).toBe(false);
    expect(result.policy_decision).toBe('ALLOWED');
  });

  test('docker build -t myapp . -> domain=cicd, not blocked', async () => {
    const result = await safeExecute('docker build -t myapp .');
    expect(result.domain).toBe('cicd');
    expect(result.blocked).toBe(false);
    expect(result.policy_decision).toBe('ALLOWED');
  });

  test('vault read secret/data/app -> domain=secrets, not blocked', async () => {
    const result = await safeExecute('vault read secret/data/app');
    expect(result.domain).toBe('secrets');
    expect(result.blocked).toBe(false);
    expect(result.policy_decision).toBe('ALLOWED');
  });

  test('iptables -L -> domain=network, not blocked', async () => {
    const result = await safeExecute('iptables -L');
    expect(result.domain).toBe('network');
    expect(result.blocked).toBe(false);
    expect(result.policy_decision).toBe('ALLOWED');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Risk Level Classification
// ─────────────────────────────────────────────────────────────────────────────

describe('Risk level classification', () => {
  test('SQL SELECT -> riskLevel=LOW', async () => {
    const result = await safeExecute('SELECT * FROM users');
    expect(result.riskLevel).toBe('LOW');
  });

  test('SQL DELETE no WHERE -> riskLevel=CRITICAL', async () => {
    const result = await safeExecute('DELETE FROM users');
    expect(result.riskLevel).toBe('CRITICAL');
  });

  test('SQL DROP TABLE -> riskLevel is HIGH or CRITICAL', async () => {
    const result = await safeExecute('DROP TABLE users');
    expect(['HIGH', 'CRITICAL']).toContain(result.riskLevel);
  });

  // Filesystem has a proper riskLevel field
  test('find (read command) -> riskLevel=LOW', async () => {
    const result = await safeExecute('find /tmp -name "*.txt"');
    expect(result.riskLevel).toBe('LOW');
  });

  test('rm -rf / -> riskLevel=CRITICAL', async () => {
    const result = await safeExecute('rm -rf /');
    expect(result.riskLevel).toBe('CRITICAL');
  });

  test('chmod 777 /etc -> riskLevel is HIGH or CRITICAL', async () => {
    const result = await safeExecute('chmod 777 /etc');
    expect(['HIGH', 'CRITICAL']).toContain(result.riskLevel);
  });

  // Cloud has proper riskLevel
  test('terraform plan -> riskLevel=LOW', async () => {
    const result = await safeExecute('terraform plan');
    expect(result.riskLevel).toBe('LOW');
  });

  test('terraform destroy -> riskLevel is HIGH or CRITICAL', async () => {
    const result = await safeExecute('terraform destroy');
    expect(['HIGH', 'CRITICAL']).toContain(result.riskLevel);
  });

  test('aws s3 rm s3://bucket --recursive -> riskLevel is HIGH or CRITICAL', async () => {
    const result = await safeExecute('aws s3 rm s3://my-bucket --recursive');
    expect(['HIGH', 'CRITICAL']).toContain(result.riskLevel);
  });

  // Kubernetes riskLevel is properly set
  test('kubectl delete namespace kube-system -> riskLevel is HIGH or CRITICAL', async () => {
    const result = await safeExecute('kubectl delete namespace kube-system');
    expect(['HIGH', 'CRITICAL']).toContain(result.riskLevel);
  });

  test('kubectl get pods -> riskLevel=LOW', async () => {
    const result = await safeExecute('kubectl get pods');
    expect(result.riskLevel).toBe('LOW');
  });

  // API has proper riskLevel
  test('GET request -> riskLevel=LOW', async () => {
    const result = await safeExecute('GET https://example.com/health');
    expect(result.riskLevel).toBe('LOW');
  });

  test('curl -X DELETE to admin endpoint -> riskLevel is CRITICAL', async () => {
    const result = await safeExecute('curl -X DELETE https://api.example.com/admin/users/123');
    expect(result.domain).toBe('api');
    expect(result.riskLevel).toBe('CRITICAL');
  });

  test('POST to payment endpoint -> riskLevel is HIGH or CRITICAL', async () => {
    const result = await safeExecute('POST https://api.stripe.com/v1/charges');
    expect(['HIGH', 'CRITICAL']).toContain(result.riskLevel);
  });

  // Network has proper riskLevel
  test('iptables -F INPUT -> riskLevel is HIGH or CRITICAL', async () => {
    const result = await safeExecute('iptables -F INPUT');
    expect(['HIGH', 'CRITICAL']).toContain(result.riskLevel);
  });

  test('nmap scan -> riskLevel is HIGH', async () => {
    const result = await safeExecute('nmap 192.168.1.1');
    expect(result.riskLevel).toBe('HIGH');
  });

  // Secrets has proper riskLevel
  test('vault read -> riskLevel is MEDIUM or lower', async () => {
    const result = await safeExecute('vault read secret/data/app');
    expect(['LOW', 'MEDIUM']).toContain(result.riskLevel);
  });

  test('vault delete -> riskLevel is HIGH or CRITICAL', async () => {
    const result = await safeExecute('vault delete secret/prod/api-key');
    expect(['HIGH', 'CRITICAL']).toContain(result.riskLevel);
  });

  // CICD has proper riskLevel
  test('docker build -> riskLevel is LOW or MEDIUM', async () => {
    const result = await safeExecute('docker build -t myapp .');
    expect(['LOW', 'MEDIUM']).toContain(result.riskLevel);
  });

  test('docker run --privileged -> riskLevel is HIGH or CRITICAL', async () => {
    const result = await safeExecute('docker run --privileged -v /:/host alpine');
    expect(['HIGH', 'CRITICAL']).toContain(result.riskLevel);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Cross-Domain Mixed Commands (50 commands)
// ─────────────────────────────────────────────────────────────────────────────

describe('Cross-domain mixed commands (50 commands)', () => {
  const commands: Array<{ command: string; expectedDomain: string }> = [
    // SQL (8)
    { command: 'SELECT id, name FROM customers', expectedDomain: 'sql' },
    { command: 'INSERT INTO events (type) VALUES ("click")', expectedDomain: 'sql' },
    { command: 'UPDATE products SET price = 19.99 WHERE id = 42', expectedDomain: 'sql' },
    { command: 'DELETE FROM logs WHERE created_at < "2024-01-01"', expectedDomain: 'sql' },
    { command: 'CREATE TABLE analytics (id BIGINT)', expectedDomain: 'sql' },
    { command: 'ALTER TABLE orders ADD COLUMN status TEXT', expectedDomain: 'sql' },
    { command: 'DROP TABLE staging_data', expectedDomain: 'sql' },
    { command: 'TRUNCATE TABLE sessions', expectedDomain: 'sql' },

    // Filesystem (7)
    { command: 'rm -rf /tmp/cache', expectedDomain: 'filesystem' },
    { command: 'chmod 644 /var/log/app.log', expectedDomain: 'filesystem' },
    { command: 'chown www-data:www-data /var/www/html', expectedDomain: 'filesystem' },
    { command: 'find / -name "*.bak" -delete', expectedDomain: 'filesystem' },
    { command: 'mv /tmp/upload /opt/data', expectedDomain: 'filesystem' },
    { command: 'cp -r /etc/nginx /backup/nginx', expectedDomain: 'filesystem' },
    { command: 'dd if=/dev/urandom of=/tmp/random bs=1M count=100', expectedDomain: 'filesystem' },

    // Cloud (6)
    { command: 'terraform apply -auto-approve', expectedDomain: 'cloud' },
    { command: 'terraform destroy -target=aws_instance.web', expectedDomain: 'cloud' },
    { command: 'aws ec2 describe-instances', expectedDomain: 'cloud' },
    { command: 'aws rds delete-db-instance --db-instance-identifier prod-db', expectedDomain: 'cloud' },
    { command: 'gcloud compute instances delete my-vm', expectedDomain: 'cloud' },
    { command: 'az storage account delete --name myaccount', expectedDomain: 'cloud' },

    // Kubernetes (6)
    { command: 'kubectl apply -f service.yaml', expectedDomain: 'kubernetes' },
    { command: 'kubectl delete pod my-pod --grace-period=0', expectedDomain: 'kubernetes' },
    { command: 'kubectl scale deployment web --replicas=0', expectedDomain: 'kubernetes' },
    { command: 'kubectl get deployments -A', expectedDomain: 'kubernetes' },
    { command: 'helm upgrade my-release chart/ --set image.tag=v2', expectedDomain: 'kubernetes' },
    { command: 'helm uninstall monitoring', expectedDomain: 'kubernetes' },

    // CI/CD (5)
    { command: 'docker build --no-cache -t api:latest .', expectedDomain: 'cicd' },
    { command: 'docker push registry.example.com/api:v1.2.3', expectedDomain: 'cicd' },
    { command: 'docker run -d -p 8080:80 nginx', expectedDomain: 'cicd' },
    { command: 'docker-compose down --volumes', expectedDomain: 'cicd' },
    { command: 'gh workflow run ci.yml --ref feature-branch', expectedDomain: 'cicd' },

    // API (5)
    { command: 'GET https://api.example.com/v2/users?limit=100', expectedDomain: 'api' },
    { command: 'POST https://api.example.com/v1/orders', expectedDomain: 'api' },
    { command: 'PUT https://api.example.com/v1/users/456', expectedDomain: 'api' },
    { command: 'PATCH https://api.example.com/v1/settings', expectedDomain: 'api' },
    { command: 'curl -s https://httpbin.org/get', expectedDomain: 'api' },

    // Secrets (5)
    { command: 'vault list secret/data/', expectedDomain: 'secrets' },
    { command: 'vault write secret/data/app key=value', expectedDomain: 'secrets' },
    { command: 'aws secretsmanager list-secrets', expectedDomain: 'secrets' },
    { command: 'aws ssm put-parameter --name /app/key --value secret123', expectedDomain: 'secrets' },
    { command: 'az keyvault secret set --name api-key --value abc123', expectedDomain: 'secrets' },

    // Network (4)
    { command: 'iptables -A INPUT -p tcp --dport 80 -j ACCEPT', expectedDomain: 'network' },
    { command: 'ufw allow 443/tcp', expectedDomain: 'network' },
    { command: 'ip route show', expectedDomain: 'network' },
    { command: 'nmap -sV 10.0.0.0/24', expectedDomain: 'network' },

    // Git (2)
    { command: 'git status', expectedDomain: 'git' },
    { command: 'git rebase -i HEAD~3', expectedDomain: 'git' },

    // Unknown (2)
    { command: 'echo "hello world"', expectedDomain: 'unknown' },
    { command: 'whoami', expectedDomain: 'unknown' },
  ];

  // Verify we have exactly 50 commands
  test('test data has exactly 50 commands', () => {
    expect(commands).toHaveLength(50);
  });

  test.each(commands.map((c, i) => [i + 1, c.command, c.expectedDomain] as const))(
    'command #%d: "%s" -> domain="%s"',
    async (_idx, command, expectedDomain) => {
      const result = await safeExecute(command);
      expect(result.domain).toBe(expectedDomain);
    },
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. safePolicyCheck Tests
// ─────────────────────────────────────────────────────────────────────────────

describe('safePolicyCheck', () => {
  describe('returns allowed=true for safe commands', () => {
    test('SQL SELECT', async () => {
      const result = await safePolicyCheck('SELECT * FROM users');
      expect(result.allowed).toBe(true);
      expect(result.domain).toBe('sql');
      expect(result.risk).toBeDefined();
    });

    test('terraform plan', async () => {
      const result = await safePolicyCheck('terraform plan');
      expect(result.allowed).toBe(true);
      expect(result.domain).toBe('cloud');
      expect(result.risk).toBe('LOW');
    });

    test('GET request', async () => {
      const result = await safePolicyCheck('GET https://example.com/health');
      expect(result.allowed).toBe(true);
      expect(result.domain).toBe('api');
      expect(result.risk).toBe('LOW');
    });

    test('kubectl get pods', async () => {
      const result = await safePolicyCheck('kubectl get pods');
      expect(result.allowed).toBe(true);
      expect(result.domain).toBe('kubernetes');
    });

    test('find /tmp -name test', async () => {
      const result = await safePolicyCheck('find /tmp -name test');
      expect(result.allowed).toBe(true);
      expect(result.domain).toBe('filesystem');
      expect(result.risk).toBe('LOW');
    });

    test('docker build', async () => {
      const result = await safePolicyCheck('docker build .');
      expect(result.allowed).toBe(true);
      expect(result.domain).toBe('cicd');
    });

    test('vault list', async () => {
      const result = await safePolicyCheck('vault list secret/');
      expect(result.allowed).toBe(true);
      expect(result.domain).toBe('secrets');
    });

    test('iptables -L', async () => {
      const result = await safePolicyCheck('iptables -L');
      expect(result.allowed).toBe(true);
      expect(result.domain).toBe('network');
    });
  });

  describe('returns allowed=false for dangerous commands', () => {
    test('DROP TABLE -> allowed=false (blocked=true)', async () => {
      const result = await safePolicyCheck('DROP TABLE production_data');
      expect(result.allowed).toBe(false);
      expect(result.domain).toBe('sql');
    });

    test('terraform destroy -> allowed=false (CRITICAL risk)', async () => {
      const result = await safePolicyCheck('terraform destroy');
      expect(result.allowed).toBe(false);
      expect(result.domain).toBe('cloud');
      expect(result.risk).toMatch(/^(HIGH|CRITICAL)$/);
    });

    test('rm -rf / -> allowed=false (blocked=true)', async () => {
      const result = await safePolicyCheck('rm -rf /');
      expect(result.allowed).toBe(false);
      expect(result.domain).toBe('filesystem');
    });

    test('iptables -F INPUT -> allowed=false (CRITICAL risk)', async () => {
      const result = await safePolicyCheck('iptables -F INPUT');
      expect(result.allowed).toBe(false);
      expect(result.domain).toBe('network');
    });

    test('curl -X DELETE to admin endpoint -> allowed=false', async () => {
      const result = await safePolicyCheck('curl -X DELETE https://api.example.com/admin/users');
      expect(result.allowed).toBe(false);
      expect(result.domain).toBe('api');
    });

    test('kubectl delete namespace kube-system -> allowed=false', async () => {
      const result = await safePolicyCheck('kubectl delete namespace kube-system');
      expect(result.allowed).toBe(false);
      expect(result.domain).toBe('kubernetes');
    });
  });

  describe('reason field behavior', () => {
    test('SQL reason comes from riskFactors descriptions', async () => {
      const result = await safePolicyCheck('DELETE FROM users');
      expect(result.domain).toBe('sql');
      // SafeIntent has riskFactors, so reason is populated
      expect(typeof result.reason).toBe('string');
      expect(result.reason!.length).toBeGreaterThan(0);
    });

    test('filesystem reason is denyReason or null', async () => {
      const result = await safePolicyCheck('rm -rf /');
      expect(result.domain).toBe('filesystem');
      // denyReason is present when isDenied is true
      // The reason fallback in safePolicyCheck: result.reason ?? (blocked ? ... : 'Operation is within safe thresholds')
      // result.reason comes from intent.denyReason ?? null
      // Since rm -rf / is denied, denyReason should be populated
      expect(result.reason).toBeTruthy();
    });

    test('cloud reason for terraform destroy is populated (destructive operation)', async () => {
      const result = await safePolicyCheck('terraform destroy');
      // reason comes from intent.isDestructive ? 'Destructive cloud operation' : null
      // safePolicyCheck: result.reason ?? (blocked ? 'High-risk operation blocked by policy' : ...)
      expect(result.reason).toBeTruthy();
    });

    test('unknown domain has reason about no parser', async () => {
      const result = await safePolicyCheck('echo hello');
      expect(result.domain).toBe('unknown');
      expect(result.reason).toBe('No parser available for this domain');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. safeAnalyze Tests
// ─────────────────────────────────────────────────────────────────────────────

describe('safeAnalyze', () => {
  test('adds note field with analysis-only message', async () => {
    const result = await safeAnalyze('SELECT * FROM users');
    expect(result.note).toBe('Analysis only — no execution performed');
  });

  test('returns same fields as safeExecute plus note', async () => {
    const [exec, analyze] = await Promise.all([
      safeExecute('SELECT * FROM users'),
      safeAnalyze('SELECT * FROM users'),
    ]);

    expect(analyze.domain).toBe(exec.domain);
    expect(analyze.operation).toBe(exec.operation);
    expect(analyze.riskLevel).toBe(exec.riskLevel);
    expect(analyze.blocked).toBe(exec.blocked);
    expect(analyze.policy_decision).toBe(exec.policy_decision);
    // safeAnalyze has the extra note field
    expect(analyze.note).toBeDefined();
    expect((exec as Record<string, unknown>)['note']).toBeUndefined();
  });

  test('note is present for every domain', async () => {
    const commands = [
      'SELECT 1',
      'rm -rf /tmp/test',
      'terraform plan',
      'kubectl get pods',
      'docker build .',
      'GET https://example.com/api',
      'vault read secret/app',
      'iptables -L',
      'echo hello',
    ];

    const results = await Promise.all(commands.map((cmd) => safeAnalyze(cmd)));

    for (const result of results) {
      expect(result.note).toBe('Analysis only — no execution performed');
    }
  });

  test('SQL analyze matches execute behavior', async () => {
    const result = await safeAnalyze('DELETE FROM users');
    expect(result.domain).toBe('sql');
    expect(result.riskLevel).toMatch(/^(HIGH|CRITICAL)$/);
    expect(result.blocked).toBe(true);
    expect(result.policy_decision).toBe('BLOCKED');
    expect(result.note).toBe('Analysis only — no execution performed');
  });

  test('filesystem analyze returns proper operation', async () => {
    const result = await safeAnalyze('find /var -name "*.conf"');
    expect(result.domain).toBe('filesystem');
    expect(result.operation).toBe('FIND');
    expect(result.riskLevel).toBe('LOW');
    expect(result.note).toBe('Analysis only — no execution performed');
  });

  test('API analyze returns proper method as operation', async () => {
    const result = await safeAnalyze('POST https://api.example.com/users');
    expect(result.domain).toBe('api');
    expect(result.operation).toBe('POST');
    expect(result.note).toBe('Analysis only — no execution performed');
  });

  test('domain override works with safeAnalyze', async () => {
    // Force a command to be parsed as a different domain
    const result = await safeAnalyze('SELECT * FROM users', 'filesystem');
    // Even though the command is SQL, domain override forces filesystem parsing
    expect(result.domain).toBe('filesystem');
    expect(result.note).toBe('Analysis only — no execution performed');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. Unknown Domain Handling
// ─────────────────────────────────────────────────────────────────────────────

describe('Unknown domain handling', () => {
  test('echo hello -> domain=unknown, operation=unknown', async () => {
    const result = await safeExecute('echo hello');
    expect(result.domain).toBe('unknown');
    expect(result.operation).toBe('unknown');
    expect(result.targets).toEqual([]);
    expect(result.riskLevel).toBe('unknown');
    expect(result.blocked).toBe(false);
    expect(result.reason).toBe('No parser available for this domain');
    expect(result.policy_decision).toBe('ALLOWED');
  });

  test('whoami -> domain=unknown', async () => {
    const result = await safeExecute('whoami');
    expect(result.domain).toBe('unknown');
    expect(result.operation).toBe('unknown');
    expect(result.policy_decision).toBe('ALLOWED');
  });

  test('ls -la /tmp -> domain=unknown (ls not in detectDomain patterns)', async () => {
    const result = await safeExecute('ls -la /tmp');
    expect(result.domain).toBe('unknown');
    expect(result.operation).toBe('unknown');
  });

  test('ping google.com -> domain=unknown', async () => {
    const result = await safeExecute('ping google.com');
    expect(result.domain).toBe('unknown');
  });

  test('whitespace-only string -> domain=unknown', async () => {
    const result = await safeExecute('   ');
    expect(result.domain).toBe('unknown');
    expect(result.operation).toBe('unknown');
  });

  test('empty string -> domain=unknown', async () => {
    const result = await safeExecute('');
    expect(result.domain).toBe('unknown');
    expect(result.operation).toBe('unknown');
    expect(result.blocked).toBe(false);
  });

  test('safePolicyCheck with unknown command', async () => {
    const result = await safePolicyCheck('echo test');
    expect(result.domain).toBe('unknown');
    expect(result.allowed).toBe(true);
    expect(result.risk).toBe('unknown');
    expect(result.reason).toBe('No parser available for this domain');
  });

  test('safeAnalyze with unknown command', async () => {
    const result = await safeAnalyze('echo test');
    expect(result.domain).toBe('unknown');
    expect(result.operation).toBe('unknown');
    expect(result.note).toBe('Analysis only — no execution performed');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. Operation Field Mapping (per-domain behavior)
// ─────────────────────────────────────────────────────────────────────────────

describe('Operation field mapping per domain', () => {
  test('SQL SELECT: operation is SELECT', async () => {
    const result = await safeExecute('SELECT * FROM users');
    expect(result.operation).toBe('SELECT');
  });

  test('SQL DELETE: operation is DELETE', async () => {
    const result = await safeExecute('DELETE FROM users');
    expect(result.operation).toBe('DELETE');
  });

  test('Filesystem: operation is commandType (RM)', async () => {
    const result = await safeExecute('rm -rf /tmp/test');
    expect(result.operation).toBe('RM');
  });

  test('Cloud READ: operation is READ (terraform plan)', async () => {
    const result = await safeExecute('terraform plan');
    expect(result.operation).toBe('READ');
  });

  test('Cloud DESTROY: operation is DESTROY (terraform destroy)', async () => {
    const result = await safeExecute('terraform destroy');
    expect(result.operation).toBe('DESTROY');
  });

  test('Kubernetes: operation is verb (get)', async () => {
    const result = await safeExecute('kubectl get pods');
    expect(result.operation).toBe('get');
  });

  test('Kubernetes delete: operation is delete', async () => {
    const result = await safeExecute('kubectl delete namespace kube-system');
    expect(result.operation).toBe('delete');
  });

  test('CICD: operation is action (build)', async () => {
    const result = await safeExecute('docker build -t myapp .');
    expect(result.operation).toBe('build');
  });

  test('CICD run: operation is run', async () => {
    const result = await safeExecute('docker run --privileged -v /:/host alpine');
    expect(result.operation).toBe('run');
  });

  test('API: operation is method (GET)', async () => {
    const result = await safeExecute('GET https://example.com/api');
    expect(result.operation).toBe('GET');
  });

  test('API POST: operation is POST', async () => {
    const result = await safeExecute('POST https://example.com/api');
    expect(result.operation).toBe('POST');
  });

  test('Secrets: operation is action (read)', async () => {
    const result = await safeExecute('vault read secret/app');
    expect(result.operation).toBe('read');
  });

  test('Network: operation is action (configure for iptables)', async () => {
    const result = await safeExecute('iptables -L');
    expect(result.operation).toBe('configure');
  });

  test('Unknown: operation is "unknown" (from default case)', async () => {
    const result = await safeExecute('echo hello');
    expect(result.operation).toBe('unknown');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 10. Targets Field Mapping (per-domain behavior)
// ─────────────────────────────────────────────────────────────────────────────

describe('Targets field mapping per domain', () => {
  test('SQL: targets contains table names', async () => {
    const result = await safeExecute('SELECT * FROM users');
    expect(result.targets).toEqual(['users']);
  });

  test('Filesystem: targets contains targetPaths', async () => {
    const result = await safeExecute('rm -rf /tmp/test');
    expect(result.targets).toContain('/tmp/test');
  });

  test('Cloud: targets is array (may be empty for terraform plan)', async () => {
    const result = await safeExecute('terraform plan');
    expect(Array.isArray(result.targets)).toBe(true);
  });

  test('Kubernetes: targets contains resource type and name', async () => {
    const result = await safeExecute('kubectl get pods');
    expect(result.targets).toContain('pods');
  });

  test('CICD: targets contains imageTag when present', async () => {
    const result = await safeExecute('docker build -t myapp .');
    expect(result.targets).toContain('myapp');
  });

  test('API: targets contains host+path', async () => {
    const result = await safeExecute('GET https://example.com/api/v1/users');
    expect(result.targets.length).toBeGreaterThan(0);
    expect(result.targets[0]).toContain('example.com');
  });

  test('Secrets: targets contains secretPath', async () => {
    const result = await safeExecute('vault read secret/app');
    expect(result.targets).toContain('secret/app');
  });

  test('Network: targets is an array (may be empty if no targetHost)', async () => {
    const result = await safeExecute('iptables -L');
    expect(Array.isArray(result.targets)).toBe(true);
  });

  test('Unknown: targets is empty (from default case)', async () => {
    const result = await safeExecute('echo hello');
    expect(result.targets).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 11. Domain Override (explicit domain parameter)
// ─────────────────────────────────────────────────────────────────────────────

describe('Domain override via explicit domain parameter', () => {
  test('SQL command can be forced to filesystem domain', async () => {
    const result = await safeExecute('SELECT * FROM users', 'filesystem');
    expect(result.domain).toBe('filesystem');
  });

  test('filesystem command can be forced to unknown domain', async () => {
    const result = await safeExecute('rm -rf /tmp', 'unknown');
    expect(result.domain).toBe('unknown');
    expect(result.operation).toBe('unknown');
  });

  test('unknown command can be forced to SQL domain', async () => {
    // This will likely throw in the SQL parser because 'echo hello' is not valid SQL
    // The parser has a regex fallback, so it may still return a result
    const result = await safeExecute('echo hello', 'sql');
    expect(result.domain).toBe('sql');
  });

  test('safeAnalyze respects domain override', async () => {
    // Forcing a filesystem command into the cloud parser throws because
    // 'rm' is not a supported cloud CLI. This verifies the override is applied.
    await expect(safeAnalyze('rm -rf /', 'cloud')).rejects.toThrow(
      /Unsupported cloud CLI/,
    );
  });

  test('safeAnalyze domain override with compatible command', async () => {
    const result = await safeAnalyze('terraform plan', 'cloud');
    expect(result.domain).toBe('cloud');
    expect(result.note).toBe('Analysis only — no execution performed');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 12. Reason Field Behavior
// ─────────────────────────────────────────────────────────────────────────────

describe('Reason field behavior across domains', () => {
  test('SQL: reason comes from riskFactors descriptions (SafeIntent has riskFactors)', async () => {
    const result = await safeExecute('DELETE FROM users');
    expect(result.domain).toBe('sql');
    // SafeIntent has riskFactors array with description fields
    expect(typeof result.reason).toBe('string');
    expect(result.reason).toBeTruthy();
  });

  test('SQL SELECT: reason may be null or describe low risk', async () => {
    const result = await safeExecute('SELECT * FROM users');
    // riskFactors may be empty for safe SELECT
    expect(result.reason === null || typeof result.reason === 'string').toBe(true);
  });

  test('Filesystem: reason from denyReason', async () => {
    const result = await safeExecute('rm -rf /');
    expect(result.domain).toBe('filesystem');
    // rm -rf / has a deny reason
    expect(result.reason).toBeTruthy();
  });

  test('Cloud: reason is "Destructive cloud operation" for terraform destroy', async () => {
    const result = await safeExecute('terraform destroy');
    expect(result.reason).toBe('Destructive cloud operation');
  });

  test('Kubernetes: reason comes from SafeIntent riskFactors', async () => {
    const result = await safeExecute('kubectl delete namespace kube-system');
    // SafeIntent has riskFactors, so this should be populated
    expect(typeof result.reason).toBe('string');
  });

  test('CICD: reason is null (no riskFactors on ParsedCicdCommand)', async () => {
    const result = await safeExecute('docker build -t myapp .');
    expect(result.reason).toBeNull();
  });

  test('API: reason is null (no riskFactors on ParsedHttpRequest)', async () => {
    const result = await safeExecute('GET https://example.com/api');
    expect(result.reason).toBeNull();
  });

  test('Secrets: reason is null (no riskFactors on ParsedSecretCommand)', async () => {
    const result = await safeExecute('vault read secret/app');
    expect(result.reason).toBeNull();
  });

  test('Network: reason is null (no riskFactors on ParsedNetworkCommand)', async () => {
    const result = await safeExecute('iptables -L');
    expect(result.reason).toBeNull();
  });

  test('Unknown: reason explains no parser is available', async () => {
    const result = await safeExecute('echo hello');
    expect(result.reason).toBe('No parser available for this domain');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 13. Result Shape Consistency
// ─────────────────────────────────────────────────────────────────────────────

describe('Result shape consistency', () => {
  const allCommands = [
    'SELECT * FROM users',
    'rm -rf /tmp/test',
    'terraform plan',
    'kubectl get pods',
    'docker build .',
    'GET https://example.com/api',
    'vault read secret/app',
    'iptables -L',
    'echo hello',
  ];

  test('safeExecute always returns required fields', async () => {
    for (const cmd of allCommands) {
      const result = await safeExecute(cmd) as Record<string, unknown>;
      expect(result).toHaveProperty('domain');
      expect(result).toHaveProperty('operation');
      expect(result).toHaveProperty('targets');
      expect(result).toHaveProperty('riskLevel');
      expect(result).toHaveProperty('blocked');
      expect(result).toHaveProperty('reason');
      expect(result).toHaveProperty('policy_decision');
      expect(Array.isArray(result['targets'])).toBe(true);
      expect(['ALLOWED', 'BLOCKED']).toContain(result['policy_decision']);
    }
  });

  test('safeAnalyze always returns required fields plus note', async () => {
    for (const cmd of allCommands) {
      const result = await safeAnalyze(cmd) as Record<string, unknown>;
      expect(result).toHaveProperty('domain');
      expect(result).toHaveProperty('operation');
      expect(result).toHaveProperty('targets');
      expect(result).toHaveProperty('riskLevel');
      expect(result).toHaveProperty('blocked');
      expect(result).toHaveProperty('reason');
      expect(result).toHaveProperty('policy_decision');
      expect(result).toHaveProperty('note');
      expect(result['note']).toBe('Analysis only — no execution performed');
    }
  });

  test('safePolicyCheck always returns required fields', async () => {
    for (const cmd of allCommands) {
      const result = await safePolicyCheck(cmd) as Record<string, unknown>;
      expect(result).toHaveProperty('allowed');
      expect(result).toHaveProperty('risk');
      expect(result).toHaveProperty('domain');
      expect(result).toHaveProperty('reason');
      expect(typeof result['allowed']).toBe('boolean');
      expect(typeof result['domain']).toBe('string');
    }
  });
});
