import { detectDomain, isValidDomain } from '../src/mcp-server/auto-detect.js';

// ─── SQL Detection ───────────────────────────────────────────────────────────

describe('SQL detection', () => {
  test('SELECT query', () => {
    expect(detectDomain('SELECT * FROM users WHERE id = 1')).toEqual({ domain: 'sql', confidence: 'high' });
  });

  test('INSERT INTO', () => {
    expect(detectDomain('INSERT INTO users (name) VALUES ($1)')).toEqual({ domain: 'sql', confidence: 'high' });
  });

  test('UPDATE with SET', () => {
    expect(detectDomain('UPDATE users SET name = $1 WHERE id = $2')).toEqual({ domain: 'sql', confidence: 'high' });
  });

  test('DELETE FROM', () => {
    expect(detectDomain('DELETE FROM users WHERE id = 1')).toEqual({ domain: 'sql', confidence: 'high' });
  });

  test('DROP TABLE', () => {
    expect(detectDomain('DROP TABLE users')).toEqual({ domain: 'sql', confidence: 'high' });
  });

  test('TRUNCATE', () => {
    expect(detectDomain('TRUNCATE TABLE users')).toEqual({ domain: 'sql', confidence: 'high' });
  });

  test('ALTER TABLE', () => {
    expect(detectDomain('ALTER TABLE users ADD COLUMN email TEXT')).toEqual({ domain: 'sql', confidence: 'high' });
  });

  test('CREATE TABLE', () => {
    expect(detectDomain('CREATE TABLE users (id SERIAL PRIMARY KEY)')).toEqual({ domain: 'sql', confidence: 'high' });
  });

  test('WITH CTE', () => {
    expect(detectDomain('WITH cte AS (SELECT 1) SELECT * FROM cte')).toEqual({ domain: 'sql', confidence: 'high' });
  });
});

// ─── Git Detection ───────────────────────────────────────────────────────────

describe('Git detection', () => {
  test('git status', () => {
    expect(detectDomain('git status')).toEqual({ domain: 'git', confidence: 'high' });
  });

  test('git push', () => {
    expect(detectDomain('git push origin main')).toEqual({ domain: 'git', confidence: 'high' });
  });

  test('git rebase', () => {
    expect(detectDomain('git rebase main')).toEqual({ domain: 'git', confidence: 'high' });
  });
});

// ─── Kubernetes Detection ────────────────────────────────────────────────────

describe('Kubernetes detection', () => {
  test('kubectl get pods', () => {
    expect(detectDomain('kubectl get pods -n production')).toEqual({ domain: 'kubernetes', confidence: 'high' });
  });

  test('kubectl delete', () => {
    expect(detectDomain('kubectl delete deployment my-app')).toEqual({ domain: 'kubernetes', confidence: 'high' });
  });

  test('helm install', () => {
    expect(detectDomain('helm install my-release ./chart')).toEqual({ domain: 'kubernetes', confidence: 'high' });
  });
});

// ─── Cloud Detection ─────────────────────────────────────────────────────────

describe('Cloud detection', () => {
  test('terraform plan', () => {
    expect(detectDomain('terraform plan')).toEqual({ domain: 'cloud', confidence: 'high' });
  });

  test('terraform destroy', () => {
    expect(detectDomain('terraform destroy')).toEqual({ domain: 'cloud', confidence: 'high' });
  });

  test('aws ec2', () => {
    expect(detectDomain('aws ec2 describe-instances')).toEqual({ domain: 'cloud', confidence: 'high' });
  });

  test('gcloud compute', () => {
    expect(detectDomain('gcloud compute instances list')).toEqual({ domain: 'cloud', confidence: 'high' });
  });

  test('az vm', () => {
    expect(detectDomain('az vm create --name my-vm')).toEqual({ domain: 'cloud', confidence: 'high' });
  });
});

// ─── CI/CD Detection ─────────────────────────────────────────────────────────

describe('CI/CD detection', () => {
  test('gh workflow run', () => {
    expect(detectDomain('gh workflow run deploy.yml')).toEqual({ domain: 'cicd', confidence: 'high' });
  });

  test('gh run list', () => {
    expect(detectDomain('gh run list')).toEqual({ domain: 'cicd', confidence: 'high' });
  });
});

// ─── Secrets Detection ───────────────────────────────────────────────────────

describe('Secrets detection', () => {
  test('vault write', () => {
    expect(detectDomain('vault write secret/my-app key=value')).toEqual({ domain: 'secrets', confidence: 'high' });
  });

  test('aws secretsmanager', () => {
    expect(detectDomain('aws secretsmanager get-secret-value --secret-id my-secret')).toEqual({ domain: 'secrets', confidence: 'high' });
  });

  test('az keyvault', () => {
    expect(detectDomain('az keyvault secret set --name my-key --value my-value')).toEqual({ domain: 'secrets', confidence: 'high' });
  });
});

// ─── Network Detection ───────────────────────────────────────────────────────

describe('Network detection', () => {
  test('iptables', () => {
    expect(detectDomain('iptables -A INPUT -p tcp --dport 80 -j ACCEPT')).toEqual({ domain: 'network', confidence: 'high' });
  });

  test('ufw', () => {
    expect(detectDomain('ufw allow 22/tcp')).toEqual({ domain: 'network', confidence: 'high' });
  });

  test('ssh', () => {
    expect(detectDomain('ssh user@host')).toEqual({ domain: 'network', confidence: 'high' });
  });

  test('ping', () => {
    expect(detectDomain('ping google.com')).toEqual({ domain: 'network', confidence: 'high' });
  });

  test('ip addr show', () => {
    expect(detectDomain('ip addr show eth0')).toEqual({ domain: 'network', confidence: 'high' });
  });
});

// ─── API Detection ───────────────────────────────────────────────────────────

describe('API detection', () => {
  test('curl', () => {
    expect(detectDomain('curl -X POST https://api.example.com/users')).toEqual({ domain: 'api', confidence: 'high' });
  });

  test('wget', () => {
    expect(detectDomain('wget https://example.com/file.zip')).toEqual({ domain: 'api', confidence: 'high' });
  });

  test('HTTP method + URL', () => {
    expect(detectDomain('POST https://api.example.com/users')).toEqual({ domain: 'api', confidence: 'high' });
  });

  test('plain URL', () => {
    expect(detectDomain('https://api.example.com/health')).toEqual({ domain: 'api', confidence: 'high' });
  });
});

// ─── Filesystem Detection ────────────────────────────────────────────────────

describe('Filesystem detection', () => {
  test('rm -rf', () => {
    expect(detectDomain('rm -rf /tmp/cache')).toEqual({ domain: 'filesystem', confidence: 'high' });
  });

  test('cp', () => {
    expect(detectDomain('cp file1.txt file2.txt')).toEqual({ domain: 'filesystem', confidence: 'high' });
  });

  test('chmod', () => {
    expect(detectDomain('chmod 755 script.sh')).toEqual({ domain: 'filesystem', confidence: 'high' });
  });

  test('sudo rm', () => {
    expect(detectDomain('sudo rm -rf /var/log/old')).toEqual({ domain: 'filesystem', confidence: 'high' });
  });
});

// ─── Queue Detection ─────────────────────────────────────────────────────────

describe('Queue detection', () => {
  test('aws sqs', () => {
    expect(detectDomain('aws sqs send-message --queue-url my-queue')).toEqual({ domain: 'queue', confidence: 'high' });
  });

  test('rabbitmqctl', () => {
    expect(detectDomain('rabbitmqctl list_queues')).toEqual({ domain: 'queue', confidence: 'high' });
  });
});

// ─── No Detection ────────────────────────────────────────────────────────────

describe('No detection', () => {
  test('empty string returns null', () => {
    expect(detectDomain('')).toBeNull();
  });

  test('random text returns null', () => {
    expect(detectDomain('hello world this is just text')).toBeNull();
  });
});

// ─── isValidDomain ───────────────────────────────────────────────────────────

describe('isValidDomain', () => {
  test('valid domains return true', () => {
    expect(isValidDomain('sql')).toBe(true);
    expect(isValidDomain('cloud')).toBe(true);
    expect(isValidDomain('kubernetes')).toBe(true);
    expect(isValidDomain('filesystem')).toBe(true);
    expect(isValidDomain('network')).toBe(true);
  });

  test('invalid domains return false', () => {
    expect(isValidDomain('unknown')).toBe(false);
    expect(isValidDomain('')).toBe(false);
    expect(isValidDomain('docker')).toBe(false);
  });
});
