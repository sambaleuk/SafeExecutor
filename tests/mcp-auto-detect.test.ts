import { detectDomain } from '../src/mcp-server/auto-detect.js';

describe('detectDomain', () => {
  // ─── SQL ───────────────────────────────────────────────────────────────────
  test('SELECT query → sql', () => expect(detectDomain('SELECT * FROM users')).toBe('sql'));
  test('INSERT query → sql', () => expect(detectDomain('INSERT INTO orders VALUES (1)')).toBe('sql'));
  test('UPDATE query → sql', () => expect(detectDomain('UPDATE users SET name = "foo"')).toBe('sql'));
  test('DELETE query → sql', () => expect(detectDomain('DELETE FROM sessions WHERE expired = true')).toBe('sql'));
  test('CREATE TABLE → sql', () => expect(detectDomain('CREATE TABLE test (id INT)')).toBe('sql'));
  test('ALTER TABLE → sql', () => expect(detectDomain('ALTER TABLE users ADD COLUMN email TEXT')).toBe('sql'));
  test('DROP TABLE → sql', () => expect(detectDomain('DROP TABLE temp_data')).toBe('sql'));
  test('TRUNCATE → sql', () => expect(detectDomain('TRUNCATE TABLE logs')).toBe('sql'));
  test('lowercase select → sql', () => expect(detectDomain('select id from products')).toBe('sql'));

  // ─── Git ──────────────────────────────────────────────────────────────────
  test('git commit → git', () => expect(detectDomain('git commit -m "fix bug"')).toBe('git'));
  test('git push → git', () => expect(detectDomain('git push origin main')).toBe('git'));
  test('git pull → git', () => expect(detectDomain('git pull')).toBe('git'));

  // ─── Kubernetes ───────────────────────────────────────────────────────────
  test('kubectl apply → kubernetes', () => expect(detectDomain('kubectl apply -f deployment.yaml')).toBe('kubernetes'));
  test('kubectl delete → kubernetes', () => expect(detectDomain('kubectl delete pod my-pod')).toBe('kubernetes'));
  test('helm install → kubernetes', () => expect(detectDomain('helm install my-release chart/')).toBe('kubernetes'));

  // ─── Cloud ────────────────────────────────────────────────────────────────
  test('terraform destroy → cloud', () => expect(detectDomain('terraform destroy -auto-approve')).toBe('cloud'));
  test('aws s3 rm → cloud', () => expect(detectDomain('aws s3 rm s3://my-bucket --recursive')).toBe('cloud'));
  test('gcloud run deploy → cloud', () => expect(detectDomain('gcloud run deploy my-service')).toBe('cloud'));
  test('az vm delete → cloud', () => expect(detectDomain('az vm delete --name myVM')).toBe('cloud'));

  // ─── CI/CD ────────────────────────────────────────────────────────────────
  test('docker build → cicd', () => expect(detectDomain('docker build -t myapp .')).toBe('cicd'));
  test('docker-compose up → cicd', () => expect(detectDomain('docker-compose up -d')).toBe('cicd'));
  test('gh workflow run → cicd', () => expect(detectDomain('gh workflow run deploy.yml')).toBe('cicd'));

  // ─── Secrets ──────────────────────────────────────────────────────────────
  test('vault kv get → secrets', () => expect(detectDomain('vault kv get secret/db')).toBe('secrets'));
  test('secretsmanager in command → secrets', () => expect(detectDomain('aws secretsmanager get-secret-value --secret-id prod/db')).toBe('secrets'));
  test('ssm in command → secrets', () => expect(detectDomain('aws ssm get-parameter --name /prod/api_key')).toBe('secrets'));
  test('keyvault in command → secrets', () => expect(detectDomain('az keyvault secret show --name mySecret')).toBe('secrets'));

  // ─── Network ──────────────────────────────────────────────────────────────
  test('iptables → network', () => expect(detectDomain('iptables -A INPUT -p tcp --dport 80 -j ACCEPT')).toBe('network'));
  test('ufw allow → network', () => expect(detectDomain('ufw allow 443')).toBe('network'));
  test('ip addr → network', () => expect(detectDomain('ip addr show')).toBe('network'));
  test('nmap scan → network', () => expect(detectDomain('nmap -sV 192.168.1.0/24')).toBe('network'));

  // ─── Queue ────────────────────────────────────────────────────────────────
  test('kafka-topics → queue', () => expect(detectDomain('kafka-topics.sh --list --bootstrap-server localhost:9092')).toBe('queue'));
  test('redis-cli → queue', () => expect(detectDomain('redis-cli FLUSHALL')).toBe('queue'));
  test('sqs in command → queue', () => expect(detectDomain('aws sqs send-message --queue-url https://sqs.us-east-1.amazonaws.com/123/myqueue')).toBe('queue'));
  test('sns in command → queue', () => expect(detectDomain('aws sns publish --topic-arn arn:aws:sns:us-east-1:123:MyTopic')).toBe('queue'));
  test('pubsub in command → queue', () => expect(detectDomain('gcloud pubsub topics publish my-topic --message="hello"')).toBe('queue'));

  // ─── API ──────────────────────────────────────────────────────────────────
  test('curl → api', () => expect(detectDomain('curl -X POST https://api.example.com/users')).toBe('api'));
  test('http prefix → api', () => expect(detectDomain('https://api.example.com/health')).toBe('api'));
  test('HTTP GET method → api', () => expect(detectDomain('GET /api/v1/users HTTP/1.1')).toBe('api'));
  test('HTTP POST method → api', () => expect(detectDomain('POST /api/v1/orders HTTP/1.1')).toBe('api'));

  // ─── Filesystem ───────────────────────────────────────────────────────────
  test('rm -rf → filesystem', () => expect(detectDomain('rm -rf /tmp/old-data')).toBe('filesystem'));
  test('chmod → filesystem', () => expect(detectDomain('chmod 755 /usr/local/bin/app')).toBe('filesystem'));
  test('chown → filesystem', () => expect(detectDomain('chown root:root /etc/config')).toBe('filesystem'));
  test('dd → filesystem', () => expect(detectDomain('dd if=/dev/zero of=/dev/sdb bs=1M')).toBe('filesystem'));
  test('find → filesystem', () => expect(detectDomain('find /var/log -name "*.log" -mtime +30')).toBe('filesystem'));
  test('mv → filesystem', () => expect(detectDomain('mv /tmp/upload /data/files/upload')).toBe('filesystem'));
  test('cp → filesystem', () => expect(detectDomain('cp -r /src /dst')).toBe('filesystem'));

  // ─── Unknown / Edge cases ─────────────────────────────────────────────────
  test('empty string → unknown', () => expect(detectDomain('')).toBe('unknown'));
  test('random command → unknown', () => expect(detectDomain('echo hello')).toBe('unknown'));
  test('whitespace only → unknown', () => expect(detectDomain('   ')).toBe('unknown'));
  test('ls command → unknown', () => expect(detectDomain('ls -la /tmp')).toBe('unknown'));
});
