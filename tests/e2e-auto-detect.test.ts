/**
 * E2E Auto-Detect Tests
 *
 * Tests the full chain: detectDomain -> adapter parser -> risk classification.
 * Each test verifies that auto-detect routes the command to the correct domain,
 * the adapter parser produces the correct structured output, and risk levels
 * are classified as expected.
 */

import { detectDomain } from '../src/mcp-server/auto-detect.js';
import { parseIntent } from '../src/adapters/sql/parser.js';
import { parseIntent as parseFilesystemIntent } from '../src/adapters/filesystem/parser.js';
import { buildCloudIntent } from '../src/adapters/cloud/parser.js';
import { parseKubeCommand, toSafeIntent } from '../src/adapters/kubernetes/parser.js';
import { parseCicdCommand } from '../src/adapters/cicd/parser.js';
import { parseHttpRequest } from '../src/adapters/api/parser.js';
import { parseSecretCommand } from '../src/adapters/secrets/parser.js';
import { parseNetworkCommand } from '../src/adapters/network/parser.js';
import { parseGitCommand } from '../src/adapters/git/parser.js';
import { parseQueueCommand } from '../src/adapters/queue/parser.js';

// ─── SQL Domain ──────────────────────────────────────────────────────────────

describe('SQL domain — full chain', () => {
  test('SELECT * FROM users → domain=sql, type=SELECT, no risk factors', async () => {
    const cmd = 'SELECT * FROM users';

    expect(detectDomain(cmd)).toBe('sql');

    const intent = await parseIntent(cmd);
    expect(intent.domain).toBe('sql');
    expect(intent.type).toBe('SELECT');
    expect(intent.riskFactors).toHaveLength(0);
    expect(intent.isDestructive).toBe(false);
    expect(intent.tables).toContain('users');
  });

  test('DELETE FROM users (no WHERE) → CRITICAL with NO_WHERE_CLAUSE', async () => {
    const cmd = 'DELETE FROM users';

    expect(detectDomain(cmd)).toBe('sql');

    const intent = await parseIntent(cmd);
    expect(intent.type).toBe('DELETE');
    expect(intent.hasWhereClause).toBe(false);
    expect(intent.isDestructive).toBe(true);
    expect(intent.isMassive).toBe(true);

    const noWhereClause = intent.riskFactors.find((f) => f.code === 'NO_WHERE_CLAUSE');
    expect(noWhereClause).toBeDefined();
    expect(noWhereClause!.severity).toBe('CRITICAL');
  });

  test('DROP TABLE production_data → DROP with DROP_OP risk factor', async () => {
    const cmd = 'DROP TABLE production_data';

    expect(detectDomain(cmd)).toBe('sql');

    const intent = await parseIntent(cmd);
    expect(intent.type).toBe('DROP');
    expect(intent.isDestructive).toBe(true);

    const dropFactor = intent.riskFactors.find((f) => f.code === 'DROP_OP');
    expect(dropFactor).toBeDefined();
    expect(dropFactor!.severity).toBe('CRITICAL');
  });

  test('UPDATE accounts SET balance = 0 (no WHERE) → HIGH with NO_WHERE_CLAUSE_UPDATE', async () => {
    const cmd = 'UPDATE accounts SET balance = 0';

    expect(detectDomain(cmd)).toBe('sql');

    const intent = await parseIntent(cmd);
    expect(intent.type).toBe('UPDATE');
    expect(intent.hasWhereClause).toBe(false);
    expect(intent.isMassive).toBe(true);

    const noWhere = intent.riskFactors.find((f) => f.code === 'NO_WHERE_CLAUSE_UPDATE');
    expect(noWhere).toBeDefined();
    expect(noWhere!.severity).toBe('HIGH');
  });
});

// ─── Cloud Domain ────────────────────────────────────────────────────────────

describe('Cloud domain — full chain', () => {
  test('terraform destroy -auto-approve → CRITICAL, DESTROY, affectsAll=true', () => {
    const cmd = 'terraform destroy -auto-approve';

    expect(detectDomain(cmd)).toBe('cloud');

    const intent = buildCloudIntent(cmd);
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.actionType).toBe('DESTROY');
    expect(intent.affectsAll).toBe(true);
    expect(intent.isDestructive).toBe(true);
  });

  test('aws ec2 terminate-instances --instance-ids i-1234 → DESTROY', () => {
    const cmd = 'aws ec2 terminate-instances --instance-ids i-1234';

    expect(detectDomain(cmd)).toBe('cloud');

    const intent = buildCloudIntent(cmd);
    expect(intent.actionType).toBe('DESTROY');
    expect(intent.isDestructive).toBe(true);
    expect(intent.command.provider).toBe('aws');
    expect(intent.command.service).toBe('ec2');
  });

  test('gcloud compute instances delete my-vm --zone us-east1-b → DESTROY', () => {
    const cmd = 'gcloud compute instances delete my-vm --zone us-east1-b';

    expect(detectDomain(cmd)).toBe('cloud');

    const intent = buildCloudIntent(cmd);
    expect(intent.actionType).toBe('DESTROY');
    expect(intent.isDestructive).toBe(true);
    expect(intent.command.provider).toBe('gcloud');
  });
});

// ─── Kubernetes Domain ───────────────────────────────────────────────────────

describe('Kubernetes domain — full chain', () => {
  test('kubectl delete namespace production → CRITICAL with delete-namespace pattern', () => {
    const cmd = 'kubectl delete namespace production';

    expect(detectDomain(cmd)).toBe('kubernetes');

    const kubeIntent = parseKubeCommand(cmd);
    expect(kubeIntent.dangerousPatterns).toContain('delete-namespace');
    expect(kubeIntent.riskLevel).toBe('CRITICAL');

    const safeIntent = toSafeIntent(kubeIntent);
    expect(safeIntent.domain).toBe('kubernetes');
    expect(safeIntent.type).toBe('DROP');
    expect(safeIntent.isDestructive).toBe(true);
  });

  test('kubectl scale deployment myapp --replicas=0 → CRITICAL with scale-to-zero', () => {
    const cmd = 'kubectl scale deployment myapp --replicas=0';

    expect(detectDomain(cmd)).toBe('kubernetes');

    const kubeIntent = parseKubeCommand(cmd);
    expect(kubeIntent.dangerousPatterns).toContain('scale-to-zero');
    expect(kubeIntent.riskLevel).toBe('CRITICAL');

    const safeIntent = toSafeIntent(kubeIntent);
    expect(safeIntent.type).toBe('TRUNCATE');
    expect(safeIntent.isMassive).toBe(true);
  });

  test('helm uninstall my-release → HIGH with helm-uninstall pattern', () => {
    const cmd = 'helm uninstall my-release';

    expect(detectDomain(cmd)).toBe('kubernetes');

    const kubeIntent = parseKubeCommand(cmd);
    expect(kubeIntent.dangerousPatterns).toContain('helm-uninstall');
    expect(kubeIntent.riskLevel).toBe('HIGH');

    const safeIntent = toSafeIntent(kubeIntent);
    expect(safeIntent.type).toBe('DROP');
    expect(safeIntent.isDestructive).toBe(true);
  });
});

// ─── Filesystem Domain ───────────────────────────────────────────────────────

describe('Filesystem domain — full chain', () => {
  test('rm -rf / → CRITICAL, isDenied=true', () => {
    const cmd = 'rm -rf /';

    expect(detectDomain(cmd)).toBe('filesystem');

    const intent = parseFilesystemIntent(cmd);
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.isDestructive).toBe(true);
    expect(intent.commandType).toBe('RM');
  });

  test('chmod 777 /tmp/test → requiresApproval=true (isChmod777)', () => {
    const cmd = 'chmod 777 /tmp/test';

    expect(detectDomain(cmd)).toBe('filesystem');

    const intent = parseFilesystemIntent(cmd);
    expect(intent.requiresApproval).toBe(true);
    expect(intent.commandType).toBe('CHMOD');
    expect(intent.metadata.modeArg).toBe('777');
  });

  test('dd if=/dev/zero of=/dev/sda → isDenied=true (dd to block device)', () => {
    const cmd = 'dd if=/dev/zero of=/dev/sda';

    expect(detectDomain(cmd)).toBe('filesystem');

    const intent = parseFilesystemIntent(cmd);
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.commandType).toBe('DD');
    expect(intent.denyReason).toContain('block device');
  });

  test('rm -rf /etc → CRITICAL, isDenied on system path', () => {
    const cmd = 'rm -rf /etc';

    expect(detectDomain(cmd)).toBe('filesystem');

    const intent = parseFilesystemIntent(cmd);
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });
});

// ─── CI/CD Domain ────────────────────────────────────────────────────────────

describe('CI/CD domain — full chain', () => {
  test('docker run --privileged alpine → isPrivileged=true, riskLevel=CRITICAL', () => {
    const cmd = 'docker run --privileged alpine';

    expect(detectDomain(cmd)).toBe('cicd');

    const parsed = parseCicdCommand(cmd);
    expect(parsed.isPrivileged).toBe(true);
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.action).toBe('run');
    expect(parsed.tool).toBe('docker');
  });

  test('docker push myimage:latest → push, isPublicRegistry=true', () => {
    const cmd = 'docker push myimage:latest';

    expect(detectDomain(cmd)).toBe('cicd');

    const parsed = parseCicdCommand(cmd);
    expect(parsed.action).toBe('push');
    expect(parsed.isPublicRegistry).toBe(true);
    expect(parsed.tool).toBe('docker');
  });

  test('docker build -t myapp:v1.0 . → build, riskLevel=LOW', () => {
    const cmd = 'docker build -t myapp:v1.0 .';

    expect(detectDomain(cmd)).toBe('cicd');

    const parsed = parseCicdCommand(cmd);
    expect(parsed.action).toBe('build');
    expect(parsed.riskLevel).toBe('LOW');
    expect(parsed.tool).toBe('docker');
  });
});

// ─── API Domain ──────────────────────────────────────────────────────────────

describe('API domain — full chain', () => {
  test('curl -X DELETE https://api.example.com/users/123 → DELETE, riskLevel=CRITICAL', () => {
    const cmd = 'curl -X DELETE https://api.example.com/users/123';

    expect(detectDomain(cmd)).toBe('api');

    const parsed = parseHttpRequest(cmd);
    expect(parsed.method).toBe('DELETE');
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.isDestructive).toBe(true);
  });

  test('POST https://api.stripe.com/v1/charges → POST, payment category, risk escalated', () => {
    const cmd = 'POST https://api.stripe.com/v1/charges';

    expect(detectDomain(cmd)).toBe('api');

    const parsed = parseHttpRequest(cmd);
    expect(parsed.method).toBe('POST');
    expect(parsed.endpointCategory).toBe('payment');
    // POST base is MEDIUM, payment escalates +2 -> CRITICAL
    expect(parsed.riskLevel).toBe('CRITICAL');
  });

  test('GET https://api.example.com/health → GET, riskLevel=LOW', () => {
    const cmd = 'GET https://api.example.com/health';

    expect(detectDomain(cmd)).toBe('api');

    const parsed = parseHttpRequest(cmd);
    expect(parsed.method).toBe('GET');
    expect(parsed.riskLevel).toBe('LOW');
    expect(parsed.isDestructive).toBe(false);
  });

  test('curl -X PUT https://api.example.com/admin/config → PUT to admin, HIGH+1=CRITICAL', () => {
    const cmd = 'curl -X PUT https://api.example.com/admin/config';

    expect(detectDomain(cmd)).toBe('api');

    const parsed = parseHttpRequest(cmd);
    expect(parsed.method).toBe('PUT');
    expect(parsed.endpointCategory).toBe('admin');
    // PUT base is HIGH, admin escalates +1 -> CRITICAL
    expect(parsed.riskLevel).toBe('CRITICAL');
  });
});

// ─── Secrets Domain ──────────────────────────────────────────────────────────

describe('Secrets domain — full chain', () => {
  test('vault read secret/data/prod/db-password → secrets, tool=vault, action=read, LOW', () => {
    const cmd = 'vault read secret/data/prod/db-password';

    expect(detectDomain(cmd)).toBe('secrets');

    const parsed = parseSecretCommand(cmd);
    expect(parsed.tool).toBe('vault');
    expect(parsed.action).toBe('read');
    expect(parsed.riskLevel).toBe('LOW');
    expect(parsed.secretPath).toBe('secret/data/prod/db-password');
  });

  test('kubectl get secret my-secret -o yaml → kubernetes domain (kubectl prefix takes priority)', () => {
    const cmd = 'kubectl get secret my-secret -o yaml';

    // detectDomain routes kubectl commands to 'kubernetes', not 'secrets'.
    // The secrets parser is used when the adapter layer detects the secret sub-resource.
    expect(detectDomain(cmd)).toBe('kubernetes');

    // The secrets parser can still parse it correctly when invoked directly
    const parsed = parseSecretCommand(cmd);
    expect(parsed.tool).toBe('kubectl-secrets');
    expect(parsed.action).toBe('read');
  });

  test('export API_KEY=sk_live_abc123 → unknown domain (no auto-detect pattern)', () => {
    const cmd = 'export API_KEY=sk_live_abc123';

    // detectDomain does not have a pattern for bare 'export' commands.
    // The secrets parser handles it as 'env-export' when invoked directly.
    expect(detectDomain(cmd)).toBe('unknown');

    // Direct parser invocation still works correctly
    const parsed = parseSecretCommand(cmd);
    expect(parsed.tool).toBe('env-export');
    expect(parsed.action).toBe('export');
  });

  test('aws secretsmanager get-secret-value --secret-id prod/db → cloud domain (aws prefix takes priority)', () => {
    const cmd = 'aws secretsmanager get-secret-value --secret-id prod/db';

    // detectDomain matches 'aws ' prefix first, routing to 'cloud' before
    // the 'secretsmanager' substring check. This documents the priority order.
    expect(detectDomain(cmd)).toBe('cloud');

    // The secrets parser handles it correctly when invoked directly
    const parsed = parseSecretCommand(cmd);
    expect(parsed.tool).toBe('aws-secrets');
    expect(parsed.action).toBe('read');
    expect(parsed.secretPath).toBe('prod/db');
    expect(parsed.isProduction).toBe(true);
  });
});

// ─── Git Domain ──────────────────────────────────────────────────────────────

describe('Git domain — full chain', () => {
  test('git push --force origin main → force-push, isProtectedBranch=true, CRITICAL', () => {
    const cmd = 'git push --force origin main';

    expect(detectDomain(cmd)).toBe('git');

    const parsed = parseGitCommand(cmd);
    expect(parsed.action).toBe('force-push');
    expect(parsed.isProtectedBranch).toBe(true);
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.isDestructive).toBe(true);
    expect(parsed.rewritesHistory).toBe(true);

    const denyPattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'force-push-to-main',
    );
    expect(denyPattern).toBeDefined();
    expect(denyPattern!.severity).toBe('DENY');
  });

  test('git reset --hard HEAD~5 → reset, isDestructive=true, has reset-hard pattern', () => {
    const cmd = 'git reset --hard HEAD~5';

    expect(detectDomain(cmd)).toBe('git');

    const parsed = parseGitCommand(cmd);
    expect(parsed.action).toBe('reset');
    expect(parsed.isDestructive).toBe(true);
    expect(parsed.rewritesHistory).toBe(true);

    const resetHard = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'reset-hard',
    );
    expect(resetHard).toBeDefined();
    expect(resetHard!.severity).toBe('CRITICAL');
  });

  test('git filter-branch --all → has filter-branch DENY pattern', () => {
    const cmd = 'git filter-branch --all';

    expect(detectDomain(cmd)).toBe('git');

    const parsed = parseGitCommand(cmd);

    const filterBranch = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'filter-branch',
    );
    expect(filterBranch).toBeDefined();
    expect(filterBranch!.severity).toBe('DENY');
    expect(parsed.riskLevel).toBe('CRITICAL');
  });
});

// ─── Network Domain ──────────────────────────────────────────────────────────

describe('Network domain — full chain', () => {
  test('iptables -F INPUT → isFirewallDisable=true, iptables-flush-input DENY, CRITICAL', () => {
    const cmd = 'iptables -F INPUT';

    expect(detectDomain(cmd)).toBe('network');

    const parsed = parseNetworkCommand(cmd);
    expect(parsed.isFirewallDisable).toBe(true);
    expect(parsed.riskLevel).toBe('CRITICAL');

    const flushInput = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'iptables-flush-input',
    );
    expect(flushInput).toBeDefined();
    expect(flushInput!.severity).toBe('DENY');
  });

  test('ufw disable → isFirewallDisable=true, CRITICAL', () => {
    const cmd = 'ufw disable';

    expect(detectDomain(cmd)).toBe('network');

    const parsed = parseNetworkCommand(cmd);
    expect(parsed.isFirewallDisable).toBe(true);
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.isDestructive).toBe(true);

    const ufwDisable = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'ufw-disable',
    );
    expect(ufwDisable).toBeDefined();
  });

  test('ip link set lo down → isInterfaceDown=true, loopback-down DENY', () => {
    const cmd = 'ip link set lo down';

    expect(detectDomain(cmd)).toBe('network');

    const parsed = parseNetworkCommand(cmd);
    expect(parsed.isInterfaceDown).toBe(true);
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.isDestructive).toBe(true);

    const loopback = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'loopback-down',
    );
    expect(loopback).toBeDefined();
    expect(loopback!.severity).toBe('DENY');
  });
});

// ─── Queue Domain ────────────────────────────────────────────────────────────

describe('Queue domain — full chain', () => {
  test('kafka-topics --delete --topic my-events --bootstrap-server localhost:9092 → CRITICAL', () => {
    const cmd = 'kafka-topics --delete --topic my-events --bootstrap-server localhost:9092';

    expect(detectDomain(cmd)).toBe('queue');

    const parsed = parseQueueCommand(cmd);
    expect(parsed.tool).toBe('kafka');
    expect(parsed.action).toBe('delete');
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.isDestructive).toBe(true);
    expect(parsed.targetName).toBe('my-events');
  });

  test('redis-cli FLUSHALL → purge, redis FLUSHALL DENY pattern', () => {
    const cmd = 'redis-cli FLUSHALL';

    expect(detectDomain(cmd)).toBe('queue');

    const parsed = parseQueueCommand(cmd);
    expect(parsed.tool).toBe('redis');
    expect(parsed.action).toBe('purge');
    expect(parsed.riskLevel).toBe('CRITICAL');

    const flushAll = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'redis FLUSHALL',
    );
    expect(flushAll).toBeDefined();
    expect(flushAll!.severity).toBe('DENY');
  });

  test('rabbitmqctl purge_queue my-queue → purge, CRITICAL', () => {
    const cmd = 'rabbitmqctl purge_queue my-queue';

    expect(detectDomain(cmd)).toBe('queue');

    const parsed = parseQueueCommand(cmd);
    expect(parsed.tool).toBe('rabbitmq');
    expect(parsed.action).toBe('purge');
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.isDestructive).toBe(true);
    expect(parsed.targetName).toBe('my-queue');
  });
});
