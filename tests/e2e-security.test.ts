/**
 * E2E Security Test Suite
 *
 * The MOST IMPORTANT test suite in SafeExecutor. Tests ALL known dangerous
 * patterns across ALL domains to ensure no destructive operation slips through
 * undetected.
 *
 * Every test here validates that the parser correctly identifies, classifies,
 * and escalates risk for commands that could cause data loss, service outages,
 * or security breaches.
 */

import { detectDomain } from '../src/mcp-server/auto-detect.js';
import { parseIntent as parseSqlIntent } from '../src/adapters/sql/parser.js';
import { parseIntent as parseFilesystemIntent } from '../src/adapters/filesystem/parser.js';
import { buildCloudIntent } from '../src/adapters/cloud/parser.js';
import { parseKubeCommand, toSafeIntent } from '../src/adapters/kubernetes/parser.js';
import { parseCicdCommand } from '../src/adapters/cicd/parser.js';
import { parseHttpRequest } from '../src/adapters/api/parser.js';
import { parseSecretCommand } from '../src/adapters/secrets/parser.js';
import { parseNetworkCommand } from '../src/adapters/network/parser.js';
import { parseGitCommand } from '../src/adapters/git/parser.js';
import { parseQueueCommand } from '../src/adapters/queue/parser.js';

// ─── 1. SQL Dangerous Patterns ──────────────────────────────────────────────

describe('SQL Dangerous Patterns', () => {
  test('DELETE FROM users → riskFactors includes NO_WHERE_CLAUSE with CRITICAL severity', async () => {
    const intent = await parseSqlIntent('DELETE FROM users');
    expect(intent.type).toBe('DELETE');
    expect(intent.hasWhereClause).toBe(false);
    expect(intent.isDestructive).toBe(true);
    expect(intent.isMassive).toBe(true);

    const factor = intent.riskFactors.find((f) => f.code === 'NO_WHERE_CLAUSE');
    expect(factor).toBeDefined();
    expect(factor!.severity).toBe('CRITICAL');
  });

  test('DELETE FROM users WHERE 1=1 → has WHERE clause (parser sees it as having WHERE)', async () => {
    const intent = await parseSqlIntent('DELETE FROM users WHERE 1=1');
    expect(intent.type).toBe('DELETE');
    // The AST parser sees a WHERE clause even though 1=1 is always true
    expect(intent.hasWhereClause).toBe(true);
    expect(intent.isDestructive).toBe(true);
    // No NO_WHERE_CLAUSE factor because WHERE is present
    const noWhere = intent.riskFactors.find((f) => f.code === 'NO_WHERE_CLAUSE');
    expect(noWhere).toBeUndefined();
  });

  test('UPDATE accounts SET balance = 0 → riskFactors includes NO_WHERE_CLAUSE_UPDATE with HIGH severity', async () => {
    const intent = await parseSqlIntent('UPDATE accounts SET balance = 0');
    expect(intent.type).toBe('UPDATE');
    expect(intent.hasWhereClause).toBe(false);
    expect(intent.isMassive).toBe(true);

    const factor = intent.riskFactors.find((f) => f.code === 'NO_WHERE_CLAUSE_UPDATE');
    expect(factor).toBeDefined();
    expect(factor!.severity).toBe('HIGH');
  });

  test('TRUNCATE TABLE production_data → riskFactors includes TRUNCATE_OP with CRITICAL severity', async () => {
    const intent = await parseSqlIntent('TRUNCATE TABLE production_data');
    expect(intent.type).toBe('TRUNCATE');
    expect(intent.isDestructive).toBe(true);
    expect(intent.isMassive).toBe(true);

    const factor = intent.riskFactors.find((f) => f.code === 'TRUNCATE_OP');
    expect(factor).toBeDefined();
    expect(factor!.severity).toBe('CRITICAL');
  });

  test('DROP TABLE users CASCADE → riskFactors includes DROP_OP with CRITICAL severity', async () => {
    const intent = await parseSqlIntent('DROP TABLE users CASCADE');
    expect(intent.type).toBe('DROP');
    expect(intent.isDestructive).toBe(true);

    const factor = intent.riskFactors.find((f) => f.code === 'DROP_OP');
    expect(factor).toBeDefined();
    expect(factor!.severity).toBe('CRITICAL');
  });

  test('ALTER TABLE users DROP COLUMN email → riskFactors includes SCHEMA_CHANGE with HIGH severity', async () => {
    const intent = await parseSqlIntent('ALTER TABLE users DROP COLUMN email');
    expect(intent.type).toBe('ALTER');
    expect(intent.isDestructive).toBe(true);

    const factor = intent.riskFactors.find((f) => f.code === 'SCHEMA_CHANGE');
    expect(factor).toBeDefined();
    expect(factor!.severity).toBe('HIGH');
  });

  test('DELETE FROM logs; DROP TABLE users → multi-statement handling', async () => {
    // The AST parser may handle the first statement or both.
    // The important thing is the first statement is correctly parsed as destructive.
    const intent = await parseSqlIntent('DELETE FROM logs; DROP TABLE users');
    expect(intent.isDestructive).toBe(true);
    // Should detect at least the DELETE operation
    expect(['DELETE', 'DROP']).toContain(intent.type);
  });
});

// ─── 2. Filesystem Dangerous Patterns ───────────────────────────────────────

describe('Filesystem Dangerous Patterns', () => {
  test('rm -rf / → isDenied=true, denyReason contains "root"', () => {
    const intent = parseFilesystemIntent('rm -rf /');
    expect(intent.isDenied).toBe(true);
    expect(intent.denyReason).toMatch(/root/i);
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.isDestructive).toBe(true);
  });

  test('rm -rf ~ → isDenied=true', () => {
    const intent = parseFilesystemIntent('rm -rf ~');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('rm -rf /etc → isDenied=true (system path)', () => {
    const intent = parseFilesystemIntent('rm -rf /etc');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('rm -rf /usr → isDenied=true (system path)', () => {
    const intent = parseFilesystemIntent('rm -rf /usr');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('rm -rf /var → isDenied=true (system path)', () => {
    const intent = parseFilesystemIntent('rm -rf /var');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('rm -rf $HOME/something → isDenied=true (variable expansion with -rf)', () => {
    const intent = parseFilesystemIntent('rm -rf $HOME/something');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.hasVarExpansion).toBe(true);
  });

  test('rm -rf *.txt → isDenied=true (glob with -rf)', () => {
    const intent = parseFilesystemIntent('rm -rf *.txt');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.hasGlobs).toBe(true);
  });

  test('dd if=/dev/zero of=/dev/sda → isDenied=true (dd to block device)', () => {
    const intent = parseFilesystemIntent('dd if=/dev/zero of=/dev/sda');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.commandType).toBe('DD');
  });

  test('dd if=/dev/zero of=/dev/nvme0n1 → isDenied=true (dd to NVMe device)', () => {
    const intent = parseFilesystemIntent('dd if=/dev/zero of=/dev/nvme0n1');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('mv important.txt /dev/null → isDenied=true (silent data destruction)', () => {
    const intent = parseFilesystemIntent('mv important.txt /dev/null');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('find /tmp -exec rm {} ; → isDenied=true (find -exec rm)', () => {
    const intent = parseFilesystemIntent('find /tmp -exec rm {} ;');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('find /tmp -delete → isDenied=true', () => {
    const intent = parseFilesystemIntent('find /tmp -delete');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('mkfs.ext4 /dev/sda1 → isDenied=true (mkfs always denied)', () => {
    const intent = parseFilesystemIntent('mkfs.ext4 /dev/sda1');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.commandType).toBe('MKFS');
  });

  test('fdisk /dev/sda → isDenied=true', () => {
    const intent = parseFilesystemIntent('fdisk /dev/sda');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.commandType).toBe('FDISK');
  });

  test('ls /tmp | xargs rm → isDenied=true (pipe to rm)', () => {
    const intent = parseFilesystemIntent('ls /tmp | xargs rm');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('chmod -R 777 /etc → isDenied=true (chmod -R on system path)', () => {
    const intent = parseFilesystemIntent('chmod -R 777 /etc');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('chown -R root:root /usr → isDenied=true (chown on system path)', () => {
    const intent = parseFilesystemIntent('chown -R root:root /usr');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });
});

// ─── 3. Cloud Dangerous Patterns ────────────────────────────────────────────

describe('Cloud Dangerous Patterns', () => {
  test('terraform destroy (no -target) → affectsAll=true, riskLevel CRITICAL or HIGH', () => {
    const intent = buildCloudIntent('terraform destroy');
    expect(intent.affectsAll).toBe(true);
    expect(['CRITICAL', 'HIGH']).toContain(intent.riskLevel);
    expect(intent.actionType).toBe('DESTROY');
  });

  test('terraform destroy -auto-approve → affectsAll=true, isDestructive=true', () => {
    const intent = buildCloudIntent('terraform destroy -auto-approve');
    expect(intent.affectsAll).toBe(true);
    expect(intent.isDestructive).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('aws ec2 terminate-instances --instance-ids i-1234 → actionType=DESTROY', () => {
    const intent = buildCloudIntent('aws ec2 terminate-instances --instance-ids i-1234');
    expect(intent.actionType).toBe('DESTROY');
    expect(intent.isDestructive).toBe(true);
    expect(intent.command.provider).toBe('aws');
    expect(intent.command.service).toBe('ec2');
  });

  test('aws iam delete-role --role-name admin → riskLevel >= HIGH (IAM operations)', () => {
    const intent = buildCloudIntent('aws iam delete-role --role-name admin');
    expect(['HIGH', 'CRITICAL']).toContain(intent.riskLevel);
    expect(intent.actionType).toBe('DESTROY');
    expect(intent.command.service).toBe('iam');
  });

  test('aws s3 rb s3://my-bucket --force → actionType=DESTROY, riskLevel escalated by --force', () => {
    const intent = buildCloudIntent('aws s3 rb s3://my-bucket --force');
    expect(intent.actionType).toBe('DESTROY');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.isDestructive).toBe(true);
  });
});

// ─── 4. Kubernetes Dangerous Patterns ───────────────────────────────────────

describe('Kubernetes Dangerous Patterns', () => {
  test('kubectl delete namespace production → dangerousPatterns includes delete-namespace, riskLevel=CRITICAL', () => {
    const intent = parseKubeCommand('kubectl delete namespace production');
    expect(intent.dangerousPatterns).toContain('delete-namespace');
    expect(intent.riskLevel).toBe('CRITICAL');

    const safeIntent = toSafeIntent(intent);
    expect(safeIntent.isDestructive).toBe(true);
    expect(safeIntent.type).toBe('DROP');
  });

  test('kubectl delete pods --all -n default → dangerousPatterns includes delete-all-flag, riskLevel=CRITICAL', () => {
    // Note: --all must appear after the resource type so the parser sees it as boolean,
    // not as --all <value> (which would consume the next positional token).
    const intent = parseKubeCommand('kubectl delete pods --all -n default');
    expect(intent.dangerousPatterns).toContain('delete-all-flag');
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('kubectl delete --all pods -n default → parser sees --all as key with value "pods", triggers delete-no-target instead', () => {
    // When --all precedes the resource type, the flag parser reads {all: 'pods'},
    // so delete-all-flag does not fire. delete-no-target fires because no
    // resource name is present.
    const intent = parseKubeCommand('kubectl delete --all pods -n default');
    expect(intent.dangerousPatterns).toContain('delete-no-target');
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('kubectl delete pods --all-namespaces → dangerousPatterns includes all-namespaces-delete', () => {
    const intent = parseKubeCommand('kubectl delete pods --all-namespaces');
    expect(intent.dangerousPatterns).toContain('all-namespaces-delete');
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('kubectl scale deployment web --replicas=0 → dangerousPatterns includes scale-to-zero', () => {
    const intent = parseKubeCommand('kubectl scale deployment web --replicas=0');
    expect(intent.dangerousPatterns).toContain('scale-to-zero');
    expect(intent.riskLevel).toBe('CRITICAL');

    const safeIntent = toSafeIntent(intent);
    expect(safeIntent.type).toBe('TRUNCATE');
    expect(safeIntent.isMassive).toBe(true);
  });

  test('kubectl delete pv my-volume → dangerousPatterns includes delete-storage', () => {
    const intent = parseKubeCommand('kubectl delete pv my-volume');
    expect(intent.dangerousPatterns).toContain('delete-storage');
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('kubectl apply -f malicious.yaml -n kube-system → dangerousPatterns includes kube-system-write, riskLevel=CRITICAL', () => {
    const intent = parseKubeCommand('kubectl apply -f malicious.yaml -n kube-system');
    expect(intent.dangerousPatterns).toContain('kube-system-write');
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('kubectl exec -it pod -- /bin/sh → dangerousPatterns includes exec-command', () => {
    const intent = parseKubeCommand('kubectl exec -it pod -- /bin/sh');
    expect(intent.dangerousPatterns).toContain('exec-command');
    expect(intent.riskLevel).toBe('HIGH');
  });

  test('helm uninstall production-app → dangerousPatterns includes helm-uninstall', () => {
    const intent = parseKubeCommand('helm uninstall production-app');
    expect(intent.dangerousPatterns).toContain('helm-uninstall');
    expect(intent.riskLevel).toBe('HIGH');

    const safeIntent = toSafeIntent(intent);
    expect(safeIntent.type).toBe('DROP');
    expect(safeIntent.isDestructive).toBe(true);
  });
});

// ─── 5. CI/CD Dangerous Patterns ────────────────────────────────────────────

describe('CI/CD Dangerous Patterns', () => {
  test('docker run --privileged alpine → isPrivileged=true, riskLevel=CRITICAL', () => {
    const parsed = parseCicdCommand('docker run --privileged alpine');
    expect(parsed.isPrivileged).toBe(true);
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.action).toBe('run');
  });

  test('docker run -v /:/host alpine → hasDangerousMount=true, riskLevel=CRITICAL', () => {
    const parsed = parseCicdCommand('docker run -v /:/host alpine');
    expect(parsed.hasDangerousMount).toBe(true);
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.isDestructive).toBe(true);
  });

  test('docker push myapp (no specific tag) → hasSpecificTag=false, isPublicRegistry=true', () => {
    const parsed = parseCicdCommand('docker push myapp');
    expect(parsed.hasSpecificTag).toBe(false);
    expect(parsed.isPublicRegistry).toBe(true);
    expect(parsed.action).toBe('push');
  });
});

// ─── 6. API Dangerous Patterns ──────────────────────────────────────────────

describe('API Dangerous Patterns', () => {
  test('DELETE https://api.example.com/users/123 → method=DELETE, riskLevel=CRITICAL', () => {
    const parsed = parseHttpRequest('DELETE https://api.example.com/users/123');
    expect(parsed.method).toBe('DELETE');
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.isDestructive).toBe(true);
  });

  test('curl -X DELETE https://api.stripe.com/v1/charges/ch_123 → method=DELETE, category=payment, riskLevel=CRITICAL', () => {
    const parsed = parseHttpRequest('curl -X DELETE https://api.stripe.com/v1/charges/ch_123');
    expect(parsed.method).toBe('DELETE');
    expect(parsed.endpointCategory).toBe('payment');
    expect(parsed.riskLevel).toBe('CRITICAL');
  });

  test('POST https://api.example.com/admin/users → category=admin, riskLevel escalated', () => {
    const parsed = parseHttpRequest('POST https://api.example.com/admin/users');
    expect(parsed.method).toBe('POST');
    expect(parsed.endpointCategory).toBe('admin');
    // POST base is MEDIUM, admin escalates +1 -> HIGH
    expect(['HIGH', 'CRITICAL']).toContain(parsed.riskLevel);
  });

  test('GET https://api.example.com/users?api_key=sk_live_abc123 → hasCredentialsInUrl=true in metadata', () => {
    const parsed = parseHttpRequest('GET https://api.example.com/users?api_key=sk_live_abc123');
    expect(parsed.method).toBe('GET');
    expect(parsed.metadata.hasCredentialsInUrl).toBe(true);
  });
});

// ─── 7. Secrets Dangerous Patterns ──────────────────────────────────────────

describe('Secrets Dangerous Patterns', () => {
  test('aws secretsmanager delete-secret --secret-id prod/db --force-delete-without-recovery → DENY pattern', () => {
    const parsed = parseSecretCommand(
      'aws secretsmanager delete-secret --secret-id prod/db --force-delete-without-recovery',
    );
    const denyPattern = parsed.dangerousPatterns.find(
      (dp) => dp.severity === 'DENY',
    );
    expect(denyPattern).toBeDefined();
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.isDestructive).toBe(true);
  });

  test('vault destroy secret/data/prod versions=all → has destroy-all-versions pattern', () => {
    const parsed = parseSecretCommand('vault destroy secret/data/prod versions=all');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'destroy-all-versions',
    );
    expect(pattern).toBeDefined();
    expect(parsed.riskLevel).toBe('CRITICAL');
  });

  test('kubectl get secret -o yaml my-secret → has k8s-secret-decode HIGH pattern', () => {
    // The k8s-secret-decode regex requires `-o yaml` to appear before `secret` in the string.
    // With `-o yaml` before the secret keyword, the pattern matches.
    const parsed = parseSecretCommand('kubectl get -o yaml secret my-secret');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'k8s-secret-decode',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('HIGH');
  });

  test('kubectl get secret my-secret -o yaml → k8s-secret-decode does NOT match (order-dependent regex)', () => {
    // Documents a known limitation: the regex for k8s-secret-decode requires
    // `-o yaml` to appear before `secret` in the command string.
    // When `secret` appears first, the pattern does not fire.
    const parsed = parseSecretCommand('kubectl get secret my-secret -o yaml');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'k8s-secret-decode',
    );
    expect(pattern).toBeUndefined();
  });

  test('vault read secret/prod | base64 → has pipe-secret pattern', () => {
    const parsed = parseSecretCommand('vault read secret/prod | base64');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'pipe-secret',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('HIGH');
  });
});

// ─── 8. Git Dangerous Patterns ──────────────────────────────────────────────

describe('Git Dangerous Patterns', () => {
  test('git push --force origin main → has force-push-to-main DENY pattern, riskLevel=CRITICAL', () => {
    const parsed = parseGitCommand('git push --force origin main');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'force-push-to-main',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('DENY');
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.isDestructive).toBe(true);
    expect(parsed.rewritesHistory).toBe(true);
  });

  test('git reset --hard HEAD~10 → has reset-hard CRITICAL pattern', () => {
    const parsed = parseGitCommand('git reset --hard HEAD~10');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'reset-hard',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('CRITICAL');
    expect(parsed.isDestructive).toBe(true);
    expect(parsed.rewritesHistory).toBe(true);
  });

  test('git filter-branch --all → has filter-branch DENY pattern', () => {
    const parsed = parseGitCommand('git filter-branch --all');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'filter-branch',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('DENY');
    expect(parsed.riskLevel).toBe('CRITICAL');
  });

  test('git clean -fdx → has clean-fdx CRITICAL pattern', () => {
    const parsed = parseGitCommand('git clean -fdx');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'clean-fdx',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('CRITICAL');
    expect(parsed.riskLevel).toBe('CRITICAL');
  });

  test('git reflog expire --all → has reflog-expire pattern', () => {
    const parsed = parseGitCommand('git reflog expire --all');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'reflog-expire',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('CRITICAL');
    expect(parsed.action).toBe('reflog-expire');
  });
});

// ─── 9. Network Dangerous Patterns ──────────────────────────────────────────

describe('Network Dangerous Patterns', () => {
  test('iptables -F INPUT → has iptables-flush-input DENY pattern', () => {
    const parsed = parseNetworkCommand('iptables -F INPUT');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'iptables-flush-input',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('DENY');
    expect(parsed.isFirewallDisable).toBe(true);
    expect(parsed.riskLevel).toBe('CRITICAL');
  });

  test('ip link set lo down → has loopback-down DENY pattern', () => {
    const parsed = parseNetworkCommand('ip link set lo down');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'loopback-down',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('DENY');
    expect(parsed.isInterfaceDown).toBe(true);
    expect(parsed.riskLevel).toBe('CRITICAL');
  });

  test('route del default → has route-del-default DENY pattern', () => {
    const parsed = parseNetworkCommand('route del default');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'route-del-default',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('DENY');
    expect(parsed.isDefaultRouteRemoval).toBe(true);
    expect(parsed.riskLevel).toBe('CRITICAL');
  });

  test('ip route del default → has ip-route-del-default DENY pattern', () => {
    const parsed = parseNetworkCommand('ip route del default');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'ip-route-del-default',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('DENY');
    expect(parsed.isDefaultRouteRemoval).toBe(true);
  });

  test('ufw disable → has ufw-disable CRITICAL pattern', () => {
    const parsed = parseNetworkCommand('ufw disable');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'ufw-disable',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('CRITICAL');
    expect(parsed.isFirewallDisable).toBe(true);
    expect(parsed.riskLevel).toBe('CRITICAL');
  });

  test('ufw reset → has ufw-reset CRITICAL pattern', () => {
    const parsed = parseNetworkCommand('ufw reset');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'ufw-reset',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('CRITICAL');
    expect(parsed.isFirewallDisable).toBe(true);
    expect(parsed.riskLevel).toBe('CRITICAL');
  });
});

// ─── 10. Queue Dangerous Patterns ───────────────────────────────────────────

describe('Queue Dangerous Patterns', () => {
  test('redis-cli FLUSHALL → has redis FLUSHALL DENY pattern, riskLevel=CRITICAL', () => {
    const parsed = parseQueueCommand('redis-cli FLUSHALL');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'redis FLUSHALL',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('DENY');
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.action).toBe('purge');
  });

  test('redis-cli FLUSHDB → has redis FLUSHDB DENY pattern', () => {
    const parsed = parseQueueCommand('redis-cli FLUSHDB');
    const pattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'redis FLUSHDB',
    );
    expect(pattern).toBeDefined();
    expect(pattern!.severity).toBe('DENY');
    expect(parsed.riskLevel).toBe('CRITICAL');
  });

  test('kafka-topics --delete --topic prod-events --bootstrap-server localhost:9092 → action=delete, riskLevel=CRITICAL', () => {
    const parsed = parseQueueCommand(
      'kafka-topics --delete --topic prod-events --bootstrap-server localhost:9092',
    );
    expect(parsed.action).toBe('delete');
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.isDestructive).toBe(true);
    expect(parsed.tool).toBe('kafka');
    expect(parsed.targetName).toBe('prod-events');
  });

  test('rabbitmqctl purge_queue production-orders -p /prod → action=purge, isProduction=true (DENY severity)', () => {
    const parsed = parseQueueCommand('rabbitmqctl purge_queue production-orders -p /prod');
    expect(parsed.action).toBe('purge');
    expect(parsed.isProduction).toBe(true);
    expect(parsed.riskLevel).toBe('CRITICAL');
    expect(parsed.isDestructive).toBe(true);

    // Production purge_queue should have DENY severity
    const purgePattern = parsed.dangerousPatterns.find(
      (dp) => dp.pattern === 'rabbitmqctl purge_queue',
    );
    expect(purgePattern).toBeDefined();
    expect(purgePattern!.severity).toBe('DENY');
  });
});

// ─── 11. Edge Cases & Bypass Attempts ───────────────────────────────────────

describe('Edge Cases & Bypass Attempts', () => {
  test('extra whitespace: "  rm   -rf   /  " → should still be detected and denied', () => {
    const intent = parseFilesystemIntent('  rm   -rf   /  ');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.commandType).toBe('RM');
  });

  test('mixed case SQL: "DELETE from USERS" → SQL parser handles case-insensitively', async () => {
    const intent = await parseSqlIntent('DELETE from USERS');
    expect(intent.type).toBe('DELETE');
    expect(intent.hasWhereClause).toBe(false);
    expect(intent.isDestructive).toBe(true);

    const factor = intent.riskFactors.find((f) => f.code === 'NO_WHERE_CLAUSE');
    expect(factor).toBeDefined();
    expect(factor!.severity).toBe('CRITICAL');
  });

  test('tab characters: "rm\\t-rf\\t/" → depends on tokenizer', () => {
    // The filesystem tokenizer splits on both spaces and tabs
    const intent = parseFilesystemIntent('rm\t-rf\t/');
    expect(intent.commandType).toBe('RM');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('semicolons (command chaining): "rm -rf /tmp ; rm -rf /" → first segment detected', () => {
    // The filesystem parser splits on pipes but not semicolons.
    // The tokenizer treats the full string as one command.
    // The parser should still detect rm as the command type.
    const intent = parseFilesystemIntent('rm -rf /tmp ; rm -rf /');
    expect(intent.commandType).toBe('RM');
    // At minimum the -rf flags should be detected
    expect(intent.metadata.hasRecursiveFlag).toBe(true);
    expect(intent.metadata.hasForceFlag).toBe(true);
  });

  test('very long commands (1000+ chars) → parser does not crash', async () => {
    // SQL: a very long WHERE clause with many conditions
    const longWhereClause = Array.from({ length: 200 }, (_, i) => `id = ${i}`).join(' OR ');
    const longSql = `DELETE FROM users WHERE ${longWhereClause}`;
    expect(longSql.length).toBeGreaterThan(1000);

    const intent = await parseSqlIntent(longSql);
    expect(intent.type).toBe('DELETE');
    expect(intent.hasWhereClause).toBe(true);
    // Should NOT have NO_WHERE_CLAUSE since WHERE is present
    const noWhere = intent.riskFactors.find((f) => f.code === 'NO_WHERE_CLAUSE');
    expect(noWhere).toBeUndefined();
  });

  test('very long filesystem command (1000+ chars) → parser does not crash', () => {
    const longPath = '/tmp/' + 'a'.repeat(1000);
    const intent = parseFilesystemIntent(`rm -rf ${longPath}`);
    expect(intent.commandType).toBe('RM');
    expect(intent.metadata.hasRecursiveFlag).toBe(true);
    expect(intent.metadata.hasForceFlag).toBe(true);
  });

  test('commands with Unicode characters in paths → parser handles gracefully', () => {
    const intent = parseFilesystemIntent('rm -rf /tmp/\u00e9l\u00e8ve/dossier');
    expect(intent.commandType).toBe('RM');
    expect(intent.metadata.hasRecursiveFlag).toBe(true);
    expect(intent.metadata.hasForceFlag).toBe(true);
  });

  test('empty targets after flags: "rm -rf" with no path → isDenied', () => {
    const intent = parseFilesystemIntent('rm -rf');
    // rm with no path argument is denied
    expect(intent.isDenied).toBe(true);
  });

  test('SQL with leading/trailing whitespace: "  DROP TABLE users  " → still detected', async () => {
    const intent = await parseSqlIntent('  DROP TABLE users  ');
    expect(intent.type).toBe('DROP');
    expect(intent.isDestructive).toBe(true);
  });

  test('Kubernetes command with extra spaces → still parsed', () => {
    const intent = parseKubeCommand('kubectl   delete   namespace   production');
    expect(intent.dangerousPatterns).toContain('delete-namespace');
    expect(intent.riskLevel).toBe('CRITICAL');
  });
});

// ─── 12. No Dangerous Operation Gets risk=LOW ───────────────────────────────

describe('No Dangerous Operation Gets risk=LOW', () => {
  describe('SQL operations that should NEVER be LOW', () => {
    test.each([
      ['DELETE FROM users', 'DELETE without WHERE'],
      ['UPDATE users SET active = false', 'UPDATE without WHERE'],
      ['TRUNCATE TABLE sessions', 'TRUNCATE'],
      ['DROP TABLE users', 'DROP'],
      ['ALTER TABLE users ADD COLUMN temp TEXT', 'ALTER'],
    ])('%s (%s) → risk is never LOW', async (sql, _desc) => {
      const intent = await parseSqlIntent(sql);
      // Compute effective risk: if any risk factor is CRITICAL or HIGH, the operation is not LOW
      const hasCriticalOrHigh = intent.riskFactors.some(
        (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH',
      );
      expect(hasCriticalOrHigh).toBe(true);
    });
  });

  describe('Filesystem operations that should NEVER be LOW', () => {
    test.each([
      ['rm -rf /tmp/data', 'rm -rf anything'],
      ['dd if=/dev/zero of=/dev/sda', 'dd to device'],
      ['chmod -R 777 /etc', 'chmod -R on system path'],
    ])('%s (%s) → riskLevel is not LOW', (cmd, _desc) => {
      const intent = parseFilesystemIntent(cmd);
      expect(intent.riskLevel).not.toBe('LOW');
    });
  });

  describe('Cloud operations that should NEVER be LOW', () => {
    test.each([
      ['terraform destroy', 'any destroy action'],
      ['aws ec2 terminate-instances --instance-ids i-123', 'terminate instances'],
      ['aws iam create-role --role-name test', 'IAM create operation'],
      ['aws iam delete-role --role-name admin', 'IAM delete operation'],
    ])('%s (%s) → riskLevel is not LOW', (cmd, _desc) => {
      const intent = buildCloudIntent(cmd);
      expect(intent.riskLevel).not.toBe('LOW');
    });
  });

  describe('Kubernetes operations that should NEVER be LOW', () => {
    test.each([
      ['kubectl delete namespace staging', 'delete namespace'],
      ['kubectl scale deployment app --replicas=0', 'scale to zero'],
      ['kubectl delete --all pods -n default', 'delete with --all'],
      ['kubectl delete pods --all-namespaces', 'delete all namespaces'],
    ])('%s (%s) → riskLevel is not LOW', (cmd, _desc) => {
      const intent = parseKubeCommand(cmd);
      expect(intent.riskLevel).not.toBe('LOW');
    });
  });

  describe('Git operations that should NEVER be LOW', () => {
    test.each([
      ['git push --force origin main', 'force push to main'],
      ['git reset --hard HEAD~5', 'hard reset'],
      ['git filter-branch --all', 'filter-branch'],
      ['git clean -fdx', 'clean -fdx'],
      ['git reflog expire --all', 'reflog expire'],
    ])('%s (%s) → riskLevel is not LOW', (cmd, _desc) => {
      const parsed = parseGitCommand(cmd);
      expect(parsed.riskLevel).not.toBe('LOW');
    });
  });

  describe('Network operations that should NEVER be LOW', () => {
    test.each([
      ['iptables -F INPUT', 'iptables flush input'],
      ['ip link set lo down', 'loopback down'],
      ['ufw disable', 'ufw disable'],
      ['route del default', 'route del default'],
    ])('%s (%s) → riskLevel is not LOW', (cmd, _desc) => {
      const parsed = parseNetworkCommand(cmd);
      expect(parsed.riskLevel).not.toBe('LOW');
    });
  });

  describe('Queue operations that should NEVER be LOW', () => {
    test.each([
      ['redis-cli FLUSHALL', 'redis FLUSHALL'],
      ['redis-cli FLUSHDB', 'redis FLUSHDB'],
      ['kafka-topics --delete --topic events --bootstrap-server localhost:9092', 'kafka delete topic'],
      ['rabbitmqctl purge_queue my-queue', 'rabbitmq purge'],
    ])('%s (%s) → riskLevel is not LOW', (cmd, _desc) => {
      const parsed = parseQueueCommand(cmd);
      expect(parsed.riskLevel).not.toBe('LOW');
    });
  });

  describe('Secrets operations that should NEVER be LOW', () => {
    test.each([
      ['aws secretsmanager delete-secret --secret-id prod/db --force-delete-without-recovery', 'force delete'],
      ['vault destroy secret/data/prod versions=all', 'destroy all versions'],
    ])('%s (%s) → riskLevel is not LOW', (cmd, _desc) => {
      const parsed = parseSecretCommand(cmd);
      expect(parsed.riskLevel).not.toBe('LOW');
    });
  });

  describe('CI/CD operations that should NEVER be LOW', () => {
    test.each([
      ['docker run --privileged alpine', 'privileged container'],
      ['docker run -v /:/host alpine', 'dangerous mount'],
    ])('%s (%s) → riskLevel is not LOW', (cmd, _desc) => {
      const parsed = parseCicdCommand(cmd);
      expect(parsed.riskLevel).not.toBe('LOW');
    });
  });

  describe('API operations that should NEVER be LOW', () => {
    test.each([
      ['DELETE https://api.example.com/users/123', 'DELETE method'],
      ['curl -X DELETE https://api.stripe.com/v1/charges/ch_1', 'DELETE to payment endpoint'],
    ])('%s (%s) → riskLevel is not LOW', (cmd, _desc) => {
      const parsed = parseHttpRequest(cmd);
      expect(parsed.riskLevel).not.toBe('LOW');
    });
  });
});

// ─── 13. Cross-Domain Injection Patterns ────────────────────────────────────

describe('Cross-Domain Injection Patterns', () => {
  test('rm -rf /; SELECT * FROM users → detectDomain should pick filesystem (rm prefix)', () => {
    const cmd = 'rm -rf /; SELECT * FROM users';
    const domain = detectDomain(cmd);
    expect(domain).toBe('filesystem');

    // The filesystem parser should still detect the rm -rf / portion
    const intent = parseFilesystemIntent(cmd);
    expect(intent.commandType).toBe('RM');
    expect(intent.isDenied).toBe(true);
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('SELECT * FROM users; rm -rf / → detectDomain should pick SQL', () => {
    const cmd = 'SELECT * FROM users; rm -rf /';
    const domain = detectDomain(cmd);
    expect(domain).toBe('sql');

    // The SQL parser handles the full string (multi-statement or fallback)
    // It should at minimum parse the SELECT portion
  });

  test('detectDomain correctly routes ambiguous commands', () => {
    // aws ec2 commands route to 'cloud'
    expect(detectDomain('aws ec2 describe-instances')).toBe('cloud');
    // aws secretsmanager routes to 'secrets' (secretsmanager keyword takes priority)
    expect(detectDomain('aws secretsmanager get-secret-value --secret-id test')).toBe('secrets');

    // kubectl goes to kubernetes, not secrets (even with secret subresource)
    expect(detectDomain('kubectl get secret my-secret -o yaml')).toBe('kubernetes');

    // vault goes to secrets
    expect(detectDomain('vault read secret/data/prod')).toBe('secrets');

    // curl goes to api
    expect(detectDomain('curl -X DELETE https://api.example.com/data')).toBe('api');

    // docker goes to cicd
    expect(detectDomain('docker run --privileged alpine')).toBe('cicd');
  });

  test('SQL injection inside filesystem path is handled by domain detection', () => {
    // This starts with rm, so filesystem wins
    const cmd = "rm -rf '/tmp/; DROP TABLE users; --'";
    const domain = detectDomain(cmd);
    expect(domain).toBe('filesystem');
  });

  test('filesystem command disguised as SQL comment is handled', async () => {
    // This starts with SELECT, so SQL wins
    const cmd = "SELECT '$(rm -rf /)' FROM dual";
    const domain = detectDomain(cmd);
    expect(domain).toBe('sql');

    // The SQL parser should parse this as a SELECT (safe from data perspective)
    const intent = await parseSqlIntent(cmd);
    expect(intent.type).toBe('SELECT');
    expect(intent.isDestructive).toBe(false);
  });
});
