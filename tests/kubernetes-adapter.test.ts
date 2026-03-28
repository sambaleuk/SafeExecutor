/**
 * Kubernetes Adapter — Unit Tests
 *
 * Tests cover the parser and risk matrix (pure functions, no cluster required).
 * The sandbox and adapter tests would require a live cluster; they are covered
 * by integration tests in a separate suite.
 */
import { parseKubeCommand, toSafeIntent } from '../src/adapters/kubernetes/parser.js';
import {
  getResourceRisk,
  getNamespaceEscalation,
  combineRisk,
  escalateRisk,
} from '../src/adapters/kubernetes/risk-matrix.js';
import { KubernetesAdapter } from '../src/adapters/kubernetes/adapter.js';

// ─── parser: kubectl ─────────────────────────────────────────────────────────

describe('parseKubeCommand — kubectl', () => {
  test('parses a simple get command', () => {
    const intent = parseKubeCommand('kubectl get pods -n staging');
    expect(intent.tool).toBe('kubectl');
    expect(intent.verb).toBe('get');
    expect(intent.resourceType).toBe('pods');
    expect(intent.namespace).toBe('staging');
    // READ verb (LOW) + staging escalation (+1) = MEDIUM
    expect(intent.riskLevel).toBe('MEDIUM');
    expect(intent.dangerousPatterns).not.toContain('kube-system-write');
  });

  test('parses get without namespace stays LOW', () => {
    const intent = parseKubeCommand('kubectl get pods');
    expect(intent.riskLevel).toBe('LOW');
    expect(intent.dangerousPatterns).toHaveLength(0);
  });

  test('parses resource/name shorthand', () => {
    // rollout is a compound command: verb=rollout, subcommand is parsed as resourceType
    const intent = parseKubeCommand('kubectl rollout undo deployment/my-app -n production');
    expect(intent.verb).toBe('rollout');
    expect(intent.namespace).toBe('production');
    // resourceName contains the resource/name from positional[2]
    expect(intent.raw).toBe('kubectl rollout undo deployment/my-app -n production');
  });

  test('parses --namespace= long-form flag', () => {
    const intent = parseKubeCommand('kubectl get pods --namespace=production');
    expect(intent.namespace).toBe('production');
  });

  test('parses inline flag values (--replicas=0)', () => {
    const intent = parseKubeCommand('kubectl scale deployment my-app --replicas=0 -n staging');
    expect(intent.verb).toBe('scale');
    expect(intent.flags['replicas']).toBe('0');
  });
});

// ─── parser: helm ────────────────────────────────────────────────────────────

describe('parseKubeCommand — helm', () => {
  test('parses helm uninstall', () => {
    const intent = parseKubeCommand('helm uninstall my-release -n production');
    expect(intent.tool).toBe('helm');
    expect(intent.verb).toBe('uninstall');
    expect(intent.resourceName).toBe('my-release');
    expect(intent.namespace).toBe('production');
    expect(intent.dangerousPatterns).toContain('helm-uninstall');
  });

  test('parses helm upgrade', () => {
    const intent = parseKubeCommand('helm upgrade my-release ./chart --set image.tag=latest');
    expect(intent.verb).toBe('upgrade');
    expect(intent.resourceName).toBe('my-release');
    expect(intent.riskLevel).toBe('MEDIUM');
  });

  test('parses helm install', () => {
    const intent = parseKubeCommand('helm install my-app ./chart -n dev');
    expect(intent.verb).toBe('install');
    expect(intent.riskLevel).toBe('MEDIUM');
  });
});

// ─── Risk classification ──────────────────────────────────────────────────────

describe('Risk classification', () => {
  test('READ verbs are LOW risk', () => {
    for (const verb of ['get', 'describe', 'logs', 'top']) {
      const intent = parseKubeCommand(`kubectl ${verb} pods`);
      expect(intent.riskLevel).toBe('LOW');
    }
  });

  test('kubectl exec is HIGH risk with exec-command pattern', () => {
    const intent = parseKubeCommand('kubectl exec -it my-pod -- /bin/bash');
    expect(intent.riskLevel).toBe('HIGH');
    expect(intent.dangerousPatterns).toContain('exec-command');
  });

  test('delete namespace is CRITICAL', () => {
    const intent = parseKubeCommand('kubectl delete namespace production');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.dangerousPatterns).toContain('delete-namespace');
  });

  test('delete ns alias is also CRITICAL', () => {
    const intent = parseKubeCommand('kubectl delete ns staging');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.dangerousPatterns).toContain('delete-namespace');
  });

  test('delete --all is CRITICAL', () => {
    const intent = parseKubeCommand('kubectl delete pods --all -n development');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.dangerousPatterns).toContain('delete-all-flag');
  });

  test('delete --all-namespaces is CRITICAL', () => {
    const intent = parseKubeCommand('kubectl delete pods --all-namespaces');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.dangerousPatterns).toContain('all-namespaces-delete');
  });

  test('delete without resource name is CRITICAL', () => {
    const intent = parseKubeCommand('kubectl delete pods -n production');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.dangerousPatterns).toContain('delete-no-target');
  });

  test('scale to 0 replicas is CRITICAL', () => {
    const intent = parseKubeCommand('kubectl scale deployment my-app --replicas=0');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.dangerousPatterns).toContain('scale-to-zero');
  });

  test('scale to >0 is HIGH (scale verb MEDIUM + deployment resource HIGH → HIGH)', () => {
    const intent = parseKubeCommand('kubectl scale deployment my-app --replicas=3');
    expect(intent.riskLevel).toBe('HIGH');
    expect(intent.dangerousPatterns).not.toContain('scale-to-zero');
  });

  test('drain node is HIGH with drain-node pattern', () => {
    const intent = parseKubeCommand('kubectl drain my-node --ignore-daemonsets');
    expect(intent.riskLevel).toBe('HIGH');
    expect(intent.dangerousPatterns).toContain('drain-node');
  });

  test('delete pvc is CRITICAL', () => {
    const intent = parseKubeCommand('kubectl delete pvc my-claim -n default');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.dangerousPatterns).toContain('delete-storage');
  });

  test('apply is MEDIUM', () => {
    const intent = parseKubeCommand('kubectl apply -f deployment.yaml -n development');
    expect(intent.riskLevel).toBe('MEDIUM');
  });

  test('kube-system write escalates to CRITICAL', () => {
    const intent = parseKubeCommand('kubectl apply -f patch.yaml -n kube-system');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.dangerousPatterns).toContain('kube-system-write');
  });

  test('kube-system read stays LOW (no escalation for reads)', () => {
    const intent = parseKubeCommand('kubectl get pods -n kube-system');
    expect(intent.riskLevel).toBe('LOW');
    expect(intent.dangerousPatterns).not.toContain('kube-system-write');
    expect(intent.isDangerous).toBe(false);
  });

  test('production namespace escalates risk by 2 levels', () => {
    // apply (MEDIUM) + production namespace (+2) = CRITICAL
    const intent = parseKubeCommand('kubectl apply -f deployment.yaml -n production');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.dangerousPatterns).toContain('production-namespace');
  });

  test('staging namespace escalates by 1 level', () => {
    // apply (MEDIUM) in staging = HIGH
    const intent = parseKubeCommand('kubectl apply -f deployment.yaml -n staging');
    expect(intent.riskLevel).toBe('HIGH');
  });

  test('helm uninstall in production is CRITICAL', () => {
    const intent = parseKubeCommand('helm uninstall my-release -n production');
    // helm uninstall = HIGH, +2 for production = CRITICAL
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('reject unsupported tool', () => {
    expect(() => parseKubeCommand('docker run nginx')).toThrow("unsupported tool 'docker'");
  });

  test('reject empty command', () => {
    expect(() => parseKubeCommand('')).toThrow('empty command');
  });
});

// ─── toSafeIntent: OperationType mapping ─────────────────────────────────────

describe('toSafeIntent — OperationType mapping', () => {
  test('get → SELECT', () => {
    const intent = toSafeIntent(parseKubeCommand('kubectl get pods'));
    expect(intent.type).toBe('SELECT');
    expect(intent.isDestructive).toBe(false);
  });

  test('apply → INSERT', () => {
    const intent = toSafeIntent(parseKubeCommand('kubectl apply -f app.yaml'));
    expect(intent.type).toBe('INSERT');
  });

  test('patch → UPDATE', () => {
    const intent = toSafeIntent(parseKubeCommand('kubectl patch deployment my-app --patch=\'{"spec":{"replicas":3}}\''));
    expect(intent.type).toBe('UPDATE');
  });

  test('scale >0 → UPDATE', () => {
    const intent = toSafeIntent(parseKubeCommand('kubectl scale deployment my-app --replicas=3'));
    expect(intent.type).toBe('UPDATE');
  });

  test('scale =0 → TRUNCATE', () => {
    const intent = toSafeIntent(parseKubeCommand('kubectl scale deployment my-app --replicas=0'));
    expect(intent.type).toBe('TRUNCATE');
    expect(intent.isDestructive).toBe(true);
    expect(intent.isMassive).toBe(true);
  });

  test('delete specific resource → DELETE', () => {
    const intent = toSafeIntent(parseKubeCommand('kubectl delete pod my-pod -n default'));
    expect(intent.type).toBe('DELETE');
    expect(intent.hasWhereClause).toBe(true);
  });

  test('delete namespace → DROP', () => {
    const intent = toSafeIntent(parseKubeCommand('kubectl delete namespace production'));
    expect(intent.type).toBe('DROP');
    expect(intent.isDestructive).toBe(true);
  });

  test('delete --all → DROP + not specific', () => {
    const intent = toSafeIntent(parseKubeCommand('kubectl delete pods --all -n staging'));
    expect(intent.type).toBe('DROP');
    expect(intent.hasWhereClause).toBe(false);
    expect(intent.isMassive).toBe(true);
  });

  test('drain → DROP', () => {
    const intent = toSafeIntent(parseKubeCommand('kubectl drain my-node'));
    expect(intent.type).toBe('DROP');
  });

  test('helm install → INSERT', () => {
    const intent = toSafeIntent(parseKubeCommand('helm install my-app ./chart'));
    expect(intent.type).toBe('INSERT');
  });

  test('helm upgrade → UPDATE', () => {
    const intent = toSafeIntent(parseKubeCommand('helm upgrade my-app ./chart'));
    expect(intent.type).toBe('UPDATE');
  });

  test('helm uninstall → DROP', () => {
    const intent = toSafeIntent(parseKubeCommand('helm uninstall my-app'));
    expect(intent.type).toBe('DROP');
    expect(intent.isDestructive).toBe(true);
  });

  test('resource path in tables field', () => {
    const intent = toSafeIntent(parseKubeCommand('kubectl delete deployment my-app -n production'));
    expect(intent.tables).toHaveLength(1);
    expect(intent.tables[0]).toBe('production/deployment/my-app');
  });

  test('missing namespace uses wildcard', () => {
    const intent = toSafeIntent(parseKubeCommand('kubectl apply -f app.yaml'));
    expect(intent.tables[0]).toMatch(/^\*\//);
  });

  test('metadata contains tool and verb', () => {
    const intent = toSafeIntent(parseKubeCommand('kubectl get pods'));
    expect(intent.metadata['tool']).toBe('kubectl');
    expect(intent.metadata['verb']).toBe('get');
    expect(intent.metadata['riskLevel']).toBe('LOW');
  });
});

// ─── Risk matrix helpers ──────────────────────────────────────────────────────

describe('risk-matrix helpers', () => {
  test('getResourceRisk: namespace → CRITICAL', () => {
    expect(getResourceRisk('namespace')).toBe('CRITICAL');
  });

  test('getResourceRisk: configmap → LOW', () => {
    expect(getResourceRisk('configmap')).toBe('LOW');
  });

  test('getResourceRisk: deployment → HIGH', () => {
    expect(getResourceRisk('deployment')).toBe('HIGH');
  });

  test('getResourceRisk: unknown defaults to MEDIUM', () => {
    expect(getResourceRisk('myCRD')).toBe('MEDIUM');
  });

  test('getNamespaceEscalation: production → 2', () => {
    expect(getNamespaceEscalation('production')).toBe(2);
  });

  test('getNamespaceEscalation: kube-system → 99', () => {
    expect(getNamespaceEscalation('kube-system')).toBe(99);
  });

  test('getNamespaceEscalation: unknown → 0', () => {
    expect(getNamespaceEscalation('my-team')).toBe(0);
  });

  test('combineRisk returns higher', () => {
    expect(combineRisk('LOW', 'HIGH')).toBe('HIGH');
    expect(combineRisk('CRITICAL', 'MEDIUM')).toBe('CRITICAL');
    expect(combineRisk('MEDIUM', 'MEDIUM')).toBe('MEDIUM');
  });

  test('escalateRisk caps at CRITICAL', () => {
    expect(escalateRisk('HIGH', 5)).toBe('CRITICAL');
    expect(escalateRisk('LOW', 1)).toBe('MEDIUM');
    expect(escalateRisk('LOW', 2)).toBe('HIGH');
    expect(escalateRisk('LOW', 3)).toBe('CRITICAL');
  });
});

// ─── KubernetesAdapter: parseIntent ──────────────────────────────────────────

describe('KubernetesAdapter.parseIntent', () => {
  const adapter = new KubernetesAdapter();

  test('returns a SafeIntent from a kubectl command', async () => {
    const intent = await adapter.parseIntent('kubectl delete deployment my-app -n production');
    expect(intent.raw).toBe('kubectl delete deployment my-app -n production');
    expect(intent.domain).toBe('kubernetes');
    expect(intent.type).toBe('DELETE');
    expect(intent.tables).toContain('production/deployment/my-app');
    expect(intent.isDestructive).toBe(true);
    expect(intent.target.type).toBe('deployment');
    expect(intent.ast).toBeDefined();
  });

  test('returns SELECT for read commands', async () => {
    const intent = await adapter.parseIntent('kubectl get pods -n kube-system');
    expect(intent.type).toBe('SELECT');
    expect(intent.isDestructive).toBe(false);
    expect(intent.domain).toBe('kubernetes');
  });

  test('throws on empty command', async () => {
    await expect(adapter.parseIntent('')).rejects.toThrow();
  });
});
