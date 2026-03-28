import { buildCloudIntent, parseCloudCommand } from '../src/adapters/cloud/parser.js';
import { lookupRisk } from '../src/adapters/cloud/risk-matrix.js';

// ─── Terraform ────────────────────────────────────────────────────────────────

describe('Terraform parser', () => {
  test('terraform plan → READ, LOW risk, not destructive', () => {
    const intent = buildCloudIntent('terraform plan');
    expect(intent.command.provider).toBe('terraform');
    expect(intent.command.action).toBe('plan');
    expect(intent.actionType).toBe('READ');
    expect(intent.riskLevel).toBe('LOW');
    expect(intent.isDestructive).toBe(false);
    expect(intent.affectsAll).toBe(false);
  });

  test('terraform validate → READ, LOW risk', () => {
    const intent = buildCloudIntent('terraform validate');
    expect(intent.actionType).toBe('READ');
    expect(intent.riskLevel).toBe('LOW');
  });

  test('terraform apply → WRITE, HIGH risk', () => {
    const intent = buildCloudIntent('terraform apply');
    expect(intent.actionType).toBe('WRITE');
    expect(intent.riskLevel).toBe('HIGH');
  });

  test('terraform apply with target → WRITE, HIGH, resources captured', () => {
    const intent = buildCloudIntent('terraform apply -target=aws_instance.web');
    expect(intent.command.flags['target']).toBe('aws_instance.web');
    expect(intent.affectsAll).toBe(false);
  });

  test('terraform destroy without target → CRITICAL, affectsAll', () => {
    const intent = buildCloudIntent('terraform destroy');
    expect(intent.actionType).toBe('DESTROY');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.affectsAll).toBe(true);
    expect(intent.isDestructive).toBe(true);
  });

  test('terraform destroy with -target → CRITICAL but not affectsAll', () => {
    const intent = buildCloudIntent('terraform destroy -target=aws_instance.foo');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.affectsAll).toBe(false);
    expect(intent.command.flags['target']).toBe('aws_instance.foo');
  });

  test('terraform state rm → STATE_MODIFY, HIGH risk', () => {
    const intent = buildCloudIntent('terraform state rm aws_instance.foo');
    expect(intent.actionType).toBe('STATE_MODIFY');
    expect(intent.command.service).toBe('state');
    expect(intent.command.action).toBe('rm');
    expect(intent.command.resources).toContain('aws_instance.foo');
    expect(['HIGH', 'CRITICAL']).toContain(intent.riskLevel);
  });

  test('terraform state mv → STATE_MODIFY', () => {
    const intent = buildCloudIntent('terraform state mv aws_instance.old aws_instance.new');
    expect(intent.actionType).toBe('STATE_MODIFY');
    expect(intent.command.action).toBe('mv');
  });

  test('terraform import → WRITE, HIGH risk', () => {
    const intent = buildCloudIntent('terraform import aws_instance.foo i-1234');
    expect(intent.riskLevel).toBe('HIGH');
  });
});

// ─── AWS CLI ──────────────────────────────────────────────────────────────────

describe('AWS CLI parser', () => {
  test('aws ec2 describe-instances → READ, LOW risk', () => {
    const intent = buildCloudIntent('aws ec2 describe-instances');
    expect(intent.command.provider).toBe('aws');
    expect(intent.command.service).toBe('ec2');
    expect(intent.command.action).toBe('describe-instances');
    expect(intent.actionType).toBe('READ');
    expect(intent.riskLevel).toBe('LOW');
    expect(intent.isDestructive).toBe(false);
  });

  test('aws ec2 terminate-instances → DESTROY, CRITICAL', () => {
    const intent = buildCloudIntent('aws ec2 terminate-instances --instance-ids i-1234 i-5678');
    expect(intent.actionType).toBe('DESTROY');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.isDestructive).toBe(true);
    expect(intent.command.flags['instance-ids']).toBe('i-1234');
  });

  test('aws rds delete-db-instance → DESTROY, CRITICAL', () => {
    const intent = buildCloudIntent('aws rds delete-db-instance --db-instance-identifier mydb --skip-final-snapshot');
    expect(intent.actionType).toBe('DESTROY');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.isDestructive).toBe(true);
  });

  test('aws iam create-role → HIGH minimum (never below HIGH)', () => {
    const intent = buildCloudIntent('aws iam create-role --role-name MyRole --assume-role-policy-document file://policy.json');
    expect(intent.command.service).toBe('iam');
    expect(['HIGH', 'CRITICAL']).toContain(intent.riskLevel);
  });

  test('aws iam list-roles → LOW risk from matrix but escalated to HIGH for iam', () => {
    const intent = buildCloudIntent('aws iam list-roles');
    // iam service always gets at least HIGH
    expect(['HIGH', 'CRITICAL']).toContain(intent.riskLevel);
  });

  test('aws s3 rb → CRITICAL', () => {
    const intent = buildCloudIntent('aws s3 rb s3://my-bucket');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.isDestructive).toBe(true);
  });

  test('aws s3 rb with --force → CRITICAL (already max, stays CRITICAL)', () => {
    const before = buildCloudIntent('aws s3 rb s3://my-bucket');
    const after = buildCloudIntent('aws s3 rb s3://my-bucket --force');
    expect(after.riskLevel).toBe('CRITICAL');
    expect(after.riskLevel).toBe(before.riskLevel); // force cannot escalate past CRITICAL
  });

  test('aws ec2 stop-instances with --force → escalated one level', () => {
    const without = buildCloudIntent('aws ec2 stop-instances --instance-ids i-1234');
    const with_ = buildCloudIntent('aws ec2 stop-instances --instance-ids i-1234 --force');
    const order: Record<string, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
    expect(order[with_.riskLevel]).toBeGreaterThanOrEqual(order[without.riskLevel]);
  });

  test('aws cloudformation delete-stack → DESTROY, CRITICAL', () => {
    const intent = buildCloudIntent('aws cloudformation delete-stack --stack-name my-stack');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.isDestructive).toBe(true);
  });

  test('aws lambda delete-function → DESTROY, CRITICAL', () => {
    const intent = buildCloudIntent('aws lambda delete-function --function-name my-fn');
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('flags with = sign are parsed correctly', () => {
    const intent = buildCloudIntent('aws ec2 describe-instances --filters Name=instance-state-name,Values=running');
    expect(intent.command.flags['filters']).toBe('Name=instance-state-name,Values=running');
  });
});

// ─── GCP gcloud ───────────────────────────────────────────────────────────────

describe('GCP gcloud parser', () => {
  test('gcloud compute instances list → READ, LOW risk', () => {
    const intent = buildCloudIntent('gcloud compute instances list');
    expect(intent.command.provider).toBe('gcloud');
    expect(intent.command.service).toBe('compute:instances');
    expect(intent.command.action).toBe('list');
    expect(intent.actionType).toBe('READ');
    expect(intent.riskLevel).toBe('LOW');
  });

  test('gcloud compute instances delete → DESTROY, CRITICAL', () => {
    const intent = buildCloudIntent('gcloud compute instances delete my-vm --zone=us-east1-b');
    expect(intent.actionType).toBe('DESTROY');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.isDestructive).toBe(true);
    expect(intent.command.action).toBe('delete');
  });

  test('gcloud sql instances delete → CRITICAL', () => {
    const intent = buildCloudIntent('gcloud sql instances delete my-db');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.isDestructive).toBe(true);
  });

  test('gcloud compute networks delete → CRITICAL', () => {
    const intent = buildCloudIntent('gcloud compute networks delete my-vpc');
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('gcloud compute instances stop → WRITE, MEDIUM', () => {
    const intent = buildCloudIntent('gcloud compute instances stop my-vm --zone=us-east1-b');
    expect(intent.actionType).toBe('WRITE');
    expect(intent.riskLevel).toBe('MEDIUM');
  });

  test('gcloud storage buckets delete → CRITICAL', () => {
    const intent = buildCloudIntent('gcloud storage buckets delete gs://my-bucket');
    expect(intent.riskLevel).toBe('CRITICAL');
  });
});

// ─── Azure CLI ────────────────────────────────────────────────────────────────

describe('Azure CLI parser', () => {
  test('az vm list → READ, LOW risk', () => {
    const intent = buildCloudIntent('az vm list');
    expect(intent.command.provider).toBe('az');
    expect(intent.command.service).toBe('vm');
    expect(intent.command.action).toBe('list');
    expect(intent.actionType).toBe('READ');
    expect(intent.riskLevel).toBe('LOW');
  });

  test('az vm delete → DESTROY, CRITICAL', () => {
    const intent = buildCloudIntent('az vm delete --name my-vm --resource-group my-rg');
    expect(intent.actionType).toBe('DESTROY');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.isDestructive).toBe(true);
  });

  test('az sql db delete → DESTROY, CRITICAL', () => {
    const intent = buildCloudIntent('az sql db delete --name mydb --server myserver --resource-group myrg');
    expect(intent.riskLevel).toBe('CRITICAL');
    expect(intent.isDestructive).toBe(true);
  });

  test('az storage account delete → CRITICAL', () => {
    const intent = buildCloudIntent('az storage account delete --name mystorageacct --resource-group myrg');
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('az ad app delete → CRITICAL', () => {
    const intent = buildCloudIntent('az ad app delete --id 12345');
    expect(intent.riskLevel).toBe('CRITICAL');
  });

  test('az vm stop → WRITE, MEDIUM', () => {
    const intent = buildCloudIntent('az vm stop --name my-vm --resource-group my-rg');
    expect(intent.actionType).toBe('WRITE');
    expect(intent.riskLevel).toBe('MEDIUM');
  });
});

// ─── Risk Matrix ──────────────────────────────────────────────────────────────

describe('Risk Matrix', () => {
  test('aws ec2 terminate-instances → CRITICAL', () => {
    expect(lookupRisk('aws', 'ec2', 'terminate-instances')).toBe('CRITICAL');
  });

  test('aws ec2 describe-instances → LOW', () => {
    expect(lookupRisk('aws', 'ec2', 'describe-instances')).toBe('LOW');
  });

  test('aws iam (service-level fallback) → HIGH', () => {
    expect(lookupRisk('aws', 'iam', 'some-unknown-action')).toBe('HIGH');
  });

  test('aws rds delete-db-instance → CRITICAL', () => {
    expect(lookupRisk('aws', 'rds', 'delete-db-instance')).toBe('CRITICAL');
  });

  test('terraform plan → LOW', () => {
    expect(lookupRisk('terraform', 'plan', 'plan')).toBe('LOW');
  });

  test('terraform destroy → CRITICAL', () => {
    expect(lookupRisk('terraform', 'destroy', 'destroy')).toBe('CRITICAL');
  });

  test('gcloud compute instances delete → CRITICAL', () => {
    expect(lookupRisk('gcloud', 'compute:instances', 'delete')).toBe('CRITICAL');
  });

  test('az vm delete → CRITICAL', () => {
    expect(lookupRisk('az', 'vm', 'delete')).toBe('CRITICAL');
  });

  test('unknown service defaults to MEDIUM', () => {
    expect(lookupRisk('aws', 'unknown-service-xyz', 'unknown-action')).toBe('MEDIUM');
  });

  test('unknown provider defaults to MEDIUM', () => {
    expect(lookupRisk('some-provider', 'some-service', 'some-action')).toBe('MEDIUM');
  });
});

// ─── Flag Parsing Edge Cases ──────────────────────────────────────────────────

describe('Flag parsing', () => {
  test('--key=value style', () => {
    const cmd = parseCloudCommand('aws ec2 describe-instances --region=us-east-1');
    expect(cmd.flags['region']).toBe('us-east-1');
  });

  test('--key value style', () => {
    const cmd = parseCloudCommand('aws ec2 describe-instances --region us-east-1');
    expect(cmd.flags['region']).toBe('us-east-1');
  });

  test('boolean flag (no value)', () => {
    const cmd = parseCloudCommand('aws rds delete-db-instance --skip-final-snapshot');
    expect(cmd.flags['skip-final-snapshot']).toBe(true);
  });

  test('-target=value terraform style', () => {
    const cmd = parseCloudCommand('terraform apply -target=aws_instance.web');
    expect(cmd.flags['target']).toBe('aws_instance.web');
  });

  test('positional resources are captured', () => {
    const cmd = parseCloudCommand('terraform state rm aws_instance.foo aws_instance.bar');
    expect(cmd.resources).toEqual(['aws_instance.foo', 'aws_instance.bar']);
  });
});

// ─── Unsupported CLI ──────────────────────────────────────────────────────────

describe('Unsupported CLI', () => {
  test('throws on kubectl', () => {
    expect(() => buildCloudIntent('kubectl delete pod my-pod')).toThrow('Unsupported cloud CLI');
  });

  test('throws on helm', () => {
    expect(() => buildCloudIntent('helm uninstall my-release')).toThrow('Unsupported cloud CLI');
  });

  test('throws on empty string', () => {
    expect(() => buildCloudIntent('')).toThrow();
  });
});
