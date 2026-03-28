import type { CloudRiskLevel } from './types.js';

/**
 * Risk matrix: maps `provider:service:action` (or `provider:service`, or `provider`) to a risk level.
 * Lookup order: full key → service key → provider key → MEDIUM default.
 *
 * Rules of thumb:
 *   - Any irreversible deletion → CRITICAL
 *   - IAM / identity changes → HIGH minimum
 *   - Network topology changes (VPC, SG) → CRITICAL
 *   - Write/modify without deletion → MEDIUM
 *   - Describe / list / plan → LOW
 */
export const RISK_MATRIX: Record<string, CloudRiskLevel> = {
  // ── Terraform ────────────────────────────────────────────────────────────
  'terraform:plan': 'LOW',
  'terraform:validate': 'LOW',
  'terraform:show': 'LOW',
  'terraform:output': 'LOW',
  'terraform:refresh': 'LOW',
  'terraform:apply': 'HIGH',
  'terraform:import': 'HIGH',
  'terraform:taint': 'HIGH',
  'terraform:untaint': 'MEDIUM',
  'terraform:destroy': 'CRITICAL',
  'terraform:state:rm': 'HIGH',
  'terraform:state:mv': 'HIGH',
  'terraform:state:pull': 'LOW',
  'terraform:state:push': 'HIGH',

  // ── AWS — IAM (always HIGH minimum) ──────────────────────────────────────
  'aws:iam': 'HIGH',
  'aws:iam:list-roles': 'LOW',
  'aws:iam:list-policies': 'LOW',
  'aws:iam:get-role': 'LOW',
  'aws:iam:create-role': 'HIGH',
  'aws:iam:delete-role': 'CRITICAL',
  'aws:iam:attach-role-policy': 'HIGH',
  'aws:iam:detach-role-policy': 'HIGH',
  'aws:iam:create-policy': 'HIGH',
  'aws:iam:delete-policy': 'CRITICAL',
  'aws:iam:put-role-policy': 'HIGH',
  'aws:iam:delete-role-policy': 'CRITICAL',

  // ── AWS — EC2 ─────────────────────────────────────────────────────────────
  'aws:ec2:describe-instances': 'LOW',
  'aws:ec2:describe-security-groups': 'LOW',
  'aws:ec2:describe-vpcs': 'LOW',
  'aws:ec2:describe-subnets': 'LOW',
  'aws:ec2:run-instances': 'MEDIUM',
  'aws:ec2:start-instances': 'LOW',
  'aws:ec2:stop-instances': 'MEDIUM',
  'aws:ec2:reboot-instances': 'MEDIUM',
  'aws:ec2:terminate-instances': 'CRITICAL',
  'aws:ec2:create-security-group': 'MEDIUM',
  'aws:ec2:delete-security-group': 'CRITICAL',
  'aws:ec2:authorize-security-group-ingress': 'HIGH',
  'aws:ec2:revoke-security-group-ingress': 'HIGH',
  'aws:ec2:authorize-security-group-egress': 'HIGH',
  'aws:ec2:revoke-security-group-egress': 'HIGH',
  'aws:ec2:create-vpc': 'MEDIUM',
  'aws:ec2:delete-vpc': 'CRITICAL',
  'aws:ec2:create-subnet': 'MEDIUM',
  'aws:ec2:delete-subnet': 'CRITICAL',

  // ── AWS — RDS ─────────────────────────────────────────────────────────────
  'aws:rds:describe-db-instances': 'LOW',
  'aws:rds:describe-db-clusters': 'LOW',
  'aws:rds:create-db-instance': 'MEDIUM',
  'aws:rds:modify-db-instance': 'HIGH',
  'aws:rds:stop-db-instance': 'MEDIUM',
  'aws:rds:start-db-instance': 'LOW',
  'aws:rds:reboot-db-instance': 'MEDIUM',
  'aws:rds:delete-db-instance': 'CRITICAL',
  'aws:rds:delete-db-cluster': 'CRITICAL',
  'aws:rds:restore-db-instance-from-db-snapshot': 'MEDIUM',

  // ── AWS — S3 ──────────────────────────────────────────────────────────────
  'aws:s3:ls': 'LOW',
  'aws:s3:cp': 'MEDIUM',
  'aws:s3:mv': 'MEDIUM',
  'aws:s3:rm': 'HIGH',
  'aws:s3:mb': 'MEDIUM',
  'aws:s3:rb': 'CRITICAL',
  'aws:s3api:list-buckets': 'LOW',
  'aws:s3api:delete-bucket': 'CRITICAL',
  'aws:s3api:put-bucket-policy': 'HIGH',
  'aws:s3api:delete-bucket-policy': 'HIGH',
  'aws:s3api:put-public-access-block': 'HIGH',

  // ── AWS — Lambda ──────────────────────────────────────────────────────────
  'aws:lambda:list-functions': 'LOW',
  'aws:lambda:get-function': 'LOW',
  'aws:lambda:create-function': 'MEDIUM',
  'aws:lambda:update-function-code': 'MEDIUM',
  'aws:lambda:update-function-configuration': 'MEDIUM',
  'aws:lambda:delete-function': 'CRITICAL',
  'aws:lambda:add-permission': 'HIGH',
  'aws:lambda:remove-permission': 'HIGH',

  // ── AWS — CloudFormation ──────────────────────────────────────────────────
  'aws:cloudformation:describe-stacks': 'LOW',
  'aws:cloudformation:list-stacks': 'LOW',
  'aws:cloudformation:create-stack': 'MEDIUM',
  'aws:cloudformation:update-stack': 'HIGH',
  'aws:cloudformation:deploy': 'HIGH',
  'aws:cloudformation:delete-stack': 'CRITICAL',

  // ── GCP — Compute ─────────────────────────────────────────────────────────
  'gcloud:compute:instances:list': 'LOW',
  'gcloud:compute:instances:describe': 'LOW',
  'gcloud:compute:instances:create': 'MEDIUM',
  'gcloud:compute:instances:start': 'LOW',
  'gcloud:compute:instances:stop': 'MEDIUM',
  'gcloud:compute:instances:reset': 'MEDIUM',
  'gcloud:compute:instances:delete': 'CRITICAL',
  'gcloud:compute:networks:list': 'LOW',
  'gcloud:compute:networks:describe': 'LOW',
  'gcloud:compute:networks:create': 'MEDIUM',
  'gcloud:compute:networks:delete': 'CRITICAL',
  'gcloud:compute:firewall-rules:list': 'LOW',
  'gcloud:compute:firewall-rules:create': 'MEDIUM',
  'gcloud:compute:firewall-rules:update': 'HIGH',
  'gcloud:compute:firewall-rules:delete': 'CRITICAL',
  'gcloud:compute:subnets:delete': 'CRITICAL',

  // ── GCP — Cloud SQL ───────────────────────────────────────────────────────
  'gcloud:sql:instances:list': 'LOW',
  'gcloud:sql:instances:describe': 'LOW',
  'gcloud:sql:instances:create': 'MEDIUM',
  'gcloud:sql:instances:patch': 'HIGH',
  'gcloud:sql:instances:stop': 'MEDIUM',
  'gcloud:sql:instances:start': 'LOW',
  'gcloud:sql:instances:delete': 'CRITICAL',
  'gcloud:sql:databases:delete': 'CRITICAL',

  // ── GCP — Storage ─────────────────────────────────────────────────────────
  'gcloud:storage:ls': 'LOW',
  'gcloud:storage:cp': 'MEDIUM',
  'gcloud:storage:rm': 'HIGH',
  'gcloud:storage:buckets:list': 'LOW',
  'gcloud:storage:buckets:create': 'MEDIUM',
  'gcloud:storage:buckets:delete': 'CRITICAL',

  // ── GCP — IAM ─────────────────────────────────────────────────────────────
  'gcloud:iam': 'HIGH',
  'gcloud:iam:service-accounts:list': 'LOW',
  'gcloud:iam:service-accounts:describe': 'LOW',
  'gcloud:iam:service-accounts:create': 'HIGH',
  'gcloud:iam:service-accounts:delete': 'CRITICAL',
  'gcloud:iam:service-accounts:keys:create': 'HIGH',
  'gcloud:iam:service-accounts:keys:delete': 'CRITICAL',

  // ── Azure — VM ────────────────────────────────────────────────────────────
  'az:vm:list': 'LOW',
  'az:vm:show': 'LOW',
  'az:vm:create': 'MEDIUM',
  'az:vm:start': 'LOW',
  'az:vm:stop': 'MEDIUM',
  'az:vm:restart': 'MEDIUM',
  'az:vm:deallocate': 'MEDIUM',
  'az:vm:delete': 'CRITICAL',

  // ── Azure — SQL ───────────────────────────────────────────────────────────
  'az:sql:server:show': 'LOW',
  'az:sql:server:list': 'LOW',
  'az:sql:server:create': 'MEDIUM',
  'az:sql:server:delete': 'CRITICAL',
  'az:sql:db:show': 'LOW',
  'az:sql:db:list': 'LOW',
  'az:sql:db:create': 'MEDIUM',
  'az:sql:db:delete': 'CRITICAL',

  // ── Azure — Storage ───────────────────────────────────────────────────────
  'az:storage:account:list': 'LOW',
  'az:storage:account:show': 'LOW',
  'az:storage:account:create': 'MEDIUM',
  'az:storage:account:delete': 'CRITICAL',
  'az:storage:blob:upload': 'MEDIUM',
  'az:storage:blob:delete': 'HIGH',
  'az:storage:container:delete': 'CRITICAL',

  // ── Azure — Active Directory ──────────────────────────────────────────────
  'az:ad': 'HIGH',
  'az:ad:app:list': 'LOW',
  'az:ad:app:show': 'LOW',
  'az:ad:app:create': 'HIGH',
  'az:ad:app:delete': 'CRITICAL',
  'az:ad:sp:list': 'LOW',
  'az:ad:sp:create': 'HIGH',
  'az:ad:sp:delete': 'CRITICAL',
  'az:ad:group:list': 'LOW',
  'az:ad:group:delete': 'HIGH',
};

/**
 * Look up risk level for a cloud operation.
 * Tries the most specific key first, falling back to broader keys.
 */
export function lookupRisk(
  provider: string,
  service: string,
  action: string,
): CloudRiskLevel {
  const fullKey = `${provider}:${service}:${action}`;
  const serviceKey = `${provider}:${service}`;
  const providerKey = provider;

  return (
    RISK_MATRIX[fullKey] ??
    RISK_MATRIX[serviceKey] ??
    RISK_MATRIX[providerKey] ??
    'MEDIUM'
  );
}
