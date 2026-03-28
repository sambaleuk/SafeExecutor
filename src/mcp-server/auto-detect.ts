/**
 * Auto-detect the domain of a command based on its patterns.
 */

const SQL_KEYWORDS = /^(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE)\s/i;
const HTTP_METHOD = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s/;

export function detectDomain(command: string): string {
  if (!command?.trim()) return 'unknown';

  const cmd = command.trim();

  if (SQL_KEYWORDS.test(cmd)) return 'sql';
  if (cmd.startsWith('git ')) return 'git';
  if (cmd.startsWith('kubectl ') || cmd.startsWith('helm ')) return 'kubernetes';
  if (
    cmd.startsWith('terraform ') ||
    cmd.startsWith('aws ') ||
    cmd.startsWith('gcloud ') ||
    cmd.startsWith('az ')
  )
    return 'cloud';
  if (
    cmd.startsWith('docker ') ||
    cmd.startsWith('docker-compose ') ||
    cmd.startsWith('gh workflow')
  )
    return 'cicd';
  if (
    cmd.startsWith('vault ') ||
    cmd.includes('secretsmanager') ||
    cmd.includes('ssm') ||
    cmd.includes('keyvault')
  )
    return 'secrets';
  if (
    cmd.startsWith('iptables ') ||
    cmd.startsWith('ufw ') ||
    cmd.startsWith('ip ') ||
    cmd.startsWith('nmap ')
  )
    return 'network';
  if (
    cmd.startsWith('kafka-') ||
    cmd.startsWith('rabbitmq') ||
    cmd.startsWith('redis-cli') ||
    cmd.includes('sqs') ||
    cmd.includes('sns') ||
    cmd.includes('pubsub')
  )
    return 'queue';
  if (cmd.startsWith('curl ') || cmd.startsWith('http') || HTTP_METHOD.test(cmd)) return 'api';
  if (
    cmd.startsWith('rm ') ||
    cmd.startsWith('chmod ') ||
    cmd.startsWith('chown ') ||
    cmd.startsWith('dd ') ||
    cmd.startsWith('find ') ||
    cmd.startsWith('mv ') ||
    cmd.startsWith('cp ')
  )
    return 'filesystem';

  return 'unknown';
}
