import type {
  QueueAction,
  ParsedQueueCommand,
  DangerousPattern,
} from './types.js';
import type { RiskLevel } from '../../types/index.js';

// ─── Production Detection ─────────────────────────────────────────────────────

const PRODUCTION_PATTERNS = [/\bprod(?:uction)?\b/i, /\bprd\b/i, /\blive\b/i];

function looksLikeProduction(value: string): boolean {
  return PRODUCTION_PATTERNS.some((p) => p.test(value));
}

// ─── Flag Parser ──────────────────────────────────────────────────────────────

/**
 * Parse CLI argument tokens into a flags map and a list of positional args.
 * Handles --key=value, --key value, --flag, and single-dash -k.
 */
function parseFlags(args: string[]): {
  flags: Record<string, string | boolean>;
  positional: string[];
} {
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];
  let i = 0;

  while (i < args.length) {
    const arg = args[i];

    if (arg.startsWith('-')) {
      const keyPart = arg.startsWith('--') ? arg.slice(2) : arg.slice(1);

      if (keyPart.includes('=')) {
        const eqIdx = keyPart.indexOf('=');
        flags[keyPart.slice(0, eqIdx)] = keyPart.slice(eqIdx + 1);
        i++;
      } else {
        const next = args[i + 1];
        if (next !== undefined && !next.startsWith('-')) {
          flags[keyPart] = next;
          i += 2;
        } else {
          flags[keyPart] = true;
          i++;
        }
      }
    } else {
      positional.push(arg);
      i++;
    }
  }

  return { flags, positional };
}

// ─── Risk Classification ──────────────────────────────────────────────────────

function classifyRisk(
  action: QueueAction,
  isProduction: boolean,
  dangerousPatterns: DangerousPattern[],
): RiskLevel {
  if (dangerousPatterns.some((p) => p.severity === 'DENY')) return 'CRITICAL';

  switch (action) {
    case 'list':
    case 'consume':
      return isProduction ? 'MEDIUM' : 'LOW';
    case 'publish':
    case 'create':
      return isProduction ? 'HIGH' : 'MEDIUM';
    case 'configure':
      return 'HIGH';
    case 'delete':
    case 'purge':
      return 'CRITICAL';
    case 'unknown':
      return 'MEDIUM';
  }
}

// ─── Kafka Parsers ────────────────────────────────────────────────────────────

/**
 * kafka-topics --create|--delete|--list|--describe|--alter [--topic <name>] ...
 */
function parseKafkaTopics(tokens: string[]): ParsedQueueCommand {
  const raw = tokens.join(' ');
  const { flags, positional: _ } = parseFlags(tokens.slice(1));

  const dangerousPatterns: DangerousPattern[] = [];

  let action: QueueAction = 'unknown';
  if (flags['create'] === true)   action = 'create';
  if (flags['delete'] === true)   action = 'delete';
  if (flags['list'] === true)     action = 'list';
  if (flags['describe'] === true) action = 'list';
  if (flags['alter'] === true)    action = 'configure';

  const targetName = typeof flags['topic'] === 'string' ? flags['topic'] : undefined;

  const isProduction =
    looksLikeProduction(raw) || (targetName ? looksLikeProduction(targetName) : false);

  // Dangerous: --delete on a production topic
  if (action === 'delete') {
    const severity = isProduction ? 'DENY' : 'CRITICAL';
    dangerousPatterns.push({
      pattern: 'kafka-topics --delete',
      description: 'Deletes a Kafka topic and all its messages permanently',
      severity,
    });
  }

  // Dangerous: --alter with retention or partition changes
  if (action === 'configure') {
    const configVal = typeof flags['config'] === 'string' ? flags['config'] : '';
    if (configVal.includes('retention') || flags['partitions'] !== undefined) {
      dangerousPatterns.push({
        pattern: 'kafka-topics --alter retention/partitions',
        description: 'Altering retention or partition count can cause data loss or consumer lag',
        severity: 'HIGH',
      });
    }
  }

  const riskLevel = classifyRisk(action, isProduction, dangerousPatterns);

  return {
    raw,
    tool: 'kafka',
    service: 'topics',
    action,
    riskLevel,
    isDestructive: action === 'delete',
    targetName,
    isProduction,
    hasActiveConsumers: false,
    flags,
    dangerousPatterns,
    metadata: {},
  };
}

/**
 * kafka-consumer-groups --list|--describe|--delete|--reset-offsets ...
 */
function parseKafkaConsumerGroups(tokens: string[]): ParsedQueueCommand {
  const raw = tokens.join(' ');
  const { flags } = parseFlags(tokens.slice(1));

  const dangerousPatterns: DangerousPattern[] = [];

  let action: QueueAction = 'unknown';
  if (flags['list'] === true)           action = 'list';
  if (flags['describe'] === true)       action = 'list';
  if (flags['delete'] === true)         action = 'delete';
  if (flags['reset-offsets'] === true)  action = 'configure';

  const consumerGroup = typeof flags['group'] === 'string' ? flags['group'] : undefined;
  const isProduction =
    looksLikeProduction(raw) || (consumerGroup ? looksLikeProduction(consumerGroup) : false);

  // --reset-offsets --to-earliest replays ALL messages (effectively re-processing everything)
  if (action === 'configure' && flags['to-earliest'] === true) {
    dangerousPatterns.push({
      pattern: 'kafka-consumer-groups --reset-offsets --to-earliest',
      description: 'Resets all consumer offsets to earliest — causes full message re-processing',
      severity: 'CRITICAL',
    });
  }

  // --delete on consumer group
  if (action === 'delete') {
    dangerousPatterns.push({
      pattern: 'kafka-consumer-groups --delete',
      description: 'Deletes consumer group metadata — offsets are lost permanently',
      severity: 'HIGH',
    });
  }

  const riskLevel = classifyRisk(action, isProduction, dangerousPatterns);

  return {
    raw,
    tool: 'kafka',
    service: 'consumer-groups',
    action,
    riskLevel,
    isDestructive: action === 'delete',
    consumerGroup,
    isProduction,
    hasActiveConsumers: consumerGroup !== undefined && action === 'delete',
    flags,
    dangerousPatterns,
    metadata: {},
  };
}

/**
 * kafka-configs --describe|--alter ...
 */
function parseKafkaConfigs(tokens: string[]): ParsedQueueCommand {
  const raw = tokens.join(' ');
  const { flags } = parseFlags(tokens.slice(1));

  const dangerousPatterns: DangerousPattern[] = [];

  let action: QueueAction = 'unknown';
  if (flags['describe'] === true) action = 'list';
  if (flags['alter'] === true)    action = 'configure';

  const targetName = typeof flags['entity-name'] === 'string' ? flags['entity-name'] : undefined;
  const isProduction =
    looksLikeProduction(raw) || (targetName ? looksLikeProduction(targetName) : false);

  if (action === 'configure') {
    dangerousPatterns.push({
      pattern: 'kafka-configs --alter',
      description: 'Altering broker/topic configs can affect cluster stability',
      severity: 'HIGH',
    });
  }

  const riskLevel = classifyRisk(action, isProduction, dangerousPatterns);

  return {
    raw,
    tool: 'kafka',
    service: 'configs',
    action,
    riskLevel,
    isDestructive: false,
    targetName,
    isProduction,
    hasActiveConsumers: false,
    flags,
    dangerousPatterns,
    metadata: {},
  };
}

// ─── RabbitMQ Parsers ─────────────────────────────────────────────────────────

function parseRabbitmqctl(tokens: string[]): ParsedQueueCommand {
  const raw = tokens.join(' ');
  // rabbitmqctl <subcommand> [args...]
  const subcommand = tokens[1] ?? 'unknown';
  const { flags } = parseFlags(tokens.slice(2));

  const dangerousPatterns: DangerousPattern[] = [];

  let action: QueueAction = 'unknown';
  const sub = subcommand.toLowerCase();

  if (sub.startsWith('list_'))        action = 'list';
  if (sub === 'purge_queue')          action = 'purge';
  if (sub === 'delete_queue')         action = 'delete';
  if (sub === 'delete_exchange')      action = 'delete';
  if (sub === 'set_policy')           action = 'configure';
  if (sub === 'clear_policy')         action = 'configure';
  if (sub === 'set_permissions')      action = 'configure';
  if (sub === 'clear_permissions')    action = 'configure';
  if (sub === 'stop_app')             action = 'configure';
  if (sub === 'start_app')            action = 'configure';

  const targetName = tokens[2] && !tokens[2].startsWith('-') ? tokens[2] : undefined;
  const vhost = typeof flags['p'] === 'string' ? flags['p'] : undefined;
  const isProduction =
    looksLikeProduction(raw) ||
    (targetName ? looksLikeProduction(targetName) : false) ||
    (vhost ? looksLikeProduction(vhost) : false);

  if (sub === 'purge_queue') {
    const severity = isProduction ? 'DENY' : 'CRITICAL';
    dangerousPatterns.push({
      pattern: 'rabbitmqctl purge_queue',
      description: 'Purges all messages from a RabbitMQ queue — data is unrecoverable',
      severity,
    });
  }

  if (sub === 'delete_queue') {
    dangerousPatterns.push({
      pattern: 'rabbitmqctl delete_queue',
      description: 'Deletes a RabbitMQ queue and all its messages',
      severity: 'CRITICAL',
    });
  }

  if (sub === 'delete_exchange') {
    dangerousPatterns.push({
      pattern: 'rabbitmqctl delete_exchange',
      description: 'Deletes an exchange — all bound queues will stop receiving messages',
      severity: 'CRITICAL',
    });
  }

  const riskLevel = classifyRisk(action, isProduction, dangerousPatterns);

  return {
    raw,
    tool: 'rabbitmq',
    service: 'rabbitmqctl',
    action,
    riskLevel,
    isDestructive: action === 'delete' || action === 'purge',
    targetName,
    isProduction,
    hasActiveConsumers: false,
    flags,
    dangerousPatterns,
    metadata: { subcommand, vhost },
  };
}

function parseRabbitmqadmin(tokens: string[]): ParsedQueueCommand {
  const raw = tokens.join(' ');
  // rabbitmqadmin <operation> <object> [field=value ...]
  const operation = tokens[1] ?? 'unknown';
  const object = tokens[2] ?? 'unknown';
  const { flags } = parseFlags(tokens.slice(3));

  const dangerousPatterns: DangerousPattern[] = [];

  let action: QueueAction = 'unknown';
  switch (operation.toLowerCase()) {
    case 'declare':   action = 'create';  break;
    case 'delete':    action = 'delete';  break;
    case 'purge':     action = 'purge';   break;
    case 'list':      action = 'list';    break;
    case 'get':       action = 'consume'; break;
    case 'publish':   action = 'publish'; break;
  }

  // Extract name from key=value tokens (rabbitmqadmin uses positional key=value pairs)
  const kvTokens = tokens.slice(3).filter((t) => !t.startsWith('-'));
  const nameKv = kvTokens.find((t) => t.startsWith('name='));
  const targetName = nameKv ? nameKv.split('=')[1] : undefined;

  const isProduction =
    looksLikeProduction(raw) || (targetName ? looksLikeProduction(targetName) : false);

  if (operation.toLowerCase() === 'purge') {
    const severity = isProduction ? 'DENY' : 'CRITICAL';
    dangerousPatterns.push({
      pattern: 'rabbitmqadmin purge',
      description: 'Purges all messages from a RabbitMQ queue',
      severity,
    });
  }

  if (operation.toLowerCase() === 'delete' && object.toLowerCase() === 'exchange') {
    dangerousPatterns.push({
      pattern: 'rabbitmqadmin delete exchange',
      description: 'Deletes an exchange — breaks all routing to bound queues',
      severity: 'CRITICAL',
    });
  }

  if (operation.toLowerCase() === 'delete') {
    dangerousPatterns.push({
      pattern: `rabbitmqadmin delete ${object}`,
      description: `Deletes RabbitMQ ${object} permanently`,
      severity: 'CRITICAL',
    });
  }

  const riskLevel = classifyRisk(action, isProduction, dangerousPatterns);

  return {
    raw,
    tool: 'rabbitmq',
    service: 'rabbitmqadmin',
    action,
    riskLevel,
    isDestructive: action === 'delete' || action === 'purge',
    targetName,
    isProduction,
    hasActiveConsumers: false,
    flags,
    dangerousPatterns,
    metadata: { operation, object },
  };
}

// ─── Redis Parser ─────────────────────────────────────────────────────────────

const REDIS_READ_COMMANDS = new Set([
  'get', 'mget', 'hget', 'hgetall', 'hmget', 'lrange', 'lindex', 'llen',
  'smembers', 'scard', 'zrange', 'zcard', 'xread', 'xlen', 'xrange',
  'type', 'ttl', 'exists', 'keys', 'scan', 'hscan', 'sscan', 'zscan',
  'strlen', 'getrange', 'srandmember', 'zrangebyscore',
]);

const REDIS_WRITE_COMMANDS = new Set([
  'set', 'mset', 'hset', 'hmset', 'lpush', 'rpush', 'sadd', 'zadd',
  'xadd', 'append', 'incr', 'decr', 'incrby', 'decrby', 'setex', 'setnx',
  'getset', 'lset', 'linsert', 'expire', 'expireat', 'persist',
]);

function parseRedisCli(tokens: string[]): ParsedQueueCommand {
  const raw = tokens.join(' ');
  // redis-cli [options] <COMMAND> [args...]
  const { flags, positional } = parseFlags(tokens.slice(1));

  const dangerousPatterns: DangerousPattern[] = [];

  // First positional arg is the Redis command
  const redisCmd = (positional[0] ?? 'unknown').toLowerCase();
  const targetName = positional[1]; // key name

  let action: QueueAction = 'unknown';
  if (REDIS_READ_COMMANDS.has(redisCmd))   action = 'consume';
  if (REDIS_WRITE_COMMANDS.has(redisCmd))  action = 'publish';
  if (redisCmd === 'del' || redisCmd === 'unlink') action = 'delete';
  if (redisCmd === 'flushall' || redisCmd === 'flushdb') action = 'purge';

  const isProduction =
    looksLikeProduction(raw) || (targetName ? looksLikeProduction(targetName) : false);

  if (redisCmd === 'flushall') {
    dangerousPatterns.push({
      pattern: 'redis FLUSHALL',
      description: 'Deletes ALL keys from ALL databases in the Redis instance — complete data loss',
      severity: 'DENY',
    });
  }

  if (redisCmd === 'flushdb') {
    dangerousPatterns.push({
      pattern: 'redis FLUSHDB',
      description: 'Deletes ALL keys from the current Redis database — data is unrecoverable',
      severity: 'DENY',
    });
  }

  if (redisCmd === 'del' && !targetName) {
    dangerousPatterns.push({
      pattern: 'redis DEL without key',
      description: 'DEL without a key name specified — potential wildcard deletion',
      severity: 'HIGH',
    });
  }

  const riskLevel = classifyRisk(action, isProduction, dangerousPatterns);

  return {
    raw,
    tool: 'redis',
    service: 'redis-cli',
    action,
    riskLevel,
    isDestructive: action === 'delete' || action === 'purge',
    targetName,
    isProduction,
    hasActiveConsumers: false,
    flags,
    dangerousPatterns,
    metadata: { redisCommand: redisCmd },
  };
}

// ─── AWS SQS Parser ───────────────────────────────────────────────────────────

function parseAwsSqs(tokens: string[]): ParsedQueueCommand {
  // aws sqs <command> [options...]
  const raw = tokens.join(' ');
  const command = tokens[2] ?? 'unknown';
  const { flags } = parseFlags(tokens.slice(3));

  const dangerousPatterns: DangerousPattern[] = [];

  let action: QueueAction = 'unknown';
  switch (command.toLowerCase()) {
    case 'create-queue':         action = 'create';  break;
    case 'delete-queue':         action = 'delete';  break;
    case 'purge-queue':          action = 'purge';   break;
    case 'send-message':         action = 'publish'; break;
    case 'send-message-batch':   action = 'publish'; break;
    case 'receive-message':      action = 'consume'; break;
    case 'list-queues':          action = 'list';    break;
    case 'get-queue-attributes': action = 'list';    break;
    case 'set-queue-attributes': action = 'configure'; break;
    case 'delete-message':       action = 'delete';  break;
    case 'delete-message-batch': action = 'delete';  break;
    case 'change-message-visibility': action = 'configure'; break;
  }

  const queueUrl = typeof flags['queue-url'] === 'string' ? flags['queue-url'] : undefined;
  const targetName = queueUrl ?? (typeof flags['queue-name'] === 'string' ? flags['queue-name'] : undefined);

  const isProduction =
    looksLikeProduction(raw) || (targetName ? looksLikeProduction(targetName) : false);

  if (command.toLowerCase() === 'purge-queue') {
    const severity = isProduction ? 'DENY' : 'CRITICAL';
    dangerousPatterns.push({
      pattern: 'aws sqs purge-queue',
      description: 'Purges all messages from an SQS queue — cannot be undone',
      severity,
    });
  }

  if (command.toLowerCase() === 'delete-queue') {
    dangerousPatterns.push({
      pattern: 'aws sqs delete-queue',
      description: 'Deletes an SQS queue and all its messages permanently',
      severity: 'CRITICAL',
    });
  }

  const riskLevel = classifyRisk(action, isProduction, dangerousPatterns);

  return {
    raw,
    tool: 'sqs',
    service: 'sqs',
    action,
    riskLevel,
    isDestructive: action === 'delete' || action === 'purge',
    targetName,
    isProduction,
    hasActiveConsumers: false,
    flags,
    dangerousPatterns,
    metadata: { command },
  };
}

// ─── AWS SNS Parser ───────────────────────────────────────────────────────────

function parseAwsSns(tokens: string[]): ParsedQueueCommand {
  // aws sns <command> [options...]
  const raw = tokens.join(' ');
  const command = tokens[2] ?? 'unknown';
  const { flags } = parseFlags(tokens.slice(3));

  const dangerousPatterns: DangerousPattern[] = [];

  let action: QueueAction = 'unknown';
  switch (command.toLowerCase()) {
    case 'create-topic':               action = 'create';    break;
    case 'delete-topic':               action = 'delete';    break;
    case 'publish':                    action = 'publish';   break;
    case 'list-topics':                action = 'list';      break;
    case 'get-topic-attributes':       action = 'list';      break;
    case 'set-topic-attributes':       action = 'configure'; break;
    case 'subscribe':                  action = 'create';    break;
    case 'unsubscribe':                action = 'delete';    break;
    case 'list-subscriptions':         action = 'list';      break;
    case 'list-subscriptions-by-topic':action = 'list';      break;
    case 'confirm-subscription':       action = 'configure'; break;
  }

  const topicArn = typeof flags['topic-arn'] === 'string' ? flags['topic-arn'] : undefined;
  const targetName = topicArn;

  const isProduction =
    looksLikeProduction(raw) || (targetName ? looksLikeProduction(targetName) : false);

  if (command.toLowerCase() === 'delete-topic') {
    dangerousPatterns.push({
      pattern: 'aws sns delete-topic',
      description: 'Deletes an SNS topic and all its subscriptions permanently',
      severity: 'CRITICAL',
    });
  }

  const riskLevel = classifyRisk(action, isProduction, dangerousPatterns);

  return {
    raw,
    tool: 'sns',
    service: 'sns',
    action,
    riskLevel,
    isDestructive: action === 'delete',
    targetName,
    isProduction,
    hasActiveConsumers: false,
    flags,
    dangerousPatterns,
    metadata: { command },
  };
}

// ─── GCloud Pub/Sub Parser ────────────────────────────────────────────────────

function parseGcloudPubsub(tokens: string[]): ParsedQueueCommand {
  // gcloud pubsub topics|subscriptions <action> [name] [options...]
  const raw = tokens.join(' ');
  const resource = tokens[2] ?? 'unknown';  // topics | subscriptions | snapshots
  const verb = tokens[3] ?? 'unknown';      // create | delete | list | describe | publish | pull
  const { flags, positional } = parseFlags(tokens.slice(4));

  const dangerousPatterns: DangerousPattern[] = [];

  let action: QueueAction = 'unknown';
  switch (verb.toLowerCase()) {
    case 'create':       action = 'create';    break;
    case 'delete':       action = 'delete';    break;
    case 'list':         action = 'list';      break;
    case 'describe':     action = 'list';      break;
    case 'publish':      action = 'publish';   break;
    case 'pull':         action = 'consume';   break;
    case 'update':       action = 'configure'; break;
    case 'set-iam-policy': action = 'configure'; break;
    case 'seek':         action = 'configure'; break; // seek can replay messages
  }

  const targetName = positional[0];
  const isProduction =
    looksLikeProduction(raw) || (targetName ? looksLikeProduction(targetName) : false);

  if (verb.toLowerCase() === 'delete') {
    dangerousPatterns.push({
      pattern: `gcloud pubsub ${resource} delete`,
      description: `Deletes a GCP Pub/Sub ${resource.slice(0, -1)} permanently`,
      severity: isProduction ? 'DENY' : 'CRITICAL',
    });
  }

  if (verb.toLowerCase() === 'seek') {
    dangerousPatterns.push({
      pattern: 'gcloud pubsub subscriptions seek',
      description: 'Seek can replay or skip messages — use with caution',
      severity: 'HIGH',
    });
  }

  const riskLevel = classifyRisk(action, isProduction, dangerousPatterns);

  return {
    raw,
    tool: 'pubsub',
    service: resource,
    action,
    riskLevel,
    isDestructive: action === 'delete',
    targetName,
    isProduction,
    hasActiveConsumers: false,
    flags,
    dangerousPatterns,
    metadata: { resource, verb },
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Parse a raw message queue CLI command into a structured ParsedQueueCommand.
 *
 * Supported CLIs:
 *   kafka-topics, kafka-consumer-groups, kafka-configs
 *   rabbitmqctl, rabbitmqadmin
 *   redis-cli
 *   aws sqs, aws sns
 *   gcloud pubsub
 *
 * @throws if the command string is empty or the CLI is not supported.
 */
export function parseQueueCommand(raw: string): ParsedQueueCommand {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('Empty command');

  const tokens = trimmed.split(/\s+/);
  const cli = tokens[0].toLowerCase();

  switch (cli) {
    case 'kafka-topics':
      return parseKafkaTopics(tokens);

    case 'kafka-consumer-groups':
      return parseKafkaConsumerGroups(tokens);

    case 'kafka-configs':
      return parseKafkaConfigs(tokens);

    case 'rabbitmqctl':
      return parseRabbitmqctl(tokens);

    case 'rabbitmqadmin':
      return parseRabbitmqadmin(tokens);

    case 'redis-cli':
      return parseRedisCli(tokens);

    case 'aws': {
      const service = tokens[1]?.toLowerCase();
      if (service === 'sqs') return parseAwsSqs(tokens);
      if (service === 'sns') return parseAwsSns(tokens);
      throw new Error(
        `Unsupported AWS service: '${tokens[1]}'. Queue adapter supports: sqs, sns`,
      );
    }

    case 'gcloud': {
      const service = tokens[1]?.toLowerCase();
      if (service === 'pubsub') return parseGcloudPubsub(tokens);
      throw new Error(
        `Unsupported gcloud service: '${tokens[1]}'. Queue adapter supports: pubsub`,
      );
    }

    default:
      throw new Error(
        `Unsupported queue CLI: '${tokens[0]}'. ` +
        'Supported: kafka-topics, kafka-consumer-groups, kafka-configs, ' +
        'rabbitmqctl, rabbitmqadmin, redis-cli, aws sqs, aws sns, gcloud pubsub',
      );
  }
}
