import { readFileSync } from 'fs';
import { parseQueueCommand } from '../src/adapters/queue/parser.js';
import { simulateQueueCommand } from '../src/adapters/queue/sandbox.js';
import { QueueAdapter, evaluateQueuePolicy } from '../src/adapters/queue/adapter.js';
import type { QueuePolicy } from '../src/adapters/queue/types.js';

// ─── Fixtures ──────────────────────────────────────────────────────────────────

const defaultPolicy = JSON.parse(
  readFileSync(new URL('../config/policies/queue-default-policy.json', import.meta.url), 'utf-8'),
) as QueuePolicy;

// ─── Parser: tool detection ────────────────────────────────────────────────────

describe('parseQueueCommand — tool detection', () => {
  test('detects kafka-topics', () => {
    const r = parseQueueCommand('kafka-topics --list --bootstrap-server localhost:9092');
    expect(r.tool).toBe('kafka');
    expect(r.service).toBe('topics');
  });

  test('detects kafka-consumer-groups', () => {
    const r = parseQueueCommand('kafka-consumer-groups --list --bootstrap-server localhost:9092');
    expect(r.tool).toBe('kafka');
    expect(r.service).toBe('consumer-groups');
  });

  test('detects kafka-configs', () => {
    const r = parseQueueCommand('kafka-configs --describe --entity-type topics --bootstrap-server localhost:9092');
    expect(r.tool).toBe('kafka');
    expect(r.service).toBe('configs');
  });

  test('detects rabbitmqctl', () => {
    const r = parseQueueCommand('rabbitmqctl list_queues');
    expect(r.tool).toBe('rabbitmq');
    expect(r.service).toBe('rabbitmqctl');
  });

  test('detects rabbitmqadmin', () => {
    const r = parseQueueCommand('rabbitmqadmin list queues');
    expect(r.tool).toBe('rabbitmq');
    expect(r.service).toBe('rabbitmqadmin');
  });

  test('detects redis-cli', () => {
    const r = parseQueueCommand('redis-cli GET mykey');
    expect(r.tool).toBe('redis');
  });

  test('detects aws sqs', () => {
    const r = parseQueueCommand('aws sqs list-queues');
    expect(r.tool).toBe('sqs');
  });

  test('detects aws sns', () => {
    const r = parseQueueCommand('aws sns list-topics');
    expect(r.tool).toBe('sns');
  });

  test('detects gcloud pubsub', () => {
    const r = parseQueueCommand('gcloud pubsub topics list');
    expect(r.tool).toBe('pubsub');
  });

  test('throws on unsupported CLI', () => {
    expect(() => parseQueueCommand('unknown-mq-tool --help')).toThrow('Unsupported queue CLI');
  });

  test('throws on empty command', () => {
    expect(() => parseQueueCommand('')).toThrow('Empty command');
  });

  test('throws on unsupported aws service', () => {
    expect(() => parseQueueCommand('aws kinesis list-streams')).toThrow('Unsupported AWS service');
  });

  test('throws on unsupported gcloud service', () => {
    expect(() => parseQueueCommand('gcloud storage buckets list')).toThrow('Unsupported gcloud service');
  });
});

// ─── Parser: action detection ──────────────────────────────────────────────────

describe('parseQueueCommand — action detection', () => {
  test('kafka-topics --create → create', () => {
    const r = parseQueueCommand('kafka-topics --create --topic my-topic --bootstrap-server localhost:9092 --partitions 3 --replication-factor 1');
    expect(r.action).toBe('create');
  });

  test('kafka-topics --delete → delete', () => {
    const r = parseQueueCommand('kafka-topics --delete --topic my-topic --bootstrap-server localhost:9092');
    expect(r.action).toBe('delete');
  });

  test('kafka-topics --list → list', () => {
    const r = parseQueueCommand('kafka-topics --list --bootstrap-server localhost:9092');
    expect(r.action).toBe('list');
  });

  test('kafka-topics --describe → list', () => {
    const r = parseQueueCommand('kafka-topics --describe --topic my-topic --bootstrap-server localhost:9092');
    expect(r.action).toBe('list');
  });

  test('kafka-topics --alter → configure', () => {
    const r = parseQueueCommand('kafka-topics --alter --topic my-topic --partitions 6 --bootstrap-server localhost:9092');
    expect(r.action).toBe('configure');
  });

  test('kafka-consumer-groups --list → list', () => {
    const r = parseQueueCommand('kafka-consumer-groups --list --bootstrap-server localhost:9092');
    expect(r.action).toBe('list');
  });

  test('kafka-consumer-groups --delete → delete', () => {
    const r = parseQueueCommand('kafka-consumer-groups --delete --group my-group --bootstrap-server localhost:9092');
    expect(r.action).toBe('delete');
  });

  test('kafka-consumer-groups --reset-offsets → configure', () => {
    const r = parseQueueCommand('kafka-consumer-groups --reset-offsets --group my-group --topic my-topic --to-latest --bootstrap-server localhost:9092');
    expect(r.action).toBe('configure');
  });

  test('rabbitmqctl list_queues → list', () => {
    const r = parseQueueCommand('rabbitmqctl list_queues');
    expect(r.action).toBe('list');
  });

  test('rabbitmqctl purge_queue → purge', () => {
    const r = parseQueueCommand('rabbitmqctl purge_queue my-queue');
    expect(r.action).toBe('purge');
  });

  test('rabbitmqctl delete_queue → delete', () => {
    const r = parseQueueCommand('rabbitmqctl delete_queue my-queue');
    expect(r.action).toBe('delete');
  });

  test('rabbitmqadmin publish → publish', () => {
    const r = parseQueueCommand('rabbitmqadmin publish exchange=amq.default routing_key=my-queue payload=hello');
    expect(r.action).toBe('publish');
  });

  test('rabbitmqadmin delete queue → delete', () => {
    const r = parseQueueCommand('rabbitmqadmin delete queue name=my-queue');
    expect(r.action).toBe('delete');
  });

  test('redis-cli GET → consume', () => {
    const r = parseQueueCommand('redis-cli GET mykey');
    expect(r.action).toBe('consume');
  });

  test('redis-cli SET → publish', () => {
    const r = parseQueueCommand('redis-cli SET mykey myvalue');
    expect(r.action).toBe('publish');
  });

  test('redis-cli XADD → publish', () => {
    const r = parseQueueCommand('redis-cli XADD mystream * field value');
    expect(r.action).toBe('publish');
  });

  test('redis-cli XREAD → consume', () => {
    const r = parseQueueCommand('redis-cli XREAD COUNT 10 STREAMS mystream 0');
    expect(r.action).toBe('consume');
  });

  test('redis-cli DEL → delete', () => {
    const r = parseQueueCommand('redis-cli DEL mykey');
    expect(r.action).toBe('delete');
  });

  test('redis-cli FLUSHALL → purge', () => {
    const r = parseQueueCommand('redis-cli FLUSHALL');
    expect(r.action).toBe('purge');
  });

  test('redis-cli FLUSHDB → purge', () => {
    const r = parseQueueCommand('redis-cli FLUSHDB');
    expect(r.action).toBe('purge');
  });

  test('aws sqs create-queue → create', () => {
    const r = parseQueueCommand('aws sqs create-queue --queue-name my-queue');
    expect(r.action).toBe('create');
  });

  test('aws sqs delete-queue → delete', () => {
    const r = parseQueueCommand('aws sqs delete-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/my-queue');
    expect(r.action).toBe('delete');
  });

  test('aws sqs purge-queue → purge', () => {
    const r = parseQueueCommand('aws sqs purge-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/my-queue');
    expect(r.action).toBe('purge');
  });

  test('aws sqs send-message → publish', () => {
    const r = parseQueueCommand('aws sqs send-message --queue-url https://sqs.us-east-1.amazonaws.com/123/my-queue --message-body "hello"');
    expect(r.action).toBe('publish');
  });

  test('aws sqs receive-message → consume', () => {
    const r = parseQueueCommand('aws sqs receive-message --queue-url https://sqs.us-east-1.amazonaws.com/123/my-queue');
    expect(r.action).toBe('consume');
  });

  test('aws sqs list-queues → list', () => {
    const r = parseQueueCommand('aws sqs list-queues');
    expect(r.action).toBe('list');
  });

  test('aws sns create-topic → create', () => {
    const r = parseQueueCommand('aws sns create-topic --name my-topic');
    expect(r.action).toBe('create');
  });

  test('aws sns delete-topic → delete', () => {
    const r = parseQueueCommand('aws sns delete-topic --topic-arn arn:aws:sns:us-east-1:123:my-topic');
    expect(r.action).toBe('delete');
  });

  test('aws sns publish → publish', () => {
    const r = parseQueueCommand('aws sns publish --topic-arn arn:aws:sns:us-east-1:123:my-topic --message "hello"');
    expect(r.action).toBe('publish');
  });

  test('aws sns list-topics → list', () => {
    const r = parseQueueCommand('aws sns list-topics');
    expect(r.action).toBe('list');
  });

  test('gcloud pubsub topics create → create', () => {
    const r = parseQueueCommand('gcloud pubsub topics create my-topic');
    expect(r.action).toBe('create');
  });

  test('gcloud pubsub topics delete → delete', () => {
    const r = parseQueueCommand('gcloud pubsub topics delete my-topic');
    expect(r.action).toBe('delete');
  });

  test('gcloud pubsub topics publish → publish', () => {
    const r = parseQueueCommand('gcloud pubsub topics publish my-topic --message hello');
    expect(r.action).toBe('publish');
  });

  test('gcloud pubsub topics list → list', () => {
    const r = parseQueueCommand('gcloud pubsub topics list');
    expect(r.action).toBe('list');
  });

  test('gcloud pubsub subscriptions pull → consume', () => {
    const r = parseQueueCommand('gcloud pubsub subscriptions pull my-sub --auto-ack');
    expect(r.action).toBe('consume');
  });

  test('gcloud pubsub subscriptions delete → delete', () => {
    const r = parseQueueCommand('gcloud pubsub subscriptions delete my-sub');
    expect(r.action).toBe('delete');
  });
});

// ─── Parser: risk classification ───────────────────────────────────────────────

describe('parseQueueCommand — risk classification', () => {
  test('list topics is LOW risk', () => {
    const r = parseQueueCommand('kafka-topics --list --bootstrap-server localhost:9092');
    expect(r.riskLevel).toBe('LOW');
  });

  test('list queues (SQS) is LOW risk', () => {
    const r = parseQueueCommand('aws sqs list-queues');
    expect(r.riskLevel).toBe('LOW');
  });

  test('receive-message is LOW risk', () => {
    const r = parseQueueCommand('aws sqs receive-message --queue-url https://sqs.us-east-1.amazonaws.com/123/dev-queue');
    expect(r.riskLevel).toBe('LOW');
  });

  test('publish (non-production) is MEDIUM risk', () => {
    const r = parseQueueCommand('aws sqs send-message --queue-url https://sqs.us-east-1.amazonaws.com/123/dev-queue --message-body "test"');
    expect(r.riskLevel).toBe('MEDIUM');
  });

  test('create topic is MEDIUM risk', () => {
    const r = parseQueueCommand('kafka-topics --create --topic my-topic --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1');
    expect(r.riskLevel).toBe('MEDIUM');
  });

  test('alter topic config is HIGH risk', () => {
    const r = parseQueueCommand('kafka-configs --alter --entity-type topics --entity-name my-topic --add-config retention.ms=3600000 --bootstrap-server localhost:9092');
    expect(r.riskLevel).toBe('HIGH');
  });

  test('delete queue is CRITICAL risk', () => {
    const r = parseQueueCommand('aws sqs delete-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/my-queue');
    expect(r.riskLevel).toBe('CRITICAL');
  });

  test('purge queue is CRITICAL risk', () => {
    const r = parseQueueCommand('aws sqs purge-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/my-queue');
    expect(r.riskLevel).toBe('CRITICAL');
  });

  test('FLUSHALL is CRITICAL risk', () => {
    const r = parseQueueCommand('redis-cli FLUSHALL');
    expect(r.riskLevel).toBe('CRITICAL');
  });

  test('publish to production topic is HIGH risk', () => {
    const r = parseQueueCommand('aws sqs send-message --queue-url https://sqs.us-east-1.amazonaws.com/123/production-queue --message-body "test"');
    expect(r.riskLevel).toBe('HIGH');
  });
});

// ─── Parser: production detection ─────────────────────────────────────────────

describe('parseQueueCommand — production detection', () => {
  test('detects production in Kafka topic name', () => {
    const r = parseQueueCommand('kafka-topics --delete --topic production-events --bootstrap-server localhost:9092');
    expect(r.isProduction).toBe(true);
  });

  test('detects prod in SQS queue URL', () => {
    const r = parseQueueCommand('aws sqs purge-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/prod-orders');
    expect(r.isProduction).toBe(true);
  });

  test('detects production in RabbitMQ vhost', () => {
    const r = parseQueueCommand('rabbitmqctl purge_queue my-queue -p production');
    expect(r.isProduction).toBe(true);
  });

  test('detects prod in gcloud pubsub topic name', () => {
    const r = parseQueueCommand('gcloud pubsub topics delete prod-notifications');
    expect(r.isProduction).toBe(true);
  });

  test('non-production staging topic', () => {
    const r = parseQueueCommand('kafka-topics --delete --topic staging-events --bootstrap-server localhost:9092');
    expect(r.isProduction).toBe(false);
  });

  test('non-production dev queue', () => {
    const r = parseQueueCommand('aws sqs delete-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/dev-queue');
    expect(r.isProduction).toBe(false);
  });
});

// ─── Parser: dangerous patterns ────────────────────────────────────────────────

describe('parseQueueCommand — dangerous patterns', () => {
  test('kafka-topics --delete emits CRITICAL pattern', () => {
    const r = parseQueueCommand('kafka-topics --delete --topic my-topic --bootstrap-server localhost:9092');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: 'kafka-topics --delete' }),
      ]),
    );
  });

  test('kafka-topics --delete on production emits DENY pattern', () => {
    const r = parseQueueCommand('kafka-topics --delete --topic production-topic --bootstrap-server localhost:9092');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: 'kafka-topics --delete', severity: 'DENY' }),
      ]),
    );
  });

  test('kafka-consumer-groups --reset-offsets --to-earliest emits CRITICAL pattern', () => {
    const r = parseQueueCommand('kafka-consumer-groups --reset-offsets --group my-group --topic my-topic --to-earliest --bootstrap-server localhost:9092');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: expect.stringContaining('reset-offsets'), severity: 'CRITICAL' }),
      ]),
    );
  });

  test('rabbitmqctl purge_queue emits CRITICAL pattern', () => {
    const r = parseQueueCommand('rabbitmqctl purge_queue my-queue');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: 'rabbitmqctl purge_queue', severity: 'CRITICAL' }),
      ]),
    );
  });

  test('rabbitmqctl purge_queue on production emits DENY pattern', () => {
    const r = parseQueueCommand('rabbitmqctl purge_queue production-queue');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: 'rabbitmqctl purge_queue', severity: 'DENY' }),
      ]),
    );
  });

  test('rabbitmqctl delete_exchange emits CRITICAL pattern', () => {
    const r = parseQueueCommand('rabbitmqctl delete_exchange my-exchange');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: 'rabbitmqctl delete_exchange', severity: 'CRITICAL' }),
      ]),
    );
  });

  test('rabbitmqadmin delete exchange emits CRITICAL pattern', () => {
    const r = parseQueueCommand('rabbitmqadmin delete exchange name=my-exchange');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: expect.stringContaining('delete exchange') }),
      ]),
    );
  });

  test('aws sqs purge-queue emits CRITICAL pattern', () => {
    const r = parseQueueCommand('aws sqs purge-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/my-queue');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: 'aws sqs purge-queue' }),
      ]),
    );
  });

  test('aws sqs purge-queue on production emits DENY pattern', () => {
    const r = parseQueueCommand('aws sqs purge-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/prod-queue');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: 'aws sqs purge-queue', severity: 'DENY' }),
      ]),
    );
  });

  test('redis-cli FLUSHALL emits DENY pattern', () => {
    const r = parseQueueCommand('redis-cli FLUSHALL');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: 'redis FLUSHALL', severity: 'DENY' }),
      ]),
    );
  });

  test('redis-cli FLUSHDB emits DENY pattern', () => {
    const r = parseQueueCommand('redis-cli FLUSHDB');
    expect(r.dangerousPatterns).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ pattern: 'redis FLUSHDB', severity: 'DENY' }),
      ]),
    );
  });

  test('list command has no dangerous patterns', () => {
    const r = parseQueueCommand('kafka-topics --list --bootstrap-server localhost:9092');
    expect(r.dangerousPatterns).toHaveLength(0);
  });
});

// ─── Parser: target name extraction ───────────────────────────────────────────

describe('parseQueueCommand — target name extraction', () => {
  test('extracts Kafka topic name from --topic', () => {
    const r = parseQueueCommand('kafka-topics --delete --topic my-events --bootstrap-server localhost:9092');
    expect(r.targetName).toBe('my-events');
  });

  test('extracts consumer group from --group', () => {
    const r = parseQueueCommand('kafka-consumer-groups --delete --group my-consumer-group --bootstrap-server localhost:9092');
    expect(r.consumerGroup).toBe('my-consumer-group');
  });

  test('extracts SQS queue URL from --queue-url', () => {
    const r = parseQueueCommand('aws sqs delete-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/my-queue');
    expect(r.targetName).toBe('https://sqs.us-east-1.amazonaws.com/123/my-queue');
  });

  test('extracts rabbitmqadmin queue name from name=', () => {
    const r = parseQueueCommand('rabbitmqadmin delete queue name=my-queue');
    expect(r.targetName).toBe('my-queue');
  });

  test('extracts gcloud pubsub topic name', () => {
    const r = parseQueueCommand('gcloud pubsub topics delete my-prod-topic');
    expect(r.targetName).toBe('my-prod-topic');
  });
});

// ─── Sandbox ───────────────────────────────────────────────────────────────────

describe('simulateQueueCommand', () => {
  test('denies FLUSHALL (DENY pattern)', async () => {
    const parsed = parseQueueCommand('redis-cli FLUSHALL');
    const result = await simulateQueueCommand(parsed);
    expect(result.feasible).toBe(false);
    expect(result.summary).toContain('DENIED');
  });

  test('denies FLUSHDB (DENY pattern)', async () => {
    const parsed = parseQueueCommand('redis-cli FLUSHDB');
    const result = await simulateQueueCommand(parsed);
    expect(result.feasible).toBe(false);
    expect(result.summary).toContain('DENIED');
  });

  test('denies production SQS purge (DENY pattern)', async () => {
    const parsed = parseQueueCommand('aws sqs purge-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/prod-queue');
    const result = await simulateQueueCommand(parsed);
    expect(result.feasible).toBe(false);
    expect(result.summary).toContain('DENIED');
  });

  test('allows list operation', async () => {
    const parsed = parseQueueCommand('kafka-topics --list --bootstrap-server localhost:9092');
    const result = await simulateQueueCommand(parsed);
    expect(result.feasible).toBe(true);
  });

  test('allows consume from non-production', async () => {
    const parsed = parseQueueCommand('aws sqs receive-message --queue-url https://sqs.us-east-1.amazonaws.com/123/dev-queue');
    const result = await simulateQueueCommand(parsed);
    expect(result.feasible).toBe(true);
  });

  test('warns on production target', async () => {
    const parsed = parseQueueCommand('aws sns delete-topic --topic-arn arn:aws:sns:us-east-1:123:production-alerts');
    const result = await simulateQueueCommand(parsed);
    expect(result.warnings).toEqual(
      expect.arrayContaining([expect.stringContaining('PRODUCTION')]),
    );
  });

  test('warns on delete action (destructive)', async () => {
    const parsed = parseQueueCommand('aws sqs delete-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/my-queue');
    const result = await simulateQueueCommand(parsed);
    expect(result.feasible).toBe(true);
    expect(result.warnings).toEqual(
      expect.arrayContaining([expect.stringContaining('permanent')]),
    );
  });

  test('warns on purge action (data loss)', async () => {
    const parsed = parseQueueCommand('rabbitmqctl purge_queue my-queue');
    const result = await simulateQueueCommand(parsed);
    expect(result.feasible).toBe(true);
    expect(result.warnings).toEqual(
      expect.arrayContaining([expect.stringContaining('ALL messages')]),
    );
  });

  test('warns on offset reset', async () => {
    const parsed = parseQueueCommand('kafka-consumer-groups --reset-offsets --group my-group --topic my-topic --to-latest --bootstrap-server localhost:9092');
    const result = await simulateQueueCommand(parsed);
    expect(result.feasible).toBe(true);
    expect(result.warnings).toEqual(
      expect.arrayContaining([expect.stringContaining('re-process or skip messages')]),
    );
  });

  test('summary includes tool, action, risk info', async () => {
    const parsed = parseQueueCommand('kafka-topics --describe --topic my-topic --bootstrap-server localhost:9092');
    const result = await simulateQueueCommand(parsed);
    expect(result.summary).toContain('[DRY-RUN]');
    expect(result.summary).toContain('kafka');
    expect(result.summary).toContain('list');
  });
});

// ─── Policy evaluator ──────────────────────────────────────────────────────────

describe('evaluateQueuePolicy', () => {
  test('denies purge on production queue', () => {
    const parsed = parseQueueCommand('aws sqs purge-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/prod-queue');
    // Force isProduction=true explicitly (already set by parser for prod- prefix)
    const decision = evaluateQueuePolicy(parsed, defaultPolicy);
    expect(decision.allowed).toBe(false);
  });

  test('denies Redis FLUSHALL/FLUSHDB', () => {
    const parsed = parseQueueCommand('redis-cli FLUSHALL');
    const decision = evaluateQueuePolicy(parsed, defaultPolicy);
    expect(decision.allowed).toBe(false);
  });

  test('denies delete with active consumers', () => {
    const parsed = parseQueueCommand('kafka-consumer-groups --delete --group my-group --bootstrap-server localhost:9092');
    // hasActiveConsumers is set to true when consumer group is specified for delete
    const decision = evaluateQueuePolicy({ ...parsed, hasActiveConsumers: true }, defaultPolicy);
    expect(decision.allowed).toBe(false);
  });

  test('requires approval for delete topic/queue', () => {
    const parsed = parseQueueCommand('aws sqs delete-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/dev-queue');
    const decision = evaluateQueuePolicy(parsed, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('requires approval for purge (non-production)', () => {
    const parsed = parseQueueCommand('rabbitmqctl purge_queue dev-queue');
    const decision = evaluateQueuePolicy(parsed, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('requires approval for kafka consumer offset reset', () => {
    const parsed = parseQueueCommand('kafka-consumer-groups --reset-offsets --group my-group --topic my-topic --to-earliest --bootstrap-server localhost:9092');
    const decision = evaluateQueuePolicy(parsed, defaultPolicy);
    expect(decision.requiresApproval).toBe(true);
  });

  test('requires dry-run for configure actions', () => {
    const parsed = parseQueueCommand('kafka-configs --alter --entity-type topics --entity-name my-topic --add-config retention.ms=3600000 --bootstrap-server localhost:9092');
    const decision = evaluateQueuePolicy(parsed, defaultPolicy);
    expect(decision.requiresDryRun).toBe(true);
  });

  test('requires dry-run for publish to production', () => {
    const parsed = parseQueueCommand('aws sqs send-message --queue-url https://sqs.us-east-1.amazonaws.com/123/production-queue --message-body "hello"');
    const decision = evaluateQueuePolicy(parsed, defaultPolicy);
    expect(decision.requiresDryRun).toBe(true);
  });

  test('auto-approves list action', () => {
    const parsed = parseQueueCommand('kafka-topics --list --bootstrap-server localhost:9092');
    const decision = evaluateQueuePolicy(parsed, defaultPolicy);
    expect(decision.allowed).toBe(true);
    expect(decision.riskLevel).toBe('LOW');
  });

  test('auto-approves non-production consume', () => {
    const parsed = parseQueueCommand('aws sqs receive-message --queue-url https://sqs.us-east-1.amazonaws.com/123/dev-queue');
    const decision = evaluateQueuePolicy(parsed, defaultPolicy);
    expect(decision.allowed).toBe(true);
  });

  test('CRITICAL risk forces dry-run + approval', () => {
    const parsed = parseQueueCommand('aws sqs delete-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/dev-queue');
    const decision = evaluateQueuePolicy(parsed, defaultPolicy);
    expect(decision.riskLevel).toBe('CRITICAL');
    expect(decision.requiresDryRun).toBe(true);
    expect(decision.requiresApproval).toBe(true);
  });

  test('blocks unknown commands when allowUnknown is false', () => {
    // Create a command from an unsupported tool that somehow gets through
    const fakeIntent = {
      raw: 'unknown-mq-tool foo',
      tool: 'unknown' as const,
      service: 'unknown',
      action: 'unknown' as const,
      riskLevel: 'MEDIUM' as const,
      isDestructive: false,
      isProduction: false,
      hasActiveConsumers: false,
      flags: {},
      dangerousPatterns: [],
      metadata: {},
    };
    const decision = evaluateQueuePolicy(fakeIntent, defaultPolicy);
    expect(decision.allowed).toBe(false);
  });
});

// ─── Adapter class ─────────────────────────────────────────────────────────────

describe('QueueAdapter', () => {
  const adapter = new QueueAdapter();

  test('has name "queue"', () => {
    expect(adapter.name).toBe('queue');
  });

  test('parseIntent delegates to parser', () => {
    const result = adapter.parseIntent('kafka-topics --list --bootstrap-server localhost:9092');
    expect(result.tool).toBe('kafka');
    expect(result.action).toBe('list');
  });

  test('sandbox delegates to simulator', async () => {
    const intent = adapter.parseIntent('aws sqs list-queues');
    const result = await adapter.sandbox(intent);
    expect(result.feasible).toBe(true);
  });

  test('sandbox returns feasible=false for DENY patterns', async () => {
    const intent = adapter.parseIntent('redis-cli FLUSHALL');
    const result = await adapter.sandbox(intent);
    expect(result.feasible).toBe(false);
  });

  test('rollback throws with snapshot reference', async () => {
    const intent = adapter.parseIntent('aws sqs delete-queue --queue-url https://sqs.us-east-1.amazonaws.com/123/dev-queue');
    const snapshot = {
      commandId: 'test-abc',
      timestamp: new Date(),
      preState: '{"ApproximateNumberOfMessages": "42"}',
    };
    await expect(adapter.rollback(intent, snapshot)).rejects.toThrow('Manual intervention');
  });

  test('rollback error includes commandId', async () => {
    const intent = adapter.parseIntent('kafka-topics --delete --topic staging-topic --bootstrap-server localhost:9092');
    const snapshot = {
      commandId: 'cmd-xyz-789',
      timestamp: new Date('2024-01-15T10:00:00Z'),
      preState: '{}',
    };
    await expect(adapter.rollback(intent, snapshot)).rejects.toThrow('cmd-xyz-789');
  });
});
