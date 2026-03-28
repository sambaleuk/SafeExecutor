import type { RiskLevel } from '../../types/index.js';

// ─── Queue Tools ──────────────────────────────────────────────────────────────

export type QueueTool =
  | 'kafka'      // kafka-topics, kafka-consumer-groups, kafka-configs
  | 'rabbitmq'   // rabbitmqctl, rabbitmqadmin
  | 'redis'      // redis-cli
  | 'sqs'        // aws sqs
  | 'sns'        // aws sns
  | 'pubsub'     // gcloud pubsub
  | 'unknown';

// ─── Queue Actions ────────────────────────────────────────────────────────────

export type QueueAction =
  | 'publish'    // send a message
  | 'consume'    // receive/read messages
  | 'create'     // create topic, queue, subscription
  | 'delete'     // delete topic, queue, subscription, exchange
  | 'purge'      // remove all messages from a queue/topic
  | 'configure'  // alter config: retention, partitions, offsets, bindings
  | 'list'       // list or describe topics/queues
  | 'unknown';

// ─── Dangerous Pattern ────────────────────────────────────────────────────────

export interface DangerousPattern {
  pattern: string;
  description: string;
  severity: 'HIGH' | 'CRITICAL' | 'DENY';
}

// ─── Parsed Queue Command ─────────────────────────────────────────────────────

/**
 * Parsed intent for a message queue operation.
 * TIntent for SafeAdapter<ParsedQueueCommand, QueueSnapshot>.
 */
export interface ParsedQueueCommand {
  raw: string;
  tool: QueueTool;
  /** Sub-command or service within the tool (e.g. 'topics', 'consumer-groups', 'configs') */
  service: string;
  action: QueueAction;
  riskLevel: RiskLevel;
  isDestructive: boolean;
  /** Topic, queue, exchange, or subscription name being targeted */
  targetName?: string;
  /** Consumer group ID (Kafka) or subscription name */
  consumerGroup?: string;
  /** True when the target name or context suggests a production environment */
  isProduction: boolean;
  /**
   * True when the command targets active consumer groups.
   * Set statically from flags (e.g. --delete --group my-group) — sandbox
   * may upgrade this after a live describe check.
   */
  hasActiveConsumers: boolean;
  /** Named CLI flags */
  flags: Record<string, string | boolean>;
  /** Dangerous patterns detected in the command */
  dangerousPatterns: DangerousPattern[];
  metadata: Record<string, unknown>;
}

// ─── Snapshot ─────────────────────────────────────────────────────────────────

/**
 * State snapshot captured before execution, used by rollback().
 */
export interface QueueSnapshot {
  commandId: string;
  timestamp: Date;
  /** Serialised describe/metadata output captured before the operation */
  preState: string;
  /** Message count before a purge (from GetQueueAttributes or equivalent) */
  messageCount?: number;
}

// ─── Policy types ─────────────────────────────────────────────────────────────

export interface QueueRuleMatch {
  tools?: QueueTool[];
  actions?: QueueAction[];
  isProduction?: boolean;
  hasActiveConsumers?: boolean;
  /** Match on a specific dangerous pattern name */
  hasDangerousPattern?: string;
}

export interface QueuePolicyRule {
  id: string;
  description: string;
  match: QueueRuleMatch;
  action: 'allow' | 'deny' | 'require_approval' | 'require_dry_run';
  riskLevel: RiskLevel;
  message?: string;
}

export interface QueuePolicy {
  version: string;
  rules: QueuePolicyRule[];
  defaults: {
    allowUnknown: boolean;
    defaultRiskLevel: RiskLevel;
  };
}

export interface QueuePolicyDecision {
  allowed: boolean;
  riskLevel: RiskLevel;
  requiresDryRun: boolean;
  requiresApproval: boolean;
  matchedRules: QueuePolicyRule[];
  message: string;
}
