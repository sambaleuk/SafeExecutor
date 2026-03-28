import * as readline from 'readline';
import type {
  ApprovalRequest,
  ApprovalResponse,
  ParsedIntent,
  PolicyDecision,
  SandboxResult,
  SafeExecutorConfig,
} from '../types/index.js';

/**
 * Approval Gate — Layer 4
 *
 * Routes the operation to the appropriate approval flow based on config:
 *   - 'auto'    → auto-approve LOW/MEDIUM risk, deny CRITICAL without sandbox
 *   - 'cli'     → interactive terminal prompt for human approval
 *   - 'webhook' → POST to configured endpoint, poll for response
 *
 * Non-bypassable: CRITICAL operations always require explicit human approval
 * regardless of mode (unless explicitly configured otherwise).
 */

let requestCounter = 0;

function generateRequestId(): string {
  return `approval-${Date.now()}-${++requestCounter}`;
}

export async function requestApproval(
  intent: ParsedIntent,
  policyDecision: PolicyDecision,
  sandboxResult: SandboxResult | null,
  config: SafeExecutorConfig,
  requestedBy: string,
): Promise<ApprovalResponse> {
  const request: ApprovalRequest = {
    id: generateRequestId(),
    operation: intent,
    riskLevel: policyDecision.riskLevel,
    sandboxResult,
    requestedAt: new Date(),
    requestedBy,
    reason: policyDecision.message,
  };

  switch (config.approval.mode) {
    case 'auto':
      return handleAutoApproval(request);
    case 'cli':
      return handleCliApproval(request);
    case 'webhook':
      return handleWebhookApproval(request, config);
    default:
      throw new Error(`Unknown approval mode: ${config.approval.mode}`);
  }
}

function handleAutoApproval(request: ApprovalRequest): ApprovalResponse {
  // CRITICAL is never auto-approved
  if (request.riskLevel === 'CRITICAL') {
    return {
      requestId: request.id,
      status: 'rejected',
      comment: 'Auto-approval denied: CRITICAL risk operations require human review',
    };
  }

  // HIGH risk requires explicit approval even in auto mode
  if (request.riskLevel === 'HIGH') {
    return {
      requestId: request.id,
      status: 'rejected',
      comment: 'Auto-approval denied: HIGH risk operations require human review (use cli or webhook mode)',
    };
  }

  return {
    requestId: request.id,
    status: 'approved',
    approvedBy: 'system:auto',
    approvedAt: new Date(),
    comment: `Auto-approved (risk: ${request.riskLevel})`,
  };
}

async function handleCliApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
  console.log('\n' + '═'.repeat(60));
  console.log('  SAFEEXECUTOR — APPROVAL REQUIRED');
  console.log('═'.repeat(60));
  console.log(`  Request ID : ${request.id}`);
  console.log(`  Risk Level : ${request.riskLevel}`);
  console.log(`  Operation  : ${request.operation.type}`);
  console.log(`  Tables     : ${request.operation.tables.join(', ') || 'unknown'}`);
  console.log(`  WHERE      : ${request.operation.hasWhereClause ? 'yes' : 'NO ⚠️'}`);
  if (request.sandboxResult) {
    console.log(`  Est. Rows  : ${request.sandboxResult.estimatedRowsAffected}`);
    if (request.sandboxResult.warnings.length > 0) {
      console.log(`  Warnings   :`);
      for (const w of request.sandboxResult.warnings) {
        console.log(`    ⚠  ${w}`);
      }
    }
  }
  console.log(`  Policy     : ${request.reason}`);
  console.log('─'.repeat(60));
  console.log(`  SQL:\n  ${request.operation.raw.substring(0, 200)}`);
  console.log('═'.repeat(60));

  const answer = await promptUser('  Approve? [yes/no]: ');
  const normalized = answer.trim().toLowerCase();

  if (normalized === 'yes' || normalized === 'y') {
    const approver = await promptUser('  Your name/ID: ');
    return {
      requestId: request.id,
      status: 'approved',
      approvedBy: approver.trim() || 'cli:unknown',
      approvedAt: new Date(),
    };
  }

  const reason = await promptUser('  Rejection reason (optional): ');
  return {
    requestId: request.id,
    status: 'rejected',
    comment: reason.trim() || 'Rejected via CLI',
  };
}

async function handleWebhookApproval(
  request: ApprovalRequest,
  config: SafeExecutorConfig,
): Promise<ApprovalResponse> {
  if (!config.approval.webhookUrl) {
    throw new Error('Webhook approval mode requires approval.webhookUrl in config');
  }

  const payload = JSON.stringify(request, null, 2);
  const timeoutMs = (config.approval.timeoutSeconds ?? 300) * 1000;

  // POST the request
  const response = await fetch(config.approval.webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: payload,
    signal: AbortSignal.timeout(timeoutMs),
  });

  if (!response.ok) {
    throw new Error(`Webhook POST failed: ${response.status} ${response.statusText}`);
  }

  const result = await response.json() as ApprovalResponse;
  return result;
}

function promptUser(question: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}
