import { parseIntent } from './intent-parser.js';
import { evaluatePolicy } from './policy-engine.js';
import { runSandbox } from './sandbox.js';
import { requestApproval } from './approval-gate.js';
import { executeWithRollback } from './executor.js';
import { writeAuditEntry, generateAuditId } from './audit.js';
import type {
  SafeExecutorConfig,
  Policy,
  PipelineContext,
  PipelineResult,
  AuditEntry,
} from '../types/index.js';
import type { DatabaseAdapter } from '../adapters/adapter.interface.js';

/**
 * Pipeline Orchestrator
 *
 * Sequences all 6 layers in strict order. Each gate must pass before
 * the next is entered. No gate can be skipped.
 *
 * Gate sequence:
 *   1. Intent Parser   → classify the operation
 *   2. Policy Engine   → evaluate against rules
 *   3. Sandbox         → simulate (if required by policy)
 *   4. Approval Gate   → human or automated approval
 *   5. Executor        → execute with rollback protection
 *   6. Audit Trail     → record everything
 */

export class SafeExecutorPipeline {
  constructor(
    private readonly config: SafeExecutorConfig,
    private readonly policy: Policy,
    private readonly adapter: DatabaseAdapter,
  ) {}

  async run(sql: string, requestedBy?: string): Promise<PipelineResult> {
    const ctx: PipelineContext = {
      config: this.config,
      sql,
      intent: null,
      policyDecision: null,
      sandboxResult: null,
      approvalResponse: null,
      executionResult: null,
      auditEntry: { id: generateAuditId(), tags: [] },
      startedAt: new Date(),
    };

    try {
      // ── Gate 1: Intent Parser ──────────────────────────────────────────
      ctx.intent = parseIntent(sql);
      ctx.auditEntry.operation = ctx.intent;

      // ── Gate 2: Policy Engine ──────────────────────────────────────────
      ctx.policyDecision = evaluatePolicy(ctx.intent, this.policy);
      ctx.auditEntry.policyDecision = ctx.policyDecision;

      if (!ctx.policyDecision.allowed) {
        return this.abort(ctx, `Policy denied: ${ctx.policyDecision.message}`);
      }

      // ── Gate 3: Sandbox (conditional) ─────────────────────────────────
      if (ctx.policyDecision.requiresDryRun) {
        ctx.sandboxResult = await runSandbox(ctx.intent, this.adapter);
        ctx.auditEntry.sandboxResult = ctx.sandboxResult;

        // Update intent with row estimate from sandbox
        if (ctx.sandboxResult.estimatedRowsAffected !== null) {
          ctx.intent.estimatedRowsAffected = ctx.sandboxResult.estimatedRowsAffected;
        }

        if (!ctx.sandboxResult.feasible) {
          return this.abort(ctx, 'Sandbox reports operation is not feasible');
        }
      }

      // ── Gate 4: Approval ───────────────────────────────────────────────
      if (ctx.policyDecision.requiresApproval) {
        ctx.approvalResponse = await requestApproval(
          ctx.intent,
          ctx.policyDecision,
          ctx.sandboxResult,
          this.config,
          requestedBy ?? this.config.executor,
        );
        ctx.auditEntry.approvalResponse = ctx.approvalResponse;

        if (ctx.approvalResponse.status === 'rejected') {
          return this.abort(ctx, `Approval rejected: ${ctx.approvalResponse.comment ?? 'no reason given'}`);
        }
      }

      // ── Gate 5: Execute ────────────────────────────────────────────────
      ctx.executionResult = await executeWithRollback(
        ctx.intent,
        this.adapter,
        this.config,
        ctx.sandboxResult?.estimatedRowsAffected ?? null,
      );
      ctx.auditEntry.executionResult = ctx.executionResult;

      const auditEntry = this.buildAuditEntry(ctx);
      await writeAuditEntry(auditEntry, this.config);

      return {
        success: ctx.executionResult.status === 'success',
        executionResult: ctx.executionResult,
        auditEntry,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return this.abort(ctx, `Pipeline error: ${message}`);
    }
  }

  private async abort(ctx: PipelineContext, reason: string): Promise<PipelineResult> {
    const auditEntry = this.buildAuditEntry(ctx);
    await writeAuditEntry(auditEntry, this.config);

    return {
      success: false,
      executionResult: null,
      auditEntry,
      abortedAt: new Date().toISOString(),
      abortReason: reason,
    };
  }

  private buildAuditEntry(ctx: PipelineContext): AuditEntry {
    return {
      id: ctx.auditEntry.id ?? generateAuditId(),
      timestamp: ctx.startedAt,
      executor: ctx.config.executor,
      operation: ctx.intent ?? {
        raw: ctx.sql,
        type: 'UNKNOWN',
        tables: [],
        hasWhereClause: false,
        estimatedRowsAffected: null,
        isDestructive: false,
        isMassive: false,
        metadata: {},
      },
      policyDecision: ctx.policyDecision ?? {
        allowed: false,
        riskLevel: 'CRITICAL',
        requiresDryRun: false,
        requiresApproval: false,
        matchedRules: [],
        message: 'Pipeline aborted before policy evaluation',
      },
      sandboxResult: ctx.sandboxResult ?? null,
      approvalResponse: ctx.approvalResponse ?? null,
      executionResult: ctx.executionResult ?? null,
      totalDurationMs: Date.now() - ctx.startedAt.getTime(),
      environment: ctx.config.environment,
      tags: ctx.auditEntry.tags ?? [],
    };
  }
}
