import type { RiskLevel } from '../types/index.js';

/**
 * Generic SafeAdapter interface for domain-specific adapters (CI/CD, Cloud, K8s, etc.)
 * Each domain implements this interface to plug into the SafeExecutor ecosystem.
 */

export interface SafeParsedCommand {
  raw: string;
  riskLevel: RiskLevel;
  isDestructive: boolean;
  metadata: Record<string, unknown>;
}

export interface SafePolicyDecision {
  allowed: boolean;
  riskLevel: RiskLevel;
  requiresDryRun: boolean;
  requiresApproval: boolean;
  message: string;
}

export interface SafeSandboxResult {
  feasible: boolean;
  warnings: string[];
  durationMs: number;
  preview: string;
}

export interface SafeExecutionResult {
  status: 'success' | 'failed' | 'dry_run' | 'denied';
  durationMs: number;
  output: string;
  error?: string;
}

export interface SafeAdapterResult {
  success: boolean;
  parsed: SafeParsedCommand;
  policyDecision: SafePolicyDecision;
  sandboxResult: SafeSandboxResult | null;
  executionResult: SafeExecutionResult | null;
  abortReason?: string;
}

export interface SafeAdapterOptions {
  dryRun?: boolean;
  requestedBy?: string;
  skipApproval?: boolean;
}

export interface SafeAdapter {
  readonly name: string;
  execute(command: string, options?: SafeAdapterOptions): Promise<SafeAdapterResult>;
}
