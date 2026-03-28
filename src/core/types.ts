/**
 * SafeAdapter — Generic Adapter Interface
 *
 * All non-SQL adapters implement this interface (Cloud, Kubernetes, etc.).
 * The SQL pipeline uses DatabaseAdapter (src/adapters/adapter.interface.ts).
 *
 * TIntent: Parsed representation of the command
 * TSnapshot: State snapshot used for rollback
 */

export interface SimulationResult {
  /** Whether the operation can proceed */
  feasible: boolean;
  /** Number of resources that will be affected (-1 if unknown) */
  resourcesImpacted: number;
  /** Human-readable summary of what will happen */
  summary: string;
  /** Non-fatal warnings to surface before execution */
  warnings: string[];
  /** Simulation duration in milliseconds */
  durationMs: number;
}

export interface AdapterExecutionResult {
  success: boolean;
  /** Raw CLI output */
  output: string;
  /** Number of resources actually affected */
  resourcesAffected: number;
  durationMs: number;
  error?: string;
}

export interface SafeAdapter<TIntent, TSnapshot = Record<string, unknown>> {
  /** Adapter identifier (e.g. 'cloud', 'k8s') */
  readonly name: string;

  /**
   * Parse a raw command string into a structured intent.
   * Must throw if the command is unsupported or malformed.
   */
  parseIntent(raw: string): TIntent;

  /**
   * Simulate the operation without committing changes.
   * For Terraform: runs `terraform plan`.
   * For AWS: uses `--dry-run` where available.
   * Always returns feasible:false if the simulation reveals an error.
   */
  sandbox(intent: TIntent): Promise<SimulationResult>;

  /**
   * Execute the operation for real.
   * Called only after policy check + sandbox + approval have all passed.
   */
  execute(intent: TIntent): Promise<AdapterExecutionResult>;

  /**
   * Attempt to rollback the operation using the provided snapshot.
   * Throws if automatic rollback is not supported for this operation type.
   */
  rollback(intent: TIntent, snapshot: TSnapshot): Promise<void>;
}
