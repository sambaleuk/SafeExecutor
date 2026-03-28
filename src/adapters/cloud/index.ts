/**
 * Cloud Infrastructure Adapter — Phase 4 (not yet implemented)
 *
 * Will support Terraform plan/apply/destroy operations.
 * See ROADMAP_V2.md — Phase 4 for full specification.
 *
 * Planned capabilities:
 *   - Parse Terraform plan JSON → SafeIntent
 *   - Detect destructive resource changes (DB instances, IAM roles, security groups)
 *   - Sandbox via `terraform plan --out`
 *   - Rollback via terraform state manipulation
 */

export {};
