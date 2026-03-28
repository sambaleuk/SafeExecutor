import type { SafeAdapter, SafeAdapterPlugin } from '../adapters/adapter.interface.js';

/**
 * Plugin Registry
 *
 * Central registry for SafeAdapter plugins.
 * Adapters register themselves here; the pipeline looks up by domain.
 *
 * Built-in adapters (@safe-executor/sql, etc.) are registered automatically.
 * Third-party adapters register via registerAdapter().
 *
 * Phase 8 will expand this into a full NPM package system with:
 *   - Config schema validation per adapter
 *   - Default policy rules per domain
 *   - Version compatibility checks
 */

const registry = new Map<string, SafeAdapterPlugin>();

/**
 * Register a SafeAdapter under its domain identifier.
 * Throws if an adapter for that domain is already registered.
 */
export function registerAdapter(plugin: SafeAdapterPlugin): void {
  if (registry.has(plugin.adapter.domain)) {
    throw new Error(
      `Adapter for domain '${plugin.adapter.domain}' is already registered. ` +
        `Use replaceAdapter() to override.`,
    );
  }
  registry.set(plugin.adapter.domain, plugin);
}

/**
 * Replace an existing adapter registration (useful for testing/overrides).
 */
export function replaceAdapter(plugin: SafeAdapterPlugin): void {
  registry.set(plugin.adapter.domain, plugin);
}

/**
 * Look up a registered adapter by domain.
 * Returns undefined if not registered.
 */
export function getAdapter(domain: string): SafeAdapter | undefined {
  return registry.get(domain)?.adapter;
}

/**
 * List all registered domain identifiers.
 */
export function listDomains(): string[] {
  return [...registry.keys()];
}

/**
 * Remove all registered adapters (primarily for test isolation).
 */
export function clearRegistry(): void {
  registry.clear();
}
