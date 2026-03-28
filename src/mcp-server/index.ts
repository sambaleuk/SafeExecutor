/**
 * SafeExecutor MCP Server
 *
 * Model Context Protocol server exposing SafeExecutor as tools for LLM agents.
 * Runs over stdio transport — configure in Claude Code MCP settings or run
 * standalone with `npx @safe-executor/mcp`.
 *
 * Tools:
 *   - safe_execute      — Full pipeline: parse → policy → gate decision
 *   - safe_analyze      — Analyze without executing
 *   - safe_policy_check — Quick allow/deny/require_approval check
 *   - configure_policy  — Update policy rules at runtime
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  TOOL_DEFINITIONS,
  handleSafeExecute,
  handleSafeAnalyze,
  handleSafePolicyCheck,
  handleConfigurePolicy,
} from './tools.js';

const SERVER_NAME = 'safe-executor';
const SERVER_VERSION = '0.1.0';

export function createServer(): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  // Register all tools
  const toolDef = TOOL_DEFINITIONS[0]; // safe_execute
  server.tool(
    toolDef.name,
    toolDef.description,
    toolDef.inputSchema.properties as Record<string, unknown>,
    (args) => handleSafeExecute(args as Record<string, unknown>),
  );

  const analyzeDef = TOOL_DEFINITIONS[1]; // safe_analyze
  server.tool(
    analyzeDef.name,
    analyzeDef.description,
    analyzeDef.inputSchema.properties as Record<string, unknown>,
    (args) => handleSafeAnalyze(args as Record<string, unknown>),
  );

  const policyCheckDef = TOOL_DEFINITIONS[2]; // safe_policy_check
  server.tool(
    policyCheckDef.name,
    policyCheckDef.description,
    policyCheckDef.inputSchema.properties as Record<string, unknown>,
    (args) => handleSafePolicyCheck(args as Record<string, unknown>),
  );

  const configureDef = TOOL_DEFINITIONS[3]; // configure_policy
  server.tool(
    configureDef.name,
    configureDef.description,
    configureDef.inputSchema.properties as Record<string, unknown>,
    (args) => handleConfigurePolicy(args as Record<string, unknown>),
  );

  return server;
}

export async function startServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// Re-export tools for programmatic use
export {
  TOOL_DEFINITIONS,
  handleSafeExecute,
  handleSafeAnalyze,
  handleSafePolicyCheck,
  handleConfigurePolicy,
  getActivePolicy,
  setActivePolicy,
} from './tools.js';

export { detectDomain, isValidDomain, SUPPORTED_DOMAINS } from './auto-detect.js';
export type { Domain, DetectionResult } from './auto-detect.js';
