#!/usr/bin/env node

/**
 * SafeExecutor MCP Server — CLI entry point
 *
 * Usage:
 *   npx safe-executor --mcp
 *   node dist/bin/safe-executor-mcp.js
 *
 * Starts the MCP server over stdio. Configure in Claude Code:
 *   {
 *     "mcpServers": {
 *       "safe-executor": {
 *         "command": "npx",
 *         "args": ["safe-executor", "--mcp"]
 *       }
 *     }
 *   }
 */

import { startServer } from '../src/mcp-server/index.js';

startServer().catch((err) => {
  process.stderr.write(`SafeExecutor MCP server failed to start: ${err}\n`);
  process.exit(1);
});
