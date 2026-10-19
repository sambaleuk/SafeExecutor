#!/usr/bin/env node
import { startServer } from '../mcp-server/index.js';

startServer().catch((err) => {
  console.error('SafeExecutor MCP server failed to start:', err);
  process.exit(1);
});
