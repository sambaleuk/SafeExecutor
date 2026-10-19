#!/usr/bin/env node
import { preToolUseResponse } from '../hooks/pre-tool-use.js';

// Claude Code passes the PreToolUse payload as JSON on stdin and reads the
// decision as JSON on stdout. No output means "no opinion".
let raw = '';
process.stdin.setEncoding('utf-8');
process.stdin.on('data', (chunk) => {
  raw += chunk;
});
process.stdin.on('end', async () => {
  const response = await preToolUseResponse(raw);
  if (response) process.stdout.write(JSON.stringify(response) + '\n');
});
