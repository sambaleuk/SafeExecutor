/**
 * SafeExecutor MCP Server
 *
 * Exposes safe_execute, safe_analyze, and safe_policy_check as MCP tools.
 * Uses StdioServerTransport — launch via: node dist/bin/safe-executor-mcp.js
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { safeExecute, safeAnalyze, safePolicyCheck } from './tools.js';

const server = new Server(
  { name: 'safe-executor', version: '0.1.0' },
  { capabilities: { tools: {} } },
);

// ─── Tool Registry ────────────────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'safe_execute',
      description:
        'Parse a command, classify its risk, and apply SafeExecutor policy. Returns domain, riskLevel, operation, targets, policy_decision, and blocked status. Does NOT execute the command.',
      inputSchema: {
        type: 'object',
        properties: {
          command: {
            type: 'string',
            description: 'The command or query to evaluate',
          },
          domain: {
            type: 'string',
            enum: ['sql', 'git', 'kubernetes', 'cloud', 'cicd', 'secrets', 'network', 'queue', 'api', 'filesystem'],
            description: 'Optional domain override. Auto-detected if omitted.',
          },
        },
        required: ['command'],
      },
    },
    {
      name: 'safe_analyze',
      description:
        'Analyze a command for risk without any execution intent. Same output as safe_execute but explicitly marks the result as analysis-only.',
      inputSchema: {
        type: 'object',
        properties: {
          command: {
            type: 'string',
            description: 'The command or query to analyze',
          },
          domain: {
            type: 'string',
            enum: ['sql', 'git', 'kubernetes', 'cloud', 'cicd', 'secrets', 'network', 'queue', 'api', 'filesystem'],
            description: 'Optional domain override. Auto-detected if omitted.',
          },
        },
        required: ['command'],
      },
    },
    {
      name: 'safe_policy_check',
      description:
        'Quick policy check: returns allowed/blocked status, risk level, and reason for a given command.',
      inputSchema: {
        type: 'object',
        properties: {
          command: {
            type: 'string',
            description: 'The command to check against SafeExecutor policy',
          },
        },
        required: ['command'],
      },
    },
  ],
}));

// ─── Tool Dispatch ────────────────────────────────────────────────────────────

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result: unknown;

    if (name === 'safe_execute') {
      result = await safeExecute(
        args?.command as string,
        args?.domain as string | undefined,
      );
    } else if (name === 'safe_analyze') {
      result = await safeAnalyze(
        args?.command as string,
        args?.domain as string | undefined,
      );
    } else if (name === 'safe_policy_check') {
      result = await safePolicyCheck(args?.command as string);
    } else {
      throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    };
  } catch (err) {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            error: err instanceof Error ? err.message : String(err),
            tool: name,
          }),
        },
      ],
      isError: true,
    };
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

export async function startServer() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
