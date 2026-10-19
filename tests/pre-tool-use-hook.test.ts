import { preToolUseResponse } from '../src/hooks/pre-tool-use.js';

const bash = (command: unknown) => JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } });

async function decision(raw: string) {
  return (await preToolUseResponse(raw))?.hookSpecificOutput.permissionDecision ?? 'defer';
}

describe('PreToolUse hook', () => {
  test.each([
    'rm -rf /',
    'sudo rm -rf /',
    'cd /tmp && rm -rf /',
    'bash -c "rm -rf /"',
    'psql -c "DROP TABLE users"',
    'git push --force origin main',
  ])('CRITICAL → deny: %s', async (command) => {
    expect(await decision(bash(command))).toBe('deny');
  });

  test.each([
    `python3 -c "import shutil; shutil.rmtree('/')"`,
    'ls -la',
    'echo $(whoami)',
  ])('unrecognized or unanalyzable → ask: %s', async (command) => {
    expect(await decision(bash(command))).toBe('ask');
  });

  test('allowed commands defer to the normal permission flow (never "allow")', async () => {
    expect(await preToolUseResponse(bash('git status'))).toBeNull();
    expect(await preToolUseResponse(bash('git status && git log --oneline'))).toBeNull();
  });

  test('SQL-looking text is still parsed as a shell command line', async () => {
    // In a shell, `||` runs the right-hand side when the left fails.
    expect(await decision(bash("SELECT 'a' || rm -rf /"))).toBe('deny');
  });

  test('the reason names the offending segment', async () => {
    const out = await preToolUseResponse(bash('cd /tmp && rm -rf /'));
    expect(out?.hookSpecificOutput.permissionDecisionReason).toMatch(/`rm -rf \/` \(filesystem, CRITICAL\)/);
  });

  test('a segment without a parser reason does not print "null"', async () => {
    const out = await preToolUseResponse(bash('rm -rf /tmp/build'));
    expect(out?.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(out?.hookSpecificOutput.permissionDecisionReason).not.toMatch(/null/);
  });

  test('other tools are ignored', async () => {
    expect(await preToolUseResponse(JSON.stringify({ tool_name: 'Read', tool_input: { file_path: '/etc/passwd' } }))).toBeNull();
  });

  test('malformed input fails closed', async () => {
    expect(await decision('not json')).toBe('deny');
    expect(await decision(bash(42))).toBe('deny');
  });
});
