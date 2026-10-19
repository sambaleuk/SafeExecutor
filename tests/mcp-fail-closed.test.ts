import { safeExecute, safePolicyCheck } from '../src/mcp-server/tools.js';
import { extractSegments } from '../src/mcp-server/command-segments.js';

// ─── Bypass regressions: wrappers, chains and unknown commands ───────────────

describe('MCP analysis fails closed', () => {
  test.each([
    'sudo rm -rf /',
    'cd /tmp && rm -rf /',
    'bash -c "rm -rf /"',
    'psql -c "DROP TABLE users"',
    `python3 -c "import shutil; shutil.rmtree('/')"`,
    'env FOO=1 sudo -u root sh -c "git status; rm -rf /"',
    'sudo /bin/rm -rf /',
    'git status || rm -rf /',
    'git log | sh',
    'echo $(rm -rf /)',
  ])('%s → BLOCKED', async (command) => {
    const r = await safeExecute(command);
    expect(r.policy_decision).toBe('BLOCKED');
    expect((await safePolicyCheck(command)).allowed).toBe(false);
  });

  test('an unrecognized command is blocked, not allowed', async () => {
    const r = await safePolicyCheck('ls -la');
    expect(r.allowed).toBe(false);
    expect(r.domain).toBe('unknown');
  });

  test('the risk of a chain is the risk of its worst segment', async () => {
    const r = await safeExecute('cd /tmp && rm -rf /');
    expect(r.riskLevel).toBe('CRITICAL');
    expect(r.domain).toBe('filesystem');
    expect(r.segments.map((s) => s.command)).toEqual(['cd /tmp', 'rm -rf /']);
  });

  test('SQL passed to psql -c is analyzed as SQL', async () => {
    const r = await safeExecute('psql -h db -c "DROP TABLE users"');
    expect(r.domain).toBe('sql');
    expect(r.riskLevel).toBe('CRITICAL');
  });

  test('a domain override cannot downgrade the auto-detected verdict', async () => {
    const r = await safeExecute('rm -rf /', 'sql');
    expect(r.blocked).toBe(true);
    expect(r.domain).toBe('filesystem');
  });

  test('recognized low-risk commands are still allowed', async () => {
    expect((await safePolicyCheck('git status')).allowed).toBe(true);
    expect((await safePolicyCheck('git status && git log --oneline')).allowed).toBe(true);
    expect((await safePolicyCheck('SELECT id FROM users WHERE id = 1')).allowed).toBe(true);
  });
});

// ─── Segmentation ────────────────────────────────────────────────────────────

describe('extractSegments', () => {
  const commands = (input: string) => extractSegments(input).map((s) => s.command);

  test('splits on &&, ||, ;, |, & and newlines', () => {
    expect(commands('a && b || c; d | e & f\ng')).toEqual(['a', 'b', 'c', 'd', 'e', 'f', 'g']);
  });

  test('does not split inside quotes or on escaped separators', () => {
    expect(commands(`git commit -m "a && b; c"`)).toEqual([`git commit -m "a && b; c"`]);
    expect(commands(`echo 'x | y'`)).toEqual([`echo 'x | y'`]);
    expect(commands('find . -exec rm {} \\;')).toEqual(['find . -exec rm {} \\;']);
  });

  test('keeps redirections that use &', () => {
    expect(commands('kubectl get pods 2>&1')).toEqual(['kubectl get pods 2>&1']);
    expect(commands('git status &>/dev/null')).toEqual(['git status &>/dev/null']);
  });

  test('unwraps sudo (with options), env, assignments and path-qualified binaries', () => {
    expect(commands('sudo -u root -E rm -rf /var')).toEqual(['rm -rf /var']);
    expect(commands('env -i PATH=/bin FOO=bar rm -rf /var')).toEqual(['rm -rf /var']);
    expect(commands('FOO=1 BAR=2 rm -rf /var')).toEqual(['rm -rf /var']);
    expect(commands('nohup nice -n 10 /usr/bin/rm -rf /var')).toEqual(['rm -rf /var']);
  });

  test('expands shell -c scripts, including combined flags', () => {
    expect(commands(`bash -lc 'cd /tmp && rm -rf /'`)).toEqual(['cd /tmp', 'rm -rf /']);
    expect(commands(`sh -o errexit -c "git pull"`)).toEqual(['git pull']);
    expect(commands('env -S "rm -rf /"')).toEqual(['rm -rf /']);
  });

  test('extracts SQL from psql -c / --command and mysql -e / --execute', () => {
    expect(extractSegments('psql -c "DROP TABLE users"')).toEqual([{ command: 'DROP TABLE users', domain: 'sql' }]);
    expect(extractSegments('psql --command="TRUNCATE logs"')).toEqual([{ command: 'TRUNCATE logs', domain: 'sql' }]);
    expect(extractSegments(`mysql -e 'DELETE FROM users'`)).toEqual([{ command: 'DELETE FROM users', domain: 'sql' }]);
  });

  test('blocks command substitution', () => {
    for (const input of ['rm -rf $(pwd)', 'rm -rf `pwd`', 'diff <(ls a) <(ls b)', 'echo "$(id)"']) {
      expect(extractSegments(input)[0]?.blockedReason).toMatch(/Command substitution/);
    }
    // Single quotes make it literal text, not a substitution.
    expect(extractSegments(`git commit -m '$(not run)'`)[0]?.blockedReason).toBeUndefined();
  });

  test('blocks shell nesting beyond the analysis depth', () => {
    const nested = 'bash -c "bash -c \\"bash -c \\\\\\"bash -c \'bash -c ls\'\\\\\\"\\""';
    expect(extractSegments(nested).some((s) => s.blockedReason?.includes('analysis depth'))).toBe(true);
  });
});
