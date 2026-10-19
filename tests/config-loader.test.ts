import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { loadConfig, loadPolicy } from '../src/config/loader.js';

const ENV_VAR = 'SAFE_EXECUTOR_DATABASE_URL';
const originalEnv = process.env[ENV_VAR];

function restoreEnv(): void {
  if (originalEnv === undefined) delete process.env[ENV_VAR];
  else process.env[ENV_VAR] = originalEnv;
}

function writeConfig(connectionString: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safe-executor-config-'));
  const file = path.join(dir, 'config.json');
  const config = JSON.parse(fs.readFileSync('./config/example-config.json', 'utf-8'));
  config.database.connectionString = connectionString;
  fs.writeFileSync(file, JSON.stringify(config));
  return file;
}

afterEach(restoreEnv);

describe('loadConfig / loadPolicy — repeated loads', () => {
  test('the same config can be loaded more than once in a process', () => {
    process.env[ENV_VAR] = 'postgresql://localhost:5432/dev';
    expect(() => {
      loadConfig('./config/example-config.json');
      loadConfig('./config/example-config.json');
    }).not.toThrow();
  });

  test('the same policy can be loaded more than once in a process', () => {
    expect(() => {
      loadPolicy('./config/default-policy.json');
      loadPolicy('./config/default-policy.json');
    }).not.toThrow();
  });
});

describe('loadConfig — connection string from environment', () => {
  test('resolves a ${VAR} reference from process.env', () => {
    process.env[ENV_VAR] = 'postgresql://app@db.internal:5432/app';
    const config = loadConfig(writeConfig('${SAFE_EXECUTOR_DATABASE_URL}'));
    expect(config.database.connectionString).toBe('postgresql://app@db.internal:5432/app');
  });

  test('fails hard when the referenced variable is not set', () => {
    delete process.env[ENV_VAR];
    expect(() => loadConfig(writeConfig('${SAFE_EXECUTOR_DATABASE_URL}'))).toThrow(
      /SAFE_EXECUTOR_DATABASE_URL, which is not set/,
    );
  });

  test('keeps a literal connection string unchanged', () => {
    const config = loadConfig(writeConfig('postgresql://localhost:5432/dev'));
    expect(config.database.connectionString).toBe('postgresql://localhost:5432/dev');
  });

  test('tracked configs hold an env reference, not a credential', () => {
    for (const file of ['./config/example-config.json', './config/e2e-test.json']) {
      const raw = JSON.parse(fs.readFileSync(file, 'utf-8'));
      expect(raw.database.connectionString).toBe('${SAFE_EXECUTOR_DATABASE_URL}');
    }
  });
});
