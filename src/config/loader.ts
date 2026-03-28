import * as fs from 'fs';
import * as path from 'path';
import AjvModule from 'ajv';
const Ajv = AjvModule.default ?? AjvModule;
import type { SafeExecutorConfig, Policy } from '../types/index.js';

/**
 * Config Loader
 *
 * Loads and validates SafeExecutorConfig and Policy from JSON files.
 * Uses AJV for strict JSON Schema validation — invalid configs fail hard.
 *
 * Pattern inherited from Modragor: config is source of truth,
 * never derived from runtime state.
 */

const ajv = new Ajv({ allErrors: true, strict: true });

function loadSchema(schemaPath: string): object {
  const resolved = path.resolve(schemaPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Schema not found: ${resolved}`);
  }
  return JSON.parse(fs.readFileSync(resolved, 'utf-8'));
}

function loadJson<T>(filePath: string): T {
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Config file not found: ${resolved}`);
  }
  return JSON.parse(fs.readFileSync(resolved, 'utf-8')) as T;
}

export function loadConfig(configPath: string): SafeExecutorConfig {
  const config = loadJson<SafeExecutorConfig>(configPath);

  const schemaDir = path.join(path.dirname(new URL(import.meta.url).pathname), '../../schemas');
  const schema = loadSchema(path.join(schemaDir, 'config.schema.json'));

  const validate = ajv.compile(schema);
  if (!validate(config)) {
    const errors = validate.errors?.map((e: { instancePath: string; message?: string }) => `  ${e.instancePath} ${e.message}`).join('\n');
    throw new Error(`Invalid config at ${configPath}:\n${errors}`);
  }

  return config;
}

export function loadPolicy(policyPath: string): Policy {
  const policy = loadJson<Policy>(policyPath);

  const schemaDir = path.join(path.dirname(new URL(import.meta.url).pathname), '../../schemas');
  const schema = loadSchema(path.join(schemaDir, 'policy.schema.json'));

  const validate = ajv.compile(schema);
  if (!validate(policy)) {
    const errors = validate.errors?.map((e: { instancePath: string; message?: string }) => `  ${e.instancePath} ${e.message}`).join('\n');
    throw new Error(`Invalid policy at ${policyPath}:\n${errors}`);
  }

  return policy;
}
