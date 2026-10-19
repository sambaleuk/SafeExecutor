import * as fs from 'fs';
import * as path from 'path';
import { Ajv } from 'ajv';
import type { ErrorObject, ValidateFunction } from 'ajv';
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

const ajv = new Ajv({ allErrors: true, strict: false });

// AJV registers each schema under its $id, so compiling the same schema twice
// throws. Validators are compiled once per schema file and reused.
const validators = new Map<string, ValidateFunction>();

function loadSchema(schemaPath: string): object {
  const resolved = path.resolve(schemaPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Schema not found: ${resolved}`);
  }
  return JSON.parse(fs.readFileSync(resolved, 'utf-8'));
}

function getValidator(schemaFile: string): ValidateFunction {
  const cached = validators.get(schemaFile);
  if (cached) return cached;

  const schemaDir = path.join(path.dirname(new URL(import.meta.url).pathname), '../../schemas');
  const validate = ajv.compile(loadSchema(path.join(schemaDir, schemaFile)));
  validators.set(schemaFile, validate);
  return validate;
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

  const validate = getValidator('config.schema.json');
  if (!validate(config)) {
    const errors = validate.errors?.map((e: ErrorObject) => `  ${e.instancePath} ${e.message}`).join('\n');
    throw new Error(`Invalid config at ${configPath}:\n${errors}`);
  }

  return config;
}

export function loadPolicy(policyPath: string): Policy {
  const policy = loadJson<Policy>(policyPath);

  const validate = getValidator('policy.schema.json');
  if (!validate(policy)) {
    const errors = validate.errors?.map((e: ErrorObject) => `  ${e.instancePath} ${e.message}`).join('\n');
    throw new Error(`Invalid policy at ${policyPath}:\n${errors}`);
  }

  return policy;
}
