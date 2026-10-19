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

const ENV_REFERENCE = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/;

/**
 * Resolves a `${VAR}` reference from process.env so credentials never have to
 * live in a config file. Literal values are returned unchanged; a reference to
 * an unset variable fails hard rather than connecting with an empty string.
 */
function resolveEnvReference(value: string, field: string): string {
  const match = ENV_REFERENCE.exec(value);
  if (!match) return value;

  const name = match[1] as string;
  const resolved = process.env[name];
  if (!resolved) {
    throw new Error(`Config field ${field} references environment variable ${name}, which is not set`);
  }
  return resolved;
}

export function loadConfig(configPath: string): SafeExecutorConfig {
  const config = loadJson<SafeExecutorConfig>(configPath);

  const validate = getValidator('config.schema.json');
  if (!validate(config)) {
    const errors = validate.errors?.map((e: ErrorObject) => `  ${e.instancePath} ${e.message}`).join('\n');
    throw new Error(`Invalid config at ${configPath}:\n${errors}`);
  }

  return {
    ...config,
    database: {
      ...config.database,
      connectionString: resolveEnvReference(config.database.connectionString, 'database.connectionString'),
    },
  };
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
