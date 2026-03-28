import type { ParsedIntent, OperationType } from '../types/index.js';

/**
 * Intent Parser — Layer 1
 *
 * Parses raw SQL into a structured intent object.
 * Identifies operation type, tables touched, presence of WHERE clause,
 * and classifies the operation as destructive or massive.
 *
 * Design principle: fails loud on ambiguous or unparseable input.
 */

// Regex patterns for operation detection
const PATTERNS: Record<OperationType, RegExp> = {
  SELECT: /^\s*SELECT\b/i,
  INSERT: /^\s*INSERT\s+INTO\b/i,
  UPDATE: /^\s*UPDATE\b/i,
  DELETE: /^\s*DELETE\s+FROM\b/i,
  TRUNCATE: /^\s*TRUNCATE\b/i,
  ALTER: /^\s*ALTER\b/i,
  DROP: /^\s*DROP\b/i,
  CREATE: /^\s*CREATE\b/i,
  UNKNOWN: /./,
};

const DESTRUCTIVE_TYPES: OperationType[] = ['DELETE', 'TRUNCATE', 'DROP', 'ALTER'];

function detectOperationType(sql: string): OperationType {
  for (const [type, pattern] of Object.entries(PATTERNS)) {
    if (type === 'UNKNOWN') continue;
    if (pattern.test(sql.trim())) return type as OperationType;
  }
  return 'UNKNOWN';
}

function extractTables(sql: string, type: OperationType): string[] {
  const tables: string[] = [];
  const normalized = sql.replace(/\s+/g, ' ').trim();

  switch (type) {
    case 'SELECT': {
      // FROM clause and JOINs
      const fromMatch = normalized.match(/\bFROM\s+([\w"`.[\]]+)/i);
      if (fromMatch) tables.push(cleanTableName(fromMatch[1]));
      const joinMatches = normalized.matchAll(/\bJOIN\s+([\w"`.[\]]+)/gi);
      for (const m of joinMatches) tables.push(cleanTableName(m[1]));
      break;
    }
    case 'INSERT': {
      const m = normalized.match(/INSERT\s+INTO\s+([\w"`.[\]]+)/i);
      if (m) tables.push(cleanTableName(m[1]));
      break;
    }
    case 'UPDATE': {
      const m = normalized.match(/UPDATE\s+([\w"`.[\]]+)/i);
      if (m) tables.push(cleanTableName(m[1]));
      break;
    }
    case 'DELETE': {
      const m = normalized.match(/DELETE\s+FROM\s+([\w"`.[\]]+)/i);
      if (m) tables.push(cleanTableName(m[1]));
      break;
    }
    case 'TRUNCATE': {
      const m = normalized.match(/TRUNCATE\s+(?:TABLE\s+)?([\w"`.[\]]+)/i);
      if (m) tables.push(cleanTableName(m[1]));
      break;
    }
    case 'ALTER':
    case 'DROP': {
      const m = normalized.match(/(?:ALTER|DROP)\s+(?:TABLE\s+)?([\w"`.[\]]+)/i);
      if (m) tables.push(cleanTableName(m[1]));
      break;
    }
  }

  return [...new Set(tables)];
}

function cleanTableName(name: string): string {
  return name.replace(/["`[\]]/g, '').toLowerCase();
}

function hasWhereClause(sql: string): boolean {
  return /\bWHERE\b/i.test(sql);
}

function detectMassive(sql: string, type: OperationType): boolean {
  // TRUNCATE is always massive, DELETE/UPDATE without WHERE is massive
  if (type === 'TRUNCATE') return true;
  if ((type === 'DELETE' || type === 'UPDATE') && !hasWhereClause(sql)) return true;
  // LIMIT clause hints at bounded operation
  if (/\bLIMIT\s+\d+\b/i.test(sql)) return false;
  return false;
}

export function parseIntent(sql: string): ParsedIntent {
  if (!sql || !sql.trim()) {
    throw new Error('Intent Parser: empty SQL provided');
  }

  const type = detectOperationType(sql);
  const tables = extractTables(sql, type);
  const whereClause = hasWhereClause(sql);
  const isDestructive = DESTRUCTIVE_TYPES.includes(type);
  const isMassive = detectMassive(sql, type);

  return {
    raw: sql.trim(),
    type,
    tables,
    hasWhereClause: whereClause,
    estimatedRowsAffected: null, // filled by sandbox layer
    isDestructive,
    isMassive,
    metadata: {
      parsedAt: new Date().toISOString(),
      normalizedLength: sql.trim().length,
    },
  };
}
