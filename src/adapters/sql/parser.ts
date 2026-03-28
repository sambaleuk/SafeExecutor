import type { SafeIntent, OperationType, RiskFactor, Target, Scope } from '../../types/index.js';

/**
 * SQL Intent Parser — AST-based
 *
 * Uses node-sql-parser to produce a full parse tree from the SQL string.
 * Extracts tables, detects WHERE clauses, joins, CTEs, and subqueries with
 * accuracy that regex cannot match.
 *
 * Falls back to the regex parser when node-sql-parser throws (exotic syntax,
 * PL/pgSQL extensions, etc.) and flags intent.metadata.parserFallback = true
 * so the policy engine can escalate risk if desired.
 */

const MASSIVE_ROW_THRESHOLD = 10_000;
const DESTRUCTIVE_TYPES: OperationType[] = ['DELETE', 'TRUNCATE', 'DROP', 'ALTER'];

// ─── AST-based parsing ───────────────────────────────────────────────────────

export async function parseIntent(sql: string): Promise<SafeIntent> {
  if (!sql?.trim()) {
    throw new Error('Intent Parser: empty SQL provided');
  }

  try {
    return await parseWithAST(sql.trim());
  } catch {
    // Fallback to regex for edge cases the AST parser can't handle
    return parseWithRegex(sql.trim(), true);
  }
}

async function parseWithAST(sql: string): Promise<SafeIntent> {
  const { Parser } = await import('node-sql-parser');
  const parser = new Parser();

  // astify returns AST | AST[] — normalize to array
  const rawAst = parser.astify(sql, { database: 'PostgreSQL' });
  const statements = (Array.isArray(rawAst) ? rawAst : [rawAst]) as unknown as Record<string, unknown>[];

  if (statements.length === 0 || !statements[0]) {
    throw new Error('Parser returned empty AST');
  }

  const primary = statements[0];

  const type = mapASTTypeToOperation(primary['type'] as string);
  const tables = extractAllTables(statements as Record<string, unknown>[]);
  const hasWhere = nodeHasWhereClause(primary);
  const hasCTE = hasCTEClause(primary);
  const hasSubquery = detectSubqueries(primary);
  const hasJoin = detectJoins(primary);
  const isParameterized = sql.includes('$1') || sql.includes('?');

  const isDestructive = DESTRUCTIVE_TYPES.includes(type);
  const isMassive = isMassiveOperation(type, hasWhere);

  const riskFactors = buildRiskFactors(type, hasWhere, isMassive, hasCTE, hasSubquery);

  const target: Target = {
    name: tables[0] ?? 'unknown',
    type: 'table',
    affectedResources: tables,
  };

  const scope: Scope = isMassive ? 'all' : tables.length > 1 ? 'batch' : 'single';

  return {
    domain: 'sql',
    type,
    raw: sql,
    target,
    scope,
    riskFactors,
    ast: {
      statements,
      hasCTE,
      hasSubquery,
      hasJoin,
      isParameterized,
      statementCount: statements.length,
    },
    tables,
    hasWhereClause: hasWhere,
    estimatedRowsAffected: null,
    isDestructive,
    isMassive,
    metadata: {
      parsedAt: new Date().toISOString(),
      parser: 'node-sql-parser',
      statementCount: statements.length,
    },
  };
}

// ─── AST traversal helpers ───────────────────────────────────────────────────

function mapASTTypeToOperation(astType: string): OperationType {
  const typeMap: Record<string, OperationType> = {
    select: 'SELECT',
    insert: 'INSERT',
    update: 'UPDATE',
    delete: 'DELETE',
    truncate: 'TRUNCATE',
    alter: 'ALTER',
    drop: 'DROP',
    create: 'CREATE',
  };
  return typeMap[(astType ?? '').toLowerCase()] ?? 'UNKNOWN';
}

/**
 * Extract all table names from an array of statement ASTs.
 * Handles FROM clauses, JOINs, CTEs, subqueries, and DDL target tables.
 */
function extractAllTables(statements: Record<string, unknown>[]): string[] {
  const tables = new Set<string>();

  for (const stmt of statements) {
    extractTablesFromStatement(stmt, tables);
  }

  return [...tables];
}

function extractTablesFromStatement(
  node: Record<string, unknown>,
  tables: Set<string>,
): void {
  if (!node || typeof node !== 'object') return;

  // WITH clause (CTEs) — recurse into each CTE body
  const withClause = node['with'];
  if (Array.isArray(withClause)) {
    for (const cte of withClause) {
      const cteNode = cte as Record<string, unknown>;
      const stmtNode = cteNode['stmt'] as Record<string, unknown> | undefined;
      if (stmtNode) {
        const innerAst = (stmtNode['ast'] ?? stmtNode) as Record<string, unknown>;
        extractTablesFromStatement(innerAst, tables);
      }
    }
  }

  // FROM clause (SELECT, DELETE with FROM, some dialects)
  const fromClause = node['from'];
  if (Array.isArray(fromClause)) {
    for (const item of fromClause) {
      const fromItem = item as Record<string, unknown>;
      const tableName = fromItem['table'];
      if (typeof tableName === 'string' && tableName) {
        tables.add(tableName.toLowerCase());
      }
      // Subquery in FROM: { expr: { ast: ... } }
      const exprNode = fromItem['expr'] as Record<string, unknown> | undefined;
      if (exprNode) {
        const innerAst = (exprNode['ast'] ?? exprNode) as Record<string, unknown>;
        if (innerAst && typeof innerAst === 'object') {
          const innerStatements = Array.isArray(innerAst) ? innerAst : [innerAst];
          for (const s of innerStatements) {
            extractTablesFromStatement(s as Record<string, unknown>, tables);
          }
        }
      }
    }
  }

  // table property (UPDATE, INSERT, TRUNCATE, CREATE, ALTER)
  const tableClause = node['table'];
  if (Array.isArray(tableClause)) {
    for (const t of tableClause) {
      const tableItem = t as Record<string, unknown>;
      if (typeof tableItem['table'] === 'string' && tableItem['table']) {
        tables.add((tableItem['table'] as string).toLowerCase());
      }
      if (typeof tableItem['name'] === 'string' && tableItem['name']) {
        tables.add((tableItem['name'] as string).toLowerCase());
      }
    }
  }

  // DROP TABLE uses a `name` array
  const nameClause = node['name'];
  if (Array.isArray(nameClause)) {
    for (const n of nameClause) {
      const nameItem = n as Record<string, unknown>;
      if (typeof nameItem['table'] === 'string' && nameItem['table']) {
        tables.add((nameItem['table'] as string).toLowerCase());
      }
    }
  }

  // Scalar `table` string (some AST nodes)
  if (typeof node['table'] === 'string' && node['table']) {
    tables.add((node['table'] as string).toLowerCase());
  }
}

function nodeHasWhereClause(node: Record<string, unknown>): boolean {
  return node['where'] !== null && node['where'] !== undefined;
}

function hasCTEClause(node: Record<string, unknown>): boolean {
  return Array.isArray(node['with']) && (node['with'] as unknown[]).length > 0;
}

function detectSubqueries(node: Record<string, unknown>): boolean {
  // Check FROM items for subquery expressions
  const fromClause = node['from'];
  if (Array.isArray(fromClause)) {
    for (const item of fromClause) {
      const fromItem = item as Record<string, unknown>;
      if (fromItem['expr'] && typeof fromItem['expr'] === 'object') {
        return true;
      }
    }
  }
  // Check WHERE for subqueries (rough heuristic: look for nested select in where)
  const whereClause = node['where'];
  if (whereClause && typeof whereClause === 'object') {
    if (JSON.stringify(whereClause).includes('"type":"select"')) {
      return true;
    }
  }
  return false;
}

function detectJoins(node: Record<string, unknown>): boolean {
  const fromClause = node['from'];
  if (!Array.isArray(fromClause)) return false;
  return fromClause.some((item) => {
    const fromItem = item as Record<string, unknown>;
    return typeof fromItem['join'] === 'string';
  });
}

// ─── Risk factors ────────────────────────────────────────────────────────────

function isMassiveOperation(type: OperationType, hasWhere: boolean): boolean {
  if (type === 'TRUNCATE') return true;
  if ((type === 'DELETE' || type === 'UPDATE') && !hasWhere) return true;
  return false;
}

function buildRiskFactors(
  type: OperationType,
  hasWhere: boolean,
  isMassive: boolean,
  hasCTE: boolean,
  hasSubquery: boolean,
): RiskFactor[] {
  const factors: RiskFactor[] = [];

  if (type === 'DELETE' && !hasWhere) {
    factors.push({
      code: 'NO_WHERE_CLAUSE',
      severity: 'CRITICAL',
      description: 'DELETE without WHERE clause — would affect all rows in the table',
    });
  }

  if (type === 'UPDATE' && !hasWhere) {
    factors.push({
      code: 'NO_WHERE_CLAUSE_UPDATE',
      severity: 'HIGH',
      description: 'UPDATE without WHERE clause — would modify all rows in the table',
    });
  }

  if (type === 'TRUNCATE') {
    factors.push({
      code: 'TRUNCATE_OP',
      severity: 'CRITICAL',
      description: 'TRUNCATE removes all rows immediately and bypasses row-level triggers',
    });
  }

  if (type === 'DROP') {
    factors.push({
      code: 'DROP_OP',
      severity: 'CRITICAL',
      description: 'DROP permanently removes the table, index, or sequence',
    });
  }

  if (type === 'ALTER') {
    factors.push({
      code: 'SCHEMA_CHANGE',
      severity: 'HIGH',
      description: 'ALTER modifies table schema — can cause table locks and data loss',
    });
  }

  if (isMassive) {
    factors.push({
      code: 'MASSIVE_OPERATION',
      severity: 'HIGH',
      description: `Operation is estimated to affect more than ${MASSIVE_ROW_THRESHOLD.toLocaleString()} rows`,
    });
  }

  if (hasCTE && ['DELETE', 'UPDATE', 'INSERT'].includes(type)) {
    factors.push({
      code: 'CTE_WITH_DML',
      severity: 'HIGH',
      description: 'CTE (WITH clause) combined with DML increases risk of unintended scope',
    });
  }

  if (hasSubquery && ['DELETE', 'UPDATE'].includes(type)) {
    factors.push({
      code: 'SUBQUERY_IN_DESTRUCTIVE',
      severity: 'HIGH',
      description: 'Subquery in DELETE/UPDATE makes the affected scope harder to predict statically',
    });
  }

  return factors;
}

// ─── Regex fallback parser ───────────────────────────────────────────────────

/**
 * Fallback regex parser — used when node-sql-parser cannot parse the input.
 * Less accurate than the AST parser but handles edge cases and exotic syntax.
 * Sets metadata.parserFallback = true to allow policy escalation.
 */
function parseWithRegex(sql: string, isFallback: boolean): SafeIntent {
  const type = detectOperationTypeRegex(sql);
  const tables = extractTablesRegex(sql, type);
  const hasWhere = /\bWHERE\b/i.test(sql);
  const isDestructive = DESTRUCTIVE_TYPES.includes(type);
  const isMassive = isMassiveOperation(type, hasWhere);
  const riskFactors = buildRiskFactors(type, hasWhere, isMassive, false, false);

  const target: Target = {
    name: tables[0] ?? 'unknown',
    type: 'table',
    affectedResources: tables,
  };

  return {
    domain: 'sql',
    type,
    raw: sql,
    target,
    scope: isMassive ? 'all' : tables.length > 1 ? 'batch' : 'single',
    riskFactors,
    ast: undefined,
    tables,
    hasWhereClause: hasWhere,
    estimatedRowsAffected: null,
    isDestructive,
    isMassive,
    metadata: {
      parsedAt: new Date().toISOString(),
      parser: 'regex-fallback',
      parserFallback: isFallback,
    },
  };
}

const REGEX_PATTERNS: Partial<Record<OperationType, RegExp>> = {
  SELECT: /^\s*SELECT\b/i,
  INSERT: /^\s*INSERT\s+INTO\b/i,
  UPDATE: /^\s*UPDATE\b/i,
  DELETE: /^\s*DELETE\s+FROM\b/i,
  TRUNCATE: /^\s*TRUNCATE\b/i,
  ALTER: /^\s*ALTER\b/i,
  DROP: /^\s*DROP\b/i,
  CREATE: /^\s*CREATE\b/i,
};

function detectOperationTypeRegex(sql: string): OperationType {
  for (const [type, pattern] of Object.entries(REGEX_PATTERNS)) {
    if (pattern?.test(sql.trim())) return type as OperationType;
  }
  return 'UNKNOWN';
}

function extractTablesRegex(sql: string, type: OperationType): string[] {
  const tables: string[] = [];
  const normalized = sql.replace(/\s+/g, ' ').trim();

  switch (type) {
    case 'SELECT': {
      const fromMatch = normalized.match(/\bFROM\s+([\w"`.[\]]+)/i);
      if (fromMatch?.[1]) tables.push(cleanName(fromMatch[1]));
      const joinMatches = normalized.matchAll(/\bJOIN\s+([\w"`.[\]]+)/gi);
      for (const m of joinMatches) {
        if (m[1]) tables.push(cleanName(m[1]));
      }
      break;
    }
    case 'INSERT': {
      const m = normalized.match(/INSERT\s+INTO\s+([\w"`.[\]]+)/i);
      if (m?.[1]) tables.push(cleanName(m[1]));
      break;
    }
    case 'UPDATE': {
      const m = normalized.match(/UPDATE\s+([\w"`.[\]]+)/i);
      if (m?.[1]) tables.push(cleanName(m[1]));
      break;
    }
    case 'DELETE': {
      const m = normalized.match(/DELETE\s+FROM\s+([\w"`.[\]]+)/i);
      if (m?.[1]) tables.push(cleanName(m[1]));
      break;
    }
    case 'TRUNCATE': {
      const m = normalized.match(/TRUNCATE\s+(?:TABLE\s+)?([\w"`.[\]]+)/i);
      if (m?.[1]) tables.push(cleanName(m[1]));
      break;
    }
    case 'ALTER':
    case 'DROP': {
      const m = normalized.match(/(?:ALTER|DROP)\s+(?:TABLE\s+)?([\w"`.[\]]+)/i);
      if (m?.[1]) tables.push(cleanName(m[1]));
      break;
    }
  }

  return [...new Set(tables)];
}

function cleanName(name: string): string {
  return name.replace(/["`[\]]/g, '').toLowerCase();
}
