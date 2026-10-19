/**
 * Shell command segmentation for the MCP analysis path.
 *
 * Agents rarely send a bare `rm -rf /`. They send `sudo rm -rf /`,
 * `cd /tmp && rm -rf /` or `bash -c "rm -rf /"`. Domain detection only looks
 * at the start of a command, so chains and wrappers are taken apart first and
 * every simple command they would run is returned as its own segment.
 *
 * Deliberately conservative: anything that cannot be reasoned about
 * statically (command substitution, nesting beyond MAX_DEPTH) comes back as a
 * segment carrying a blockedReason.
 */

export interface CommandSegment {
  /** Simple command to classify, with chains and wrappers removed */
  command: string;
  /** Domain implied by the unwrapping step (SQL passed to psql -c / mysql -e) */
  domain?: 'sql';
  /** Set when the segment cannot be analyzed and must be blocked */
  blockedReason?: string;
}

interface Token {
  value: string;
  start: number;
  end: number;
}

const MAX_DEPTH = 4;

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh']);
const PLAIN_PREFIXES = new Set(['nohup', 'time', 'exec']);
// sudo short options that take a value (-u root, -g wheel, ...)
const SUDO_VALUE_FLAGS = /^-[A-Za-z]*[ughpCDrtUT]$/;
// env options that take a value; -S/--split-string carries a whole command line
const ENV_VALUE_FLAGS = new Set(['-u', '-C', '-S', '--unset', '--chdir', '--split-string']);
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

export function extractSegments(command: string, depth = 0): CommandSegment[] {
  if (depth > MAX_DEPTH) {
    return [{ command, blockedReason: `Nested shell invocations exceed analysis depth (${MAX_DEPTH})` }];
  }

  const { parts, hasSubstitution } = splitOnOperators(command);
  if (hasSubstitution) {
    return [
      {
        command: command.trim(),
        blockedReason: 'Command substitution ($(...), backticks, <(...)) cannot be analyzed statically',
      },
    ];
  }

  return parts.flatMap((part) => unwrap(part, depth));
}

// ─── Chain splitting ─────────────────────────────────────────────────────────

/**
 * Splits on unquoted &&, ||, |, |&, ;, &, newlines and subshell parentheses.
 * `&` that belongs to a redirection (2>&1, &>file) is not a separator.
 */
function splitOnOperators(input: string): { parts: string[]; hasSubstitution: boolean } {
  const parts: string[] = [];
  let current = '';
  let quote: "'" | '"' | null = null;
  let hasSubstitution = false;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i] as string;
    const next = input[i + 1];

    if (quote === "'") {
      current += ch;
      if (ch === "'") quote = null;
      continue;
    }
    if (ch === '\\') {
      current += ch + (next ?? '');
      i++;
      continue;
    }
    if (ch === '`' || (ch === '$' && next === '(')) hasSubstitution = true;
    if (quote === '"') {
      current += ch;
      if (ch === '"') quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      current += ch;
      continue;
    }
    if ((ch === '<' || ch === '>') && next === '(') hasSubstitution = true;

    const isRedirection = ch === '&' && (/[<>]$/.test(current) || next === '>');
    if (ch === ';' || ch === '\n' || ch === '|' || ch === '(' || ch === ')' || (ch === '&' && !isRedirection)) {
      parts.push(current);
      current = '';
      if ((ch === '&' && next === '&') || (ch === '|' && (next === '|' || next === '&'))) i++;
      continue;
    }
    current += ch;
  }
  parts.push(current);

  return { parts: parts.map((p) => p.trim()).filter(Boolean), hasSubstitution };
}

// ─── Tokenizing ──────────────────────────────────────────────────────────────

/** Splits a simple command into words, resolving quotes and escapes. */
function tokenize(segment: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < segment.length) {
    while (i < segment.length && /\s/.test(segment[i] as string)) i++;
    if (i >= segment.length) break;

    const start = i;
    let value = '';
    while (i < segment.length && !/\s/.test(segment[i] as string)) {
      const ch = segment[i] as string;
      if (ch === "'") {
        const close = segment.indexOf("'", i + 1);
        const end = close === -1 ? segment.length : close;
        value += segment.slice(i + 1, end);
        i = end + 1;
      } else if (ch === '"') {
        i++;
        while (i < segment.length && segment[i] !== '"') {
          const c = segment[i] as string;
          const n = segment[i + 1];
          if (c === '\\' && n !== undefined && '$`"\\\n'.includes(n)) {
            value += n;
            i += 2;
          } else {
            value += c;
            i++;
          }
        }
        i++;
      } else if (ch === '\\' && i + 1 < segment.length) {
        value += segment[i + 1];
        i += 2;
      } else {
        value += ch;
        i++;
      }
    }
    tokens.push({ value, start, end: Math.min(i, segment.length) });
  }

  return tokens;
}

/** `/usr/bin/sudo` → `sudo`; words that are not paths (URLs, plain names) are kept. */
function basename(word: string): string {
  return /^(\/|\.\.?\/)/.test(word) ? word.slice(word.lastIndexOf('/') + 1) : word;
}

// ─── Unwrapping ──────────────────────────────────────────────────────────────

/**
 * Peels leading VAR=value assignments and transparent wrappers (sudo, doas,
 * env, nohup, time, exec, nice), then expands shell -c scripts and SQL passed
 * to psql -c / mysql -e.
 */
function unwrap(part: string, depth: number): CommandSegment[] {
  const tokens = tokenize(part);
  let k = 0;

  while (k < tokens.length) {
    const word = basename((tokens[k] as Token).value);

    if (ENV_ASSIGNMENT.test((tokens[k] as Token).value)) {
      k++;
    } else if (word === 'sudo' || word === 'doas') {
      k = skipOptions(tokens, k + 1, (flag) => SUDO_VALUE_FLAGS.test(flag));
    } else if (word === 'env') {
      const optionsEnd = skipOptions(tokens, k + 1, (flag) => ENV_VALUE_FLAGS.has(flag));
      const split = findOptionValue(tokens.slice(k + 1, optionsEnd), 0, ['-S'], ['--split-string']);
      if (split !== undefined) return extractSegments(split, depth + 1);
      k = optionsEnd;
    } else if (word === 'nice') {
      k = skipOptions(tokens, k + 1, (flag) => flag === '-n');
    } else if (PLAIN_PREFIXES.has(word)) {
      k = skipOptions(tokens, k + 1, () => false);
    } else {
      break;
    }
  }

  const head = tokens[k];
  if (!head) return [{ command: part }];

  const program = basename(head.value);
  const rest = tokens.slice(k + 1);

  if (SHELLS.has(program)) {
    const script = shellScript(rest);
    if (script !== undefined) return extractSegments(script, depth + 1);
  }

  if (program === 'psql' || program === 'mysql') {
    const sql =
      program === 'psql'
        ? findOptionValue(rest, 0, ['-c'], ['--command'])
        : findOptionValue(rest, 0, ['-e'], ['--execute']);
    if (sql !== undefined) return [{ command: sql.trim(), domain: 'sql' }];
  }

  return [{ command: program + part.slice(head.end) }];
}

/** Returns the index of the first non-option word, skipping option values. */
function skipOptions(tokens: Token[], from: number, takesValue: (flag: string) => boolean): number {
  let i = from;
  while (i < tokens.length) {
    const word = (tokens[i] as Token).value;
    if (word === '--') return i + 1;
    if (!word.startsWith('-') || word === '-') return i;
    i += takesValue(word) ? 2 : 1;
  }
  return i;
}

/** Finds `-x value`, `-xvalue`, `--long=value` or `--long value`. */
function findOptionValue(tokens: Token[], from: number, short: string[], long: string[]): string | undefined {
  for (let i = from; i < tokens.length; i++) {
    const word = (tokens[i] as Token).value;
    for (const flag of short) {
      if (word === flag) return tokens[i + 1]?.value;
      if (word.startsWith(flag) && !word.startsWith('--')) return word.slice(flag.length);
    }
    for (const flag of long) {
      if (word === flag) return tokens[i + 1]?.value;
      if (word.startsWith(`${flag}=`)) return word.slice(flag.length + 1);
    }
  }
  return undefined;
}

/** For `bash [-opts] -c 'script'`, returns the script; undefined otherwise. */
function shellScript(args: Token[]): string | undefined {
  let hasC = false;
  for (let i = 0; i < args.length; i++) {
    const word = (args[i] as Token).value;
    if (word === '-o' || word === '+o') {
      i++;
      continue;
    }
    if (/^--[A-Za-z-]+$/.test(word)) continue;
    if (/^-[A-Za-z]+$/.test(word)) {
      if (word.includes('c')) hasC = true;
      continue;
    }
    return hasC ? word : undefined;
  }
  return undefined;
}
