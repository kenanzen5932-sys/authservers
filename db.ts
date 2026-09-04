import initSqlJs, { Database as SqlJsDatabase } from 'sql.js';

type SqlValue = string | number | Uint8Array | null;
type SqlRow = SqlValue[];
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.join(__dirname, 'auth.db');

let db: SqlJsDatabase;

function saveDb() {
  fs.writeFileSync(DB_PATH, db.export());
}

export async function initDb(): Promise<void> {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS tokens (
      id TEXT PRIMARY KEY,
      label TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      last_used_at INTEGER
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS usage_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_id TEXT NOT NULL,
      action TEXT NOT NULL,
      ip TEXT,
      timestamp INTEGER NOT NULL
    )
  `);

  saveDb();
}

export function insertToken(
  id: string, label: string, token_hash: string,
  created_at: number, expires_at: number
): void {
  db.run(
    'INSERT INTO tokens (id, label, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
    [id, label, token_hash, created_at, expires_at]
  );
  saveDb();
}

export function getTokenByHash(hash: string): Record<string, unknown> | undefined {
  const rows = db.exec(
    'SELECT * FROM tokens WHERE token_hash = ? AND revoked = 0',
    [hash]
  );
  if (rows.length === 0 || rows[0].values.length === 0) return undefined;
  return rowToObj(rows[0]);
}

export function getAllTokens(): Record<string, unknown>[] {
  const rows = db.exec(
    'SELECT id, label, created_at, expires_at, revoked, last_used_at FROM tokens ORDER BY created_at DESC'
  );
  if (rows.length === 0) return [];
  return rows[0].values.map((row: unknown[]) =>
    rowToObjFromValues(['id', 'label', 'created_at', 'expires_at', 'revoked', 'last_used_at'], row)
  );
}

export function getTokenById(id: string): Record<string, unknown> | undefined {
  const rows = db.exec(
    'SELECT * FROM tokens WHERE id = ?',
    [id]
  );
  if (rows.length === 0 || rows[0].values.length === 0) return undefined;
  return rowToObj(rows[0]);
}

export function revokeTokenById(id: string): void {
  db.run('UPDATE tokens SET revoked = 1 WHERE id = ?', [id]);
  saveDb();
}

export function deleteTokenById(id: string): void {
  db.run('DELETE FROM tokens WHERE id = ?', [id]);
  db.run('DELETE FROM usage_log WHERE token_id = ?', [id]);
  saveDb();
}

export function extendTokenById(expires_at: number, id: string): void {
  db.run('UPDATE tokens SET expires_at = ? WHERE id = ? AND revoked = 0', [expires_at, id]);
  saveDb();
}

export function updateLastUsed(timestamp: number, id: string): void {
  db.run('UPDATE tokens SET last_used_at = ? WHERE id = ?', [timestamp, id]);
  saveDb();
}

export function insertUsageLog(
  token_id: string, action: string, ip: string, timestamp: number
): void {
  db.run(
    'INSERT INTO usage_log (token_id, action, ip, timestamp) VALUES (?, ?, ?, ?)',
    [token_id, action, ip, timestamp]
  );
  saveDb();
}

export function getUsageLogs(limit = 200): Record<string, unknown>[] {
  const rows = db.exec(
    `SELECT usage_log.id, usage_log.token_id, usage_log.action, usage_log.ip, usage_log.timestamp, tokens.label
     FROM usage_log
     JOIN tokens ON usage_log.token_id = tokens.id
     ORDER BY usage_log.timestamp DESC LIMIT ?`,
    [limit]
  );
  if (rows.length === 0) return [];
  return rows[0].values.map((row: unknown[]) =>
    rowToObjFromValues(['id', 'token_id', 'action', 'ip', 'timestamp', 'label'], row)
  );
}

// SQL.js her sütunu typed array'e çeviriyor, row'ı objeye çevirelim
function rowToObj(result: { columns: string[]; values: unknown[][] }): Record<string, unknown> {
  const obj: Record<string, unknown> = {};
  for (let i = 0; i < result.columns.length; i++) {
    obj[result.columns[i]] = result.values[0][i];
  }
  return obj;
}

function rowToObjFromValues(columns: string[], values: unknown[]): Record<string, unknown> {
  const obj: Record<string, unknown> = {};
  for (let i = 0; i < columns.length; i++) {
    obj[columns[i]] = values[i];
  }
  return obj;
}