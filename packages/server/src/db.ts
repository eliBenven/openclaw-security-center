import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export type RunRow = {
  id: string;
  collectedAt: string;
  snapshotJson: string;
};

export function openDb(dbPath?: string) {
  const p = dbPath ?? path.join(os.homedir(), '.openclaw-security-center', 'ocsec.sqlite');
  const dir = path.dirname(p);
  fs.mkdirSync(dir, { recursive: true });
  const db = new Database(p);

  db.exec(`
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS runs (
      id TEXT PRIMARY KEY,
      collectedAt TEXT NOT NULL,
      snapshotJson TEXT NOT NULL
    );
  `);

  return db;
}

export function insertRun(db: Database.Database, run: { id: string; collectedAt: string; snapshot: unknown }) {
  const stmt = db.prepare('INSERT INTO runs (id, collectedAt, snapshotJson) VALUES (?, ?, ?)');
  stmt.run(run.id, run.collectedAt, JSON.stringify(run.snapshot));
}

export function listRuns(db: Database.Database, limit = 50): RunRow[] {
  const stmt = db.prepare('SELECT id, collectedAt, snapshotJson FROM runs ORDER BY collectedAt DESC LIMIT ?');
  return stmt.all(limit) as RunRow[];
}

export function getRun(db: Database.Database, id: string): RunRow | undefined {
  const stmt = db.prepare('SELECT id, collectedAt, snapshotJson FROM runs WHERE id = ?');
  return stmt.get(id) as RunRow | undefined;
}
