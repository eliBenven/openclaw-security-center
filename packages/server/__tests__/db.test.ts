import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { openDb, insertRun, getRun, listRuns } from '../src/db.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import type Database from 'better-sqlite3';

let tmpDir: string;
let db: Database.Database;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ocsec-test-'));
});

afterEach(() => {
  if (db) {
    try { db.close(); } catch { /* ignore */ }
  }
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('openDb', () => {
  it('creates the database file', () => {
    const dbPath = path.join(tmpDir, 'test.sqlite');
    db = openDb(dbPath);
    expect(fs.existsSync(dbPath)).toBe(true);
  });

  it('creates the runs table', () => {
    const dbPath = path.join(tmpDir, 'test.sqlite');
    db = openDb(dbPath);
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='runs'").all();
    expect(tables).toHaveLength(1);
  });

  it('creates nested directories if needed', () => {
    const dbPath = path.join(tmpDir, 'nested', 'deep', 'test.sqlite');
    db = openDb(dbPath);
    expect(fs.existsSync(dbPath)).toBe(true);
  });
});

describe('insertRun + getRun roundtrip', () => {
  it('stores and retrieves a run', () => {
    const dbPath = path.join(tmpDir, 'test.sqlite');
    db = openDb(dbPath);

    const snapshot = { collectedAt: '2025-01-15T10:00:00Z', host: { os: { platform: 'darwin' } } };
    insertRun(db, { id: 'run-001', collectedAt: '2025-01-15T10:00:00Z', snapshot });

    const row = getRun(db, 'run-001');
    expect(row).toBeDefined();
    expect(row!.id).toBe('run-001');
    expect(row!.collectedAt).toBe('2025-01-15T10:00:00Z');
    expect(JSON.parse(row!.snapshotJson)).toEqual(snapshot);
  });

  it('stores multiple runs and retrieves each', () => {
    const dbPath = path.join(tmpDir, 'test.sqlite');
    db = openDb(dbPath);

    insertRun(db, { id: 'a', collectedAt: '2025-01-01T00:00:00Z', snapshot: { a: 1 } });
    insertRun(db, { id: 'b', collectedAt: '2025-01-02T00:00:00Z', snapshot: { b: 2 } });

    expect(getRun(db, 'a')!.id).toBe('a');
    expect(getRun(db, 'b')!.id).toBe('b');
    expect(JSON.parse(getRun(db, 'a')!.snapshotJson)).toEqual({ a: 1 });
    expect(JSON.parse(getRun(db, 'b')!.snapshotJson)).toEqual({ b: 2 });
  });
});

describe('listRuns', () => {
  it('returns runs ordered by collectedAt DESC', () => {
    const dbPath = path.join(tmpDir, 'test.sqlite');
    db = openDb(dbPath);

    insertRun(db, { id: 'old', collectedAt: '2025-01-01T00:00:00Z', snapshot: {} });
    insertRun(db, { id: 'new', collectedAt: '2025-01-10T00:00:00Z', snapshot: {} });
    insertRun(db, { id: 'mid', collectedAt: '2025-01-05T00:00:00Z', snapshot: {} });

    const runs = listRuns(db);
    expect(runs[0].id).toBe('new');
    expect(runs[1].id).toBe('mid');
    expect(runs[2].id).toBe('old');
  });

  it('respects the limit parameter', () => {
    const dbPath = path.join(tmpDir, 'test.sqlite');
    db = openDb(dbPath);

    for (let i = 0; i < 10; i++) {
      insertRun(db, {
        id: `run-${i}`,
        collectedAt: `2025-01-${String(i + 1).padStart(2, '0')}T00:00:00Z`,
        snapshot: {}
      });
    }

    const runs = listRuns(db, 3);
    expect(runs).toHaveLength(3);
    // Most recent first
    expect(runs[0].id).toBe('run-9');
  });

  it('returns empty array when no runs exist', () => {
    const dbPath = path.join(tmpDir, 'test.sqlite');
    db = openDb(dbPath);
    expect(listRuns(db)).toEqual([]);
  });
});

describe('getRun with nonexistent ID', () => {
  it('returns undefined', () => {
    const dbPath = path.join(tmpDir, 'test.sqlite');
    db = openDb(dbPath);
    expect(getRun(db, 'does-not-exist')).toBeUndefined();
  });
});
