import express from 'express';
import { collectAll } from '@ocsec/agent';
import crypto from 'node:crypto';
import { openDb, insertRun, listRuns, getRun } from './db.js';
import { renderDashboard } from './render.js';

const app = express();
app.use(express.json({ limit: '1mb' }));

const db = openDb(process.env.OCSEC_DB);

app.get('/api/runs', (req, res) => {
  const limit = Math.min(200, Number(req.query.limit ?? 50));
  const rows = listRuns(db, limit);
  res.json({ runs: rows.map(r => ({ id: r.id, collectedAt: r.collectedAt })) });
});

app.get('/api/runs/:id', (req, res) => {
  const row = getRun(db, req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  res.json({ id: row.id, collectedAt: row.collectedAt, snapshot: JSON.parse(row.snapshotJson) });
});

app.post('/api/collect', async (_req, res) => {
  const snap = await collectAll();
  const id = crypto.randomUUID();
  insertRun(db, { id, collectedAt: snap.collectedAt, snapshot: snap });
  res.json({ id, collectedAt: snap.collectedAt });
});

app.get('/', async (_req, res) => {
  // If no runs, auto-collect once
  let runs = listRuns(db, 10);
  let id = runs[0]?.id;
  if (!id) {
    const snap = await collectAll();
    id = crypto.randomUUID();
    insertRun(db, { id, collectedAt: snap.collectedAt, snapshot: snap });
    runs = listRuns(db, 10);
  }
  const row = getRun(db, id!);
  const snap = JSON.parse(row!.snapshotJson);
  const recentRuns = runs.map(r => ({ id: r.id, collectedAt: r.collectedAt }));
  res.type('html').send(renderDashboard(id!, snap, recentRuns));
});

const port = Number(process.env.PORT ?? 7337);
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`ocsec server listening on http://localhost:${port}`);
});
