# QUICKSTART

## Prereqs
- Node 20+
- OpenClaw installed and available on PATH (`openclaw status` works)

## Run the dashboard (local)
```bash
npm install
npm run build
npm run dashboard
```
Then open: http://localhost:7337

## Collect a snapshot (JSON)
```bash
npm run collect > snapshot.json
```

## Generate a remediation plan (no changes)
```bash
npm run plan
```

## Notes
- This project is **local-first** and does not send data anywhere.
- `apply` is intentionally gated until you explicitly enable it.
