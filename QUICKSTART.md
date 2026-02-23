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

## Apply remediation (interactive)
```bash
npm run apply
```
Each step requires explicit confirmation. You can skip individual steps or abort entirely.

## Compare two runs
```bash
# Using run IDs (from the dashboard or /api/runs)
ocsec diff <runIdA> <runIdB>

# Using file paths
ocsec diff snapshot1.json snapshot2.json
```

## Set up monitoring
```bash
# Check for regressions (compares latest two stored runs)
ocsec monitor

# Get a sample cron entry for weekly checks
ocsec monitor --cron

# Machine-readable alert output
ocsec monitor --json
```

## Notes
- This project is **local-first** and does not send data anywhere.
- `apply` prompts for confirmation before every step. Nothing runs without your explicit approval.
- Run history is stored in SQLite at `~/.openclaw-security-center/ocsec.sqlite`.
