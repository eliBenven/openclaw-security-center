# openclaw-security-center

Security control plane for OpenClaw deployments.

## What it does
- **Posture dashboard**: OpenClaw security audit + host security signals with risk scoring in one place
- **Guided remediation**: generates a plan + executes only with explicit per-step approvals
- **Continuous monitoring**: scheduled audits + alerts on regressions (firewall, encryption, new ports, audit status)
- **Audit trail**: diffable history of findings and actions stored in local SQLite

## v1 Success criteria (definition of done)
### 1) One-command dashboard
- [x] `npx ocsec dashboard` starts a local web UI
- [x] UI shows: OpenClaw audit status, update status, listening ports (parsed table), firewall state, disk encryption, auto-updates
- [x] Risk score (0-100) with deduction breakdown and remediation list
- [x] Recent runs list (audit trail) and "Collect Now" button
- [x] Works on **macOS + Ubuntu** (best-effort; unsupported signals degrade gracefully)

### 2) Safe remediation workflow
- [x] `npx ocsec plan` outputs a numbered remediation plan with exact commands + rollback notes
- [x] `npx ocsec apply` requires explicit confirmation per step (interactive readline loop)
- [x] Includes rollback tracking and skip/abort support
- [x] Includes OpenClaw-only fix path: `openclaw security audit --fix`

### 3) Monitoring + alerts
- [x] `npx ocsec monitor --cron` generates a cron entry for scheduling weekly audits
- [x] `npx ocsec monitor` compares latest two runs and flags regressions (firewall, encryption, auto-updates, new ports, audit errors)
- [x] `npx ocsec monitor --json` emits structured alert JSON for automation

### 4) Audit history
- [x] Stores run history locally (SQLite with WAL mode)
- [x] `npx ocsec diff <runA> <runB>` shows colored diffs between runs (supports run IDs from DB and file paths)
- [x] Can export JSON reports via `npx ocsec collect > snapshot.json`

## Architecture
- `packages/agent` -- collectors (OpenClaw + host signals), structured port parsing
- `packages/cli` -- `ocsec` commands (collect, plan, apply, dashboard, diff, monitor)
- `packages/server` -- local Express API + SQLite store + HTML dashboard renderer
- `packages/web` -- dashboard UI (reserved for future React/SPA migration)

## Quick start
```bash
npm install
npm run build
npm run dashboard        # starts server + opens browser at http://localhost:7337
```

## CLI commands
```bash
ocsec collect            # collect snapshot and print JSON
ocsec dashboard          # start local dashboard server
ocsec plan               # generate remediation plan (no changes)
ocsec apply              # apply plan with interactive confirmation per step
ocsec diff <a> <b>       # diff two snapshots (run IDs or file paths)
ocsec monitor            # compare latest two runs, flag regressions
ocsec monitor --cron     # print a sample cron entry
ocsec monitor --json     # output alert as JSON
```

## License
MIT
