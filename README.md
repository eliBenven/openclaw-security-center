# openclaw-security-center

Security control plane for OpenClaw deployments.

## What it does
- **Posture dashboard**: OpenClaw security audit + host security signals in one place
- **Guided remediation**: generates a plan + executes only with explicit approvals
- **Continuous monitoring**: scheduled audits + alerts on regressions
- **Audit trail**: diffable history of findings and actions

## v1 Success criteria (definition of done)
### 1) One-command dashboard
- [ ] `npx ocsec dashboard` starts a local web UI
- [ ] UI shows: OpenClaw audit status, update status, listening ports, firewall state, disk encryption, auto-updates
- [ ] Works on **macOS + Ubuntu** (best-effort; unsupported signals degrade gracefully)

### 2) Safe remediation workflow
- [ ] `npx ocsec plan` outputs a numbered remediation plan with exact commands + rollback notes
- [ ] `npx ocsec apply` requires explicit confirmation per step
- [ ] Includes OpenClaw-only fix path: `openclaw security audit --fix`

### 3) Monitoring + alerts
- [ ] Can schedule weekly audit via OpenClaw cron (opt-in)
- [ ] Emits an alert when posture regresses (new open port / audit worsened / update available)

### 4) Audit history
- [ ] Stores run history locally (sqlite)
- [ ] Can export JSON reports and show diffs between runs

## Architecture (planned)
- `packages/agent` — collectors (OpenClaw + host signals)
- `packages/cli` — `ocsec` commands (plan/apply/dashboard)
- `packages/server` — local API + sqlite store
- `packages/web` — dashboard UI

## License
MIT
