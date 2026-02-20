import type { NormalizedSnapshot } from '@ocsec/agent';

function badge(state: string | undefined) {
  const s = state ?? 'unknown';
  const color = s === 'on' ? '#0a0' : s === 'off' ? '#999' : '#c90';
  return `<span style="display:inline-block;padding:2px 8px;border-radius:999px;background:${color};color:#fff;font-weight:600;font-size:12px">${escapeHtml(s)}</span>`;
}

function escapeHtml(s: string) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function renderDashboard(runId: string, snap: NormalizedSnapshot) {
  const host = snap.host;
  const oc = snap.openclaw;

  const auditOk = oc.securityAudit?.ok ? 'ok' : 'error';
  const updateOk = oc.updateStatus?.ok ? 'ok' : 'error';

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OpenClaw Security Center</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 24px; color: #111; }
    .grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 16px; }
    .card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; background: #fff; }
    .muted { color: #6b7280; }
    pre { white-space: pre-wrap; word-break: break-word; background:#0b1020; color:#e5e7eb; padding:12px; border-radius: 10px; }
    a { color: #2563eb; }
  </style>
</head>
<body>
  <h1>OpenClaw Security Center</h1>
  <div class="muted">Run: ${escapeHtml(runId)} · Collected: ${escapeHtml(snap.collectedAt)}</div>

  <div class="grid" style="margin-top:16px">
    <div class="card" style="grid-column: span 6">
      <h2>OpenClaw</h2>
      <div>Security audit: ${badge(auditOk)}</div>
      <div>Update status: ${badge(updateOk)}</div>
      <details style="margin-top:12px">
        <summary>Raw outputs</summary>
        <h3>security audit</h3>
        <pre>${escapeHtml(JSON.stringify(oc.securityAudit, null, 2))}</pre>
        <h3>update status</h3>
        <pre>${escapeHtml(JSON.stringify(oc.updateStatus, null, 2))}</pre>
      </details>
    </div>

    <div class="card" style="grid-column: span 6">
      <h2>Host</h2>
      <div>Platform: <b>${escapeHtml(host.os.platform)}</b> ${escapeHtml(host.os.release)} (${escapeHtml(host.os.arch)})</div>
      <div style="margin-top:8px">Firewall: ${badge(host.firewall?.state)}</div>
      <div>Disk encryption: ${badge(host.diskEncryption?.state)}</div>
      <div>Auto-updates: ${badge(host.autoUpdates?.state)}</div>
      <div>Backups: ${badge(host.backups?.state)}</div>
      <details style="margin-top:12px">
        <summary>Listening ports (raw)</summary>
        <pre>${escapeHtml(host.listening?.raw ?? '')}</pre>
      </details>
    </div>

    <div class="card" style="grid-column: span 12">
      <h2>Next steps</h2>
      <ol>
        <li>Run <code>ocsec plan</code> to generate a numbered remediation plan (no changes).</li>
        <li>Run <code>ocsec apply</code> to execute the plan with per-step confirmations.</li>
        <li>Optionally schedule monitoring via OpenClaw cron (generated command).</li>
      </ol>
    </div>
  </div>

  <p class="muted" style="margin-top:24px">Privacy note: this is local-only. Secrets are never displayed; tool stores only posture snapshots and command outputs.</p>
</body>
</html>`;
}
