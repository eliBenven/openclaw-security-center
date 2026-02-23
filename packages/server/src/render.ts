import type { NormalizedSnapshot, ListeningPort } from '@ocsec/agent';

function badge(state: string | undefined) {
  const s = state ?? 'unknown';
  const color = s === 'on' ? '#16a34a' : s === 'off' ? '#dc2626' : s === 'ok' ? '#16a34a' : s === 'error' ? '#dc2626' : '#d97706';
  return `<span class="badge" style="background:${color}">${escapeHtml(s)}</span>`;
}

function escapeHtml(s: string) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** Compute risk score 0-100 (100 = perfect, lower = worse) */
function computeRiskScore(snap: NormalizedSnapshot): { score: number; deductions: Array<{ reason: string; points: number }> } {
  let score = 100;
  const deductions: Array<{ reason: string; points: number }> = [];

  if (snap.host.firewall?.state === 'off') {
    score -= 30;
    deductions.push({ reason: 'Host firewall is off', points: -30 });
  } else if (snap.host.firewall?.state === 'unknown') {
    score -= 15;
    deductions.push({ reason: 'Host firewall state unknown', points: -15 });
  }

  if (snap.host.diskEncryption?.state === 'off') {
    score -= 25;
    deductions.push({ reason: 'Disk encryption is off', points: -25 });
  } else if (snap.host.diskEncryption?.state === 'unknown') {
    score -= 10;
    deductions.push({ reason: 'Disk encryption state unknown', points: -10 });
  }

  if (snap.host.autoUpdates?.state === 'off') {
    score -= 15;
    deductions.push({ reason: 'Auto-updates are off', points: -15 });
  } else if (snap.host.autoUpdates?.state === 'unknown') {
    score -= 5;
    deductions.push({ reason: 'Auto-updates state unknown', points: -5 });
  }

  const tcpPorts = snap.host.listening?.tcp ?? [];
  if (tcpPorts.length > 5) {
    score -= 10;
    deductions.push({ reason: `${tcpPorts.length} listening ports (>5)`, points: -10 });
  }

  if (!snap.openclaw.securityAudit?.ok) {
    score -= 20;
    deductions.push({ reason: 'OpenClaw security audit has errors', points: -20 });
  }

  if (!snap.openclaw.updateStatus?.ok) {
    score -= 5;
    deductions.push({ reason: 'OpenClaw update status check failed', points: -5 });
  }

  return { score: Math.max(0, score), deductions };
}

function riskScoreColor(score: number): string {
  if (score >= 80) return '#16a34a';
  if (score >= 60) return '#d97706';
  if (score >= 40) return '#ea580c';
  return '#dc2626';
}

function riskScoreLabel(score: number): string {
  if (score >= 80) return 'Good';
  if (score >= 60) return 'Fair';
  if (score >= 40) return 'Poor';
  return 'Critical';
}

function renderPortsTable(ports: ListeningPort[]): string {
  if (ports.length === 0) {
    return '<p class="muted">No TCP listening ports detected.</p>';
  }
  let html = `<table>
    <thead><tr><th>Port</th><th>Process</th><th>PID</th></tr></thead>
    <tbody>`;
  for (const p of ports) {
    html += `<tr><td>${p.port}</td><td>${escapeHtml(p.process)}</td><td>${p.pid ?? 'N/A'}</td></tr>`;
  }
  html += '</tbody></table>';
  return html;
}

function renderRemediations(deductions: Array<{ reason: string; points: number }>): string {
  if (deductions.length === 0) {
    return '<p style="color:#16a34a;font-weight:600">All checks passed. No remediations needed.</p>';
  }
  // Sort by severity (most points deducted first)
  const sorted = [...deductions].sort((a, b) => a.points - b.points);
  let html = '<ol class="remediation-list">';
  for (const d of sorted) {
    const severity = d.points <= -25 ? 'high' : d.points <= -10 ? 'medium' : 'low';
    const sevColor = severity === 'high' ? '#dc2626' : severity === 'medium' ? '#d97706' : '#6b7280';
    html += `<li><span style="color:${sevColor};font-weight:600">[${severity}]</span> ${escapeHtml(d.reason)} <span class="muted">(${d.points} pts)</span></li>`;
  }
  html += '</ol>';
  return html;
}

type RunSummary = { id: string; collectedAt: string };

export function renderDashboard(runId: string, snap: NormalizedSnapshot, recentRuns?: RunSummary[]) {
  const host = snap.host;
  const oc = snap.openclaw;
  const { score, deductions } = computeRiskScore(snap);
  const scoreColor = riskScoreColor(score);
  const scoreLabel = riskScoreLabel(score);
  const tcpPorts = host.listening?.tcp ?? [];

  const auditOk = oc.securityAudit?.ok ? 'ok' : 'error';
  const updateOk = oc.updateStatus?.ok ? 'ok' : 'error';

  const runsHtml = (recentRuns && recentRuns.length > 0)
    ? recentRuns.map((r) =>
        `<tr>
          <td><a href="/api/runs/${escapeHtml(r.id)}" title="${escapeHtml(r.id)}">${escapeHtml(r.id.slice(0, 8))}...</a></td>
          <td>${escapeHtml(r.collectedAt)}</td>
          <td>${r.id === runId ? '<span class="badge" style="background:#2563eb">current</span>' : ''}</td>
        </tr>`
      ).join('')
    : '<tr><td colspan="3" class="muted">No previous runs</td></tr>';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OpenClaw Security Center</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0; padding: 24px 32px; color: #1e293b; background: #f8fafc;
      line-height: 1.6;
    }
    .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; flex-wrap: wrap; gap: 12px; }
    .header h1 { margin: 0; font-size: 24px; }
    .header-actions { display: flex; gap: 8px; align-items: center; }
    .btn {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 8px 16px; border-radius: 8px; border: 1px solid #e2e8f0;
      background: #fff; color: #334155; font-size: 13px; font-weight: 500;
      cursor: pointer; transition: all 0.15s;
    }
    .btn:hover { background: #f1f5f9; border-color: #cbd5e1; }
    .btn-primary { background: #2563eb; color: #fff; border-color: #2563eb; }
    .btn-primary:hover { background: #1d4ed8; }
    .grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 16px; }
    .card {
      border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px;
      background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    .card h2 { margin: 0 0 12px; font-size: 16px; color: #334155; }
    .badge {
      display: inline-block; padding: 2px 10px; border-radius: 999px;
      color: #fff; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.3px;
    }
    .score-ring {
      width: 120px; height: 120px; border-radius: 50%;
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      border: 6px solid ${scoreColor}; margin: 0 auto 12px;
    }
    .score-number { font-size: 36px; font-weight: 700; color: ${scoreColor}; line-height: 1; }
    .score-label { font-size: 13px; color: #64748b; margin-top: 2px; }
    .signal-row { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px solid #f1f5f9; }
    .signal-row:last-child { border-bottom: none; }
    .muted { color: #64748b; font-size: 13px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 8px 12px; background: #f8fafc; color: #64748b; font-weight: 600; border-bottom: 2px solid #e2e8f0; font-size: 12px; text-transform: uppercase; letter-spacing: 0.3px; }
    td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; }
    tr:hover td { background: #f8fafc; }
    pre { white-space: pre-wrap; word-break: break-word; background: #0f172a; color: #e2e8f0; padding: 14px; border-radius: 10px; font-size: 12px; line-height: 1.5; }
    a { color: #2563eb; text-decoration: none; }
    a:hover { text-decoration: underline; }
    details { margin-top: 12px; }
    summary { cursor: pointer; color: #64748b; font-size: 13px; font-weight: 500; }
    .remediation-list { padding-left: 20px; }
    .remediation-list li { margin-bottom: 6px; font-size: 14px; }
    .footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid #e2e8f0; }
    @media (max-width: 768px) {
      body { padding: 16px; }
      .grid { grid-template-columns: 1fr; }
      .card { grid-column: span 1 !important; }
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>OpenClaw Security Center</h1>
    <div class="header-actions">
      <span class="muted">Run: ${escapeHtml(runId.slice(0, 8))}... &middot; ${escapeHtml(snap.collectedAt)}</span>
      <button class="btn btn-primary" onclick="collectNow()" id="collectBtn">Collect Now</button>
      <button class="btn" onclick="location.reload()">Refresh</button>
    </div>
  </div>

  <div class="grid">
    <!-- Risk Score -->
    <div class="card" style="grid-column: span 3">
      <h2>Risk Score</h2>
      <div class="score-ring">
        <div class="score-number">${score}</div>
        <div class="score-label">${scoreLabel}</div>
      </div>
      <p class="muted" style="text-align:center;margin:0">out of 100 &middot; higher is better</p>
    </div>

    <!-- Top Remediations -->
    <div class="card" style="grid-column: span 9">
      <h2>Remediations</h2>
      ${renderRemediations(deductions)}
      <p class="muted" style="margin-top:12px">Run <code>ocsec plan</code> for detailed commands, or <code>ocsec apply</code> for guided remediation.</p>
    </div>

    <!-- OpenClaw -->
    <div class="card" style="grid-column: span 6">
      <h2>OpenClaw Status</h2>
      <div class="signal-row">
        <span>Security Audit</span>
        ${badge(auditOk)}
      </div>
      <div class="signal-row">
        <span>Update Status</span>
        ${badge(updateOk)}
      </div>
      <details>
        <summary>Raw outputs</summary>
        <h3 style="font-size:13px;margin:12px 0 4px">security audit</h3>
        <pre>${escapeHtml(JSON.stringify(oc.securityAudit, null, 2))}</pre>
        <h3 style="font-size:13px;margin:12px 0 4px">update status</h3>
        <pre>${escapeHtml(JSON.stringify(oc.updateStatus, null, 2))}</pre>
      </details>
    </div>

    <!-- Host Signals -->
    <div class="card" style="grid-column: span 6">
      <h2>Host Security</h2>
      <div style="margin-bottom:8px;font-size:14px">
        Platform: <b>${escapeHtml(host.os.platform)}</b> ${escapeHtml(host.os.release)} (${escapeHtml(host.os.arch)})
      </div>
      <div class="signal-row">
        <span>Firewall</span>
        ${badge(host.firewall?.state)}
      </div>
      <div class="signal-row">
        <span>Disk Encryption</span>
        ${badge(host.diskEncryption?.state)}
      </div>
      <div class="signal-row">
        <span>Auto-updates</span>
        ${badge(host.autoUpdates?.state)}
      </div>
      <div class="signal-row">
        <span>Backups</span>
        ${badge(host.backups?.state)}
      </div>
    </div>

    <!-- Listening Ports Table -->
    <div class="card" style="grid-column: span 6">
      <h2>Listening Ports (TCP)</h2>
      ${renderPortsTable(tcpPorts)}
      <details>
        <summary>Raw output</summary>
        <pre>${escapeHtml(host.listening?.raw ?? 'No data')}</pre>
      </details>
    </div>

    <!-- Recent Runs (Audit Trail) -->
    <div class="card" style="grid-column: span 6">
      <h2>Recent Runs</h2>
      <table>
        <thead><tr><th>Run ID</th><th>Collected At</th><th></th></tr></thead>
        <tbody>
          ${runsHtml}
        </tbody>
      </table>
    </div>

    <!-- Next Steps -->
    <div class="card" style="grid-column: span 12">
      <h2>Getting Started</h2>
      <ol style="font-size:14px;padding-left:20px">
        <li>Run <code>ocsec plan</code> to generate a numbered remediation plan (no changes).</li>
        <li>Run <code>ocsec apply</code> to execute the plan with per-step confirmations.</li>
        <li>Run <code>ocsec monitor --cron</code> to generate a cron entry for scheduled monitoring.</li>
        <li>Run <code>ocsec diff &lt;runA&gt; &lt;runB&gt;</code> to compare two snapshots.</li>
      </ol>
    </div>
  </div>

  <div class="footer">
    <p class="muted">Privacy: this dashboard is local-only. No data is sent externally. Only posture snapshots and command outputs are stored.</p>
  </div>

  <script>
    async function collectNow() {
      const btn = document.getElementById('collectBtn');
      btn.textContent = 'Collecting...';
      btn.disabled = true;
      try {
        const res = await fetch('/api/collect', { method: 'POST' });
        if (res.ok) {
          location.reload();
        } else {
          btn.textContent = 'Error';
          setTimeout(() => { btn.textContent = 'Collect Now'; btn.disabled = false; }, 2000);
        }
      } catch (e) {
        btn.textContent = 'Error';
        setTimeout(() => { btn.textContent = 'Collect Now'; btn.disabled = false; }, 2000);
      }
    }
  </script>
</body>
</html>`;
}
