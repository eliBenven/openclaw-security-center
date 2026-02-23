import { describe, it, expect } from 'vitest';
import { computeRiskScore, badge, renderDashboard } from '../src/render.js';
import type { NormalizedSnapshot } from '@ocsec/agent';

function makeSnapshot(overrides: Partial<NormalizedSnapshot> = {}): NormalizedSnapshot {
  return {
    collectedAt: '2025-01-15T12:00:00Z',
    openclaw: {
      securityAudit: { ok: true, value: {} },
      updateStatus: { ok: true, value: 'up to date' },
      statusDeep: { ok: true, value: 'all good' },
    },
    host: {
      os: { platform: 'darwin', release: '24.0.0', arch: 'arm64' },
      firewall: { state: 'on' },
      diskEncryption: { state: 'on' },
      autoUpdates: { state: 'on' },
      backups: { state: 'on' },
      listening: { tcp: [] },
    },
    ...overrides,
  };
}

describe('computeRiskScore', () => {
  it('returns 100 when everything is good', () => {
    const snap = makeSnapshot();
    const { score, deductions } = computeRiskScore(snap);
    expect(score).toBe(100);
    expect(deductions).toHaveLength(0);
  });

  it('deducts 30 for firewall off', () => {
    const snap = makeSnapshot({
      host: {
        ...makeSnapshot().host,
        firewall: { state: 'off' },
      },
    });
    const { score, deductions } = computeRiskScore(snap);
    expect(score).toBe(70);
    expect(deductions).toContainEqual(expect.objectContaining({ reason: 'Host firewall is off', points: -30 }));
  });

  it('deducts 15 for firewall unknown', () => {
    const snap = makeSnapshot({
      host: {
        ...makeSnapshot().host,
        firewall: { state: 'unknown' },
      },
    });
    const { score } = computeRiskScore(snap);
    expect(score).toBe(85);
  });

  it('deducts 25 for disk encryption off', () => {
    const snap = makeSnapshot({
      host: {
        ...makeSnapshot().host,
        diskEncryption: { state: 'off' },
      },
    });
    const { score } = computeRiskScore(snap);
    expect(score).toBe(75);
  });

  it('deducts 15 for auto-updates off', () => {
    const snap = makeSnapshot({
      host: {
        ...makeSnapshot().host,
        autoUpdates: { state: 'off' },
      },
    });
    const { score } = computeRiskScore(snap);
    expect(score).toBe(85);
  });

  it('deducts 10 for more than 5 listening ports', () => {
    const ports = Array.from({ length: 6 }, (_, i) => ({ port: 3000 + i, pid: 100 + i, process: `proc${i}` }));
    const snap = makeSnapshot({
      host: {
        ...makeSnapshot().host,
        listening: { tcp: ports },
      },
    });
    const { score } = computeRiskScore(snap);
    expect(score).toBe(90);
  });

  it('deducts 20 for failed openclaw security audit', () => {
    const snap = makeSnapshot({
      openclaw: {
        securityAudit: { ok: false, error: 'audit failed' },
        updateStatus: { ok: true, value: 'ok' },
      },
    });
    const { score } = computeRiskScore(snap);
    expect(score).toBe(80);
  });

  it('deducts 5 for failed openclaw update status', () => {
    const snap = makeSnapshot({
      openclaw: {
        securityAudit: { ok: true, value: {} },
        updateStatus: { ok: false, error: 'failed' },
      },
    });
    const { score } = computeRiskScore(snap);
    expect(score).toBe(95);
  });

  it('all bad returns a very low score (clamped to 0)', () => {
    const ports = Array.from({ length: 10 }, (_, i) => ({ port: 3000 + i, pid: 100 + i, process: `proc${i}` }));
    const snap: NormalizedSnapshot = {
      collectedAt: '2025-01-15T12:00:00Z',
      openclaw: {
        securityAudit: { ok: false, error: 'fail' },
        updateStatus: { ok: false, error: 'fail' },
      },
      host: {
        os: { platform: 'linux', release: '6.0', arch: 'x86_64' },
        firewall: { state: 'off' },
        diskEncryption: { state: 'off' },
        autoUpdates: { state: 'off' },
        listening: { tcp: ports },
      },
    };
    const { score } = computeRiskScore(snap);
    // 100 - 30 - 25 - 15 - 10 - 20 - 5 = -5, clamped to 0
    expect(score).toBe(0);
  });
});

describe('badge', () => {
  it('returns green badge for "on"', () => {
    const html = badge('on');
    expect(html).toContain('#16a34a');
    expect(html).toContain('on');
  });

  it('returns red badge for "off"', () => {
    const html = badge('off');
    expect(html).toContain('#dc2626');
    expect(html).toContain('off');
  });

  it('returns yellow/amber badge for "unknown"', () => {
    const html = badge('unknown');
    expect(html).toContain('#d97706');
    expect(html).toContain('unknown');
  });

  it('returns yellow/amber badge for undefined', () => {
    const html = badge(undefined);
    expect(html).toContain('#d97706');
    expect(html).toContain('unknown');
  });

  it('returns green badge for "ok"', () => {
    const html = badge('ok');
    expect(html).toContain('#16a34a');
    expect(html).toContain('ok');
  });

  it('returns red badge for "error"', () => {
    const html = badge('error');
    expect(html).toContain('#dc2626');
    expect(html).toContain('error');
  });
});

describe('renderDashboard', () => {
  it('returns valid HTML with doctype', () => {
    const snap = makeSnapshot();
    const html = renderDashboard('run-123', snap);
    expect(html).toContain('<!doctype html>');
    expect(html).toContain('</html>');
  });

  it('contains the title', () => {
    const snap = makeSnapshot();
    const html = renderDashboard('run-123', snap);
    expect(html).toContain('<title>OpenClaw Security Center</title>');
  });

  it('contains risk score section', () => {
    const snap = makeSnapshot();
    const html = renderDashboard('run-123', snap);
    expect(html).toContain('Risk Score');
    expect(html).toContain('100');
  });

  it('contains host security section', () => {
    const snap = makeSnapshot();
    const html = renderDashboard('run-123', snap);
    expect(html).toContain('Host Security');
    expect(html).toContain('Firewall');
    expect(html).toContain('Disk Encryption');
    expect(html).toContain('Auto-updates');
  });

  it('contains OpenClaw status section', () => {
    const snap = makeSnapshot();
    const html = renderDashboard('run-123', snap);
    expect(html).toContain('OpenClaw Status');
    expect(html).toContain('Security Audit');
    expect(html).toContain('Update Status');
  });

  it('contains listening ports section', () => {
    const snap = makeSnapshot();
    const html = renderDashboard('run-123', snap);
    expect(html).toContain('Listening Ports');
  });

  it('contains remediations section', () => {
    const snap = makeSnapshot();
    const html = renderDashboard('run-123', snap);
    expect(html).toContain('Remediations');
  });

  it('includes recent runs when provided', () => {
    const snap = makeSnapshot();
    const recentRuns = [
      { id: 'run-123', collectedAt: '2025-01-15T12:00:00Z' },
      { id: 'run-456', collectedAt: '2025-01-14T12:00:00Z' },
    ];
    const html = renderDashboard('run-123', snap, recentRuns);
    expect(html).toContain('Recent Runs');
    expect(html).toContain('run-456');
  });

  it('escapes HTML in run IDs', () => {
    const snap = makeSnapshot();
    const html = renderDashboard('<script>alert(1)</script>', snap);
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
  });
});
