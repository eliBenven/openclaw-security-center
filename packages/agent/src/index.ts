import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';

const execFileAsync = promisify(execFile);

export type CollectorResult<T> = {
  ok: boolean;
  value?: T;
  error?: string;
  meta?: Record<string, unknown>;
};

export type OpenClawAudit = unknown;

export type HostSignals = {
  os: { platform: string; release: string; arch: string };
  listening?: { tcp?: string[]; raw?: string };
  firewall?: { state?: 'on' | 'off' | 'unknown'; raw?: string };
  diskEncryption?: { state?: 'on' | 'off' | 'unknown'; raw?: string };
  autoUpdates?: { state?: 'on' | 'off' | 'unknown'; raw?: string };
  backups?: { state?: 'on' | 'off' | 'unknown'; raw?: string };
};

export type NormalizedSnapshot = {
  collectedAt: string;
  openclaw: {
    securityAudit?: CollectorResult<OpenClawAudit>;
    updateStatus?: CollectorResult<string>;
    statusDeep?: CollectorResult<string>;
  };
  host: HostSignals;
};

async function run(cmd: string, args: string[], timeoutMs = 30_000): Promise<CollectorResult<string>> {
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, { timeout: timeoutMs });
    const out = `${stdout ?? ''}`.trim();
    const err = `${stderr ?? ''}`.trim();
    const merged = [out, err].filter(Boolean).join('\n');
    return { ok: true, value: merged };
  } catch (e: any) {
    return { ok: false, error: e?.message ?? String(e) };
  }
}

async function runJson(cmd: string, args: string[], timeoutMs = 30_000): Promise<CollectorResult<any>> {
  const res = await run(cmd, args, timeoutMs);
  if (!res.ok) return res as CollectorResult<any>;
  try {
    return { ok: true, value: JSON.parse(res.value || 'null') };
  } catch (e: any) {
    return { ok: false, error: `Failed to parse JSON: ${e?.message ?? e}`, meta: { raw: res.value } };
  }
}

export async function collectOpenClaw(): Promise<NormalizedSnapshot['openclaw']> {
  return {
    securityAudit: await runJson('openclaw', ['security', 'audit', '--deep', '--json']),
    updateStatus: await run('openclaw', ['update', 'status']),
    statusDeep: await run('openclaw', ['status', '--deep'])
  };
}

export async function collectHostSignals(): Promise<HostSignals> {
  const platform = os.platform();
  const host: HostSignals = {
    os: { platform, release: os.release(), arch: os.arch() }
  };

  // Listening ports
  if (platform === 'darwin') {
    const lsof = await run('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN']);
    host.listening = { raw: lsof.ok ? lsof.value : lsof.error ? `ERROR: ${lsof.error}` : undefined };

    // Firewall
    const fw = await run('/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getglobalstate']);
    host.firewall = {
      state: fw.ok
        ? /enabled/i.test(fw.value || '')
          ? 'on'
          : /disabled/i.test(fw.value || '')
            ? 'off'
            : 'unknown'
        : 'unknown',
      raw: fw.ok ? fw.value : fw.error
    };

    // Disk encryption (FileVault)
    const fv = await run('fdesetup', ['status']);
    host.diskEncryption = {
      state: fv.ok ? (/FileVault is On/i.test(fv.value || '') ? 'on' : /Off/i.test(fv.value || '') ? 'off' : 'unknown') : 'unknown',
      raw: fv.ok ? fv.value : fv.error
    };

    // Auto-updates (best-effort)
    const su = await run('softwareupdate', ['--schedule']);
    host.autoUpdates = {
      state: su.ok ? (/on/i.test(su.value || '') ? 'on' : /off/i.test(su.value || '') ? 'off' : 'unknown') : 'unknown',
      raw: su.ok ? su.value : su.error
    };

    // Backups (Time Machine)
    const tm = await run('tmutil', ['status']);
    host.backups = {
      state: tm.ok ? (/Running/i.test(tm.value || '') ? 'on' : 'unknown') : 'unknown',
      raw: tm.ok ? tm.value : tm.error
    };
  } else {
    // Linux-ish
    const ss = await run('ss', ['-ltnp']);
    host.listening = { raw: ss.ok ? ss.value : ss.error };

    const ufw = await run('ufw', ['status']);
    host.firewall = {
      state: ufw.ok ? (/Status: active/i.test(ufw.value || '') ? 'on' : /inactive/i.test(ufw.value || '') ? 'off' : 'unknown') : 'unknown',
      raw: ufw.ok ? ufw.value : ufw.error
    };

    const luks = await run('lsblk', ['-o', 'NAME,TYPE,MOUNTPOINT,FSTYPE']);
    host.diskEncryption = { state: 'unknown', raw: luks.ok ? luks.value : luks.error };

    const unattended = await run('systemctl', ['is-enabled', 'unattended-upgrades']);
    host.autoUpdates = {
      state: unattended.ok ? (/enabled/i.test(unattended.value || '') ? 'on' : 'off') : 'unknown',
      raw: unattended.ok ? unattended.value : unattended.error
    };
  }

  return host;
}

export async function collectAll(): Promise<NormalizedSnapshot> {
  const [openclaw, host] = await Promise.all([collectOpenClaw(), collectHostSignals()]);
  return {
    collectedAt: new Date().toISOString(),
    openclaw,
    host
  };
}
