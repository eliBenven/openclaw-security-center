#!/usr/bin/env node
import { Command } from 'commander';
import { collectAll } from '@ocsec/agent';
import type { NormalizedSnapshot } from '@ocsec/agent';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import open from 'open';
import readline from 'node:readline';

function printJson(x: unknown) {
  process.stdout.write(JSON.stringify(x, null, 2) + '\n');
}

// ── colour helpers (respects NO_COLOR) ──
const useColor = !process.env.NO_COLOR && process.stdout.isTTY;
const c = {
  red: (s: string) => (useColor ? `\x1b[31m${s}\x1b[0m` : s),
  green: (s: string) => (useColor ? `\x1b[32m${s}\x1b[0m` : s),
  yellow: (s: string) => (useColor ? `\x1b[33m${s}\x1b[0m` : s),
  cyan: (s: string) => (useColor ? `\x1b[36m${s}\x1b[0m` : s),
  bold: (s: string) => (useColor ? `\x1b[1m${s}\x1b[0m` : s),
  dim: (s: string) => (useColor ? `\x1b[2m${s}\x1b[0m` : s),
};

const program = new Command();
program
  .name('ocsec')
  .description('OpenClaw Security Center')
  .option('--serverPort <port>', 'server port', '7337');

program
  .command('collect')
  .description('Collect OpenClaw + host security signals and print JSON')
  .option('--json', 'print JSON (default)', true)
  .action(async () => {
    const snap = await collectAll();
    printJson(snap);
  });

program
  .command('dashboard')
  .description('Start local dashboard server and open browser')
  .option('--no-open', 'do not open browser')
  .action(async (opts) => {
    const port = Number(program.opts().serverPort);
    const req = createRequire(import.meta.url);
    const serverEntry = req.resolve('@ocsec/server/dist/index.js');
    const child = spawn('node', ['--enable-source-maps', serverEntry], {
      stdio: 'inherit',
      env: { ...process.env, PORT: String(port) }
    });
    // Give server a moment
    setTimeout(async () => {
      if (opts.open) await open(`http://localhost:${port}`);
    }, 600);
    child.on('exit', (code) => process.exit(code ?? 0));
  });

program
  .command('plan')
  .description('Generate a numbered remediation plan (no changes).')
  .action(async () => {
    const snap = await collectAll();

    const steps: Array<{ title: string; command: string; rollback: string; notes?: string }> = [];

    // OpenClaw safe fixes (does not touch host firewall/SSH)
    steps.push({
      title: 'Tighten OpenClaw defaults (safe fix)'
      , command: 'openclaw security audit --fix'
      , rollback: 'Re-run `openclaw security audit --deep` to confirm; revert config manually if needed.'
      , notes: 'This only affects OpenClaw config/file permissions. It does NOT change firewall/SSH/OS updates.'
    });

    // Host suggestions (plan-only; user decides)
    if (snap.host.firewall?.state === 'off') {
      steps.push({
        title: 'Enable host firewall (recommended)'
        , command: snap.host.os.platform === 'darwin'
          ? 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on'
          : 'sudo ufw enable'
        , rollback: snap.host.os.platform === 'darwin'
          ? 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off'
          : 'sudo ufw disable'
      });
    }

    if (snap.host.autoUpdates?.state === 'off') {
      steps.push({
        title: 'Enable automatic OS updates'
        , command: snap.host.os.platform === 'darwin'
          ? 'sudo softwareupdate --schedule on'
          : 'sudo dpkg-reconfigure -plow unattended-upgrades'
        , rollback: snap.host.os.platform === 'darwin'
          ? 'sudo softwareupdate --schedule off'
          : 'sudo dpkg-reconfigure unattended-upgrades'
      });
    }

    if (snap.host.diskEncryption?.state === 'off') {
      steps.push({
        title: 'Enable disk encryption'
        , command: snap.host.os.platform === 'darwin'
          ? 'sudo fdesetup enable'
          : 'echo "LUKS encryption must be configured manually for existing volumes"'
        , rollback: snap.host.os.platform === 'darwin'
          ? 'sudo fdesetup disable'
          : 'echo "LUKS decryption requires manual steps"'
        , notes: 'Disk encryption on existing Linux volumes requires careful planning.'
      });
    }

    const out = {
      collectedAt: snap.collectedAt,
      notes: 'This is plan-only. Nothing has been changed.',
      steps: steps.map((s, i) => ({ n: i + 1, ...s }))
    };
    printJson(out);
  });

// ── apply command ──

program
  .command('apply')
  .description('Apply remediation plan with explicit confirmation per step (interactive).')
  .action(async () => {
    const snap = await collectAll();

    const steps: Array<{ title: string; command: string; rollback: string; notes?: string }> = [];

    steps.push({
      title: 'Tighten OpenClaw defaults (safe fix)',
      command: 'openclaw security audit --fix',
      rollback: 'Re-run `openclaw security audit --deep` to confirm; revert config manually if needed.',
      notes: 'This only affects OpenClaw config/file permissions.'
    });

    if (snap.host.firewall?.state === 'off') {
      steps.push({
        title: 'Enable host firewall',
        command: snap.host.os.platform === 'darwin'
          ? 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on'
          : 'sudo ufw enable',
        rollback: snap.host.os.platform === 'darwin'
          ? 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off'
          : 'sudo ufw disable'
      });
    }

    if (snap.host.autoUpdates?.state === 'off') {
      steps.push({
        title: 'Enable automatic OS updates',
        command: snap.host.os.platform === 'darwin'
          ? 'sudo softwareupdate --schedule on'
          : 'sudo dpkg-reconfigure -plow unattended-upgrades',
        rollback: snap.host.os.platform === 'darwin'
          ? 'sudo softwareupdate --schedule off'
          : 'sudo dpkg-reconfigure unattended-upgrades'
      });
    }

    if (steps.length === 0) {
      console.log(c.green('Nothing to remediate. Posture looks good.'));
      return;
    }

    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const ask = (q: string): Promise<string> => new Promise((resolve) => rl.question(q, resolve));

    const rollbackLog: Array<{ step: number; title: string; rollback: string; status: 'applied' | 'skipped' }> = [];

    console.log(c.bold(`\nRemediation Plan: ${steps.length} step(s)\n`));

    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      console.log(c.bold(`Step ${i + 1}/${steps.length}: ${step.title}`));
      console.log(`  Command:  ${c.cyan(step.command)}`);
      console.log(`  Rollback: ${c.dim(step.rollback)}`);
      if (step.notes) console.log(`  Notes:    ${c.dim(step.notes)}`);

      const answer = await ask(`\n  Apply this step? [y/n/abort] `);
      const choice = answer.trim().toLowerCase();

      if (choice === 'abort' || choice === 'a') {
        console.log(c.yellow('\nAborted by user. No further steps will run.'));
        rollbackLog.push({ step: i + 1, title: step.title, rollback: step.rollback, status: 'skipped' });
        break;
      }

      if (choice !== 'y' && choice !== 'yes') {
        console.log(c.yellow(`  Skipped step ${i + 1}.`));
        rollbackLog.push({ step: i + 1, title: step.title, rollback: step.rollback, status: 'skipped' });
        continue;
      }

      // Execute the command
      console.log(c.dim(`  Running: ${step.command}`));
      const exitCode = await new Promise<number>((resolve) => {
        const parts = step.command.split(' ');
        const child = spawn(parts[0], parts.slice(1), { stdio: 'inherit', shell: true });
        child.on('error', (err) => {
          console.error(c.red(`  Error spawning command: ${err.message}`));
          resolve(1);
        });
        child.on('exit', (code) => resolve(code ?? 1));
      });

      if (exitCode === 0) {
        console.log(c.green(`  Step ${i + 1} completed successfully.`));
        rollbackLog.push({ step: i + 1, title: step.title, rollback: step.rollback, status: 'applied' });
      } else {
        console.log(c.red(`  Step ${i + 1} exited with code ${exitCode}.`));
        rollbackLog.push({ step: i + 1, title: step.title, rollback: step.rollback, status: 'applied' });
      }
      console.log();
    }

    rl.close();

    // Print rollback summary
    const applied = rollbackLog.filter((r) => r.status === 'applied');
    if (applied.length > 0) {
      console.log(c.bold('\n── Rollback Reference ──'));
      for (const r of applied) {
        console.log(`  Step ${r.step} (${r.title}): ${c.dim(r.rollback)}`);
      }
    }

    console.log(c.bold('\n── Summary ──'));
    console.log(`  Applied: ${applied.length}  Skipped: ${rollbackLog.length - applied.length}`);
    console.log();
  });

// ── diff command ──

program
  .command('diff')
  .description('Diff two snapshots. Arguments can be run IDs (from DB) or file paths.')
  .argument('<a>', 'Run ID or path to snapshot A')
  .argument('<b>', 'Run ID or path to snapshot B')
  .option('--server <url>', 'server URL', 'http://localhost:7337')
  .action(async (a: string, b: string, opts: { server: string }) => {
    const snapA = await resolveSnapshot(a, opts.server);
    const snapB = await resolveSnapshot(b, opts.server);

    console.log(c.bold('\n── Snapshot Diff ──'));
    console.log(`  A: ${c.dim(a)} (${snapA.collectedAt})`);
    console.log(`  B: ${c.dim(b)} (${snapB.collectedAt})`);
    console.log();

    const changes = diffDeep(snapA, snapB);
    if (changes.length === 0) {
      console.log(c.green('  No differences found.'));
    } else {
      for (const change of changes) {
        const label = change.type === 'added'
          ? c.green('+ added')
          : change.type === 'removed'
            ? c.red('- removed')
            : c.yellow('~ changed');
        console.log(`  ${label}  ${c.bold(change.path)}`);
        if (change.type === 'changed') {
          console.log(`    ${c.red('- ' + truncate(String(change.oldValue), 120))}`);
          console.log(`    ${c.green('+ ' + truncate(String(change.newValue), 120))}`);
        } else if (change.type === 'added') {
          console.log(`    ${c.green('+ ' + truncate(String(change.newValue), 120))}`);
        } else {
          console.log(`    ${c.red('- ' + truncate(String(change.oldValue), 120))}`);
        }
      }
    }
    console.log();
  });

type DiffEntry = {
  path: string;
  type: 'added' | 'removed' | 'changed';
  oldValue?: unknown;
  newValue?: unknown;
};

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + '...' : s;
}

function diffDeep(a: any, b: any, prefix = ''): DiffEntry[] {
  const out: DiffEntry[] = [];
  const keysA = a && typeof a === 'object' ? Object.keys(a) : [];
  const keysB = b && typeof b === 'object' ? Object.keys(b) : [];
  const allKeys = new Set([...keysA, ...keysB]);

  for (const k of allKeys) {
    const pa = a?.[k];
    const pb = b?.[k];
    const p = prefix ? `${prefix}.${k}` : k;

    if (pa === undefined && pb !== undefined) {
      out.push({ path: p, type: 'added', newValue: pb });
    } else if (pa !== undefined && pb === undefined) {
      out.push({ path: p, type: 'removed', oldValue: pa });
    } else if (typeof pa === 'object' && pa && typeof pb === 'object' && pb) {
      out.push(...diffDeep(pa, pb, p));
    } else if (JSON.stringify(pa) !== JSON.stringify(pb)) {
      out.push({ path: p, type: 'changed', oldValue: pa, newValue: pb });
    }
  }
  return out;
}

async function resolveSnapshot(ref: string, serverUrl: string): Promise<NormalizedSnapshot> {
  // Try as file path first
  const fs = await import('node:fs/promises');
  try {
    await fs.access(ref);
    const content = await fs.readFile(ref, 'utf8');
    const parsed = JSON.parse(content);
    // If it has a snapshot field (server format), unwrap it
    return parsed.snapshot ?? parsed;
  } catch {
    // Not a file — try as run ID from server
  }

  // Try fetching from server DB
  try {
    const resp = await fetch(`${serverUrl}/api/runs/${encodeURIComponent(ref)}`);
    if (resp.ok) {
      const data = await resp.json() as { snapshot: NormalizedSnapshot };
      return data.snapshot;
    }
  } catch {
    // Server might not be running
  }

  // Try resolving directly from the DB (in-process)
  try {
    const dbMod = '@ocsec/server/dist/db.js';
    const { openDb, getRun } = await import(/* webpackIgnore: true */ dbMod) as any;
    const db = openDb();
    const row = getRun(db, ref);
    if (row) {
      return JSON.parse(row.snapshotJson);
    }
  } catch {
    // DB module not available
  }

  console.error(c.red(`Could not resolve snapshot: ${ref}`));
  console.error(c.dim('Provide a valid file path or run ID. If using run IDs, ensure the server is running or DB is accessible.'));
  process.exit(1);
}

// ── monitor command ──

program
  .command('monitor')
  .description('Compare latest two runs and flag regressions. Useful for cron-based monitoring.')
  .option('--server <url>', 'server URL', 'http://localhost:7337')
  .option('--cron', 'Output a sample cron entry for scheduling')
  .option('--json', 'Output alert in JSON format')
  .action(async (opts: { server: string; cron?: boolean; json?: boolean }) => {
    if (opts.cron) {
      const cronLine = `0 8 * * 1  cd ${process.cwd()} && npx ocsec collect | npx ocsec monitor --json >> /var/log/ocsec-alerts.json 2>&1`;
      console.log(c.bold('Sample cron entry (weekly Monday 8am):'));
      console.log(c.dim(cronLine));
      console.log();
      console.log(c.bold('Or with OpenClaw cron:'));
      console.log(c.dim(`openclaw cron add --schedule "0 8 * * 1" --command "npx ocsec collect && npx ocsec monitor --json"`));
      return;
    }

    // Fetch latest 2 runs
    let runs: Array<{ id: string; collectedAt: string }> = [];
    try {
      const resp = await fetch(`${opts.server}/api/runs?limit=2`);
      if (resp.ok) {
        const data = await resp.json() as { runs: typeof runs };
        runs = data.runs;
      }
    } catch {
      // Server not running — try direct DB access
    }

    if (runs.length < 2) {
      // Try direct DB access
      try {
        const dbMod2 = '@ocsec/server/dist/db.js';
        const { openDb, listRuns } = await import(/* webpackIgnore: true */ dbMod2) as any;
        const db = openDb();
        const rows = listRuns(db, 2);
        runs = rows.map((r: any) => ({ id: r.id, collectedAt: r.collectedAt }));
      } catch {
        // DB not available
      }
    }

    if (runs.length < 2) {
      if (opts.json) {
        printJson({ alert: false, reason: 'insufficient_runs', message: 'Need at least 2 runs to compare.' });
      } else {
        console.log(c.yellow('Need at least 2 runs stored to compare. Run `ocsec collect` via the server first.'));
      }
      return;
    }

    const latest = await resolveSnapshot(runs[0].id, opts.server);
    const previous = await resolveSnapshot(runs[1].id, opts.server);

    const regressions: Array<{ field: string; was: string; now: string; severity: 'high' | 'medium' | 'low' }> = [];

    // Check firewall
    if (previous.host.firewall?.state === 'on' && latest.host.firewall?.state !== 'on') {
      regressions.push({ field: 'host.firewall', was: 'on', now: latest.host.firewall?.state ?? 'unknown', severity: 'high' });
    }

    // Check disk encryption
    if (previous.host.diskEncryption?.state === 'on' && latest.host.diskEncryption?.state !== 'on') {
      regressions.push({ field: 'host.diskEncryption', was: 'on', now: latest.host.diskEncryption?.state ?? 'unknown', severity: 'high' });
    }

    // Check auto-updates
    if (previous.host.autoUpdates?.state === 'on' && latest.host.autoUpdates?.state !== 'on') {
      regressions.push({ field: 'host.autoUpdates', was: 'on', now: latest.host.autoUpdates?.state ?? 'unknown', severity: 'medium' });
    }

    // Check new open ports
    const prevPorts = new Set((previous.host.listening?.tcp ?? []).map((p) => p.port));
    const currPorts = (latest.host.listening?.tcp ?? []);
    const newPorts = currPorts.filter((p) => !prevPorts.has(p.port));
    if (newPorts.length > 0) {
      regressions.push({
        field: 'host.listening.tcp',
        was: `${prevPorts.size} ports`,
        now: `${currPorts.length} ports (new: ${newPorts.map((p) => p.port).join(', ')})`,
        severity: 'medium'
      });
    }

    // Check OpenClaw audit
    if (previous.openclaw.securityAudit?.ok && !latest.openclaw.securityAudit?.ok) {
      regressions.push({ field: 'openclaw.securityAudit', was: 'ok', now: 'error', severity: 'high' });
    }

    const alert = {
      alert: regressions.length > 0,
      timestamp: new Date().toISOString(),
      latestRun: runs[0].id,
      previousRun: runs[1].id,
      regressions,
      summary: regressions.length > 0
        ? `${regressions.length} regression(s) detected`
        : 'No regressions. Posture stable.'
    };

    if (opts.json) {
      printJson(alert);
    } else {
      console.log(c.bold('\n── Monitor: Regression Check ──'));
      console.log(`  Latest:   ${c.dim(runs[0].id)} (${runs[0].collectedAt})`);
      console.log(`  Previous: ${c.dim(runs[1].id)} (${runs[1].collectedAt})`);
      console.log();

      if (regressions.length === 0) {
        console.log(c.green('  No regressions detected. Posture stable.'));
      } else {
        console.log(c.red(`  ${regressions.length} regression(s) found:\n`));
        for (const r of regressions) {
          const sev = r.severity === 'high' ? c.red(`[${r.severity}]`) : r.severity === 'medium' ? c.yellow(`[${r.severity}]`) : c.dim(`[${r.severity}]`);
          console.log(`  ${sev} ${c.bold(r.field)}`);
          console.log(`    Was: ${c.dim(r.was)}  Now: ${c.dim(r.now)}`);
        }
      }
      console.log();
    }
  });

program.parseAsync(process.argv);
