#!/usr/bin/env node
import { Command } from 'commander';
import { collectAll } from '@ocsec/agent';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import open from 'open';

function printJson(x: unknown) {
  process.stdout.write(JSON.stringify(x, null, 2) + '\n');
}

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

    const out = {
      collectedAt: snap.collectedAt,
      notes: 'This is plan-only. Nothing has been changed.',
      steps: steps.map((s, i) => ({ n: i + 1, ...s }))
    };
    printJson(out);
  });

program
  .command('apply')
  .description('Apply remediation plan with explicit confirmation per step (interactive).')
  .action(async () => {
    // We intentionally do NOT auto-run anything here yet.
    // This will be implemented fully once Eli wants it installed/used.
    console.error('Not implemented yet: apply is intentionally gated. Use `ocsec plan` for now.');
    process.exit(2);
  });

program
  .command('diff')
  .description('Diff two JSON snapshots (paste file paths)')
  .argument('<a>', 'path to snapshot A')
  .argument('<b>', 'path to snapshot B')
  .action(async (a, b) => {
    const fs = await import('node:fs/promises');
    const ja = JSON.parse(await fs.readFile(a, 'utf8'));
    const jb = JSON.parse(await fs.readFile(b, 'utf8'));
    printJson({
      hint: 'basic diff (keys that changed) – v1 will improve this',
      changed: diffKeys(ja, jb)
    });
  });

function diffKeys(a: any, b: any, prefix = ''): string[] {
  const out: string[] = [];
  const keys = new Set([...(a ? Object.keys(a) : []), ...(b ? Object.keys(b) : [])]);
  for (const k of keys) {
    const pa = a?.[k];
    const pb = b?.[k];
    const p = prefix ? `${prefix}.${k}` : k;
    if (typeof pa === 'object' && pa && typeof pb === 'object' && pb) {
      out.push(...diffKeys(pa, pb, p));
    } else {
      if (JSON.stringify(pa) !== JSON.stringify(pb)) out.push(p);
    }
  }
  return out;
}

program.parseAsync(process.argv);
