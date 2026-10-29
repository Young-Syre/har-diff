import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { describe, it } from 'node:test';
import { promisify } from 'node:util';

import { parseArgs } from '../src/cli.js';
import { ADMIN_HAR, CLI, FIXTURE_SECRETS, USER_HAR } from './helpers.js';

const run = promisify(execFile);

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

async function cli(...args: string[]): Promise<Run> {
  try {
    const { stdout, stderr } = await run(process.execPath, [CLI, ...args], { maxBuffer: 20 * 1024 * 1024 });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const failure = error as { code?: number; stdout?: string; stderr?: string };
    return { code: failure.code ?? 1, stdout: failure.stdout ?? '', stderr: failure.stderr ?? '' };
  }
}

describe('parseArgs', () => {
  it('reads a command, files and repeated labels', () => {
    const options = parseArgs(['diff', 'a.har', 'b.har', '--label', 'admin', '--label', 'user']);
    assert.equal(options.command, 'diff');
    assert.deepEqual(options.files, ['a.har', 'b.har']);
    assert.deepEqual(options.labels, ['admin', 'user']);
  });

  it('accepts both --flag value and --flag=value', () => {
    assert.equal(parseArgs(['diff', '--format', 'json']).format, 'json');
    assert.equal(parseArgs(['diff', '--format=markdown']).format, 'markdown');
    assert.equal(parseArgs(['diff', '--format=md']).format, 'markdown');
    assert.equal(parseArgs(['diff', '--privileged=admin']).privileged, 'admin');
    assert.equal(parseArgs(['plan', '--out=plan.md']).out, 'plan.md');
  });

  it('defaults to no explicit format and to redaction on', () => {
    const options = parseArgs(['plan', 'a.har', 'b.har']);
    assert.equal(options.format, null);
    assert.equal(options.showSecrets, false);
    assert.equal(options.templateSlugs, false);
  });

  it('reads the numeric options and the flags', () => {
    const options = parseArgs(['plan', '--max-depth', '3', '--limit', '5', '--neighbours', '2', '--template-slugs', '--unsafe-show-secrets']);
    assert.equal(options.maxDepth, 3);
    assert.equal(options.limitPerKind, 5);
    assert.equal(options.neighbours, 2);
    assert.equal(options.templateSlugs, true);
    assert.equal(options.showSecrets, true);
  });

  it('treats everything after -- as a file', () => {
    assert.deepEqual(parseArgs(['parse', '--', '--weird-name.har']).files, ['--weird-name.har']);
  });

  it('recognises help and version', () => {
    assert.equal(parseArgs(['--help']).help, true);
    assert.equal(parseArgs(['-V']).version, true);
  });
});

describe('cli end to end', () => {
  it('prints usage and exits non-zero with no arguments', async () => {
    const result = await cli();
    assert.equal(result.code, 1);
    assert.match(result.stdout, /USAGE/);
  });

  it('prints usage and exits zero for --help', async () => {
    const result = await cli('--help');
    assert.equal(result.code, 0);
    assert.match(result.stdout, /har-diff <command>/);
    assert.match(result.stdout, /Authorised testing only/);
  });

  it('rejects an unknown command', async () => {
    const result = await cli('explode', ADMIN_HAR);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /unknown command "explode"/);
  });

  it('rejects an unknown option', async () => {
    const result = await cli('parse', ADMIN_HAR, '--nope');
    assert.equal(result.code, 1);
    assert.match(result.stderr, /unknown option "--nope"/);
  });

  it('requires two files for diff and plan', async () => {
    for (const command of ['diff', 'plan']) {
      const result = await cli(command, ADMIN_HAR);
      assert.equal(result.code, 1);
      assert.match(result.stderr, /at least two HAR files/);
    }
  });

  it('reports a missing file without a stack trace', async () => {
    const result = await cli('parse', '/nonexistent/nope.har');
    assert.equal(result.code, 1);
    assert.match(result.stderr, /ENOENT|no such file/);
    assert.equal(result.stderr.includes('at Object.'), false);
  });

  it('runs every subcommand in every format', async () => {
    for (const command of ['parse', 'diff', 'objects', 'plan']) {
      for (const format of ['text', 'json', 'markdown']) {
        const result = await cli(command, ADMIN_HAR, USER_HAR, '--label', 'admin', '--label', 'user', '--format', format);
        assert.equal(result.code, 0, `${command}/${format} exited ${result.code}: ${result.stderr}`);
        assert.ok(result.stdout.length > 200, `${command}/${format} produced no output`);
        if (format === 'json') {
          assert.doesNotThrow(() => JSON.parse(result.stdout), `${command}/json is not valid JSON`);
        }
      }
    }
  });

  it('never prints a fixture credential from the command line', async () => {
    for (const command of ['parse', 'diff', 'objects', 'plan']) {
      for (const format of ['text', 'json', 'markdown']) {
        const result = await cli(command, ADMIN_HAR, USER_HAR, '--label', 'admin', '--label', 'user', '--format', format);
        const combined = result.stdout + result.stderr;
        for (const secret of FIXTURE_SECRETS) {
          assert.equal(combined.includes(secret), false, `${command}/${format} leaked a fixture credential`);
        }
        assert.equal(combined.includes('FIXTURE'), false, `${command}/${format} leaked the FIXTURE marker`);
      }
    }
  });

  it('warns on stderr before showing secrets', async () => {
    const result = await cli('objects', USER_HAR, '--label', 'user', '--unsafe-show-secrets');
    assert.equal(result.code, 0);
    assert.match(result.stderr, /WARNING: --unsafe-show-secrets/);
    assert.ok(result.stdout.includes('FIXTURE-SIGNATURE-NOT-REAL'));
  });

  it('labels captures by filename when --label is omitted', async () => {
    const result = await cli('diff', ADMIN_HAR, USER_HAR);
    assert.equal(result.code, 0);
    assert.match(result.stdout, /admin \(privileged\)/);
    assert.match(result.stdout, /\buser\b/);
  });

  it('honours --privileged', async () => {
    const result = await cli('diff', ADMIN_HAR, USER_HAR, '--privileged', 'user', '--format', 'json');
    assert.equal(result.code, 0);
    assert.equal((JSON.parse(result.stdout) as { privilegedLabel: string }).privilegedLabel, 'user');
  });

  it('rejects more labels than files', async () => {
    const result = await cli('parse', ADMIN_HAR, '--label', 'a', '--label', 'b');
    assert.equal(result.code, 1);
    assert.match(result.stderr, /more --label values/);
  });

  it('defaults the plan to markdown and the others to text', async () => {
    const plan = await cli('plan', ADMIN_HAR, USER_HAR);
    assert.match(plan.stdout, /^# Authorisation test plan/);
    const diff = await cli('diff', ADMIN_HAR, USER_HAR);
    assert.match(diff.stdout, /^har-diff\n=+/);
  });
});
