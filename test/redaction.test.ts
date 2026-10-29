import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { diffCaptures } from '../src/diff.js';
import { renderDiff, renderObjects, renderParse, renderPlan } from '../src/format.js';
import { extractObjects } from '../src/objects.js';
import { buildPlan } from '../src/plan.js';
import { multipartBoundary, parseHar } from '../src/har.js';
import { isSensitiveHeader, isSensitiveKey, looksLikeSecret, Redactor } from '../src/redact.js';
import type { OutputFormat } from '../src/types.js';
import { FIXTURE_SECRETS, loadFixtures, makeHar } from './helpers.js';

const FORMATS: OutputFormat[] = ['text', 'json', 'markdown'];

async function renderEverything(showSecrets = false): Promise<{ command: string; format: OutputFormat; output: string }[]> {
  const { admin, user } = await loadFixtures();
  const captures = [admin, user];
  const redactor = new Redactor(captures.flatMap((capture) => capture.secrets), { showSecrets });
  const objects = extractObjects(captures);
  const diff = diffCaptures(captures, { objects });
  const plan = buildPlan(captures, diff);
  const refs = captures.map((capture) => ({
    label: capture.label,
    file: capture.file,
    requestCount: capture.requests.length,
  }));

  const out: { command: string; format: OutputFormat; output: string }[] = [];
  for (const format of FORMATS) {
    out.push({ command: 'parse', format, output: renderParse(captures, format, redactor) });
    out.push({ command: 'diff', format, output: renderDiff(diff, format, redactor) });
    out.push({ command: 'objects', format, output: renderObjects(objects, refs, format, redactor) });
    out.push({ command: 'plan', format, output: renderPlan(plan, format, redactor) });
  }
  return out;
}

describe('no fixture credential reaches any output by default', () => {
  it('strips every known fixture secret from every command in every format', async () => {
    const rendered = await renderEverything();
    assert.equal(rendered.length, 12);
    for (const { command, format, output } of rendered) {
      for (const secret of FIXTURE_SECRETS) {
        assert.equal(
          output.includes(secret),
          false,
          `${command}/${format} leaked ${secret.slice(0, 24)}...`,
        );
      }
    }
  });

  it('leaves no trace of the fixture credential prefix anywhere', async () => {
    const rendered = await renderEverything();
    for (const { command, format, output } of rendered) {
      assert.equal(output.includes('FIXTURE'), false, `${command}/${format} contains the FIXTURE marker`);
      assert.equal(/\beyJ[A-Za-z0-9_-]{6,}\./.test(output), false, `${command}/${format} contains a JWT`);
    }
  });

  it('still produces useful output, not an empty document', async () => {
    const rendered = await renderEverything();
    for (const { command, format, output } of rendered) {
      assert.ok(output.length > 200, `${command}/${format} is suspiciously short`);
      assert.ok(output.includes('/api/v1/users'), `${command}/${format} lost the endpoint data`);
    }
  });

  it('marks the plan with redaction placeholders rather than dropping the command', async () => {
    const rendered = await renderEverything();
    const plan = rendered.find((entry) => entry.command === 'plan' && entry.format === 'markdown');
    assert.ok(plan);
    assert.match(plan.output, /\$HARDIFF_USER_TOKEN/);
    assert.match(plan.output, /\$HARDIFF_USER_COOKIE/);
  });

  it('prints the credentials when --unsafe-show-secrets is in effect', async () => {
    const rendered = await renderEverything(true);
    const objects = rendered.find((entry) => entry.command === 'objects' && entry.format === 'json');
    assert.ok(objects);
    assert.ok(objects.output.includes('FIXTURE-SIGNATURE-NOT-REAL'), 'the escape hatch has to actually work');
  });
});

describe('Redactor', () => {
  it('replaces a known literal and its percent-encoded form', () => {
    const redactor = new Redactor(['s3cret-session-value']);
    assert.equal(redactor.text('cookie=s3cret-session-value;'), 'cookie=[REDACTED];');
    assert.equal(redactor.text('cookie=s3cret-session-value%3B'), 'cookie=[REDACTED]%3B');
  });

  it('ignores literals too short to be credentials', () => {
    const redactor = new Redactor(['ab']);
    assert.equal(redactor.literalCount, 0);
    assert.equal(redactor.text('ab'), 'ab');
  });

  it('recognises token shapes it was never told about', () => {
    const redactor = new Redactor([]);
    assert.match(redactor.text('Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig-value'), /REDACTED/);
    assert.match(redactor.text('AKIAIOSFODNN7EXAMPLE'), /REDACTED:aws-key-id/);
    assert.match(redactor.text('sk_live_01234567890abcdef'), /REDACTED:stripe-key/);
    assert.match(redactor.text('ghp_0123456789abcdefghijklmnopqrstuvwx'), /REDACTED:github-token/);
    assert.match(redactor.text('xoxb-0123456789-abcdefghij'), /REDACTED:slack-token/);
  });

  it('does not eat har-diff credential placeholders', () => {
    const redactor = new Redactor([]);
    const line = 'curl -H "Authorization: Bearer $HARDIFF_USER_TOKEN" https://x.test/a';
    assert.equal(redactor.text(line), line);
  });

  it('does not eat object identifiers', () => {
    const redactor = new Redactor([]);
    const line = 'GET /api/v1/documents/9f2b4c6d-15a7-4e3b-93c8-2d7a6b41e0f5 -> 200';
    assert.equal(redactor.text(line), line);
  });

  it('redacts credential headers by name and keeps the rest', () => {
    const redactor = new Redactor([]);
    const headers = redactor.headers([
      { name: 'Authorization', value: 'Bearer abc' },
      { name: 'Cookie', value: 'session=abc' },
      { name: 'X-Api-Key', value: 'abc' },
      { name: 'Accept', value: 'application/json' },
    ]);
    assert.deepEqual(headers, [
      { name: 'Authorization', value: '[REDACTED]' },
      { name: 'Cookie', value: '[REDACTED]' },
      { name: 'X-Api-Key', value: '[REDACTED]' },
      { name: 'Accept', value: 'application/json' },
    ]);
  });

  it('redacts credential query parameters and keeps the others', () => {
    const redactor = new Redactor([]);
    assert.equal(
      redactor.url('https://x.test/a?page=2&access_token=abc123def456&sort=name'),
      'https://x.test/a?page=2&access_token=[REDACTED]&sort=name',
    );
  });

  it('is a no-op when secrets are shown', () => {
    const redactor = new Redactor(['s3cret-session-value'], { showSecrets: true });
    assert.equal(redactor.enabled, false);
    assert.equal(redactor.text('s3cret-session-value'), 's3cret-session-value');
  });
});

describe('sensitivity classification', () => {
  it('knows which headers carry credentials', () => {
    for (const name of ['Authorization', 'cookie', 'Set-Cookie', 'X-API-Key', 'x-csrf-token']) {
      assert.equal(isSensitiveHeader(name), true, `${name} should be sensitive`);
    }
    for (const name of ['Accept', 'Content-Type', 'User-Agent', 'X-Request-Id']) {
      assert.equal(isSensitiveHeader(name), false, `${name} should not be sensitive`);
    }
  });

  it('knows which field names carry credentials', () => {
    for (const name of ['password', 'access_token', 'invite_token', 'apiKey', 'client_secret', 'user.session']) {
      assert.equal(isSensitiveKey(name), true, `${name} should be sensitive`);
    }
    for (const name of ['email', 'display_name', 'role', 'org_id', 'tokens_remaining']) {
      assert.equal(isSensitiveKey(name), false, `${name} should not be sensitive`);
    }
  });

  it('recognises credential-shaped values without a key name', () => {
    assert.equal(looksLikeSecret('eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig-value'), true);
    assert.equal(looksLikeSecret('AKIAIOSFODNN7EXAMPLE'), true);
    assert.equal(looksLikeSecret('9f2b4c6d-15a7-4e3b-93c8-2d7a6b41e0f5'), false);
    assert.equal(looksLikeSecret('8123'), false);
  });
});

describe('the three layers that used to miss a credential', () => {
  const BOUNDARY = '----WebKitFormBoundaryAbC123';
  const PASSWORD = 'MULTIPART-PLAINTEXT-PW';
  const REFERER_TOKEN = 'PWRESET-SECRET-9f8e7d6c5b4a';
  const CAMEL_TOKENS = ['AUTHTOKEN-OPAQUE-1234567890', 'SESSTOK-OPAQUE-0987654321'];

  const multipartBody = [
    `--${BOUNDARY}\r\nContent-Disposition: form-data; name="username"\r\n\r\nalice\r\n`,
    `--${BOUNDARY}\r\nContent-Disposition: form-data; name="password"\r\n\r\n${PASSWORD}\r\n`,
    `--${BOUNDARY}--\r\n`,
  ].join('');

  async function planFor(): Promise<string> {
    const privileged = parseHar(
      makeHar([
        {
          url: 'https://app.t.test/api/admin/users/8123',
          headers: [
            { name: 'Referer', value: `https://app.t.test/invite/accept?invite_token=${REFERER_TOKEN}` },
          ],
          response: { ok: true },
        },
        {
          method: 'POST',
          url: 'https://app.t.test/api/login',
          headers: [{ name: 'Content-Type', value: `multipart/form-data; boundary=${BOUNDARY}` }],
          body: { mimeType: `multipart/form-data; boundary=${BOUNDARY}`, text: multipartBody },
          response: { ok: true },
        },
        {
          method: 'POST',
          url: 'https://app.t.test/api/profile',
          headers: [{ name: 'Content-Type', value: 'application/json' }],
          body: {
            mimeType: 'application/json',
            text: JSON.stringify({ authToken: CAMEL_TOKENS[0], sessionToken: CAMEL_TOKENS[1] }),
          },
          response: { ok: true },
        },
      ]),
      { label: 'admin' },
    );
    const unprivileged = parseHar(
      makeHar([{ url: 'https://app.t.test/api/profile', response: { ok: true } }]),
      { label: 'user' },
    );
    const captures = [privileged, unprivileged];
    const redactor = new Redactor(captures.flatMap((capture) => capture.secrets));
    const objects = extractObjects(captures);
    const diff = diffCaptures(captures, { objects });
    return renderPlan(buildPlan(captures, diff), 'markdown', redactor);
  }

  it('a token in a Referer does not reach the plan', async () => {
    // Referer is kept because it changes how the server routes and
    // authorises. It is also a whole URL, and the URL that sent you somewhere
    // is where a one-time invite or reset token lives.
    assert.doesNotMatch(await planFor(), new RegExp(REFERER_TOKEN));
  });

  it('a multipart password does not reach the plan', async () => {
    const plan = await planFor();
    assert.doesNotMatch(plan, new RegExp(PASSWORD));
    assert.match(plan, /alice/, 'a part that is not a credential is left alone');
  });

  it('a camelCase credential field does not reach the plan', async () => {
    const plan = await planFor();
    for (const token of CAMEL_TOKENS) assert.doesNotMatch(plan, new RegExp(token));
  });

  it('camelCase and snake_case spellings of a field name agree', () => {
    for (const name of [
      'authToken',
      'sessionToken',
      'apiToken',
      'userToken',
      'sessionKey',
      'accessToken',
      'auth_token',
      'session-key',
    ]) {
      assert.equal(isSensitiveKey(name), true, name);
    }
  });

  it('the boundary is recovered from the body when the content type lost it', () => {
    // A canonical request keeps the content type without its parameters, so by
    // the time a body reaches the plan the boundary is only in the body.
    assert.equal(multipartBoundary(multipartBody, 'multipart/form-data'), BOUNDARY);
    assert.equal(multipartBoundary(multipartBody, null), BOUNDARY);
    assert.equal(multipartBoundary('{"a":1}', 'application/json'), null);
  });

  it('the in-memory API reports no file rather than its label', () => {
    const capture = parseHar(makeHar([{ url: 'https://app.t.test/a' }]), { label: 'admin' });
    assert.equal(capture.label, 'admin');
    assert.equal(capture.file, '<memory>');
  });
});
