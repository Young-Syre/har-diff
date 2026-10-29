import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { groupBySignature, parseHar, walkJson } from '../src/har.js';
import { loadFixtures, makeHar } from './helpers.js';

describe('parseHar', () => {
  it('rejects input that is not a HAR document', () => {
    assert.throws(() => parseHar('not json', { label: 'x' }), /not valid JSON/);
    assert.throws(() => parseHar({ notALog: true }, { label: 'x' }), /missing "log"/);
  });

  it('reads the creator and entry count from a HAR 1.2 file', async () => {
    const { admin, user } = await loadFixtures();
    assert.equal(admin.requests.length, 12);
    assert.equal(user.requests.length, 8);
    assert.match(admin.creator ?? '', /har-diff fixture/);
    assert.deepEqual(admin.warnings, []);
  });

  it('normalises scheme, host, port and method', async () => {
    const { admin } = await loadFixtures();
    const first = admin.requests[0];
    assert.ok(first);
    assert.equal(first.method, 'GET');
    assert.equal(first.scheme, 'https:');
    assert.equal(first.host, 'api.shopfront.test');
    assert.equal(first.port, 443);
  });

  it('sorts query and body parameter names', async () => {
    const { admin } = await loadFixtures();
    const list = admin.requests.find((request) => request.templatePath === '/api/v1/users');
    assert.ok(list);
    assert.deepEqual(list.queryNames, ['page', 'per_page']);

    const patch = admin.requests.find((request) => request.method === 'PATCH');
    assert.ok(patch);
    assert.deepEqual(patch.bodyParamNames, ['display_name', 'org_id', 'role']);
  });

  it('builds a signature that excludes query and body parameters', async () => {
    const { admin } = await loadFixtures();
    const signatures = admin.requests
      .filter((request) => request.templatePath === '/api/v1/users/{int}' && request.method === 'GET')
      .map((request) => request.signature);
    assert.equal(signatures.length, 3);
    assert.equal(new Set(signatures).size, 1, 'three different user ids share one signature');
    assert.equal(signatures[0], 'GET https://api.shopfront.test/api/v1/users/{int}');
  });

  it('omits the default port from the signature but keeps a custom one', () => {
    const capture = parseHar(
      makeHar([{ url: 'https://api.example.test:8443/api/users/1' }, { url: 'https://api.example.test/api/users/1' }]),
      { label: 'x' },
    );
    assert.equal(capture.requests[0]?.signature, 'GET https://api.example.test:8443/api/users/{int}');
    assert.equal(capture.requests[1]?.signature, 'GET https://api.example.test/api/users/{int}');
  });

  it('groups requests by signature', async () => {
    const { admin } = await loadFixtures();
    const groups = groupBySignature(admin.requests);
    assert.equal(groups.size, 10);
    assert.equal(groups.get('GET https://api.shopfront.test/api/v1/users/{int}')?.length, 3);
  });

  it('records the response status and size', async () => {
    const { user } = await loadFixtures();
    const forbidden = user.requests.find((request) => request.status === 403);
    assert.ok(forbidden, 'the user capture contains a 403');
    assert.equal(forbidden.templatePath, '/api/v1/admin/settings');
    assert.ok(forbidden.responseSize > 0);
  });

  it('skips unusable entries and records a warning instead of throwing', () => {
    const capture = parseHar(
      JSON.stringify({
        log: {
          version: '1.2',
          entries: [{ request: { method: 'GET' } }, { notARequest: true }, { request: { method: 'GET', url: 'nonsense' } }],
        },
      }),
      { label: 'broken' },
    );
    assert.equal(capture.requests.length, 0);
    assert.equal(capture.warnings.length, 3);
    assert.match(capture.warnings.join('\n'), /missing request.url/);
    assert.match(capture.warnings.join('\n'), /unparseable url/);
  });

  it('collects credential values seen in headers, cookies, queries and bodies', async () => {
    const { admin } = await loadFixtures();
    const joined = admin.secrets.join('\n');
    assert.match(joined, /FIXTUREadminSESSIONvalue/);
    assert.match(joined, /FIXTUREadminCSRFvalue/);
    assert.match(joined, /FIXTURE-SIGNATURE-NOT-REAL/);
  });

  it('parses form-encoded bodies into parameter names', () => {
    const capture = parseHar(
      makeHar([
        {
          method: 'POST',
          url: 'https://api.example.test/login',
          headers: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
          body: { mimeType: 'application/x-www-form-urlencoded', text: 'username=sam&password=hunter2&next=%2Fhome' },
        },
      ]),
      { label: 'x' },
    );
    assert.deepEqual(capture.requests[0]?.bodyParamNames, ['next', 'password', 'username']);
    assert.ok(capture.secrets.includes('hunter2'), 'the password value is recorded as a secret');
  });
});

describe('walkJson', () => {
  it('collapses array indices so a list does not explode into many parameters', () => {
    const leaves = walkJson({ users: [{ id: 1 }, { id: 2 }, { id: 3 }] });
    assert.deepEqual(
      leaves.map((leaf) => leaf.path),
      ['users[].id', 'users[].id', 'users[].id'],
    );
  });

  it('honours the depth cap', () => {
    const deep = { a: { b: { c: { d: { e: 'leaf' } } } } };
    assert.equal(walkJson(deep, 10).length, 1);
    assert.equal(walkJson(deep, 2).length, 0);
  });

  it('survives a cyclic object', () => {
    const cyclic: Record<string, unknown> = { id: 7 };
    cyclic['self'] = cyclic;
    assert.doesNotThrow(() => walkJson(cyclic));
  });
});
