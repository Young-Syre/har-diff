import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { diffCaptures } from '../src/diff.js';
import { parseHar } from '../src/har.js';
import { loadFixtures, makeHar } from './helpers.js';

describe('diffCaptures', () => {
  it('requires at least two captures', async () => {
    const { admin } = await loadFixtures();
    assert.throws(() => diffCaptures([admin]), /at least two captures/);
  });

  it('rejects duplicate labels', async () => {
    const { admin } = await loadFixtures();
    assert.throws(() => diffCaptures([admin, admin]), /duplicate capture label/);
  });

  it('rejects a privileged label that is not one of the captures', async () => {
    const { admin, user } = await loadFixtures();
    assert.throws(() => diffCaptures([admin, user], { privilegedLabel: 'root' }), /is not one of/);
  });

  it('treats the first capture as privileged by default', async () => {
    const { admin, user } = await loadFixtures();
    assert.equal(diffCaptures([admin, user]).privilegedLabel, 'admin');
    assert.equal(diffCaptures([user, admin]).privilegedLabel, 'user');
  });

  it('finds the admin-only endpoint', async () => {
    const { admin, user } = await loadFixtures();
    const diff = diffCaptures([admin, user]);
    const auditLog = diff.exclusive.find((endpoint) => endpoint.templatePath === '/api/v1/admin/audit-log');
    assert.ok(auditLog, 'the audit log endpoint is admin-only');
    assert.equal(auditLog.label, 'admin');
    assert.equal(auditLog.privileged, true);
    assert.equal(auditLog.method, 'GET');
    assert.equal(auditLog.examples[0]?.status, 200);
  });

  it('does not report shared endpoints as exclusive', async () => {
    const { admin, user } = await loadFixtures();
    const diff = diffCaptures([admin, user]);
    const shared = ['/api/v1/users', '/api/v1/users/{int}', '/api/v1/documents/{uuid}'];
    for (const templatePath of shared) {
      assert.ok(diff.shared.some((signature) => signature.endsWith(templatePath)), `${templatePath} is shared`);
      assert.equal(
        diff.exclusive.some((endpoint) => endpoint.templatePath === templatePath),
        false,
        `${templatePath} must not be reported as exclusive`,
      );
    }
  });

  it('sorts privileged-exclusive endpoints first', async () => {
    const { admin, user } = await loadFixtures();
    const diff = diffCaptures([admin, user]);
    const firstNonPrivileged = diff.exclusive.findIndex((endpoint) => !endpoint.privileged);
    const lastPrivileged = diff.exclusive.reduce(
      (last, endpoint, position) => (endpoint.privileged ? position : last),
      -1,
    );
    assert.ok(lastPrivileged < firstNonPrivileged);
  });

  it('finds the role parameter the admin session sent and the user session did not', async () => {
    const { admin, user } = await loadFixtures();
    const diff = diffCaptures([admin, user]);
    const patch = diff.parameterDiffs.find(
      (entry) => entry.method === 'PATCH' && entry.templatePath === '/api/v1/users/{int}',
    );
    assert.ok(patch, 'PATCH /api/v1/users/{int} has a parameter difference');
    assert.equal(patch.label, 'admin');
    assert.equal(patch.privileged, true);
    assert.deepEqual(patch.params, [
      { name: 'org_id', location: 'request-body' },
      { name: 'role', location: 'request-body' },
    ]);
    assert.deepEqual(patch.presentIn.sort(), ['admin', 'user']);
  });

  it('does not report a parameter both captures sent', async () => {
    const { admin, user } = await loadFixtures();
    const diff = diffCaptures([admin, user]);
    const names = diff.parameterDiffs.flatMap((entry) => entry.params.map((param) => param.name));
    assert.equal(names.includes('display_name'), false, 'both captures sent display_name');
    assert.equal(names.includes('page'), false, 'both captures sent page');
  });

  it('detects a query-string parameter difference', () => {
    const a = parseHar(makeHar([{ url: 'https://api.x.test/api/reports?scope=all&format=csv' }]), { label: 'a' });
    const b = parseHar(makeHar([{ url: 'https://api.x.test/api/reports?format=csv' }]), { label: 'b' });
    const diff = diffCaptures([a, b]);
    assert.deepEqual(diff.parameterDiffs[0]?.params, [{ name: 'scope', location: 'query' }]);
  });

  it('flags the shared endpoint whose response size differs', async () => {
    const { admin, user } = await loadFixtures();
    const diff = diffCaptures([admin, user]);
    const divergence = diff.responseDiffs.find((entry) => entry.templatePath === '/api/v1/users');
    assert.ok(divergence, 'GET /api/v1/users returned different amounts of data per session');
    assert.equal(divergence.sizeDiffers, true);
    assert.equal(divergence.statusDiffers, false);
    const byLabel = new Map(divergence.observations.map((observation) => [observation.label, observation]));
    assert.ok((byLabel.get('admin')?.medianSize ?? 0) > (byLabel.get('user')?.medianSize ?? 0));
  });

  it('flags a status difference on the same signature', () => {
    const a = parseHar(makeHar([{ url: 'https://api.x.test/api/settings', status: 200, response: { ok: true } }]), {
      label: 'a',
    });
    const b = parseHar(makeHar([{ url: 'https://api.x.test/api/settings', status: 403, response: { ok: true } }]), {
      label: 'b',
    });
    const diff = diffCaptures([a, b]);
    assert.equal(diff.responseDiffs.length, 1);
    assert.equal(diff.responseDiffs[0]?.statusDiffers, true);
  });

  it('ignores response sizes that differ only trivially', () => {
    const a = parseHar(makeHar([{ url: 'https://api.x.test/api/ping', response: { pong: 'aaaaaaaaaa' } }]), { label: 'a' });
    const b = parseHar(makeHar([{ url: 'https://api.x.test/api/ping', response: { pong: 'aaaaaaaaab' } }]), { label: 'b' });
    assert.deepEqual(diffCaptures([a, b]).responseDiffs, []);
  });

  it("lists object references seen only in the admin capture's responses", async () => {
    const { admin, user } = await loadFixtures();
    const diff = diffCaptures([admin, user]);
    const values = new Set(diff.objectsOnlyIn.filter((object) => object.privileged).map((object) => object.value));
    assert.ok(values.has('8123'), "admin's own user id");
    assert.ok(values.has('9f2b4c6d-15a7-4e3b-93c8-2d7a6b41e0f5'), "admin's document uuid");
    assert.ok(values.has('dana.keeler@shopfront.test'), 'an admin-side email address');
    assert.equal(values.has('9001'), false, "the user's own id is not admin-only");
    assert.equal(values.has('41'), false, 'org_id 41 appears in both captures');
  });

  it('offers input slots for an opaque value and withholds them for a bare integer', async () => {
    const { admin, user } = await loadFixtures();
    const diff = diffCaptures([admin, user]);
    const uuid = diff.objectsOnlyIn.find((object) => object.value === '9f2b4c6d-15a7-4e3b-93c8-2d7a6b41e0f5');
    assert.ok(uuid);
    assert.ok(
      uuid.inputSlots.some((slot) => slot.includes('/api/v1/documents/{uuid}|path|4')),
      'the document uuid can be substituted into the documents path slot',
    );

    // 1240 only ever appeared as a response field ("rows"), never as an input,
    // so there is nowhere to put it - and being an integer it does not inherit
    // every other integer slot.
    const rows = diff.objectsOnlyIn.find((object) => object.value === '1240');
    assert.ok(rows);
    assert.deepEqual(rows.inputSlots, []);
  });

  it('supports an N-way diff', async () => {
    const { admin, user } = await loadFixtures();
    const manager = { ...user, label: 'manager', file: 'manager.har' };
    const diff = diffCaptures([admin, manager, user], { privilegedLabel: 'admin' });
    assert.deepEqual(
      diff.captures.map((capture) => capture.label),
      ['admin', 'manager', 'user'],
    );
    assert.equal(diff.privilegedLabel, 'admin');
    // An endpoint present in two of three captures is exclusive to neither.
    assert.equal(
      diff.exclusive.some((endpoint) => endpoint.templatePath === '/api/v1/notifications'),
      false,
    );
    assert.ok(diff.exclusive.every((endpoint) => endpoint.label === 'admin'));
  });
});
