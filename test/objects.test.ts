import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { parseHar } from '../src/har.js';
import { extractObjects, findSequentialSlots, slotKey } from '../src/objects.js';
import type { IdentifierKind, ObjectRef } from '../src/types.js';
import { loadFixtures, makeHar } from './helpers.js';

function find(refs: readonly ObjectRef[], value: string): ObjectRef {
  const ref = refs.find((candidate) => candidate.value === value);
  assert.ok(ref, `expected an object reference for ${value}`);
  return ref;
}

describe('extractObjects', () => {
  it('classifies every identifier shape present in the fixtures', async () => {
    const { admin, user } = await loadFixtures();
    const { refs } = extractObjects([admin, user]);
    const kinds = new Set(refs.map((ref) => ref.kind));
    const expected: IdentifierKind[] = [
      'integer',
      'uuid',
      'ulid',
      'objectid',
      'hex',
      'base64url',
      'email',
      'slug',
      'jwt',
    ];
    for (const kind of expected) {
      assert.ok(kinds.has(kind), `expected at least one ${kind} identifier`);
    }
  });

  it('assigns the right kind to each fixture value', async () => {
    const { admin, user } = await loadFixtures();
    const { refs } = extractObjects([admin, user]);
    assert.equal(find(refs, '8123').kind, 'integer');
    assert.equal(find(refs, '9f2b4c6d-15a7-4e3b-93c8-2d7a6b41e0f5').kind, 'uuid');
    assert.equal(find(refs, '01HQ3M7XK8ZJ4N5P6Q7R8S9TVW').kind, 'ulid');
    assert.equal(find(refs, '65f1c2a9b4d3e8f012345678').kind, 'objectid');
    assert.equal(find(refs, '9f8e7d6c5b4a39281706f5e4d3c2b1a0').kind, 'hex');
    assert.equal(find(refs, 'Zm9vYmFyLTEyMzQ1Njc4OQ').kind, 'base64url');
    assert.equal(find(refs, 'dana.keeler@shopfront.test').kind, 'email');
    assert.equal(find(refs, 'acme-corp').kind, 'slug');
  });

  it('marks integer identifiers as enumerable and opaque ones as not', async () => {
    const { admin, user } = await loadFixtures();
    const { refs } = extractObjects([admin, user]);
    assert.equal(find(refs, '8123').enumerable, true);
    assert.equal(find(refs, '9f2b4c6d-15a7-4e3b-93c8-2d7a6b41e0f5').enumerable, false);
    assert.equal(find(refs, 'acme-corp').enumerable, false);
  });

  it('records which capture and which slot each value came from', async () => {
    const { admin, user } = await loadFixtures();
    const { refs } = extractObjects([admin, user]);
    const ref = find(refs, '8123');
    const captures = new Set(ref.occurrences.map((occurrence) => occurrence.capture));
    assert.deepEqual([...captures], ['admin']);

    const pathOccurrence = ref.occurrences.find((occurrence) => occurrence.location === 'path');
    assert.ok(pathOccurrence, '8123 appears as a path segment');
    assert.equal(pathOccurrence.field, '4');
    assert.equal(pathOccurrence.slot, slotKey('GET https://api.shopfront.test/api/v1/users/{int}', 'path', '4'));

    const responseOccurrence = ref.occurrences.find((occurrence) => occurrence.location === 'response-body');
    assert.ok(responseOccurrence, '8123 also appears in a response body');
  });

  it('extracts identifiers from query strings', async () => {
    const { admin } = await loadFixtures();
    const { refs } = extractObjects([admin]);
    const cursor = find(refs, '01HQ3M7XK8ZJ4N5P6Q7R8S9TVW');
    const query = cursor.occurrences.find((occurrence) => occurrence.location === 'query');
    assert.ok(query);
    assert.equal(query.field, 'cursor');
  });

  it('extracts identifiers from request bodies', () => {
    const capture = parseHar(
      makeHar([
        {
          method: 'POST',
          url: 'https://api.example.test/api/transfers',
          headers: [{ name: 'Content-Type', value: 'application/json' }],
          body: { mimeType: 'application/json', text: JSON.stringify({ to: { account_id: 4471 } }) },
          response: { ok: true },
        },
      ]),
      { label: 'x' },
    );
    const { refs } = extractObjects([capture]);
    const ref = find(refs, '4471');
    const occurrence = ref.occurrences.find((candidate) => candidate.location === 'request-body');
    assert.ok(occurrence);
    assert.equal(occurrence.field, 'to.account_id');
  });

  it('flags values found in credential positions as sensitive', async () => {
    const { user } = await loadFixtures();
    const { refs } = extractObjects([user]);
    const jwt = refs.find((ref) => ref.kind === 'jwt');
    assert.ok(jwt, 'the user capture contains a JWT in a query parameter');
    assert.equal(jwt.sensitive, true);
  });

  it('does not treat an ordinary object id as sensitive', async () => {
    const { admin } = await loadFixtures();
    const { refs } = extractObjects([admin]);
    assert.equal(find(refs, '65f1c2a9b4d3e8f012345678').sensitive, false);
    assert.equal(find(refs, '8123').sensitive, false);
  });
});

describe('sequential integer detection', () => {
  it('calls out a consecutive, dense id slot', async () => {
    const { admin, user } = await loadFixtures();
    const { sequential } = extractObjects([admin, user]);
    const slot = sequential.find(
      (candidate) => candidate.templatePath === '/api/v1/admin/audit-log' && candidate.field === 'entries[].id',
    );
    assert.ok(slot, 'audit log entry ids form a sequential slot');
    assert.deepEqual(slot.values, [77201, 77202]);
    assert.equal(slot.span, 1);
    assert.equal(slot.consecutive, true);
    assert.equal(slot.dense, true);
  });

  it('reports the path slot that held several user ids', async () => {
    const { admin, user } = await loadFixtures();
    const { sequential } = extractObjects([admin, user]);
    const slot = sequential.find(
      (candidate) =>
        candidate.templatePath === '/api/v1/users/{int}' && candidate.location === 'path' && candidate.method === 'GET',
    );
    assert.ok(slot);
    assert.deepEqual(slot.values, [8123, 8124, 8125, 9001]);
  });

  it('ignores slots that only ever held one value', () => {
    const slots = findSequentialSlots([
      {
        value: '7',
        kind: 'integer',
        enumerable: true,
        sensitive: false,
        occurrences: [
          {
            capture: 'a',
            signature: 'GET https://x.test/api/items/{int}',
            method: 'GET',
            templatePath: '/api/items/{int}',
            location: 'path',
            field: '3',
            slot: slotKey('GET https://x.test/api/items/{int}', 'path', '3'),
          },
        ],
      },
    ]);
    assert.deepEqual(slots, []);
  });

  it('marks a wide, gappy range as neither consecutive nor dense', () => {
    const base = {
      capture: 'a',
      signature: 'GET https://x.test/api/items/{int}',
      method: 'GET',
      templatePath: '/api/items/{int}',
      location: 'path' as const,
      field: '3',
      slot: slotKey('GET https://x.test/api/items/{int}', 'path', '3'),
    };
    const slots = findSequentialSlots([
      { value: '1', kind: 'integer', enumerable: true, sensitive: false, occurrences: [base] },
      { value: '900000', kind: 'integer', enumerable: true, sensitive: false, occurrences: [base] },
    ]);
    assert.equal(slots.length, 1);
    assert.equal(slots[0]?.consecutive, false);
    assert.equal(slots[0]?.dense, false);
    assert.equal(slots[0]?.span, 899999);
  });
});
