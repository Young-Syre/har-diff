import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { classifyIdentifier, looksLikeCollection, placeholderFor, templatePath } from '../src/identifiers.js';

describe('classifyIdentifier', () => {
  it('classifies integers', () => {
    assert.equal(classifyIdentifier('8123'), 'integer');
    assert.equal(classifyIdentifier('0'), 'integer');
  });

  it('classifies UUIDs for versions 1 through 8', () => {
    const uuids = [
      ['6ba7b810-9dad-11d1-80b4-00c04fd430c8', 'v1'],
      ['000003e8-ff23-21ee-9e00-325096b39f47', 'v2'],
      ['3f2504e0-4f89-31d3-9a0c-0305e82c3301', 'v3'],
      ['9f2b4c6d-15a7-4e3b-93c8-2d7a6b41e0f5', 'v4'],
      ['74738ff5-5367-5958-9aee-98fffdcd1876', 'v5'],
      ['1ef21d2f-1207-6660-8c4f-419efbd44d48', 'v6'],
      ['018f7b9e-5e0a-7a1b-b3f6-9a7f3d2c1b0e', 'v7'],
      ['018f7b9e-5e0a-8a1b-b3f6-9a7f3d2c1b0e', 'v8'],
    ] as const;
    for (const [value, version] of uuids) {
      assert.equal(classifyIdentifier(value), 'uuid', `${version} (${value}) should classify as uuid`);
    }
  });

  it('accepts uppercase UUIDs and the nil UUID', () => {
    assert.equal(classifyIdentifier('9F2B4C6D-15A7-4E3B-93C8-2D7A6B41E0F5'), 'uuid');
    assert.equal(classifyIdentifier('00000000-0000-0000-0000-000000000000'), 'uuid');
  });

  it('does not mistake near-UUIDs for UUIDs', () => {
    // Version nibble 9 is not a defined UUID version, and the segment lengths
    // below are wrong. Both are still opaque identifiers, so they fall through
    // to base64url rather than being dropped - but neither is reported as a
    // UUID, which is what matters for substitution by shape.
    assert.equal(classifyIdentifier('9f2b4c6d-15a7-9e3b-93c8-2d7a6b41e0f5'), 'base64url');
    assert.equal(classifyIdentifier('9f2b4c6d-15a7-4e3b-93c8-2d7a6b41e0f'), 'base64url');
  });

  it('classifies ULIDs and rejects Crockford-excluded letters', () => {
    assert.equal(classifyIdentifier('01HQ3M7XK8ZJ4N5P6Q7R8S9TVW'), 'ulid');
    // I, L, O and U are not in the Crockford alphabet, and a ULID's leading
    // character is bounded to 0-7. Neither of these is reported as a ULID.
    assert.notEqual(classifyIdentifier('01HQ3M7XKIZJ4N5P6Q7R8S9TVW'), 'ulid');
    assert.notEqual(classifyIdentifier('91HQ3M7XK8ZJ4N5P6Q7R8S9TVW'), 'ulid');
  });

  it('classifies MongoDB ObjectIds', () => {
    assert.equal(classifyIdentifier('65f1c2a9b4d3e8f012345678'), 'objectid');
  });

  it('classifies long hex digests separately from ObjectIds', () => {
    assert.equal(classifyIdentifier('9f8e7d6c5b4a39281706f5e4d3c2b1a0'), 'hex');
  });

  it('classifies JWTs', () => {
    assert.equal(
      classifyIdentifier('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.FIXTURE-SIGNATURE-NOT-REAL'),
      'jwt',
    );
  });

  it('classifies emails', () => {
    assert.equal(classifyIdentifier('dana.keeler@shopfront.test'), 'email');
    assert.equal(classifyIdentifier('not-an-email'), null);
  });

  it('classifies opaque base64url values but not ordinary words', () => {
    assert.equal(classifyIdentifier('Zm9vYmFyLTEyMzQ1Njc4OQ'), 'base64url');
    assert.equal(classifyIdentifier('notifications'), null);
    // Long enough, but only one character class: not treated as an identifier.
    assert.equal(classifyIdentifier('aaaaaaaaaaaaaaaaaaaa'), null);
  });

  it('classifies slugs only in slug context', () => {
    assert.equal(classifyIdentifier('acme-corp'), null);
    assert.equal(classifyIdentifier('acme-corp', { slugContext: true }), 'slug');
    assert.equal(classifyIdentifier('acme-corp', { key: 'slug' }), 'slug');
    assert.equal(classifyIdentifier('acme-corp', { key: 'description' }), null);
  });

  it('returns null for empty values', () => {
    assert.equal(classifyIdentifier(''), null);
  });
});

describe('looksLikeCollection', () => {
  it('accepts plural path segments and rejects api versions', () => {
    assert.equal(looksLikeCollection('projects'), true);
    assert.equal(looksLikeCollection('users'), true);
    assert.equal(looksLikeCollection('v1'), false);
    assert.equal(looksLikeCollection('me'), false);
  });
});

describe('templatePath', () => {
  it('templates a numeric id segment and keeps the real value', () => {
    const result = templatePath('/api/users/8123');
    assert.equal(result.templatePath, '/api/users/{int}');
    assert.deepEqual(result.params, [{ index: 3, kind: 'integer', value: '8123', placeholder: '{int}' }]);
  });

  it('templates a UUID segment', () => {
    const result = templatePath('/api/v1/documents/9f2b4c6d-15a7-4e3b-93c8-2d7a6b41e0f5');
    assert.equal(result.templatePath, '/api/v1/documents/{uuid}');
  });

  it('templates several identifier segments in one path', () => {
    const result = templatePath('/api/v1/orgs/41/users/9f2b4c6d-15a7-4e3b-93c8-2d7a6b41e0f5/avatar');
    assert.equal(result.templatePath, '/api/v1/orgs/{int}/users/{uuid}/avatar');
    assert.equal(result.params.length, 2);
    assert.deepEqual(
      result.params.map((param) => param.kind),
      ['integer', 'uuid'],
    );
  });

  it('does not template version segments or ordinary route words', () => {
    assert.equal(templatePath('/api/v2/account/reset-password').templatePath, '/api/v2/account/reset-password');
  });

  it('templates every opaque identifier shape', () => {
    assert.equal(templatePath('/api/orders/65f1c2a9b4d3e8f012345678').templatePath, '/api/orders/{objectid}');
    assert.equal(
      templatePath('/api/exports/9f8e7d6c5b4a39281706f5e4d3c2b1a0').templatePath,
      '/api/exports/{hex}',
    );
    assert.equal(templatePath('/api/events/01HQ3M7XK8ZJ4N5P6Q7R8S9TVW').templatePath, '/api/events/{ulid}');
    assert.equal(templatePath('/api/attachments/Zm9vYmFyLTEyMzQ1Njc4OQ').templatePath, '/api/attachments/{b64}');
  });

  it('leaves slugs alone unless slug templating is requested', () => {
    assert.equal(templatePath('/api/projects/acme-corp').templatePath, '/api/projects/acme-corp');
    assert.equal(templatePath('/api/projects/acme-corp', true).templatePath, '/api/projects/{slug}');
  });

  it('preserves a trailing slash', () => {
    assert.equal(templatePath('/api/users/8123/').templatePath, '/api/users/{int}/');
  });

  it('decodes percent-encoded segments before classifying', () => {
    assert.equal(templatePath('/api/users/dana%40shopfront.test').templatePath, '/api/users/{email}');
  });

  it('exposes the placeholder for each kind', () => {
    assert.equal(placeholderFor('integer'), '{int}');
    assert.equal(placeholderFor('uuid'), '{uuid}');
  });
});
