import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { diffCaptures } from '../src/diff.js';
import { applySubstitution, buildPlan, cookieVarFor, sanitiseBody, tokenVarFor } from '../src/plan.js';
import type { PlanCandidate, TestPlan } from '../src/types.js';
import { loadFixtures } from './helpers.js';

async function fixturePlan(): Promise<TestPlan> {
  const { admin, user } = await loadFixtures();
  return buildPlan([admin, user], diffCaptures([admin, user]));
}

function ofKind(plan: TestPlan, kind: PlanCandidate['kind']): PlanCandidate[] {
  return plan.candidates.filter((candidate) => candidate.kind === kind);
}

describe('buildPlan', () => {
  it('produces candidates of every kind the fixtures support', async () => {
    const plan = await fixturePlan();
    assert.ok(plan.candidates.length > 0);
    for (const kind of [
      'privileged-only-endpoint',
      'privileged-only-parameter',
      'object-reference-substitution',
      'enumerable-identifier',
      'response-divergence',
    ] as const) {
      assert.ok(ofKind(plan, kind).length > 0, `expected at least one ${kind} candidate`);
    }
  });

  it('gives every candidate a unique, ordered id', async () => {
    const plan = await fixturePlan();
    const ids = plan.candidates.map((candidate) => candidate.id);
    assert.equal(new Set(ids).size, ids.length);
    assert.equal(ids[0], 'HD-001');
    assert.match(ids[ids.length - 1] ?? '', /^HD-\d{3}$/);
  });

  it('plans a replay of the admin-only endpoint with the user credential', async () => {
    const plan = await fixturePlan();
    const candidate = ofKind(plan, 'privileged-only-endpoint').find((entry) =>
      entry.request.url.includes('/api/v1/admin/audit-log'),
    );
    assert.ok(candidate);
    assert.equal(candidate.replayAs, 'user');
    assert.equal(candidate.sourceCapture, 'admin');
    assert.equal(candidate.request.method, 'GET');
    assert.match(candidate.expected, /401, 403 or 404/);
    assert.match(candidate.indicatesFinding, /function-level authorisation/);
  });

  it('plans the object-reference substitution against the user request shape', async () => {
    const plan = await fixturePlan();
    const candidate = ofKind(plan, 'object-reference-substitution').find(
      (entry) => entry.substitutions[0]?.to === '8123',
    );
    assert.ok(candidate, 'admin user id 8123 is substituted into a user request');
    assert.equal(candidate.replayAs, 'user');
    assert.equal(candidate.sourceCapture, 'user');
    assert.deepEqual(candidate.substitutions, [{ location: 'path', field: '4', from: '9001', to: '8123' }]);
    assert.ok(candidate.request.url.endsWith('/api/v1/users/8123'));
    assert.equal(candidate.request.url.includes('9001'), false, 'the original id is gone from the replay url');
  });

  it('substitutes a uuid into the path of the document endpoint', async () => {
    const plan = await fixturePlan();
    const candidate = ofKind(plan, 'object-reference-substitution').find(
      (entry) => entry.substitutions[0]?.to === '9f2b4c6d-15a7-4e3b-93c8-2d7a6b41e0f5',
    );
    assert.ok(candidate);
    assert.ok(candidate.request.url.endsWith('/api/v1/documents/9f2b4c6d-15a7-4e3b-93c8-2d7a6b41e0f5'));
  });

  it('carries the admin-only body parameters into the mass-assignment candidate', async () => {
    const plan = await fixturePlan();
    const candidate = ofKind(plan, 'privileged-only-parameter')[0];
    assert.ok(candidate);
    assert.equal(candidate.replayAs, 'user');
    assert.deepEqual(
      candidate.substitutions.map((substitution) => substitution.field).sort(),
      ['org_id', 'role'],
    );
    assert.match(candidate.request.body ?? '', /"role"\s*:\s*"billing"/);
    assert.match(candidate.indicatesFinding, /mass assignment/);
  });

  it('suggests a contiguous range for an enumerable integer slot', async () => {
    const plan = await fixturePlan();
    const candidate = ofKind(plan, 'enumerable-identifier').find((entry) =>
      entry.title.startsWith('GET /api/v1/users/{int}'),
    );
    assert.ok(candidate);
    const substitution = candidate.substitutions[0];
    assert.ok(substitution);
    assert.equal(substitution.from, '9001');
    assert.deepEqual(substitution.to.split(', '), ['8998', '8999', '9000', '9002', '9003', '9004']);
  });

  it('honours the per-kind candidate limit', async () => {
    const { admin, user } = await loadFixtures();
    const plan = buildPlan([admin, user], diffCaptures([admin, user]), { limitPerKind: 1 });
    for (const kind of new Set(plan.candidates.map((candidate) => candidate.kind))) {
      assert.equal(ofKind(plan, kind).length, 1, `${kind} should be capped at one candidate`);
    }
  });

  it('honours the neighbour count', async () => {
    const { admin, user } = await loadFixtures();
    const plan = buildPlan([admin, user], diffCaptures([admin, user]), { enumerateNeighbours: 1 });
    const candidate = ofKind(plan, 'enumerable-identifier')[0];
    assert.equal(candidate?.substitutions[0]?.to.split(', ').length, 2);
  });

  it('names a credential variable per capture and never an actual token', async () => {
    const plan = await fixturePlan();
    assert.deepEqual(Object.keys(plan.credentialPlaceholders), ['admin', 'user']);
    assert.match(plan.credentialPlaceholders['user'] ?? '', /HARDIFF_USER_TOKEN/);
    assert.equal(tokenVarFor('low priv'), 'HARDIFF_LOW_PRIV_TOKEN');
    assert.equal(cookieVarFor('admin'), 'HARDIFF_ADMIN_COOKIE');
  });

  it('states up front that candidates are not findings', async () => {
    const plan = await fixturePlan();
    assert.match(plan.notes.join(' '), /candidate, not a finding/);
  });
});

describe('curl emission', () => {
  it('uses the replay session variable in the Authorization header', async () => {
    const plan = await fixturePlan();
    for (const candidate of plan.candidates) {
      assert.match(
        candidate.curl,
        new RegExp(`\\$HARDIFF_${candidate.replayAs.toUpperCase()}_(TOKEN|COOKIE)`),
        `${candidate.id} should reference the ${candidate.replayAs} credential variable`,
      );
      assert.equal(
        candidate.curl.includes('$HARDIFF_ADMIN_TOKEN'),
        false,
        `${candidate.id} must not replay with the privileged credential`,
      );
    }
  });

  it('single-quotes the url and keeps the method explicit', async () => {
    const plan = await fixturePlan();
    const candidate = plan.candidates[0];
    assert.ok(candidate);
    assert.match(candidate.curl, /^curl -i -s -X [A-Z]+ '/);
  });

  it('sends a body only for requests that had one', async () => {
    const plan = await fixturePlan();
    for (const candidate of plan.candidates) {
      const hasBody = candidate.request.body !== null && candidate.request.body.length > 0;
      assert.equal(candidate.curl.includes('--data-raw'), hasBody, `${candidate.id} body handling`);
    }
  });
});

describe('applySubstitution', () => {
  it('replaces a path segment, a query value and a nested body field', async () => {
    const { admin, user } = await loadFixtures();

    const get = user.requests.find((request) => request.templatePath === '/api/v1/users/{int}');
    assert.ok(get);
    assert.equal(
      applySubstitution(get, { location: 'path', field: '4', from: '9001' }, '8123').url,
      'https://api.shopfront.test/api/v1/users/8123',
    );

    const events = admin.requests.find((request) => request.templatePath === '/api/v1/events');
    assert.ok(events);
    const requeried = applySubstitution(
      events,
      { location: 'query', field: 'cursor', from: '01HQ3M7XK8ZJ4N5P6Q7R8S9TVW' },
      '01HQ3M7XK8ZJ4N5P6Q7R8S9TVX',
    );
    assert.match(requeried.url, /cursor=01HQ3M7XK8ZJ4N5P6Q7R8S9TVX/);
    assert.match(requeried.url, /limit=20/, 'other query parameters survive');

    const patch = admin.requests.find((request) => request.method === 'PATCH');
    assert.ok(patch);
    const rebodied = applySubstitution(patch, { location: 'request-body', field: 'org_id', from: '41' }, '99');
    assert.equal(JSON.parse(rebodied.body ?? '{}').org_id, '99');
  });

  it('leaves the request alone when the slot does not exist', async () => {
    const { user } = await loadFixtures();
    const request = user.requests[0];
    assert.ok(request);
    const result = applySubstitution(request, { location: 'query', field: 'nope', from: 'x' }, 'y');
    assert.equal(result.url, request.url);
  });
});

describe('sanitiseBody', () => {
  it('redacts credential fields in a JSON body and keeps the rest', () => {
    const body = sanitiseBody(
      JSON.stringify({ email: 'sam@x.test', password: 'hunter2', nested: { api_key: 'abc123xyz' } }),
      'application/json',
    );
    assert.ok(body);
    const parsed = JSON.parse(body) as Record<string, unknown>;
    assert.equal(parsed['email'], 'sam@x.test');
    assert.equal(parsed['password'], '[REDACTED]');
    assert.equal((parsed['nested'] as Record<string, unknown>)['api_key'], '[REDACTED]');
  });

  it('redacts credential fields in a form body', () => {
    const body = sanitiseBody('username=sam&password=hunter2', 'application/x-www-form-urlencoded');
    assert.equal(body, 'username=sam&password=%5BREDACTED%5D');
  });

  it('passes through an empty body', () => {
    assert.equal(sanitiseBody(null, 'application/json'), null);
  });
});
