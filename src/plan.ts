/**
 * Authorisation test plan generation.
 *
 * Turns the diff into a list of concrete replays. Each candidate says which
 * request to send, which session's credential to send it with, which object
 * reference to substitute, what a correctly-authorising server should do, and
 * what result would indicate a finding.
 *
 * Nothing here confirms anything. The plan is the work list; running it is the
 * test.
 */

import { walkJson } from './har.js';
import { isSensitiveHeader, isSensitiveKey, redactBodyString, REDACTED } from './redact.js';
import type {
  Capture,
  CanonicalRequest,
  DiffResult,
  HarHeader,
  PlanCandidate,
  PlanOptions,
  PlanRequest,
  Substitution,
  TestPlan,
} from './types.js';

/** Request headers that change how the server routes or parses the request. */
const KEEP_HEADERS: ReadonlySet<string> = new Set([
  'content-type',
  'accept',
  'accept-language',
  'x-requested-with',
  'origin',
  'referer',
]);

/** Authentication schemes safe to echo back - the scheme is not the secret. */
const AUTH_SCHEMES: ReadonlySet<string> = new Set([
  'bearer',
  'basic',
  'digest',
  'token',
  'jwt',
  'apikey',
  'ssws',
  'negotiate',
  'ntlm',
]);

export function tokenVarFor(label: string): string {
  return `HARDIFF_${label.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '')}_TOKEN`;
}

export function cookieVarFor(label: string): string {
  return `HARDIFF_${label.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '')}_COOKIE`;
}

/** "a uuid" / "an integer" - small thing, but the plan is read by people. */
function article(word: string): string {
  return /^[aeiou]/i.test(word) ? 'an' : 'a';
}

/** Keep rationales readable when a value appears across many endpoints. */
function summariseList(items: readonly string[], max = 3): string {
  if (items.length <= max) return items.join(', ');
  return `${items.slice(0, max).join(', ')} and ${items.length - max} more`;
}

function shellSingleQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Strip credential-bearing query parameters from a URL, keeping the rest. */
function sanitiseUrl(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return url;
  }
  let changed = false;
  for (const name of [...parsed.searchParams.keys()]) {
    if (isSensitiveKey(name)) {
      parsed.searchParams.set(name, REDACTED);
      changed = true;
    }
  }
  if (!changed) return url;
  return parsed.toString().replace(/%5BREDACTED%5D/gi, REDACTED);
}

function isJsonBody(contentType: string | null): boolean {
  if (contentType === null) return false;
  return contentType === 'application/json' || contentType.endsWith('+json') || contentType === 'text/json';
}

/** Replace credential values inside a body, keeping its structure intact. */
export function sanitiseBody(body: string | null, contentType: string | null): string | null {
  if (body === null || body.length === 0) return body;
  if (isJsonBody(contentType)) {
    const replaced = replaceJsonLeaves(body, (path) => (isSensitiveKey(path) ? REDACTED : undefined));
    if (replaced !== null) return replaced;
  }
  if (contentType === 'application/x-www-form-urlencoded') {
    const params = new URLSearchParams(body);
    let changed = false;
    for (const name of [...params.keys()]) {
      if (isSensitiveKey(name)) {
        params.set(name, REDACTED);
        changed = true;
      }
    }
    if (changed) return params.toString();
    return body;
  }
  return redactBodyString(body);
}

/**
 * Rewrite scalar leaves of a JSON document. `mutate` receives the dotted leaf
 * path and current value and returns a replacement, or undefined to keep it.
 * Returns null when the body is not JSON.
 */
export function replaceJsonLeaves(
  body: string,
  mutate: (path: string, value: string | number | boolean | null) => string | undefined,
): string | null {
  let root: unknown;
  try {
    root = JSON.parse(body) as unknown;
  } catch {
    return null;
  }

  const visit = (value: unknown, path: string): unknown => {
    if (Array.isArray(value)) return value.map((item) => visit(item, `${path}[]`));
    if (typeof value === 'object' && value !== null) {
      const out: Record<string, unknown> = {};
      for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
        out[key] = visit(child, path === '' ? key : `${path}.${key}`);
      }
      return out;
    }
    const replacement = mutate(path, value as string | number | boolean | null);
    return replacement === undefined ? value : replacement;
  };

  return JSON.stringify(visit(root, ''));
}

interface ReplayHeaderPlan {
  headers: HarHeader[];
  curlHeaders: string[];
  notes: string[];
}

function planHeaders(request: CanonicalRequest, replayLabel: string): ReplayHeaderPlan {
  const headers: HarHeader[] = [];
  const curlHeaders: string[] = [];
  const notes: string[] = [];

  for (const header of request.requestHeaders) {
    const lower = header.name.toLowerCase();
    if (!KEEP_HEADERS.has(lower)) continue;
    headers.push({ name: header.name, value: header.value });
    curlHeaders.push(`-H ${shellSingleQuote(`${header.name}: ${header.value}`)}`);
  }

  const authHeader = request.requestHeaders.find((header) => header.name.toLowerCase() === 'authorization');
  const cookieHeader = request.requestHeaders.find((header) => header.name.toLowerCase() === 'cookie');
  const apiKeyHeader = request.requestHeaders.find(
    (header) => isSensitiveHeader(header.name) && !['authorization', 'cookie'].includes(header.name.toLowerCase()),
  );

  const tokenVar = tokenVarFor(replayLabel);
  const cookieVar = cookieVarFor(replayLabel);

  if (authHeader !== undefined) {
    const firstWord = authHeader.value.trim().split(/\s+/, 1)[0] ?? '';
    const scheme = AUTH_SCHEMES.has(firstWord.toLowerCase()) ? firstWord : 'Bearer';
    headers.push({ name: 'Authorization', value: `${scheme} $${tokenVar}` });
    curlHeaders.push(`-H "Authorization: ${scheme} $${tokenVar}"`);
  }
  if (cookieHeader !== undefined) {
    headers.push({ name: 'Cookie', value: `$${cookieVar}` });
    curlHeaders.push(`-H "Cookie: $${cookieVar}"`);
  }
  if (apiKeyHeader !== undefined) {
    headers.push({ name: apiKeyHeader.name, value: `$${tokenVar}` });
    curlHeaders.push(`-H "${apiKeyHeader.name}: $${tokenVar}"`);
  }
  if (authHeader === undefined && cookieHeader === undefined && apiKeyHeader === undefined) {
    headers.push({ name: 'Cookie', value: `$${cookieVar}` });
    curlHeaders.push(`-H "Cookie: $${cookieVar}"`);
    notes.push(
      'No credential header was recorded for this request. If the session is carried by a cookie the capture omitted, set the cookie variable; if the endpoint is genuinely unauthenticated, that is itself worth checking.',
    );
  }

  return { headers, curlHeaders, notes };
}

function buildCurl(method: string, url: string, curlHeaders: readonly string[], body: string | null): string {
  const parts = ['curl', '-i', '-s', '-X', method, shellSingleQuote(url), ...curlHeaders];
  if (body !== null && body.length > 0) parts.push('--data-raw', shellSingleQuote(body));
  return parts.join(' ');
}

interface SubstitutionTarget {
  location: Substitution['location'];
  field: string;
  from: string;
}

/** Apply one value substitution to a request, returning the new url/body. */
export function applySubstitution(
  request: CanonicalRequest,
  target: SubstitutionTarget,
  to: string,
): { url: string; body: string | null } {
  let url = request.url;
  let body = request.requestBody;

  if (target.location === 'path') {
    const index = Number.parseInt(target.field, 10);
    try {
      const parsed = new URL(url);
      const segments = parsed.pathname.split('/');
      if (Number.isInteger(index) && index >= 0 && index < segments.length) {
        segments[index] = encodeURIComponent(to);
        parsed.pathname = segments.join('/');
        url = parsed.toString();
      }
    } catch {
      /* leave url unchanged */
    }
  } else if (target.location === 'query') {
    try {
      const parsed = new URL(url);
      if (parsed.searchParams.has(target.field)) {
        parsed.searchParams.set(target.field, to);
        url = parsed.toString();
      }
    } catch {
      /* leave url unchanged */
    }
  } else if (target.location === 'request-body' && body !== null) {
    const rewritten = replaceJsonLeaves(body, (path, value) =>
      path === target.field && String(value) === target.from ? to : undefined,
    );
    if (rewritten !== null) {
      body = rewritten;
    } else if (request.requestContentType === 'application/x-www-form-urlencoded') {
      const params = new URLSearchParams(body);
      if (params.get(target.field) === target.from) {
        params.set(target.field, to);
        body = params.toString();
      }
    }
  }

  return { url, body };
}

function requestIndex(captures: readonly Capture[]): Map<string, Map<string, CanonicalRequest[]>> {
  const index = new Map<string, Map<string, CanonicalRequest[]>>();
  for (const capture of captures) {
    const bySignature = new Map<string, CanonicalRequest[]>();
    for (const request of capture.requests) {
      const existing = bySignature.get(request.signature);
      if (existing === undefined) bySignature.set(request.signature, [request]);
      else existing.push(request);
    }
    index.set(capture.label, bySignature);
  }
  return index;
}

function parseSlot(slot: string): { signature: string; location: Substitution['location']; field: string } | null {
  const first = slot.indexOf('|');
  const second = slot.indexOf('|', first + 1);
  if (first === -1 || second === -1) return null;
  return {
    signature: slot.slice(0, first),
    location: slot.slice(first + 1, second) as Substitution['location'],
    field: slot.slice(second + 1),
  };
}

/**
 * Build an authorisation test plan from a diff.
 *
 * `captures` must be the same captures the diff was built from - the plan needs
 * the original request shapes to emit replayable commands.
 */
export function buildPlan(captures: readonly Capture[], diff: DiffResult, options: PlanOptions = {}): TestPlan {
  const limitPerKind = options.limitPerKind ?? 50;
  const neighbours = options.enumerateNeighbours ?? 3;
  const index = requestIndex(captures);
  const labels = captures.map((capture) => capture.label);
  const otherLabels = labels.filter((label) => label !== diff.privilegedLabel);

  const candidates: PlanCandidate[] = [];
  const counters = new Map<PlanCandidate['kind'], number>();
  let nextId = 1;

  const emit = (candidate: Omit<PlanCandidate, 'id'>): void => {
    const used = counters.get(candidate.kind) ?? 0;
    if (used >= limitPerKind) return;
    counters.set(candidate.kind, used + 1);
    candidates.push({ id: `HD-${String(nextId).padStart(3, '0')}`, ...candidate });
    nextId += 1;
  };

  const makeRequest = (
    request: CanonicalRequest,
    replayLabel: string,
    url: string,
    body: string | null,
  ): { plan: PlanRequest; curl: string; notes: string[] } => {
    const headerPlan = planHeaders(request, replayLabel);
    const safeUrl = sanitiseUrl(url);
    const safeBody = sanitiseBody(body, request.requestContentType);
    return {
      plan: { method: request.method, url: safeUrl, headers: headerPlan.headers, body: safeBody },
      curl: buildCurl(request.method, safeUrl, headerPlan.curlHeaders, safeBody),
      notes: headerPlan.notes,
    };
  };

  // --- 1. endpoints only the privileged session touched ------------------
  for (const endpoint of diff.exclusive) {
    if (!endpoint.privileged) continue;
    const requests = index.get(endpoint.label)?.get(endpoint.signature) ?? [];
    const base = requests[0];
    if (base === undefined) continue;
    for (const replayLabel of otherLabels) {
      const built = makeRequest(base, replayLabel, base.url, base.requestBody);
      emit({
        kind: 'privileged-only-endpoint',
        title: `${endpoint.method} ${endpoint.templatePath} - replay as ${replayLabel}`,
        rationale:
          `Observed in the "${endpoint.label}" capture only; the "${replayLabel}" capture never requested it. ` +
          `The ${replayLabel} session may still be authorised to call it.` +
          (built.notes.length > 0 ? ` ${built.notes.join(' ')}` : ''),
        request: built.plan,
        replayAs: replayLabel,
        sourceCapture: endpoint.label,
        substitutions: [],
        expected: `401, 403 or 404 for the ${replayLabel} session.`,
        indicatesFinding:
          `A 2xx response, or any response carrying ${endpoint.label}-scoped data, indicates missing function-level ` +
          `authorisation (BFLA). Compare the body against what ${endpoint.label} received, not just the status code.`,
        curl: built.curl,
        evidence: endpoint.examples,
      });
    }
  }

  // --- 2. object reference substitution ---------------------------------
  const substituted = new Set<string>();
  for (const object of diff.objectsOnlyIn) {
    if (object.sensitive) continue;
    if (!object.privileged) continue;
    for (const slot of object.inputSlots) {
      const parsed = parseSlot(slot);
      if (parsed === null) continue;
      if (parsed.location === 'response-body' || parsed.location === 'header') continue;

      // Prefer a non-privileged request on the same endpoint: that is exactly
      // "the low-privilege session asking for the privileged object".
      const owner = otherLabels.find((label) => (index.get(label)?.get(parsed.signature)?.length ?? 0) > 0);
      const replayLabel = owner ?? otherLabels[0];
      if (replayLabel === undefined) continue;
      const sourceLabel = owner ?? diff.privilegedLabel;
      const base = index.get(sourceLabel)?.get(parsed.signature)?.[0];
      if (base === undefined) continue;

      const from = currentSlotValue(base, parsed.location, parsed.field);
      if (from === null || from === object.value) continue;
      const dedupe = `${slot}=>${object.value}`;
      if (substituted.has(dedupe)) continue;
      substituted.add(dedupe);

      const applied = applySubstitution(base, { location: parsed.location, field: parsed.field, from }, object.value);
      const built = makeRequest(base, replayLabel, applied.url, applied.body);
      emit({
        kind: 'object-reference-substitution',
        title: `${base.method} ${base.templatePath} - substitute ${object.kind} ${object.value} (${parsed.location}:${parsed.field})`,
        rationale:
          `${object.value} appeared only in the "${object.label}" capture's responses (${summariseList(object.seenIn)}). ` +
          `${base.method} ${base.templatePath} accepts ${article(object.kind)} ${object.kind} at ${parsed.location}:${parsed.field}, ` +
          `so the ${replayLabel} session can be made to ask for it.`,
        request: built.plan,
        replayAs: replayLabel,
        sourceCapture: sourceLabel,
        substitutions: [{ location: parsed.location, field: parsed.field, from, to: object.value }],
        expected: `401, 403 or 404 - the ${replayLabel} session has no relationship to that object.`,
        indicatesFinding:
          `A 2xx response containing the object's attributes is an IDOR/BOLA finding. A 200 with an empty list or a ` +
          `null body is not: confirm the response actually discloses ${object.label}'s data.`,
        curl: built.curl,
        evidence: [],
      });
    }
  }

  // --- 3. parameters only the privileged session sent -------------------
  for (const diffEntry of diff.parameterDiffs) {
    if (!diffEntry.privileged) continue;
    const base = index.get(diffEntry.label)?.get(diffEntry.signature)?.[0];
    if (base === undefined) continue;
    const replayLabel = otherLabels.find((label) => diffEntry.presentIn.includes(label)) ?? otherLabels[0];
    if (replayLabel === undefined) continue;
    const built = makeRequest(base, replayLabel, base.url, base.requestBody);
    const names = diffEntry.params.map((param) => `${param.location}:${param.name}`).join(', ');
    emit({
      kind: 'privileged-only-parameter',
      title: `${diffEntry.method} ${diffEntry.templatePath} - send ${names} as ${replayLabel}`,
      rationale:
        `Both captures use this endpoint, but only "${diffEntry.label}" sent ${names}. ` +
        `If the server binds that parameter without re-checking the caller's role, the ${replayLabel} session can set it too.`,
      request: built.plan,
      replayAs: replayLabel,
      sourceCapture: diffEntry.label,
      substitutions: diffEntry.params.map((param) => ({
        location: param.location === 'query' ? ('query' as const) : ('request-body' as const),
        field: param.name,
        from: '(absent)',
        to: currentSlotValue(base, param.location === 'query' ? 'query' : 'request-body', param.name) ?? '(see capture)',
      })),
      expected: `The parameter is ignored or rejected, and the stored object is unchanged.`,
      indicatesFinding:
        `If the response reflects the parameter, or a follow-up read shows it was persisted, this is mass assignment / ` +
        `privilege escalation via parameter binding. Re-read the object as ${diffEntry.label} to confirm it stuck.`,
      curl: built.curl,
      evidence: [],
    });
  }

  // --- 4. enumerable integer identifiers --------------------------------
  for (const slot of diff.objects.sequential) {
    const parsed = parseSlot(slot.slot);
    if (parsed === null) continue;
    if (parsed.location === 'response-body' || parsed.location === 'header') continue;
    const owner = otherLabels.find((label) => (index.get(label)?.get(parsed.signature)?.length ?? 0) > 0);
    const sourceLabel = owner ?? diff.privilegedLabel;
    const base = index.get(sourceLabel)?.get(parsed.signature)?.[0];
    if (base === undefined) continue;
    const replayLabel = owner ?? otherLabels[0] ?? diff.privilegedLabel;

    const from = currentSlotValue(base, parsed.location, parsed.field);
    if (from === null) continue;
    const anchor = Number.parseInt(from, 10);
    if (!Number.isSafeInteger(anchor)) continue;
    const targets: number[] = [];
    for (let step = neighbours; step >= 1; step -= 1) {
      if (anchor - step > 0) targets.push(anchor - step);
    }
    for (let step = 1; step <= neighbours; step += 1) targets.push(anchor + step);
    const probe = targets[0];
    if (probe === undefined) continue;

    const applied = applySubstitution(base, { location: parsed.location, field: parsed.field, from }, String(probe));
    const built = makeRequest(base, replayLabel, applied.url, applied.body);
    emit({
      kind: 'enumerable-identifier',
      title: `${base.method} ${base.templatePath} - walk integer ids at ${parsed.location}:${parsed.field}`,
      rationale:
        `Integer ids observed in this slot: ${slot.values.join(', ')} (span ${slot.span}` +
        `${slot.consecutive ? ', consecutive' : ''}${slot.dense ? ', dense' : ''}). ` +
        `An integer object reference needs no leaked value to attack - it can be counted to.`,
      request: built.plan,
      replayAs: replayLabel,
      sourceCapture: sourceLabel,
      substitutions: [{ location: parsed.location, field: parsed.field, from, to: targets.join(', ') }],
      expected: `401, 403 or 404 for every id the ${replayLabel} session does not own.`,
      indicatesFinding:
        `Any id outside the session's own objects that returns 2xx with content is an IDOR. Sweep a contiguous range ` +
        `rather than a single neighbour; ids adjacent to your own often belong to the same tenant and prove nothing.`,
      curl: built.curl,
      evidence: [],
    });
  }

  // --- 5. same endpoint, divergent responses ----------------------------
  for (const divergence of diff.responseDiffs) {
    const base = index.get(diff.privilegedLabel)?.get(divergence.signature)?.[0];
    if (base === undefined) continue;
    const replayLabel = otherLabels[0];
    if (replayLabel === undefined) continue;
    const built = makeRequest(base, replayLabel, base.url, base.requestBody);
    const summary = divergence.observations
      .map((observation) => `${observation.label}: status ${observation.statuses.join('/')}, ~${observation.medianSize}B`)
      .join('; ');
    emit({
      kind: 'response-divergence',
      title: `${divergence.method} ${divergence.templatePath} - compare responses across sessions`,
      rationale:
        `The same endpoint answered differently per session (${summary}). That is usually just different data, but it ` +
        `is also what a server looks like when it returns more to one role than another from the same request.`,
      request: built.plan,
      replayAs: replayLabel,
      sourceCapture: diff.privilegedLabel,
      substitutions: [],
      expected: `The ${replayLabel} session receives only its own scope, matching what it received in its own capture.`,
      indicatesFinding:
        `A response closer in size and shape to the ${diff.privilegedLabel} body than to the ${replayLabel} body suggests ` +
        `the endpoint keys off the request rather than the session. Diff the bodies field by field.`,
      curl: built.curl,
      evidence: divergence.observations.map((observation) => ({
        capture: observation.label,
        url: index.get(observation.label)?.get(divergence.signature)?.[0]?.url ?? divergence.templatePath,
        status: observation.statuses[0] ?? 0,
        responseSize: observation.medianSize,
      })),
    });
  }

  const credentialPlaceholders: Record<string, string> = {};
  for (const label of labels) {
    credentialPlaceholders[label] = `${tokenVarFor(label)} / ${cookieVarFor(label)}`;
  }

  return {
    captures: diff.captures,
    privilegedLabel: diff.privilegedLabel,
    credentialPlaceholders,
    candidates,
    notes: planNotes(diff, otherLabels),
  };
}

function planNotes(diff: DiffResult, otherLabels: readonly string[]): string[] {
  const notes = [
    'Every item below is a candidate, not a finding. A candidate becomes a finding only when you replay it and the response discloses or mutates data the replaying session should not reach.',
    'Set the credential environment variables before running any command; the plan never contains a real token.',
    'Replay in a session you are authorised to test, against an environment you are authorised to test.',
  ];
  if (otherLabels.length === 0) {
    notes.push('Only one capture label was supplied, so no cross-privilege replay could be derived.');
  }
  const nonPrivilegedExclusive = diff.exclusive.filter((endpoint) => !endpoint.privileged).length;
  if (nonPrivilegedExclusive > 0) {
    notes.push(
      `${nonPrivilegedExclusive} endpoint(s) were exclusive to a non-privileged capture. They are listed by \`diff\` but ` +
        'are not replay candidates here: the privileged session is assumed to already be authorised for them.',
    );
  }
  return notes;
}

/** The value currently occupying a slot in a given request, if any. */
export function currentSlotValue(
  request: CanonicalRequest,
  location: Substitution['location'],
  field: string,
): string | null {
  if (location === 'path') {
    const index = Number.parseInt(field, 10);
    const segments = request.path.split('/');
    if (!Number.isInteger(index) || index < 0 || index >= segments.length) return null;
    const segment = segments[index];
    return segment === undefined || segment === '' ? null : decodeURIComponent(segment);
  }
  if (location === 'query') {
    const param = request.query.find((candidate) => candidate.name === field);
    return param === undefined ? null : param.value;
  }
  if (location === 'request-body') {
    const param = request.bodyParams.find((candidate) => candidate.name === field);
    if (param !== undefined) return param.value;
    if (request.requestBody === null) return null;
    for (const leaf of walkJson(safeJson(request.requestBody))) {
      if (leaf.path === field && leaf.value !== null) return String(leaf.value);
    }
    return null;
  }
  return null;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return {};
  }
}
