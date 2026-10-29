/**
 * HAR 1.2 parsing and normalisation.
 *
 * The goal is a canonical request shape that makes two captures of the same
 * application comparable: identifier segments templated out of the path,
 * parameter names sorted, and everything credential-shaped recorded so it can
 * be stripped from output.
 */

import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';

import { classifyIdentifier, safeDecode, templatePath } from './identifiers.js';
import { isSensitiveHeader, isSensitiveKey, looksLikeSecret } from './redact.js';
import type {
  BodyParam,
  Capture,
  CanonicalRequest,
  HarHeader,
  ParseOptions,
  QueryParam,
} from './types.js';

const DEFAULT_MAX_DEPTH = 8;
const DEFAULT_MAX_BODY_BYTES = 1_000_000;

const DEFAULT_PORTS: Record<string, number> = { 'http:': 80, 'https:': 443, 'ws:': 80, 'wss:': 443 };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function readNameValuePairs(value: unknown): { name: string; value: string }[] {
  if (!Array.isArray(value)) return [];
  const out: { name: string; value: string }[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const name = asString(item['name']);
    if (name === null) continue;
    out.push({ name, value: asString(item['value']) ?? '' });
  }
  return out;
}

function contentTypeOf(headers: readonly HarHeader[], fallback: string | null): string | null {
  for (const header of headers) {
    if (header.name.toLowerCase() === 'content-type') {
      return normaliseContentType(header.value);
    }
  }
  return fallback === null ? null : normaliseContentType(fallback);
}

function normaliseContentType(value: string): string {
  const semicolon = value.indexOf(';');
  const base = semicolon === -1 ? value : value.slice(0, semicolon);
  return base.trim().toLowerCase();
}

function isJsonContentType(contentType: string | null): boolean {
  if (contentType === null) return false;
  return contentType === 'application/json' || contentType.endsWith('+json') || contentType === 'text/json';
}

function isFormContentType(contentType: string | null): boolean {
  return contentType === 'application/x-www-form-urlencoded';
}

/** A scalar leaf found while walking a JSON document. */
export interface JsonLeaf {
  /** Dotted path with `[]` for array membership, e.g. `user.roles[]`. */
  path: string;
  value: string | number | boolean | null;
}

/**
 * Walk a parsed JSON value and yield every scalar leaf with its dotted path.
 * Array indices collapse to `[]` so that `items[0].id` and `items[1].id` share
 * one parameter name - otherwise a list of fifty results produces fifty
 * distinct "parameters".
 */
export function walkJson(root: unknown, maxDepth = DEFAULT_MAX_DEPTH): JsonLeaf[] {
  const leaves: JsonLeaf[] = [];
  // Ancestors on the current path, not everything visited. A cycle is only a
  // cycle if the value is its own ancestor; a global visited set also drops
  // *shared* references, so `{a: shared, b: shared}` reported only `a`'s
  // leaves. Every call site inside this package passes JSON.parse output,
  // which can have both and neither, but walkJson is exported and takes
  // `unknown`.
  const ancestors = new Set<object>();

  const visit = (value: unknown, path: string, depth: number): void => {
    if (depth > maxDepth) return;
    if (Array.isArray(value) || isRecord(value)) {
      if (ancestors.has(value)) return;
      ancestors.add(value);
      if (Array.isArray(value)) {
        for (const item of value) visit(item, `${path}[]`, depth + 1);
      } else {
        for (const [key, child] of Object.entries(value)) {
          visit(child, path === '' ? key : `${path}.${key}`, depth + 1);
        }
      }
      ancestors.delete(value);
      return;
    }
    if (value === undefined) return;
    leaves.push({ path, value: value as string | number | boolean | null });
  };

  visit(root, '', 0);
  return leaves;
}

function leafToString(value: string | number | boolean | null): string | null {
  if (value === null) return null;
  return String(value);
}

/**
 * Credential-named query values inside a URL written in a header value.
 * Returns nothing when the value is not a URL, which is the common case.
 */
function sensitiveQueryValues(value: string): string[] {
  if (!/^https?:\/\//i.test(value.trim())) return [];
  let parsed: URL;
  try {
    parsed = new URL(value.trim());
  } catch {
    return [];
  }
  const found: string[] = [];
  for (const [name, param] of parsed.searchParams) {
    if (param !== '' && (isSensitiveKey(name) || looksLikeSecret(param))) found.push(param);
  }
  return found;
}

/**
 * The boundary of a multipart body: from the content type when it carries one,
 * otherwise from the body's own opening delimiter.
 *
 * The fallback is not a nicety. A canonical request keeps the content type
 * without its parameters, so by the time a body reaches the plan the boundary
 * is only still present in the body itself.
 */
export function multipartBoundary(body: string, contentType: string | null): string | null {
  if (contentType !== null) {
    const match = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(contentType);
    const declared = match?.[1] ?? match?.[2];
    if (declared !== undefined && declared !== '') return declared;
  }
  const first = /^--(\S+?)(--)?\r?(?:\n|$)/.exec(body);
  const observed = first?.[1];
  return observed === undefined || observed === '' ? null : observed;
}

interface MultipartPart {
  readonly name: string;
  readonly value: string;
}

/**
 * Split a multipart body into its named parts. Returns null when the content
 * type is not multipart or carries no boundary.
 *
 * This is a reader for a captured body, not a conformant parser: a part whose
 * name cannot be read is skipped rather than guessed at, and a file part's
 * bytes are treated as its value so that a credential pasted into one is still
 * seen.
 */
function multipartParts(body: string, contentType: string | null): MultipartPart[] | null {
  if (contentType === null || !contentType.toLowerCase().startsWith('multipart/')) return null;
  const boundary = multipartBoundary(body, contentType);
  if (boundary === null) return null;

  const parts: MultipartPart[] = [];
  for (const chunk of body.split(`--${boundary}`)) {
    const trimmed = chunk.replace(/^\r?\n/, '');
    if (trimmed === '' || trimmed.startsWith('--')) continue;
    const split = /\r?\n\r?\n/.exec(trimmed);
    if (split === null) continue;
    const head = trimmed.slice(0, split.index);
    const value = trimmed.slice(split.index + split[0].length).replace(/\r?\n$/, '');
    const nameMatch = /name=(?:"([^"]*)"|([^;\r\n]+))/i.exec(head);
    const name = nameMatch?.[1] ?? nameMatch?.[2];
    if (name === undefined || name === '') continue;
    parts.push({ name, value });
  }
  return parts;
}

interface BodyAnalysis {
  params: BodyParam[];
  secrets: string[];
}

function analyseBody(
  body: string | null,
  contentType: string | null,
  formParams: readonly QueryParam[],
  maxDepth: number,
  maxBodyBytes: number,
): BodyAnalysis {
  const params: BodyParam[] = [];
  const secrets: string[] = [];

  const record = (name: string, value: string | null, encoding: BodyParam['encoding']): void => {
    params.push({ name, value, encoding });
    if (value === null) return;
    if (isSensitiveKey(name) || looksLikeSecret(value)) secrets.push(value);
  };

  if (formParams.length > 0) {
    for (const param of formParams) record(param.name, param.value, 'form');
  }

  if (body === null || body.length === 0) return { params, secrets };
  if (body.length > maxBodyBytes) return { params, secrets };

  if (isJsonContentType(contentType)) {
    const parsed = tryParseJson(body);
    if (parsed.ok) {
      for (const leaf of walkJson(parsed.value, maxDepth)) {
        if (leaf.path === '') continue;
        record(leaf.path, leafToString(leaf.value), 'json');
      }
      return { params, secrets };
    }
  }

  if (isFormContentType(contentType) && formParams.length === 0) {
    for (const [name, value] of new URLSearchParams(body)) record(name, value, 'form');
    return { params, secrets };
  }

  // multipart/form-data writes its field names in a Content-Disposition
  // header rather than as key=value, so neither the JSON walk nor the
  // URLSearchParams pass sees them, and a password in a multipart login form
  // reached the plan in plaintext.
  const multipart = multipartParts(body, contentType);
  if (multipart !== null) {
    for (const part of multipart) record(part.name, part.value, 'form');
    return { params, secrets };
  }

  // Unknown content type: try JSON anyway, since plenty of APIs mislabel it.
  if (formParams.length === 0) {
    const parsed = tryParseJson(body);
    if (parsed.ok && (isRecord(parsed.value) || Array.isArray(parsed.value))) {
      for (const leaf of walkJson(parsed.value, maxDepth)) {
        if (leaf.path === '') continue;
        record(leaf.path, leafToString(leaf.value), 'unknown');
      }
    }
  }

  return { params, secrets };
}

function tryParseJson(text: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

/** Scan a response body for credential-shaped values so they can be stripped. */
function responseSecrets(body: string | null, contentType: string | null, maxDepth: number, maxBodyBytes: number): string[] {
  if (body === null || body.length === 0 || body.length > maxBodyBytes) return [];
  const secrets: string[] = [];
  const parsed = tryParseJson(body);
  if (parsed.ok && (isRecord(parsed.value) || Array.isArray(parsed.value))) {
    for (const leaf of walkJson(parsed.value, maxDepth)) {
      const value = leafToString(leaf.value);
      if (value === null) continue;
      if (isSensitiveKey(leaf.path) || looksLikeSecret(value)) secrets.push(value);
    }
    return secrets;
  }
  if (isJsonContentType(contentType)) return secrets;
  if (looksLikeSecret(body)) secrets.push(body.trim());
  return secrets;
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function buildSignature(method: string, scheme: string, host: string, port: number, path: string): string {
  const defaultPort = DEFAULT_PORTS[scheme] ?? -1;
  const authority = port === defaultPort ? host : `${host}:${port}`;
  return `${method} ${scheme}//${authority}${path}`;
}

/**
 * Normalise one HAR entry. Returns null when the entry has no usable request.
 */
function normaliseEntry(
  entry: unknown,
  index: number,
  options: Required<Pick<ParseOptions, 'maxDepth' | 'maxBodyBytes' | 'templateSlugs'>>,
  warnings: string[],
  secrets: string[],
): CanonicalRequest | null {
  if (!isRecord(entry)) {
    warnings.push(`entry ${index}: not an object, skipped`);
    return null;
  }
  const request = isRecord(entry['request']) ? entry['request'] : null;
  if (request === null) {
    warnings.push(`entry ${index}: missing request, skipped`);
    return null;
  }
  const rawUrl = asString(request['url']);
  if (rawUrl === null) {
    warnings.push(`entry ${index}: missing request.url, skipped`);
    return null;
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    warnings.push(`entry ${index}: unparseable url, skipped`);
    return null;
  }

  const method = (asString(request['method']) ?? 'GET').toUpperCase();
  const requestHeaders = readNameValuePairs(request['headers']);
  const response = isRecord(entry['response']) ? entry['response'] : null;
  const responseHeaders = response === null ? [] : readNameValuePairs(response['headers']);

  for (const header of requestHeaders) {
    if (isSensitiveHeader(header.name) || looksLikeSecret(header.value)) {
      secrets.push(header.value);
      secrets.push(...cookieValues(header.value));
    }
    // Referer and Origin are kept in a replay plan because they change how the
    // server routes and authorises the request. A Referer is a whole URL, and
    // the URL that sent you somewhere is exactly where a one-time invite or
    // password-reset token lives.
    secrets.push(...sensitiveQueryValues(header.value));
  }
  for (const header of responseHeaders) {
    if (isSensitiveHeader(header.name) || looksLikeSecret(header.value)) {
      secrets.push(header.value);
      secrets.push(...cookieValues(header.value));
    }
  }
  for (const cookie of readNameValuePairs(request['cookies'])) secrets.push(cookie.value);
  if (response !== null) {
    for (const cookie of readNameValuePairs(response['cookies'])) secrets.push(cookie.value);
  }

  // Query parameters: prefer the URL itself, which is always present, and fall
  // back to the HAR queryString array for exotic encodings.
  const query: QueryParam[] = [];
  for (const [name, value] of parsedUrl.searchParams) query.push({ name, value });
  if (query.length === 0) {
    for (const param of readNameValuePairs(request['queryString'])) {
      query.push({ name: param.name, value: safeDecode(param.value) });
    }
  }
  for (const param of query) {
    if (isSensitiveKey(param.name) || looksLikeSecret(param.value)) secrets.push(param.value);
  }

  const postData = isRecord(request['postData']) ? request['postData'] : null;
  const requestBody = postData === null ? null : asString(postData['text']);
  const postMime = postData === null ? null : asString(postData['mimeType']);
  const requestContentType = contentTypeOf(requestHeaders, postMime);
  const formParams = postData === null ? [] : readNameValuePairs(postData['params']).map((p) => ({ name: p.name, value: safeDecode(p.value) }));

  const bodyAnalysis = analyseBody(requestBody, requestContentType, formParams, options.maxDepth, options.maxBodyBytes);
  secrets.push(...bodyAnalysis.secrets);

  const content = response !== null && isRecord(response['content']) ? response['content'] : null;
  const responseBody = content === null ? null : asString(content['text']);
  const responseContentType = contentTypeOf(responseHeaders, content === null ? null : asString(content['mimeType']));
  secrets.push(...responseSecrets(responseBody, responseContentType, options.maxDepth, options.maxBodyBytes));

  const declaredSize = content === null ? null : asNumber(content['size']);
  const bodySize = response === null ? null : asNumber(response['bodySize']);
  const responseSize =
    declaredSize !== null && declaredSize >= 0
      ? declaredSize
      : bodySize !== null && bodySize >= 0
        ? bodySize
        : responseBody === null
          ? 0
          : Buffer.byteLength(responseBody, 'utf8');

  const scheme = parsedUrl.protocol;
  const defaultPort = DEFAULT_PORTS[scheme] ?? 0;
  const port = parsedUrl.port === '' ? defaultPort : Number.parseInt(parsedUrl.port, 10);
  const path = parsedUrl.pathname;
  const templated = templatePath(path, options.templateSlugs);

  return {
    index,
    method,
    scheme,
    host: parsedUrl.hostname,
    port,
    url: rawUrl,
    path,
    templatePath: templated.templatePath,
    pathParams: templated.params,
    query,
    queryNames: uniqueSorted(query.map((param) => param.name)),
    bodyParams: bodyAnalysis.params,
    bodyParamNames: uniqueSorted(bodyAnalysis.params.map((param) => param.name)),
    requestContentType,
    responseContentType,
    requestHeaders,
    requestHeaderNames: uniqueSorted(requestHeaders.map((header) => header.name.toLowerCase())),
    requestBody,
    responseBody,
    status: response === null ? 0 : (asNumber(response['status']) ?? 0),
    statusText: response === null ? '' : (asString(response['statusText']) ?? ''),
    responseSize,
    signature: buildSignature(method, scheme, parsedUrl.hostname, port, templated.templatePath),
  };
}

/** Split a Cookie / Set-Cookie header into its individual values. */
function cookieValues(headerValue: string): string[] {
  const out: string[] = [];
  for (const part of headerValue.split(/[;,]/)) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const value = part.slice(eq + 1).trim();
    if (value.length >= 8) out.push(value);
  }
  return out;
}

/**
 * Parse a HAR 1.2 document into a {@link Capture}.
 *
 * Accepts either the JSON text or an already-parsed object.
 */
export function parseHar(source: string | unknown, options: ParseOptions = {}): Capture {
  const label = options.label ?? 'capture';
  const resolved = {
    maxDepth: options.maxDepth ?? DEFAULT_MAX_DEPTH,
    maxBodyBytes: options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES,
    templateSlugs: options.templateSlugs ?? false,
  };

  let document: unknown = source;
  if (typeof source === 'string') {
    const parsed = tryParseJson(source);
    if (!parsed.ok) throw new Error(`${label}: not valid JSON, so not a HAR file`);
    document = parsed.value;
  }

  if (!isRecord(document)) throw new Error(`${label}: HAR root is not an object`);
  const log = isRecord(document['log']) ? document['log'] : null;
  if (log === null) throw new Error(`${label}: missing "log" object - is this a HAR 1.2 file?`);

  const warnings: string[] = [];
  const version = asString(log['version']);
  if (version !== null && version !== '1.2') {
    warnings.push(`HAR version ${version} (expected 1.2); parsing anyway`);
  }

  const creatorRecord = isRecord(log['creator']) ? log['creator'] : null;
  const creator =
    creatorRecord === null
      ? null
      : [asString(creatorRecord['name']), asString(creatorRecord['version'])].filter((part) => part !== null).join(' ') || null;

  const entries = Array.isArray(log['entries']) ? log['entries'] : [];
  if (!Array.isArray(log['entries'])) warnings.push('log.entries missing or not an array');

  const secrets: string[] = [];
  const requests: CanonicalRequest[] = [];
  for (const [index, entry] of entries.entries()) {
    const normalised = normaliseEntry(entry, index, resolved, warnings, secrets);
    if (normalised !== null) requests.push(normalised);
  }

  return {
    label,
    // parseHar has no file. parseHarFile overrides this with the real path;
    // using the label here put a label in the FILE column of every report
    // that went through the in-memory API.
    file: '<memory>',
    requests,
    warnings,
    secrets: [...new Set(secrets.filter((value) => value.trim().length > 0))],
    creator,
  };
}

/** Read and parse a HAR file from disk. The label defaults to the filename. */
export async function parseHarFile(file: string, options: ParseOptions = {}): Promise<Capture> {
  const text = await readFile(file, 'utf8');
  const label = options.label ?? basename(file).replace(/\.har$/i, '');
  const capture = parseHar(text, { ...options, label });
  return { ...capture, file };
}

/** Group a capture's requests by canonical signature, preserving order. */
export function groupBySignature(requests: readonly CanonicalRequest[]): Map<string, CanonicalRequest[]> {
  const groups = new Map<string, CanonicalRequest[]>();
  for (const request of requests) {
    const existing = groups.get(request.signature);
    if (existing === undefined) groups.set(request.signature, [request]);
    else existing.push(request);
  }
  return groups;
}

/** Re-export so callers can classify ad-hoc values with the same rules. */
export { classifyIdentifier };
