/**
 * Identifier shape detection.
 *
 * These heuristics decide two things: which path segments get templated (and
 * so which requests group together), and which values are reported as
 * candidate object references. They are deliberately conservative - a false
 * positive here turns into noise in the test plan.
 */

import type { IdentifierKind } from './types.js';

const INTEGER = /^\d{1,18}$/;
/** RFC 9562 UUID, versions 1-8, with the standard variant nibble. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NIL_UUID = '00000000-0000-0000-0000-000000000000';
const MAX_UUID = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
/** Crockford base32, excluding I, L, O and U; first char bounded to 0-7. */
const ULID = /^[0-7][0-9ABCDEFGHJKMNPQRSTVWXYZ]{25}$/;
const OBJECTID = /^[0-9a-f]{24}$/i;
const HEX = /^[0-9a-f]{32,}$/i;
const JWT = /^eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*$/;
const EMAIL = /^[^\s@/\\]{1,64}@[^\s@./\\]+(?:\.[^\s@./\\]+)+$/;
const BASE64URL = /^[A-Za-z0-9_-]{16,512}$/;
const SLUG = /^[a-z0-9]+(?:[-_][a-z0-9]+)+$/;

/** Key names whose value is treated as a slug/handle rather than free text. */
const SLUG_KEY = /(?:^|[._-])(?:slug|handle|username|login|alias|shortname|permalink)$/i;

/** Placeholder written into a templated path for each kind. */
const PLACEHOLDER: Record<IdentifierKind, string> = {
  integer: '{int}',
  uuid: '{uuid}',
  ulid: '{ulid}',
  objectid: '{objectid}',
  hex: '{hex}',
  jwt: '{jwt}',
  email: '{email}',
  base64url: '{b64}',
  slug: '{slug}',
};

export function placeholderFor(kind: IdentifierKind): string {
  return PLACEHOLDER[kind];
}

export interface ClassifyContext {
  /**
   * True when the value sits in a position where a bare slug is plausibly an
   * object reference: a path segment following a collection name, or the value
   * of a slug-like key.
   */
  slugContext?: boolean;
  /** Key or parameter name the value came from, when there is one. */
  key?: string;
}

/**
 * How many of lower, upper and digit the value draws on. Separators are
 * deliberately not counted: a hyphen is what route names are made of, so
 * counting it made every lowercase path segment of 16 characters or more
 * ("two-factor-authentication") read as an opaque token, and two unrelated
 * routes then templated to the same slot.
 */
function charClasses(value: string): number {
  let n = 0;
  if (/[a-z]/.test(value)) n += 1;
  if (/[A-Z]/.test(value)) n += 1;
  if (/\d/.test(value)) n += 1;
  return n;
}

/**
 * Classify a single scalar value. Returns null when the value does not look
 * like an object identifier.
 */
export function classifyIdentifier(
  value: string,
  ctx: ClassifyContext = {},
): IdentifierKind | null {
  if (value.length === 0) return null;

  if (INTEGER.test(value)) return 'integer';
  if (UUID.test(value) || value === NIL_UUID || value.toLowerCase() === MAX_UUID) return 'uuid';
  if (ULID.test(value)) return 'ulid';
  if (JWT.test(value)) return 'jwt';
  if (OBJECTID.test(value)) return 'objectid';
  if (HEX.test(value)) return 'hex';
  if (EMAIL.test(value)) return 'email';
  // Opaque tokens: long, URL-safe, and mixing at least two character classes.
  if (BASE64URL.test(value) && charClasses(value) >= 2) return 'base64url';

  const slugContext = ctx.slugContext === true || (ctx.key !== undefined && SLUG_KEY.test(ctx.key));
  if (slugContext && value.length >= 3 && value.length <= 128 && SLUG.test(value)) return 'slug';

  return null;
}

/**
 * True when a path segment immediately before another segment reads like a
 * collection name, which is what makes the following segment a likely object
 * reference (`/projects/acme-corp`, `/users/8123`).
 */
export function looksLikeCollection(segment: string): boolean {
  if (segment.length < 3) return false;
  if (!/^[a-z][a-z0-9_-]*$/i.test(segment)) return false;
  if (/^v\d+$/i.test(segment)) return false;
  return segment.endsWith('s') || segment.endsWith('List');
}

export interface TemplateResult {
  templatePath: string;
  params: { index: number; kind: IdentifierKind; value: string; placeholder: string }[];
}

/**
 * Replace identifier-shaped path segments with placeholders, keeping the real
 * values so they can be reported and substituted later.
 *
 * Slug segments are only templated when `templateSlugs` is set: slugs and
 * ordinary route words are indistinguishable without a route table, and
 * templating them collapses `/account/reset-password` into `/account/{slug}`.
 */
export function templatePath(path: string, templateSlugs = false): TemplateResult {
  const trailingSlash = path.length > 1 && path.endsWith('/');
  const segments = path.split('/');
  const params: TemplateResult['params'] = [];

  const out = segments.map((segment, index) => {
    if (segment === '') return segment;
    const decoded = safeDecode(segment);
    const previous = index > 0 ? segments[index - 1] : undefined;
    const kind = classifyIdentifier(decoded, {
      slugContext: templateSlugs && previous !== undefined && looksLikeCollection(previous),
    });
    if (kind === null) return segment;
    if (kind === 'slug' && !templateSlugs) return segment;
    const placeholder = PLACEHOLDER[kind];
    params.push({ index, kind, value: decoded, placeholder });
    return placeholder;
  });

  let templatePathValue = out.join('/');
  if (trailingSlash && !templatePathValue.endsWith('/')) templatePathValue += '/';
  return { templatePath: templatePathValue, params };
}

export function safeDecode(value: string): string {
  if (!value.includes('%')) return value;
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
