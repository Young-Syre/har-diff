/**
 * Secret hygiene.
 *
 * A HAR file is a verbatim recording of an authenticated browsing session, so
 * it contains live session cookies, bearer tokens, API keys and sometimes
 * passwords. har-diff therefore redacts by default, in three layers:
 *
 *  1. Structural - headers, cookies, query parameters and body fields whose
 *     name marks them as credentials are replaced before they are ever put
 *     into an output object.
 *  2. Literal - every credential-shaped string seen while parsing is recorded
 *     and removed from the rendered output by exact match, including its
 *     percent-encoded form. This is the backstop that makes the guarantee
 *     hold even if a value escapes layer 1.
 *  3. Pattern - a final sweep for high-confidence token shapes (JWTs, AWS
 *     access key ids, Stripe/GitHub/Slack/Google key prefixes, PEM blocks).
 *
 * Layer 3 is intentionally limited to distinctive prefixes. A broad
 * "anything long and random" sweep would also destroy the object references
 * the tool exists to report.
 */

import type { HarHeader } from './types.js';

export const REDACTED = '[REDACTED]';

/** Header names (lowercased) whose value is always a credential. */
export const SENSITIVE_HEADERS: ReadonlySet<string> = new Set([
  'authorization',
  'proxy-authorization',
  'authentication',
  'cookie',
  'cookie2',
  'set-cookie',
  'set-cookie2',
  'x-api-key',
  'api-key',
  'apikey',
  'x-auth-token',
  'x-auth',
  'x-access-token',
  'x-session-token',
  'x-session-id',
  'x-csrf-token',
  'x-xsrf-token',
  'x-amz-security-token',
  'x-goog-api-key',
  'x-functions-key',
  'x-shopify-access-token',
  'private-token',
  'authorization-token',
]);

/** Parameter/field names whose value is treated as a credential. */
export const SENSITIVE_KEY =
  /^(?:.*[._-])?(?:access[_-]?token|refresh[_-]?token|id[_-]?token|bearer[_-]?token|api[_-]?key|apikey|app[_-]?secret|client[_-]?secret|private[_-]?key|secret|password|passwd|pwd|passphrase|credential|credentials|session[_-]?id|sessionid|session[_-]?key|session|sid|jsessionid|phpsessid|token|auth|authorization|csrf|csrf[_-]?token|xsrf[_-]?token|signature|sig|otp|mfa[_-]?code|totp|recovery[_-]?code)$/i;

interface TokenPattern {
  readonly label: string;
  readonly re: RegExp;
  readonly replacement: string;
}

/**
 * High-confidence credential shapes. Each has a distinctive prefix or
 * structure, so it cannot collide with an object identifier - and none of them
 * match har-diff's own `$HARDIFF_*_TOKEN` placeholders, because `$` is outside
 * every token character class below.
 */
const TOKEN_PATTERNS: readonly TokenPattern[] = [
  {
    label: 'jwt',
    re: /eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}/g,
    replacement: '[REDACTED:jwt]',
  },
  {
    label: 'bearer',
    re: /\b(Bearer|Basic|Digest|Token|SSWS|GenieKey)\s+[A-Za-z0-9._~+/=-]{12,}/gi,
    replacement: '$1 [REDACTED]',
  },
  { label: 'aws-access-key', re: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g, replacement: '[REDACTED:aws-key-id]' },
  { label: 'stripe', re: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}/g, replacement: '[REDACTED:stripe-key]' },
  { label: 'github', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}/g, replacement: '[REDACTED:github-token]' },
  { label: 'slack', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g, replacement: '[REDACTED:slack-token]' },
  { label: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, replacement: '[REDACTED:google-api-key]' },
  { label: 'npm', re: /\bnpm_[A-Za-z0-9]{30,}\b/g, replacement: '[REDACTED:npm-token]' },
  {
    label: 'pem',
    re: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/g,
    replacement: '[REDACTED:private-key]',
  },
];

/**
 * `key=value` / `"key": "value"` sweep. Applied only to request body strings
 * that could not be parsed as JSON or form data, never to rendered output.
 */
const KEY_VALUE_IN_BODY =
  /(\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|apikey|client[_-]?secret|secret|password|passwd|pwd|passphrase|session|sessionid|sid|token|auth|authorization|csrf[_-]?token|xsrf[_-]?token|signature)\b["']?\s*[:=]\s*["']?)([^"'\s,&;}\]]{4,})/gi;

export function isSensitiveHeader(name: string): boolean {
  return SENSITIVE_HEADERS.has(name.trim().toLowerCase());
}

/**
 * Insert a separator at every camelCase boundary, so that one spelling of a
 * field name is tested. SENSITIVE_KEY's prefix group requires an explicit
 * `.`, `_` or `-`, which meant `accessToken` matched (the alternation
 * happens to span it) while `authToken`, `sessionToken`, `apiToken` and
 * `userToken` did not.
 */
function snakeify(name: string): string {
  return name.replace(/([a-z0-9])([A-Z])/g, '$1_$2');
}

export function isSensitiveKey(name: string): boolean {
  // For dotted body paths, judge the last segment.
  const leaf = name.split(/[.[]/).filter((part) => part !== '' && part !== ']').pop() ?? name;
  for (const candidate of [leaf, name]) {
    if (SENSITIVE_KEY.test(candidate) || SENSITIVE_KEY.test(snakeify(candidate))) return true;
  }
  return false;
}

/** True when a value matches one of the high-confidence credential shapes. */
export function looksLikeSecret(value: string): boolean {
  return TOKEN_PATTERNS.some((pattern) => {
    const re = new RegExp(pattern.re.source, pattern.re.flags.replace('g', ''));
    return re.test(value);
  });
}

/** Redact credential-ish `key=value` pairs inside an opaque body string. */
export function redactBodyString(body: string): string {
  return body.replace(KEY_VALUE_IN_BODY, (_match, prefix: string) => `${prefix}${REDACTED}`);
}

/**
 * Removes credentials from rendered output.
 *
 * Construct one per run from the secrets every capture reported, then pass all
 * final output through `text()`.
 */
export class Redactor {
  readonly enabled: boolean;
  readonly #literals: string[];

  constructor(literals: Iterable<string> = [], options: { showSecrets?: boolean } = {}) {
    this.enabled = options.showSecrets !== true;
    const set = new Set<string>();
    for (const literal of literals) {
      if (typeof literal !== 'string') continue;
      const trimmed = literal.trim();
      // Short values are skipped: redacting them would mangle unrelated output
      // and they are not credentials worth protecting on their own.
      if (trimmed.length < 8) continue;
      set.add(trimmed);
      const encoded = encodeURIComponent(trimmed);
      if (encoded !== trimmed) set.add(encoded);
      try {
        const decoded = decodeURIComponent(trimmed);
        if (decoded !== trimmed && decoded.length >= 8) set.add(decoded);
      } catch {
        /* not percent-encoded */
      }
    }
    // Longest first so a longer secret is not left partially replaced.
    this.#literals = [...set].sort((a, b) => b.length - a.length);
  }

  /** Number of distinct literal secrets this redactor will strip. */
  get literalCount(): number {
    return this.#literals.length;
  }

  /** Redact a single value, e.g. a header value or a parameter value. */
  value(value: string): string {
    if (!this.enabled) return value;
    return this.text(value);
  }

  /** Redact rendered output of any format. Safe to call on whole documents. */
  text(input: string): string {
    if (!this.enabled) return input;
    let out = input;
    for (const literal of this.#literals) {
      out = out.split(literal).join(REDACTED);
    }
    for (const pattern of TOKEN_PATTERNS) {
      out = out.replace(new RegExp(pattern.re.source, pattern.re.flags), pattern.replacement);
    }
    return out;
  }

  /** Replace credential headers with a redaction marker, keeping their names. */
  headers(headers: readonly HarHeader[]): HarHeader[] {
    return headers.map((header) => {
      if (this.enabled && isSensitiveHeader(header.name)) {
        return { name: header.name, value: REDACTED };
      }
      return { name: header.name, value: this.value(header.value) };
    });
  }

  /** Rebuild a URL with credential-bearing query parameters removed. */
  url(url: string): string {
    if (!this.enabled) return url;
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return this.text(url);
    }
    let changed = false;
    for (const name of [...parsed.searchParams.keys()]) {
      if (isSensitiveKey(name)) {
        parsed.searchParams.set(name, REDACTED);
        changed = true;
      }
    }
    const rendered = changed ? decodeRedactionMarkers(parsed.toString()) : url;
    return this.text(rendered);
  }
}

/** `URL` percent-encodes the brackets in `[REDACTED]`; put them back. */
function decodeRedactionMarkers(url: string): string {
  return url.replace(/%5BREDACTED%5D/gi, REDACTED);
}

export const UNSAFE_WARNING =
  'WARNING: --unsafe-show-secrets is set. Output below contains live session ' +
  'credentials copied verbatim from the capture. Do not paste it into a ' +
  'report, an issue tracker, a chat client or an LLM.';
