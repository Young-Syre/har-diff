import { fileURLToPath } from 'node:url';

import { parseHarFile } from '../src/har.js';
import type { Capture } from '../src/types.js';

export const ADMIN_HAR = fileURLToPath(new URL('../../test/fixtures/admin.har', import.meta.url));
export const USER_HAR = fileURLToPath(new URL('../../test/fixtures/user.har', import.meta.url));
export const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));

/** Credential values that live in the fixtures and must never be printed. */
export const FIXTURE_SECRETS = [
  'FIXTURE-SIGNATURE-NOT-REAL',
  'FIXTUREadminSESSIONvalue0000000000',
  'FIXTUREuserSESSIONvalue00000000000',
  'FIXTUREadminCSRFvalue00000',
  'FIXTUREuserCSRFvalue000000',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  'eyJzdWIiOiI4MDAxIiwicm9sZSI6ImFkbWluIiwiaXNzIjoiaGFyLWRpZmYtZml4dHVyZSIsIm5vdGUiOiJmYWtlIHRva2VuIGZvciB0ZXN0cyBvbmx5In0',
] as const;

export async function loadFixtures(): Promise<{ admin: Capture; user: Capture }> {
  const [admin, user] = await Promise.all([
    parseHarFile(ADMIN_HAR, { label: 'admin' }),
    parseHarFile(USER_HAR, { label: 'user' }),
  ]);
  return { admin: admin as Capture, user: user as Capture };
}

/** Build a minimal in-memory HAR for focused unit tests. */
export function makeHar(
  entries: readonly {
    method?: string;
    url: string;
    headers?: { name: string; value: string }[];
    body?: { mimeType: string; text: string };
    status?: number;
    response?: unknown;
  }[],
): string {
  return JSON.stringify({
    log: {
      version: '1.2',
      creator: { name: 'unit-test', version: '1.0' },
      entries: entries.map((entry) => {
        const text = entry.response === undefined ? '' : JSON.stringify(entry.response);
        return {
          request: {
            method: entry.method ?? 'GET',
            url: entry.url,
            headers: entry.headers ?? [],
            queryString: [],
            cookies: [],
            ...(entry.body === undefined ? {} : { postData: entry.body }),
          },
          response: {
            status: entry.status ?? 200,
            statusText: 'OK',
            headers: [{ name: 'Content-Type', value: 'application/json' }],
            cookies: [],
            content: { size: Buffer.byteLength(text), mimeType: 'application/json', text },
          },
        };
      }),
    },
  });
}
