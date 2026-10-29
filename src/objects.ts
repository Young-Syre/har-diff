/**
 * Candidate object reference extraction.
 *
 * Every value in a request path, query string, request body or response body
 * that has the shape of an object identifier is a value you can try
 * substituting into another account's request. This module finds them, records
 * every position ("slot") each one appeared in, and flags the slots where
 * integer ids make enumeration trivial.
 */

import { classifyIdentifier, looksLikeCollection, safeDecode } from './identifiers.js';
import { walkJson } from './har.js';
import { isSensitiveKey, looksLikeSecret } from './redact.js';
import type {
  Capture,
  CanonicalRequest,
  IdentifierKind,
  ObjectIndex,
  ObjectOccurrence,
  ObjectRef,
  SequentialSlot,
  ValueLocation,
} from './types.js';

export interface ExtractOptions {
  /** Recursion cap when walking response bodies. Default 8. */
  maxDepth?: number;
  /** Skip response bodies larger than this many bytes. Default 1_000_000. */
  maxBodyBytes?: number;
  /** Include values that sit in credential positions, flagged as sensitive. */
  includeSensitive?: boolean;
}

const KIND_ORDER: readonly IdentifierKind[] = [
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

export function slotKey(signature: string, location: ValueLocation, field: string): string {
  return `${signature}|${location}|${field}`;
}

interface Sighting {
  value: string;
  kind: IdentifierKind;
  sensitive: boolean;
  occurrence: ObjectOccurrence;
}

function sight(
  capture: Capture,
  request: CanonicalRequest,
  location: ValueLocation,
  field: string,
  value: string,
  kind: IdentifierKind,
  sensitive: boolean,
): Sighting {
  return {
    value,
    kind,
    sensitive,
    occurrence: {
      capture: capture.label,
      signature: request.signature,
      method: request.method,
      templatePath: request.templatePath,
      location,
      field,
      slot: slotKey(request.signature, location, field),
    },
  };
}

function isSensitiveValue(value: string, key: string | undefined, secrets: ReadonlySet<string>): boolean {
  if (secrets.has(value)) return true;
  if (looksLikeSecret(value)) return true;
  if (key !== undefined && isSensitiveKey(key)) return true;
  return false;
}

function collectFromRequest(
  capture: Capture,
  request: CanonicalRequest,
  secrets: ReadonlySet<string>,
  maxDepth: number,
  maxBodyBytes: number,
): Sighting[] {
  const out: Sighting[] = [];

  // --- path -------------------------------------------------------------
  const templated = new Map(request.pathParams.map((param) => [param.index, param]));
  const segments = request.path.split('/');
  for (const [index, rawSegment] of segments.entries()) {
    if (rawSegment === '') continue;
    const param = templated.get(index);
    if (param !== undefined) {
      out.push(
        sight(capture, request, 'path', String(index), param.value, param.kind, isSensitiveValue(param.value, undefined, secrets)),
      );
      continue;
    }
    // Slugs are not templated (see identifiers.ts) but are still object refs
    // when they follow a collection segment.
    const previous = index > 0 ? segments[index - 1] : undefined;
    if (previous === undefined || !looksLikeCollection(previous)) continue;
    const decoded = safeDecode(rawSegment);
    const kind = classifyIdentifier(decoded, { slugContext: true });
    if (kind !== 'slug') continue;
    out.push(sight(capture, request, 'path', String(index), decoded, kind, false));
  }

  // --- query ------------------------------------------------------------
  for (const param of request.query) {
    const kind = classifyIdentifier(param.value, { key: param.name });
    if (kind === null) continue;
    out.push(
      sight(capture, request, 'query', param.name, param.value, kind, isSensitiveValue(param.value, param.name, secrets)),
    );
  }

  // --- request body -----------------------------------------------------
  for (const param of request.bodyParams) {
    if (param.value === null) continue;
    const kind = classifyIdentifier(param.value, { key: param.name });
    if (kind === null) continue;
    out.push(
      sight(capture, request, 'request-body', param.name, param.value, kind, isSensitiveValue(param.value, param.name, secrets)),
    );
  }

  // --- response body ----------------------------------------------------
  const body = request.responseBody;
  if (body !== null && body.length > 0 && body.length <= maxBodyBytes) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(body) as unknown;
    } catch {
      parsed = undefined;
    }
    if (parsed !== undefined) {
      for (const leaf of walkJson(parsed, maxDepth)) {
        if (leaf.value === null || typeof leaf.value === 'boolean') continue;
        const value = String(leaf.value);
        const kind = classifyIdentifier(value, { key: leaf.path });
        if (kind === null) continue;
        out.push(
          sight(capture, request, 'response-body', leaf.path, value, kind, isSensitiveValue(value, leaf.path, secrets)),
        );
      }
    }
  }

  return out;
}

function compareRefs(a: ObjectRef, b: ObjectRef): number {
  const kindDelta = KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind);
  if (kindDelta !== 0) return kindDelta;
  if (a.kind === 'integer') {
    const delta = Number(a.value) - Number(b.value);
    if (delta !== 0) return delta;
  }
  return a.value < b.value ? -1 : a.value > b.value ? 1 : 0;
}

/**
 * Find sequentially-numbered integer slots.
 *
 * A slot holding more than one integer across the captures tells you the id
 * space is walkable; `consecutive` and `dense` say how cheaply.
 */
export function findSequentialSlots(refs: readonly ObjectRef[]): SequentialSlot[] {
  interface Accumulator {
    values: Set<number>;
    occurrence: ObjectOccurrence;
  }
  const bySlot = new Map<string, Accumulator>();

  for (const ref of refs) {
    if (ref.kind !== 'integer') continue;
    const numeric = Number(ref.value);
    if (!Number.isSafeInteger(numeric)) continue;
    for (const occurrence of ref.occurrences) {
      const existing = bySlot.get(occurrence.slot);
      if (existing === undefined) {
        bySlot.set(occurrence.slot, { values: new Set([numeric]), occurrence });
      } else {
        existing.values.add(numeric);
      }
    }
  }

  const slots: SequentialSlot[] = [];
  for (const [slot, accumulator] of bySlot) {
    if (accumulator.values.size < 2) continue;
    const values = [...accumulator.values].sort((a, b) => a - b);
    const first = values[0] as number;
    const last = values[values.length - 1] as number;
    const span = last - first;
    let consecutive = true;
    for (let i = 1; i < values.length; i += 1) {
      if ((values[i] as number) - (values[i - 1] as number) !== 1) {
        consecutive = false;
        break;
      }
    }
    slots.push({
      slot,
      signature: accumulator.occurrence.signature,
      method: accumulator.occurrence.method,
      templatePath: accumulator.occurrence.templatePath,
      location: accumulator.occurrence.location,
      field: accumulator.occurrence.field,
      values,
      span,
      consecutive,
      dense: span + 1 <= Math.max(values.length * 4, 10),
    });
  }

  slots.sort((a, b) => (a.slot < b.slot ? -1 : a.slot > b.slot ? 1 : 0));
  return slots;
}

/**
 * Extract every candidate object identifier across one or more captures.
 *
 * Integer identifiers are always marked `enumerable`: regardless of how many
 * were observed, an integer object reference can be walked by hand.
 */
export function extractObjects(captures: readonly Capture[], options: ExtractOptions = {}): ObjectIndex {
  const maxDepth = options.maxDepth ?? 8;
  const maxBodyBytes = options.maxBodyBytes ?? 1_000_000;
  const includeSensitive = options.includeSensitive ?? true;

  const byValue = new Map<string, ObjectRef>();

  for (const capture of captures) {
    const secrets = new Set(capture.secrets);
    for (const request of capture.requests) {
      for (const sighting of collectFromRequest(capture, request, secrets, maxDepth, maxBodyBytes)) {
        if (sighting.sensitive && !includeSensitive) continue;
        const existing = byValue.get(sighting.value);
        if (existing === undefined) {
          byValue.set(sighting.value, {
            value: sighting.value,
            kind: sighting.kind,
            enumerable: sighting.kind === 'integer',
            sensitive: sighting.sensitive,
            occurrences: [sighting.occurrence],
          });
          continue;
        }
        existing.sensitive = existing.sensitive || sighting.sensitive;
        const duplicate = existing.occurrences.some(
          (occurrence) => occurrence.capture === sighting.occurrence.capture && occurrence.slot === sighting.occurrence.slot,
        );
        if (!duplicate) existing.occurrences.push(sighting.occurrence);
      }
    }
  }

  const refs = [...byValue.values()].sort(compareRefs);
  return { refs, sequential: findSequentialSlots(refs) };
}

/** Index refs by the slot they were seen in. */
export function refsBySlot(refs: readonly ObjectRef[]): Map<string, ObjectRef[]> {
  const bySlot = new Map<string, ObjectRef[]>();
  for (const ref of refs) {
    for (const occurrence of ref.occurrences) {
      const existing = bySlot.get(occurrence.slot);
      if (existing === undefined) bySlot.set(occurrence.slot, [ref]);
      else if (!existing.includes(ref)) existing.push(ref);
    }
  }
  return bySlot;
}
