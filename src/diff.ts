/**
 * N-way capture diff.
 *
 * The first capture is treated as the privileged one unless told otherwise.
 * Everything the diff reports is a candidate, not a finding: the tool observes
 * what each session was *able to request*, which is not the same as what the
 * server would have *allowed* a different session to request. Confirming that
 * is the replay step, which is what `plan` is for.
 */

import { groupBySignature } from './har.js';
import { extractObjects } from './objects.js';
import type {
  Capture,
  CanonicalRequest,
  CaptureRef,
  DiffResult,
  EndpointExample,
  ExclusiveEndpoint,
  ObjectDiff,
  ObjectIndex,
  ParameterDiff,
  ResponseDiff,
  ResponseObservation,
} from './types.js';

export interface DiffOptions {
  /** Label of the privileged capture. Defaults to the first capture's label. */
  privilegedLabel?: string;
  /**
   * Response sizes are treated as differing when they vary by at least this
   * fraction of the larger value. Default 0.1.
   */
  sizeTolerance?: number;
  /** And by at least this many bytes. Default 32. */
  sizeFloorBytes?: number;
  /** Maximum example requests recorded per endpoint. Default 3. */
  examplesPerEndpoint?: number;
  objects?: ObjectIndex;
}

function median(values: readonly number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 1) return sorted[middle] as number;
  return Math.round(((sorted[middle - 1] as number) + (sorted[middle] as number)) / 2);
}

function exampleOf(capture: Capture, request: CanonicalRequest): EndpointExample {
  return {
    capture: capture.label,
    url: request.url,
    status: request.status,
    responseSize: request.responseSize,
  };
}

function parametersOf(requests: readonly CanonicalRequest[]): Map<string, 'query' | 'request-body'> {
  const params = new Map<string, 'query' | 'request-body'>();
  for (const request of requests) {
    for (const name of request.queryNames) params.set(name, 'query');
    for (const name of request.bodyParamNames) {
      if (!params.has(name)) params.set(name, 'request-body');
    }
  }
  return params;
}

function firstRequest(requests: readonly CanonicalRequest[]): CanonicalRequest {
  const request = requests[0];
  if (request === undefined) throw new Error('empty endpoint group');
  return request;
}

/**
 * Compare two or more captures of the same application taken at different
 * privilege levels.
 */
export function diffCaptures(captures: readonly Capture[], options: DiffOptions = {}): DiffResult {
  if (captures.length < 2) {
    throw new Error('diffCaptures needs at least two captures');
  }
  const labels = captures.map((capture) => capture.label);
  const duplicateLabel = labels.find((label, index) => labels.indexOf(label) !== index);
  if (duplicateLabel !== undefined) {
    throw new Error(`duplicate capture label "${duplicateLabel}" - pass distinct --label values`);
  }

  const privilegedLabel = options.privilegedLabel ?? (labels[0] as string);
  if (!labels.includes(privilegedLabel)) {
    throw new Error(`privileged label "${privilegedLabel}" is not one of: ${labels.join(', ')}`);
  }
  const sizeTolerance = options.sizeTolerance ?? 0.1;
  const sizeFloorBytes = options.sizeFloorBytes ?? 32;
  const examplesPerEndpoint = options.examplesPerEndpoint ?? 3;

  const grouped = captures.map((capture) => ({ capture, groups: groupBySignature(capture.requests) }));
  const allSignatures = [...new Set(grouped.flatMap(({ groups }) => [...groups.keys()]))].sort();

  const captureRefs: CaptureRef[] = captures.map((capture) => ({
    label: capture.label,
    file: capture.file,
    requestCount: capture.requests.length,
  }));

  const shared: string[] = [];
  const exclusive: ExclusiveEndpoint[] = [];
  const parameterDiffs: ParameterDiff[] = [];
  const responseDiffs: ResponseDiff[] = [];

  for (const signature of allSignatures) {
    const present = grouped.filter(({ groups }) => groups.has(signature));
    if (present.length === captures.length) shared.push(signature);

    if (present.length === 1) {
      const only = present[0] as (typeof grouped)[number];
      const requests = only.groups.get(signature) as CanonicalRequest[];
      const head = firstRequest(requests);
      exclusive.push({
        signature,
        method: head.method,
        templatePath: head.templatePath,
        label: only.capture.label,
        privileged: only.capture.label === privilegedLabel,
        examples: requests.slice(0, examplesPerEndpoint).map((request) => exampleOf(only.capture, request)),
      });
      continue;
    }

    // Shared by at least two captures: compare parameters and responses.
    const perLabel = present.map(({ capture, groups }) => {
      const requests = groups.get(signature) as CanonicalRequest[];
      return { capture, requests, params: parametersOf(requests) };
    });
    const head = firstRequest((perLabel[0] as (typeof perLabel)[number]).requests);

    for (const entry of perLabel) {
      const others = perLabel.filter((candidate) => candidate !== entry);
      const unique: ParameterDiff['params'] = [];
      for (const [name, location] of entry.params) {
        if (others.every((other) => !other.params.has(name))) unique.push({ name, location });
      }
      if (unique.length === 0) continue;
      unique.sort((a, b) => (a.name < b.name ? -1 : 1));
      parameterDiffs.push({
        signature,
        method: head.method,
        templatePath: head.templatePath,
        label: entry.capture.label,
        privileged: entry.capture.label === privilegedLabel,
        params: unique,
        presentIn: perLabel.map((item) => item.capture.label),
      });
    }

    const observations: ResponseObservation[] = perLabel.map((entry) => {
      const statuses = [...new Set(entry.requests.map((request) => request.status))].sort((a, b) => a - b);
      const sizes = entry.requests.map((request) => request.responseSize);
      return { label: entry.capture.label, statuses, sizes, medianSize: median(sizes) };
    });

    const statusKeys = new Set(observations.map((observation) => observation.statuses.join(',')));
    const medians = observations.map((observation) => observation.medianSize);
    const minMedian = Math.min(...medians);
    const maxMedian = Math.max(...medians);
    const sizeDelta = maxMedian - minMedian;
    const sizeDiffers = sizeDelta >= sizeFloorBytes && maxMedian > 0 && sizeDelta / maxMedian >= sizeTolerance;
    const statusDiffers = statusKeys.size > 1;

    if (statusDiffers || sizeDiffers) {
      responseDiffs.push({
        signature,
        method: head.method,
        templatePath: head.templatePath,
        observations,
        statusDiffers,
        sizeDiffers,
      });
    }
  }

  exclusive.sort((a, b) => {
    if (a.privileged !== b.privileged) return a.privileged ? -1 : 1;
    return a.signature < b.signature ? -1 : 1;
  });
  parameterDiffs.sort((a, b) => {
    if (a.privileged !== b.privileged) return a.privileged ? -1 : 1;
    return a.signature < b.signature ? -1 : 1;
  });

  const objects = options.objects ?? extractObjects(captures);
  const objectsOnlyIn = objectsExclusiveToCapture(objects, labels, privilegedLabel);

  return {
    captures: captureRefs,
    privilegedLabel,
    shared,
    exclusive,
    parameterDiffs,
    responseDiffs,
    objectsOnlyIn,
    objects,
  };
}

/**
 * Object references that appeared in one capture's responses and were never
 * seen anywhere in any other capture. These are the concrete values to
 * substitute when replaying with the other capture's credential.
 *
 * `inputSlots` answers "where could this value be sent?" and is built from two
 * rules:
 *
 *  1. the value itself was observed in that slot, so the slot provably accepts
 *     it;
 *  2. for opaque kinds (UUID, ULID, ObjectId, hex, base64url, email, slug),
 *     any slot that accepted another value of the same kind - a leaked opaque
 *     id is worth trying wherever that shape is accepted.
 *
 * Rule 2 deliberately excludes integers. Every small integer looks like every
 * other small integer, so pairing arbitrary integers with arbitrary integer
 * slots produces mostly noise; integer object references are covered properly
 * by the enumerable-slot analysis instead.
 */
export function objectsExclusiveToCapture(
  objects: ObjectIndex,
  labels: readonly string[],
  privilegedLabel: string,
): ObjectDiff[] {
  const inputSlotsByKind = new Map<string, Set<string>>();
  const inputSlotsByValue = new Map<string, Set<string>>();
  for (const ref of objects.refs) {
    for (const occurrence of ref.occurrences) {
      if (occurrence.location === 'response-body' || occurrence.location === 'header') continue;
      addTo(inputSlotsByKind, ref.kind, occurrence.slot);
      addTo(inputSlotsByValue, ref.value, occurrence.slot);
    }
  }

  const out: ObjectDiff[] = [];
  for (const ref of objects.refs) {
    const seenCaptures = new Set(ref.occurrences.map((occurrence) => occurrence.capture));
    if (seenCaptures.size !== 1) continue;
    const [label] = [...seenCaptures] as [string];
    if (!labels.includes(label)) continue;
    const responseSignatures = [
      ...new Set(
        ref.occurrences
          .filter((occurrence) => occurrence.location === 'response-body')
          .map((occurrence) => occurrence.signature),
      ),
    ].sort();
    if (responseSignatures.length === 0) continue;

    const slots = new Set(inputSlotsByValue.get(ref.value) ?? []);
    if (ref.kind !== 'integer') {
      for (const slot of inputSlotsByKind.get(ref.kind) ?? []) slots.add(slot);
    }

    out.push({
      label,
      privileged: label === privilegedLabel,
      value: ref.value,
      kind: ref.kind,
      enumerable: ref.enumerable,
      sensitive: ref.sensitive,
      seenIn: responseSignatures,
      inputSlots: [...slots].sort(),
    });
  }

  out.sort((a, b) => {
    if (a.privileged !== b.privileged) return a.privileged ? -1 : 1;
    if (a.kind !== b.kind) return a.kind < b.kind ? -1 : 1;
    return a.value < b.value ? -1 : 1;
  });
  return out;
}

function addTo(map: Map<string, Set<string>>, key: string, value: string): void {
  const existing = map.get(key);
  if (existing === undefined) map.set(key, new Set([value]));
  else existing.add(value);
}
