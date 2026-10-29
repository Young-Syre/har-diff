/**
 * Shared types for har-diff.
 *
 * Everything here is plain data so that any output can be serialised to JSON
 * and so the programmatic API is usable without importing implementation code.
 */

/** Shape of an identifier found in a URL, query string or body. */
export type IdentifierKind =
  | 'integer'
  | 'uuid'
  | 'ulid'
  | 'objectid'
  | 'hex'
  | 'jwt'
  | 'email'
  | 'base64url'
  | 'slug';

/** Where in a request/response a value was observed. */
export type ValueLocation =
  | 'path'
  | 'query'
  | 'request-body'
  | 'response-body'
  | 'header';

export interface HarHeader {
  name: string;
  value: string;
}

export interface QueryParam {
  name: string;
  value: string;
}

/** A templated path segment and the concrete value it replaced. */
export interface PathParam {
  /** Zero-based index of the segment within the path. */
  index: number;
  kind: IdentifierKind;
  value: string;
  /** The placeholder written into the template, e.g. `{int}`. */
  placeholder: string;
}

/** A parameter name discovered in a JSON or form-encoded body. */
export interface BodyParam {
  /** Dotted path, with `[]` for array elements, e.g. `user.roles[]`. */
  name: string;
  /** Stringified scalar value, or null for objects/arrays/null. */
  value: string | null;
  encoding: 'json' | 'form' | 'unknown';
}

/**
 * A HAR entry normalised into a comparable shape.
 *
 * `signature` is the grouping key used by every diff: it deliberately excludes
 * query and body parameter names so that two captures of the same endpoint
 * group together and their parameters can be compared.
 */
export interface CanonicalRequest {
  /** Index of the source entry within its HAR log. */
  index: number;
  method: string;
  scheme: string;
  host: string;
  port: number;
  /** Full original URL. Redacted before it reaches any output. */
  url: string;
  /** Raw path, no query string. */
  path: string;
  /** Path with identifier segments replaced by placeholders. */
  templatePath: string;
  pathParams: PathParam[];
  query: QueryParam[];
  /** Sorted, de-duplicated query parameter names. */
  queryNames: string[];
  bodyParams: BodyParam[];
  /** Sorted, de-duplicated body parameter names. */
  bodyParamNames: string[];
  requestContentType: string | null;
  responseContentType: string | null;
  requestHeaders: HarHeader[];
  /** Lowercased, sorted request header names. */
  requestHeaderNames: string[];
  requestBody: string | null;
  responseBody: string | null;
  status: number;
  statusText: string;
  /** Response body size in bytes, from `content.size` where available. */
  responseSize: number;
  /** `METHOD scheme://host[:port]<templatePath>` */
  signature: string;
}

/** One parsed HAR file. */
export interface Capture {
  label: string;
  file: string;
  requests: CanonicalRequest[];
  /** Non-fatal problems found while parsing (unsupported fields, bad URLs). */
  warnings: string[];
  /**
   * Literal credential-shaped strings seen in this capture. Used to guarantee
   * they are stripped from output; never rendered.
   */
  secrets: string[];
  /** HAR creator name/version, when the file declares one. */
  creator: string | null;
}

export interface ParseOptions {
  label?: string;
  /** Maximum recursion depth when walking JSON bodies. Default 8. */
  maxDepth?: number;
  /**
   * Maximum number of bytes of a body that will be walked for parameters and
   * identifiers. Default 1_000_000.
   */
  maxBodyBytes?: number;
  /**
   * Also template slug-shaped path segments (`/projects/acme-corp` ->
   * `/projects/{slug}`). Off by default because it over-groups real routes.
   */
  templateSlugs?: boolean;
}

export interface ObjectOccurrence {
  capture: string;
  signature: string;
  method: string;
  templatePath: string;
  location: ValueLocation;
  /**
   * Identifies the position within the location: the segment index for `path`,
   * the parameter name for `query`, the dotted path for bodies.
   */
  field: string;
  /** `signature|location|field` - a stable slot key for sequence analysis. */
  slot: string;
}

export interface ObjectRef {
  value: string;
  kind: IdentifierKind;
  /** True when the shape is trivially guessable, i.e. an integer id. */
  enumerable: boolean;
  /** True when the value was seen in a credential position; never printed. */
  sensitive: boolean;
  occurrences: ObjectOccurrence[];
}

/** A slot that held more than one integer id across the captures. */
export interface SequentialSlot {
  slot: string;
  signature: string;
  method: string;
  templatePath: string;
  location: ValueLocation;
  field: string;
  /** Sorted, distinct integer values seen in this slot. */
  values: number[];
  /** max - min. */
  span: number;
  /** True when every sorted neighbour differs by exactly one. */
  consecutive: boolean;
  /** True when the values are dense enough to be worth enumerating. */
  dense: boolean;
}

export interface ObjectIndex {
  refs: ObjectRef[];
  sequential: SequentialSlot[];
}

export interface CaptureRef {
  label: string;
  file: string;
  requestCount: number;
}

export interface EndpointExample {
  capture: string;
  url: string;
  status: number;
  responseSize: number;
}

/** An endpoint signature observed in exactly one capture. */
export interface ExclusiveEndpoint {
  signature: string;
  method: string;
  templatePath: string;
  label: string;
  privileged: boolean;
  examples: EndpointExample[];
}

/** Parameters present on a shared endpoint in one capture only. */
export interface ParameterDiff {
  signature: string;
  method: string;
  templatePath: string;
  label: string;
  privileged: boolean;
  params: { name: string; location: 'query' | 'request-body' }[];
  presentIn: string[];
}

export interface ResponseObservation {
  label: string;
  statuses: number[];
  sizes: number[];
  medianSize: number;
}

export interface ResponseDiff {
  signature: string;
  method: string;
  templatePath: string;
  observations: ResponseObservation[];
  statusDiffers: boolean;
  sizeDiffers: boolean;
}

/** An object reference seen in one capture's responses and nowhere else. */
export interface ObjectDiff {
  label: string;
  privileged: boolean;
  value: string;
  kind: IdentifierKind;
  enumerable: boolean;
  sensitive: boolean;
  /** Endpoint signatures whose responses contained the value. */
  seenIn: string[];
  /** Slots where a value of this kind appears as an input, if any. */
  inputSlots: string[];
}

export interface DiffResult {
  captures: CaptureRef[];
  privilegedLabel: string;
  /** Signatures observed in every capture. */
  shared: string[];
  exclusive: ExclusiveEndpoint[];
  parameterDiffs: ParameterDiff[];
  responseDiffs: ResponseDiff[];
  objectsOnlyIn: ObjectDiff[];
  objects: ObjectIndex;
}

export type CandidateKind =
  | 'privileged-only-endpoint'
  | 'privileged-only-parameter'
  | 'object-reference-substitution'
  | 'enumerable-identifier'
  | 'response-divergence';

export interface Substitution {
  location: ValueLocation;
  field: string;
  from: string;
  to: string;
}

export interface PlanRequest {
  method: string;
  url: string;
  headers: HarHeader[];
  body: string | null;
}

export interface PlanCandidate {
  id: string;
  kind: CandidateKind;
  title: string;
  /** Why this candidate exists, stated in terms of what was observed. */
  rationale: string;
  request: PlanRequest;
  /** Label of the capture whose credential should be used for the replay. */
  replayAs: string;
  /** Label of the capture the request shape was taken from. */
  sourceCapture: string;
  substitutions: Substitution[];
  /** What a correctly authorising server should do. */
  expected: string;
  /** What result would indicate a finding. */
  indicatesFinding: string;
  curl: string;
  evidence: EndpointExample[];
}

export interface TestPlan {
  captures: CaptureRef[];
  privilegedLabel: string;
  /** Environment variable names the emitted curl commands expect. */
  credentialPlaceholders: Record<string, string>;
  candidates: PlanCandidate[];
  notes: string[];
}

export interface PlanOptions {
  /** Cap on candidates per kind. Default 50. */
  limitPerKind?: number;
  /** Number of neighbouring ids to suggest for enumerable slots. Default 3. */
  enumerateNeighbours?: number;
}

export type OutputFormat = 'text' | 'json' | 'markdown';
