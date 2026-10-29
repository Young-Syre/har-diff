/**
 * Output rendering for text, JSON and markdown.
 *
 * Two rules hold for every renderer:
 *  - raw request and response bodies are never rendered, only their content
 *    type, size and parameter names;
 *  - the finished string is passed through the redactor before it is returned,
 *    so a credential that survived structural redaction is still stripped.
 */

import { Redactor } from './redact.js';
import type {
  Capture,
  CaptureRef,
  DiffResult,
  ObjectIndex,
  ObjectRef,
  OutputFormat,
  TestPlan,
} from './types.js';

function maskValue(ref: Pick<ObjectRef, 'value' | 'kind' | 'sensitive'>, redactor: Redactor): string {
  if (ref.sensitive && redactor.enabled) return `[REDACTED:${ref.kind}]`;
  return ref.value;
}

function heading(text: string): string {
  return `${text}\n${'='.repeat(text.length)}`;
}

function subheading(text: string): string {
  return `${text}\n${'-'.repeat(text.length)}`;
}

function table(headers: readonly string[], rows: readonly (readonly string[])[]): string {
  if (rows.length === 0) return '  (none)';
  const widths = headers.map((header, column) =>
    Math.max(header.length, ...rows.map((row) => (row[column] ?? '').length)),
  );
  const line = (cells: readonly string[]): string =>
    `  ${cells.map((cell, column) => cell.padEnd(widths[column] ?? 0)).join('  ').trimEnd()}`;
  return [line(headers), line(widths.map((width) => '-'.repeat(width))), ...rows.map(line)].join('\n');
}

function mdTable(headers: readonly string[], rows: readonly (readonly string[])[]): string {
  if (rows.length === 0) return '_none_';
  const escape = (cell: string): string => cell.replace(/\|/g, '\\|');
  return [
    `| ${headers.join(' | ')} |`,
    `| ${headers.map(() => '---').join(' | ')} |`,
    ...rows.map((row) => `| ${row.map((cell) => escape(cell ?? '')).join(' | ')} |`),
  ].join('\n');
}

function json(value: unknown, redactor: Redactor): string {
  return redactor.text(JSON.stringify(value, null, 2));
}

// --------------------------------------------------------------------------
// parse
// --------------------------------------------------------------------------

function parseView(captures: readonly Capture[], redactor: Redactor): unknown {
  return {
    captures: captures.map((capture) => ({
      label: capture.label,
      file: capture.file,
      creator: capture.creator,
      requestCount: capture.requests.length,
      distinctEndpoints: new Set(capture.requests.map((request) => request.signature)).size,
      secretsRedacted: redactor.enabled ? capture.secrets.length : 0,
      warnings: capture.warnings,
      requests: capture.requests.map((request) => ({
        index: request.index,
        method: request.method,
        url: redactor.url(request.url),
        scheme: request.scheme,
        host: request.host,
        port: request.port,
        path: request.path,
        templatePath: request.templatePath,
        pathParams: request.pathParams,
        queryNames: request.queryNames,
        bodyParamNames: request.bodyParamNames,
        requestHeaderNames: request.requestHeaderNames,
        requestContentType: request.requestContentType,
        responseContentType: request.responseContentType,
        status: request.status,
        responseSize: request.responseSize,
        signature: request.signature,
      })),
    })),
  };
}

export function renderParse(captures: readonly Capture[], format: OutputFormat, redactor: Redactor): string {
  if (format === 'json') return json(parseView(captures, redactor), redactor);

  const blocks: string[] = [];
  for (const capture of captures) {
    const rows = capture.requests.map((request) => [
      request.method,
      request.templatePath,
      String(request.status),
      `${request.responseSize}B`,
      request.queryNames.join(',') || '-',
      request.bodyParamNames.join(',') || '-',
    ]);
    const headers = ['METHOD', 'TEMPLATE PATH', 'STATUS', 'SIZE', 'QUERY PARAMS', 'BODY PARAMS'];
    const summary = [
      `requests: ${capture.requests.length}`,
      `distinct endpoints: ${new Set(capture.requests.map((request) => request.signature)).size}`,
      redactor.enabled ? `credential values redacted: ${capture.secrets.length}` : 'REDACTION DISABLED',
    ].join(' | ');

    if (format === 'markdown') {
      blocks.push(
        `## ${capture.label}\n\n` +
          `\`${capture.file}\`${capture.creator === null ? '' : ` (${capture.creator})`}\n\n` +
          `${summary}\n\n` +
          mdTable(headers, rows) +
          (capture.warnings.length > 0 ? `\n\nWarnings:\n${capture.warnings.map((w) => `- ${w}`).join('\n')}` : ''),
      );
    } else {
      blocks.push(
        `${subheading(`${capture.label}  (${capture.file})`)}\n` +
          `  ${summary}\n` +
          (capture.creator === null ? '' : `  creator: ${capture.creator}\n`) +
          `\n${table(headers, rows)}` +
          (capture.warnings.length > 0 ? `\n\n  warnings:\n${capture.warnings.map((w) => `    - ${w}`).join('\n')}` : ''),
      );
    }
  }

  const title = format === 'markdown' ? '# har-diff parse' : heading('har-diff parse');
  return redactor.text([title, ...blocks].join('\n\n').trimEnd() + '\n');
}

// --------------------------------------------------------------------------
// diff
// --------------------------------------------------------------------------

function diffView(diff: DiffResult, redactor: Redactor): unknown {
  return {
    captures: diff.captures,
    privilegedLabel: diff.privilegedLabel,
    sharedEndpointCount: diff.shared.length,
    shared: diff.shared,
    exclusive: diff.exclusive.map((endpoint) => ({
      ...endpoint,
      examples: endpoint.examples.map((example) => ({ ...example, url: redactor.url(example.url) })),
    })),
    parameterDiffs: diff.parameterDiffs,
    responseDiffs: diff.responseDiffs,
    objectsOnlyIn: diff.objectsOnlyIn.map((object) => ({ ...object, value: maskValue(object, redactor) })),
  };
}

export function renderDiff(diff: DiffResult, format: OutputFormat, redactor: Redactor): string {
  if (format === 'json') return json(diffView(diff, redactor), redactor);

  const md = format === 'markdown';
  const t = md ? mdTable : table;
  const h1 = md ? (text: string) => `# ${text}` : heading;
  // The trailing newline gives markdown a blank line before the table.
  const h2 = md ? (text: string) => `## ${text}\n` : subheading;

  const captureRows = diff.captures.map((capture) => [
    capture.label + (capture.label === diff.privilegedLabel ? ' (privileged)' : ''),
    capture.file,
    String(capture.requestCount),
  ]);

  const exclusiveRows = diff.exclusive.map((endpoint) => [
    endpoint.label,
    endpoint.privileged ? 'yes' : 'no',
    endpoint.method,
    endpoint.templatePath,
    endpoint.examples.map((example) => String(example.status)).join(',') || '-',
  ]);

  const paramRows = diff.parameterDiffs.map((entry) => [
    entry.label,
    entry.privileged ? 'yes' : 'no',
    entry.method,
    entry.templatePath,
    entry.params.map((param) => `${param.location}:${param.name}`).join(', '),
  ]);

  const responseRows = diff.responseDiffs.map((entry) => [
    entry.method,
    entry.templatePath,
    entry.statusDiffers ? 'status' : '',
    entry.sizeDiffers ? 'size' : '',
    entry.observations.map((o) => `${o.label}=${o.statuses.join('/')}@${o.medianSize}B`).join('  '),
  ]);

  const objectRows = diff.objectsOnlyIn.map((object) => [
    object.label,
    object.kind,
    maskValue(object, redactor),
    object.enumerable ? 'yes' : 'no',
    object.seenIn.length > 2 ? `${object.seenIn.slice(0, 2).join(', ')} +${object.seenIn.length - 2}` : object.seenIn.join(', '),
  ]);

  const sections = [
    h1('har-diff'),
    '',
    h2('Captures'),
    t(['LABEL', 'FILE', 'REQUESTS'], captureRows),
    '',
    `Shared endpoints (present in every capture): ${diff.shared.length}`,
    '',
    h2('Endpoints seen in one capture only'),
    md
      ? 'Endpoints exclusive to the privileged capture are the primary broken-function-level-authorisation candidates.'
      : '  Endpoints exclusive to the privileged capture are the primary BFLA candidates.',
    '',
    t(['CAPTURE', 'PRIVILEGED', 'METHOD', 'TEMPLATE PATH', 'STATUSES'], exclusiveRows),
    '',
    h2('Parameters present in one capture only'),
    md
      ? 'The endpoint exists for both sessions, but only one session sent these parameters - mass-assignment and privilege-parameter candidates.'
      : '  Endpoint shared, parameter not: mass-assignment / privilege-parameter candidates.',
    '',
    t(['CAPTURE', 'PRIVILEGED', 'METHOD', 'TEMPLATE PATH', 'PARAMETERS'], paramRows),
    '',
    h2('Divergent responses for the same request signature'),
    t(['METHOD', 'TEMPLATE PATH', 'STATUS', 'SIZE', 'OBSERVATIONS'], responseRows),
    '',
    h2('Object references seen in one capture only'),
    md
      ? "Values that appeared in one capture's responses and nowhere in the others. These are the concrete values to substitute when replaying."
      : '  Values from one capture\'s responses, absent everywhere else: substitute these when replaying.',
    '',
    t(['CAPTURE', 'KIND', 'VALUE', 'ENUMERABLE', 'SEEN IN'], objectRows),
    '',
  ];

  return redactor.text(sections.join('\n').trimEnd() + '\n');
}

// --------------------------------------------------------------------------
// objects
// --------------------------------------------------------------------------

function objectsView(index: ObjectIndex, captures: readonly CaptureRef[], redactor: Redactor): unknown {
  return {
    captures,
    counts: countByKind(index),
    refs: index.refs.map((ref) => ({
      value: maskValue(ref, redactor),
      kind: ref.kind,
      enumerable: ref.enumerable,
      sensitive: ref.sensitive,
      captures: [...new Set(ref.occurrences.map((occurrence) => occurrence.capture))].sort(),
      occurrences: ref.occurrences,
    })),
    sequential: index.sequential,
  };
}

function countByKind(index: ObjectIndex): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const ref of index.refs) counts[ref.kind] = (counts[ref.kind] ?? 0) + 1;
  return counts;
}

export function renderObjects(
  index: ObjectIndex,
  captures: readonly CaptureRef[],
  format: OutputFormat,
  redactor: Redactor,
): string {
  if (format === 'json') return json(objectsView(index, captures, redactor), redactor);

  const md = format === 'markdown';
  const t = md ? mdTable : table;
  const h1 = md ? (text: string) => `# ${text}` : heading;
  const h2 = md ? (text: string) => `## ${text}\n` : subheading;

  const counts = countByKind(index);
  const countRows = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([kind, count]) => [kind, String(count)]);

  const refRows = index.refs.map((ref) => [
    ref.kind,
    maskValue(ref, redactor),
    ref.enumerable ? 'yes' : 'no',
    [...new Set(ref.occurrences.map((occurrence) => occurrence.capture))].sort().join(','),
    [...new Set(ref.occurrences.map((occurrence) => `${occurrence.location}:${occurrence.field}`))]
      .slice(0, 3)
      .join(' '),
    `${ref.occurrences[0]?.method ?? ''} ${ref.occurrences[0]?.templatePath ?? ''}`.trim(),
  ]);

  const seqRows = index.sequential.map((slot) => [
    slot.method,
    slot.templatePath,
    `${slot.location}:${slot.field}`,
    slot.values.join(','),
    String(slot.span),
    slot.consecutive ? 'yes' : 'no',
    slot.dense ? 'yes' : 'no',
  ]);

  const enumerableCount = index.refs.filter((ref) => ref.enumerable).length;

  const sections = [
    h1('har-diff objects'),
    '',
    h2('Identifier shapes'),
    t(['KIND', 'COUNT'], countRows),
    '',
    `${enumerableCount} of ${index.refs.length} identifiers are integers, and therefore enumerable without needing a leaked value.`,
    '',
    h2('Candidate object references'),
    t(['KIND', 'VALUE', 'ENUMERABLE', 'CAPTURES', 'SLOTS', 'FIRST SEEN AT'], refRows),
    '',
    h2('Enumerable integer slots'),
    md
      ? 'Slots that held more than one integer id. `consecutive` means every observed id differs from its neighbour by one; `dense` means the range is small enough to walk exhaustively.'
      : '  Slots holding more than one integer id. consecutive = ids differ by 1; dense = range is small enough to walk.',
    '',
    t(['METHOD', 'TEMPLATE PATH', 'SLOT', 'VALUES', 'SPAN', 'CONSECUTIVE', 'DENSE'], seqRows),
    '',
  ];

  return redactor.text(sections.join('\n').trimEnd() + '\n');
}

// --------------------------------------------------------------------------
// plan
// --------------------------------------------------------------------------

export function renderPlan(plan: TestPlan, format: OutputFormat, redactor: Redactor): string {
  if (format === 'json') return json(plan, redactor);

  if (format === 'markdown') {
    const lines: string[] = [
      '# Authorisation test plan',
      '',
      `Privileged capture: **${plan.privilegedLabel}**`,
      '',
      mdTable(
        ['CAPTURE', 'FILE', 'REQUESTS'],
        plan.captures.map((capture) => [capture.label, capture.file, String(capture.requestCount)]),
      ),
      '',
      '## Before you start',
      '',
      ...plan.notes.map((note) => `- ${note}`),
      '',
      'Credential variables expected by the commands below:',
      '',
      mdTable(
        ['CAPTURE', 'ENVIRONMENT VARIABLES'],
        Object.entries(plan.credentialPlaceholders).map(([label, vars]) => [label, `\`${vars}\``]),
      ),
      '',
      `## Candidates (${plan.candidates.length})`,
      '',
    ];

    for (const candidate of plan.candidates) {
      lines.push(`### [ ] ${candidate.id} - ${candidate.title}`);
      lines.push('');
      lines.push(`**Kind:** \`${candidate.kind}\``);
      lines.push('');
      lines.push(`**Why:** ${candidate.rationale}`);
      lines.push('');
      lines.push(`**Replay as:** \`${candidate.replayAs}\` (request shape taken from \`${candidate.sourceCapture}\`)`);
      lines.push('');
      if (candidate.substitutions.length > 0) {
        lines.push('**Substitute:**');
        lines.push('');
        lines.push(
          mdTable(
            ['LOCATION', 'FIELD', 'FROM', 'TO'],
            candidate.substitutions.map((sub) => [sub.location, sub.field, sub.from, sub.to]),
          ),
        );
        lines.push('');
      }
      lines.push(`**Expected:** ${candidate.expected}`);
      lines.push('');
      lines.push(`**Indicates a finding:** ${candidate.indicatesFinding}`);
      lines.push('');
      lines.push('```bash');
      lines.push(candidate.curl);
      lines.push('```');
      lines.push('');
      if (candidate.evidence.length > 0) {
        lines.push('<details><summary>Observed in capture</summary>');
        lines.push('');
        lines.push(
          mdTable(
            ['CAPTURE', 'URL', 'STATUS', 'SIZE'],
            candidate.evidence.map((example) => [
              example.capture,
              redactor.url(example.url),
              String(example.status),
              `${example.responseSize}B`,
            ]),
          ),
        );
        lines.push('');
        lines.push('</details>');
        lines.push('');
      }
    }

    return redactor.text(lines.join('\n').trimEnd() + '\n');
  }

  const lines: string[] = [
    heading('Authorisation test plan'),
    '',
    `privileged capture: ${plan.privilegedLabel}`,
    `candidates: ${plan.candidates.length}`,
    '',
    table(
      ['CAPTURE', 'FILE', 'REQUESTS'],
      plan.captures.map((capture) => [capture.label, capture.file, String(capture.requestCount)]),
    ),
    '',
    subheading('Before you start'),
    ...plan.notes.map((note) => `  - ${note}`),
    '',
    table(['CAPTURE', 'ENVIRONMENT VARIABLES'], Object.entries(plan.credentialPlaceholders).map(([label, vars]) => [label, vars])),
    '',
  ];

  for (const candidate of plan.candidates) {
    lines.push(subheading(`[ ] ${candidate.id}  ${candidate.title}`));
    lines.push(`  kind      : ${candidate.kind}`);
    lines.push(`  why       : ${candidate.rationale}`);
    lines.push(`  replay as : ${candidate.replayAs}  (shape from ${candidate.sourceCapture})`);
    for (const sub of candidate.substitutions) {
      lines.push(`  substitute: ${sub.location}:${sub.field}  ${sub.from} -> ${sub.to}`);
    }
    lines.push(`  expected  : ${candidate.expected}`);
    lines.push(`  finding if: ${candidate.indicatesFinding}`);
    lines.push(`  command   : ${candidate.curl}`);
    for (const example of candidate.evidence) {
      lines.push(`  observed  : ${example.capture} -> ${example.status} (${example.responseSize}B) ${redactor.url(example.url)}`);
    }
    lines.push('');
  }

  return redactor.text(lines.join('\n').trimEnd() + '\n');
}
