#!/usr/bin/env node
/**
 * har-diff command line interface.
 *
 * Hand-rolled argument parsing, no runtime dependencies.
 */

import { readFileSync, realpathSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { fileURLToPath } from 'node:url';

import { diffCaptures } from './diff.js';
import { renderDiff, renderObjects, renderParse, renderPlan } from './format.js';
import { parseHarFile } from './har.js';
import { extractObjects } from './objects.js';
import { buildPlan } from './plan.js';
import { Redactor, UNSAFE_WARNING } from './redact.js';
import type { Capture, OutputFormat } from './types.js';

const COMMANDS = ['parse', 'diff', 'objects', 'plan'] as const;
type Command = (typeof COMMANDS)[number];

interface Options {
  command: Command | null;
  files: string[];
  labels: string[];
  format: OutputFormat | null;
  privileged: string | null;
  showSecrets: boolean;
  templateSlugs: boolean;
  maxDepth: number;
  limitPerKind: number;
  neighbours: number;
  out: string | null;
  help: boolean;
  version: boolean;
}

function version(): string {
  try {
    const raw = readFileSync(new URL('../../package.json', import.meta.url), 'utf8');
    const parsed = JSON.parse(raw) as { version?: unknown };
    return typeof parsed.version === 'string' ? parsed.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

const USAGE = `har-diff ${version()} - authorisation testing from HAR captures

USAGE
  har-diff <command> [options] <capture.har> [capture.har ...]

COMMANDS
  parse      Normalise HAR entries into canonical requests and show what was found.
  diff       Compare two or more captures: endpoints, parameters, responses and
             object references that exist for one session and not another.
  objects    Extract and classify every candidate object identifier.
  plan       Emit an authorisation test plan: what to replay, as whom, with
             which object reference substituted, and what would be a finding.

OPTIONS
  -f, --format <text|json|markdown>
                          Output format. Default: text (markdown for 'plan').
      --label <name>      Name for a capture. Repeat once per file, in file
                          order. Defaults to each file's basename.
      --privileged <name> Label of the privileged capture. Default: the first.
      --unsafe-show-secrets
                          Print credentials verbatim. Prints a warning first.
                          Do not use for anything you will share.
      --template-slugs    Also template slug-shaped path segments
                          (/projects/acme -> /projects/{slug}).
      --max-depth <n>     Recursion cap when walking JSON bodies. Default 8.
      --limit <n>         Max plan candidates per kind. Default 50.
      --neighbours <n>    Neighbouring integer ids to suggest. Default 3.
  -o, --out <file>        Write output to a file instead of stdout.
  -h, --help              Show this help.
  -V, --version           Show the version.

EXAMPLES
  har-diff diff admin.har user.har --label admin --label user
  har-diff plan admin.har user.har --label admin --label user > plan.md
  har-diff objects user.har --format json
  har-diff diff admin.har manager.har user.har \\
    --label admin --label manager --label user --privileged admin

SECRETS
  HAR captures contain live session cookies and bearer tokens. har-diff
  redacts credential headers, cookies, credential-shaped parameters and known
  token formats from all output by default, and strips every credential value
  it saw while parsing from the rendered result. Treat the capture files
  themselves as secrets regardless.

Authorised testing only. har-diff reports candidates; it never sends a request.
`;

function fail(message: string): never {
  process.stderr.write(`har-diff: ${message}\n`);
  process.stderr.write(`Run 'har-diff --help' for usage.\n`);
  process.exit(1);
}

function requireValue(flag: string, value: string | undefined): string {
  if (value === undefined) fail(`${flag} requires a value`);
  return value;
}

function parseFormat(value: string): OutputFormat {
  if (value === 'text' || value === 'json' || value === 'markdown') return value;
  if (value === 'md') return 'markdown';
  return fail(`unknown format "${value}" (expected text, json or markdown)`);
}

function parsePositiveInt(flag: string, value: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < 0) fail(`${flag} expects a non-negative integer`);
  return parsed;
}

export function parseArgs(argv: readonly string[]): Options {
  const options: Options = {
    command: null,
    files: [],
    labels: [],
    format: null,
    privileged: null,
    showSecrets: false,
    templateSlugs: false,
    maxDepth: 8,
    limitPerKind: 50,
    neighbours: 3,
    out: null,
    help: false,
    version: false,
  };

  let index = 0;
  while (index < argv.length) {
    const arg = argv[index] as string;
    index += 1;

    if (arg === '--') {
      options.files.push(...argv.slice(index));
      break;
    }
    if (arg === '-h' || arg === '--help') {
      options.help = true;
      continue;
    }
    if (arg === '-V' || arg === '--version') {
      options.version = true;
      continue;
    }
    if (arg === '-f' || arg === '--format') {
      options.format = parseFormat(requireValue(arg, argv[index]));
      index += 1;
      continue;
    }
    if (arg.startsWith('--format=')) {
      options.format = parseFormat(arg.slice('--format='.length));
      continue;
    }
    if (arg === '--label') {
      options.labels.push(requireValue(arg, argv[index]));
      index += 1;
      continue;
    }
    if (arg.startsWith('--label=')) {
      options.labels.push(arg.slice('--label='.length));
      continue;
    }
    if (arg === '--privileged') {
      options.privileged = requireValue(arg, argv[index]);
      index += 1;
      continue;
    }
    if (arg.startsWith('--privileged=')) {
      options.privileged = arg.slice('--privileged='.length);
      continue;
    }
    if (arg === '--unsafe-show-secrets') {
      options.showSecrets = true;
      continue;
    }
    if (arg === '--template-slugs') {
      options.templateSlugs = true;
      continue;
    }
    if (arg === '--max-depth') {
      options.maxDepth = parsePositiveInt(arg, requireValue(arg, argv[index]));
      index += 1;
      continue;
    }
    if (arg === '--limit') {
      options.limitPerKind = parsePositiveInt(arg, requireValue(arg, argv[index]));
      index += 1;
      continue;
    }
    if (arg === '--neighbours' || arg === '--neighbors') {
      options.neighbours = parsePositiveInt(arg, requireValue(arg, argv[index]));
      index += 1;
      continue;
    }
    if (arg === '-o' || arg === '--out') {
      options.out = requireValue(arg, argv[index]);
      index += 1;
      continue;
    }
    if (arg.startsWith('--out=')) {
      options.out = arg.slice('--out='.length);
      continue;
    }
    if (arg.startsWith('-') && arg !== '-') {
      fail(`unknown option "${arg}"`);
    }
    if (options.command === null && (COMMANDS as readonly string[]).includes(arg)) {
      options.command = arg as Command;
      continue;
    }
    options.files.push(arg);
  }

  return options;
}

function labelFor(options: Options, file: string, position: number): string {
  const explicit = options.labels[position];
  if (explicit !== undefined) return explicit;
  return basename(file).replace(/\.har$/i, '') || `capture${position + 1}`;
}

async function loadCaptures(options: Options): Promise<Capture[]> {
  const captures: Capture[] = [];
  for (const [position, file] of options.files.entries()) {
    try {
      captures.push(
        await parseHarFile(file, {
          label: labelFor(options, file, position),
          maxDepth: options.maxDepth,
          templateSlugs: options.templateSlugs,
        }),
      );
    } catch (error) {
      fail(`${file}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return captures;
}

async function emit(text: string, out: string | null): Promise<void> {
  if (out === null) {
    process.stdout.write(text);
    return;
  }
  await writeFile(out, text, 'utf8');
  process.stderr.write(`har-diff: wrote ${out}\n`);
}

export async function run(argv: readonly string[]): Promise<number> {
  const options = parseArgs(argv);

  if (options.version && options.command === null) {
    process.stdout.write(`${version()}\n`);
    return 0;
  }
  if (options.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (options.command === null) {
    const first = options.files[0];
    if (first !== undefined) fail(`unknown command "${first}" (expected one of: ${COMMANDS.join(', ')})`);
    process.stdout.write(USAGE);
    return 1;
  }
  if (options.files.length === 0) fail(`${options.command} needs at least one HAR file`);
  if (options.labels.length > options.files.length) {
    fail(`more --label values (${options.labels.length}) than files (${options.files.length})`);
  }
  if ((options.command === 'diff' || options.command === 'plan') && options.files.length < 2) {
    fail(`${options.command} needs at least two HAR files - one per privilege level`);
  }
  if (options.showSecrets) process.stderr.write(`${UNSAFE_WARNING}\n`);

  const captures = await loadCaptures(options);
  const redactor = new Redactor(
    captures.flatMap((capture) => capture.secrets),
    { showSecrets: options.showSecrets },
  );
  const format: OutputFormat = options.format ?? (options.command === 'plan' ? 'markdown' : 'text');

  if (options.command === 'parse') {
    await emit(renderParse(captures, format, redactor), options.out);
    return 0;
  }

  if (options.command === 'objects') {
    const objects = extractObjects(captures, { maxDepth: options.maxDepth });
    const refs = captures.map((capture) => ({
      label: capture.label,
      file: capture.file,
      requestCount: capture.requests.length,
    }));
    await emit(renderObjects(objects, refs, format, redactor), options.out);
    return 0;
  }

  const objects = extractObjects(captures, { maxDepth: options.maxDepth });
  let diff;
  try {
    diff = diffCaptures(captures, {
      objects,
      ...(options.privileged === null ? {} : { privilegedLabel: options.privileged }),
    });
  } catch (error) {
    return fail(error instanceof Error ? error.message : String(error));
  }

  if (options.command === 'diff') {
    await emit(renderDiff(diff, format, redactor), options.out);
    return 0;
  }

  const plan = buildPlan(captures, diff, {
    limitPerKind: options.limitPerKind,
    enumerateNeighbours: options.neighbours,
  });
  await emit(renderPlan(plan, format, redactor), options.out);
  return 0;
}

/**
 * True when this module is the process entry point. `process.argv[1]` is the
 * path node was given, which for a globally installed or `npm link`ed CLI is a
 * symlink to this file - so both sides are resolved before comparing.
 */
function isEntryPoint(): boolean {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return realpathSync(argv1) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  run(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      process.stderr.write(`har-diff: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    });
}
