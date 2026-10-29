# har-diff

[![tests](https://github.com/Young-Syre/har-diff/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/har-diff/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![node](https://img.shields.io/badge/node-%E2%89%A520-brightgreen.svg)](package.json)
[![runtime dependencies: 0](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen.svg)](package.json)
[![TypeScript: strict](https://img.shields.io/badge/TypeScript-strict-3178c6.svg)](tsconfig.json)
[![redacts secrets by default](https://img.shields.io/badge/secrets-redacted%20by%20default-important.svg)](#har-files-contain-live-credentials)

**Take HAR captures of the same application from two or more sessions at different privilege levels, and get back the authorisation test plan: which endpoints, parameters and object references exist for one role and not another.**

---

## Why

The reliable way to find IDOR/BOLA is a two-account test. Register two accounts — one privileged, one not — capture a session as each, then replay the privileged requests with the low-privilege credential and see what succeeds. It is not clever, but it is the method that actually finds the bug, because it tests the server's authorisation decision directly instead of guessing at it from the outside.

The part that goes wrong is the bookkeeping. A few minutes of clicking through an admin panel produces several hundred HAR entries. Doing the comparison by eye means reading two long lists side by side and noticing which paths, which query parameters, which body fields and which object ids appear in one and not the other — and then keeping track of which of them you have actually replayed. That is where things get missed: not in the exploitation, in the diff.

har-diff mechanises the diff and the candidate selection. It templates identifier segments out of paths so that `/api/users/8123` and `/api/users/8124` group into one endpoint, groups both captures by canonical request signature, and reports the differences that matter for authorisation. Then it writes the work list: for each candidate, the request to replay, which credential to replay it with, the object reference to substitute, and what result would indicate a finding.

It never sends a request. You do that.

## Install

```bash
git clone https://github.com/Young-Syre/har-diff
cd har-diff
npm install
npm test
```

Then either `node dist/src/cli.js …` or `npm link` for a `har-diff` on your `PATH`.

Node >= 20. Zero runtime dependencies — a HAR file is just JSON, and the rest is the standard library.

## Commands

| Command | What it does |
| --- | --- |
| `har-diff parse <capture.har>…` | Normalise HAR entries into canonical requests: method, scheme/host/port, templated path, sorted query and body parameter names, content types, status, response size. Use it to sanity-check a capture before diffing it. |
| `har-diff diff <a.har> <b.har>…` | Compare captures. Reports endpoints present in one capture only, parameters present on a shared endpoint in one capture only, divergent status/size for the same signature, and object references seen in one capture's responses and nowhere else. |
| `har-diff objects <capture.har>…` | Extract every candidate object identifier from paths, query strings, request bodies and response bodies, classified by shape, with the endpoints and slots each appeared in. Calls out enumerable integer id slots. |
| `har-diff plan <a.har> <b.har>…` | Emit the authorisation test plan as a markdown checklist (or JSON), with ready-to-run `curl` commands that take the credential from an environment variable. |

Common options:

| Option | Effect |
| --- | --- |
| `-f, --format text\|json\|markdown` | Output format. Default `text`, except `plan`, which defaults to `markdown`. |
| `--label <name>` | Name a capture. Repeat once per file, in file order. Defaults to each file's basename. |
| `--privileged <name>` | Which capture is the privileged one. Default: the first. |
| `--unsafe-show-secrets` | Print credentials verbatim. Prints a warning to stderr first. |
| `--template-slugs` | Also template slug-shaped path segments (`/projects/acme-corp` -> `/projects/{slug}`). |
| `--max-depth <n>` | Recursion cap when walking JSON bodies. Default 8. |
| `--limit <n>` | Maximum plan candidates per kind. Default 50. |
| `--neighbours <n>` | Neighbouring integer ids to suggest for enumerable slots. Default 3. |
| `-o, --out <file>` | Write to a file instead of stdout. |

N-way diffs work: pass three or more captures and label them. The privileged capture is compared against all the others, and an endpoint present in some but not all captures is reported as exclusive to none of them.

## Worked example

The repository ships two small synthetic captures of a toy API, `test/fixtures/admin.har` and `test/fixtures/user.har`. Everything below is real, unedited output from those two files.

The admin session browsed twelve requests; the user session eight. Both hit `GET /api/v1/users`, `GET /api/v1/users/{id}`, `PATCH /api/v1/users/{id}` and `GET /api/v1/documents/{uuid}`.

### `har-diff diff`

```console
$ har-diff diff test/fixtures/admin.har test/fixtures/user.har --label admin --label user
har-diff
========

Captures
--------
  LABEL               FILE                     REQUESTS
  ------------------  -----------------------  --------
  admin (privileged)  test/fixtures/admin.har  12
  user                test/fixtures/user.har   8

Shared endpoints (present in every capture): 4

Endpoints seen in one capture only
----------------------------------
  Endpoints exclusive to the privileged capture are the primary BFLA candidates.

  CAPTURE  PRIVILEGED  METHOD  TEMPLATE PATH                 STATUSES
  -------  ----------  ------  ----------------------------  --------
  admin    yes         GET     /api/v1/admin/audit-log       200
  admin    yes         GET     /api/v1/attachments/{b64}     200
  admin    yes         GET     /api/v1/events                200
  admin    yes         GET     /api/v1/exports/{hex}         200
  admin    yes         GET     /api/v1/orders/{objectid}     200
  admin    yes         GET     /api/v1/projects/acme-corp    200
  user     no          GET     /api/v1/admin/settings        403
  user     no          GET     /api/v1/invites/accept        200
  user     no          GET     /api/v1/notifications         200
  user     no          GET     /api/v1/projects/zenith-labs  200

Parameters present in one capture only
--------------------------------------
  Endpoint shared, parameter not: mass-assignment / privilege-parameter candidates.

  CAPTURE  PRIVILEGED  METHOD  TEMPLATE PATH        PARAMETERS
  -------  ----------  ------  -------------------  --------------------------------------
  admin    yes         PATCH   /api/v1/users/{int}  request-body:org_id, request-body:role

Divergent responses for the same request signature
--------------------------------------------------
  METHOD  TEMPLATE PATH  STATUS  SIZE  OBSERVATIONS
  ------  -------------  ------  ----  -----------------------------
  GET     /api/v1/users          size  admin=200@312B  user=200@120B
```

Three things to notice.

`GET /api/v1/admin/audit-log` is the obvious candidate: the admin session called it, the user session never did. That does not mean the user session *cannot* call it, which is exactly the point.

`PATCH /api/v1/users/{int}` is shared, but only the admin session sent `role` and `org_id` in the body. If the handler binds the whole body onto the model, a member can promote themselves.

The slug endpoints show up as two separate admin-only and user-only entries, because `acme-corp` and `zenith-labs` are not templated by default — a slug and an ordinary route word look identical without a route table, and templating them would collapse `/account/reset-password` into `/account/{slug}`. Pass `--template-slugs` and they group into one shared `/api/v1/projects/{slug}` endpoint.

The object reference table (truncated here) is the part that feeds substitution:

```console
Object references seen in one capture only
------------------------------------------
  Values from one capture's responses, absent everywhere else: substitute these when replaying.

  CAPTURE  KIND       VALUE                                 ENUMERABLE  SEEN IN
  -------  ---------  ------------------------------------  ----------  -------------------------------------
  admin    base64url  Zm9vYmFyLTEyMzQ1Njc4OQ                no          GET …/api/v1/attachments/{b64}
  admin    email      dana.keeler@shopfront.test            no          GET …/api/v1/users, GET …/users/{int}
  admin    hex        9f8e7d6c5b4a39281706f5e4d3c2b1a0      no          GET …/api/v1/exports/{hex}
  admin    integer    8123                                  yes         GET …/api/v1/users +6
  admin    objectid   65f1c2a9b4d3e8f012345678              no          GET …/api/v1/orders/{objectid}
  admin    slug       acme-corp                             no          GET …/api/v1/projects/acme-corp
  admin    uuid       9f2b4c6d-15a7-4e3b-93c8-2d7a6b41e0f5  no          GET …/api/v1/documents/{uuid}
```

### `har-diff objects`

Every value in a path, query string or body that has the shape of an object identifier, classified and located. The enumerable section is the one worth reading first:

```console
$ har-diff objects test/fixtures/admin.har test/fixtures/user.har --label admin --label user
…
Enumerable integer slots
------------------------
  Slots holding more than one integer id. consecutive = ids differ by 1; dense = range is small enough to walk.

  METHOD  TEMPLATE PATH             SLOT                               VALUES               SPAN  CONSECUTIVE  DENSE
  ------  ------------------------  ---------------------------------  -------------------  ----  -----------  -----
  GET     /api/v1/admin/audit-log   response-body:entries[].id         77201,77202          1     yes          yes
  GET     /api/v1/admin/audit-log   response-body:entries[].target_id  8124,8125            1     yes          yes
  GET     /api/v1/users/{int}       path:4                             8123,8124,8125,9001  878   no           no
  PATCH   /api/v1/users/{int}       path:4                             8124,9001            877   no           no
```

An integer object reference does not need a leaked value to attack — it can be counted to. `consecutive` means every observed id differed from its neighbour by one; `dense` means the range is small enough to walk exhaustively.

### `har-diff plan`

```console
$ har-diff plan test/fixtures/admin.har test/fixtures/user.har --label admin --label user > plan.md
```

The result is a checklist you work through. Two candidates from it, unedited:

> ### [ ] HD-007 - GET /api/v1/users/{int} - substitute integer 8123 (path:4)
>
> **Kind:** `object-reference-substitution`
>
> **Why:** 8123 appeared only in the "admin" capture's responses (GET https://api.shopfront.test/api/v1/admin/audit-log, GET https://api.shopfront.test/api/v1/attachments/{b64}, GET https://api.shopfront.test/api/v1/documents/{uuid} and 4 more). GET /api/v1/users/{int} accepts an integer at path:4, so the user session can be made to ask for it.
>
> **Replay as:** `user` (request shape taken from `user`)
>
> **Substitute:**
>
> | LOCATION | FIELD | FROM | TO |
> | --- | --- | --- | --- |
> | path | 4 | 9001 | 8123 |
>
> **Expected:** 401, 403 or 404 - the user session has no relationship to that object.
>
> **Indicates a finding:** A 2xx response containing the object's attributes is an IDOR/BOLA finding. A 200 with an empty list or a null body is not: confirm the response actually discloses admin's data.
>
> ```bash
> curl -i -s -X GET 'https://api.shopfront.test/api/v1/users/8123' -H 'Accept: application/json' -H 'X-Requested-With: XMLHttpRequest' -H "Authorization: Bearer $HARDIFF_USER_TOKEN" -H "Cookie: $HARDIFF_USER_COOKIE"
> ```

> ### [ ] HD-014 - PATCH /api/v1/users/{int} - send request-body:org_id, request-body:role as user
>
> **Kind:** `privileged-only-parameter`
>
> **Why:** Both captures use this endpoint, but only "admin" sent request-body:org_id, request-body:role. If the server binds that parameter without re-checking the caller's role, the user session can set it too.
>
> **Replay as:** `user` (request shape taken from `admin`)
>
> **Substitute:**
>
> | LOCATION | FIELD | FROM | TO |
> | --- | --- | --- | --- |
> | request-body | org_id | (absent) | 41 |
> | request-body | role | (absent) | billing |
>
> **Expected:** The parameter is ignored or rejected, and the stored object is unchanged.
>
> **Indicates a finding:** If the response reflects the parameter, or a follow-up read shows it was persisted, this is mass assignment / privilege escalation via parameter binding. Re-read the object as admin to confirm it stuck.
>
> ```bash
> curl -i -s -X PATCH 'https://api.shopfront.test/api/v1/users/8124' -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-Requested-With: XMLHttpRequest' -H "Authorization: Bearer $HARDIFF_USER_TOKEN" -H "Cookie: $HARDIFF_USER_COOKIE" --data-raw '{"display_name":"Ravi Subedi","role":"billing","org_id":41}'
> ```

Set `HARDIFF_USER_TOKEN` and `HARDIFF_USER_COOKIE` from the low-privilege session, then run the commands. No token ever appears in the plan.

### Candidate kinds

| Kind | Derived from | Tests for |
| --- | --- | --- |
| `privileged-only-endpoint` | An endpoint signature in the privileged capture only | Broken function level authorisation (BFLA) |
| `object-reference-substitution` | A value in the privileged capture's responses, absent from the others, paired with a slot that accepts that shape | IDOR / BOLA |
| `privileged-only-parameter` | A parameter sent on a shared endpoint by the privileged session only | Mass assignment, privilege parameters |
| `enumerable-identifier` | A slot that held more than one integer id | IDOR by enumeration |
| `response-divergence` | The same signature answering with a different status or size per session | An endpoint keying off the request rather than the session |

Integer values are deliberately *not* paired with arbitrary integer slots. Every small integer looks like every other small integer, so that pairing produces mostly noise; integers get `enumerable-identifier` candidates instead, and only substitute into slots where that exact value was actually observed.

## Capturing a HAR

### Chrome / Edge DevTools

1. Open DevTools (F12) and go to **Network**.
2. Enable **Preserve log** so navigation does not clear the capture.
3. Leave **Disable cache** on, so you capture requests rather than cache hits.
4. Click through the application as the privileged user: every page, every list, every detail view, every settings screen. The diff can only reason about requests you actually made.
5. Right-click anywhere in the request list and export the HAR. **Include response content** — without response bodies there are no object references to extract.
6. Log in as the low-privilege user in a separate browser profile and repeat into a second file.

Use two separate browser profiles rather than logging out and back in. It keeps the sessions from contaminating each other, and it is what you will want anyway when you replay.

**On sanitized exports.** Chromium 130 and later sanitize DevTools HAR exports by default, stripping `Cookie`, `Set-Cookie` and `Authorization` headers; the export menu item is labelled accordingly, and an unsanitized export needs *Settings -> Preferences -> Network -> "Allow to generate HAR with sensitive data"* turned on first. Exact menu wording moves between versions, so read the two export entries before picking one.

A sanitized HAR is still perfectly usable here. Paths, parameters, bodies, statuses and response content all survive, so the diff and the object extraction are unaffected. The one thing lost is which header carried the session: without it, `plan` cannot tell whether the API authenticated by bearer token or by cookie, so it emits a `Cookie: $HARDIFF_<LABEL>_COOKIE` placeholder and says so in the candidate. Fix it by hand, or export with sensitive data and let har-diff's own redaction handle the credentials — which is the case it is built for.

### Burp Suite

Burp has no native HAR export of proxy history, so this takes a conversion step. In rough order of least friction:

- Capture in the browser's own DevTools *while proxying through Burp*. You keep Burp's history for replay and get a HAR directly.
- **Proxy -> HTTP history**, select the rows you want, right-click -> **Save items**. That writes Burp XML, which needs converting to HAR.
- **Logger++** (BApp Store) exports to CSV, JSON or Elasticsearch — not HAR — so it also needs a conversion step, but its JSON is easier to transform than Burp XML.

Going the other way, the **HAR Importer** BApp loads a HAR into Burp's site map, which is a convenient way to get har-diff's candidates into Repeater once you have picked the ones you want to replay.

Either way, set your scope before you start browsing and filter the history to in-scope hosts, and keep one Burp project per privilege level so the two histories stay separate.

### mitmproxy

mitmproxy 10.1 and later writes HAR natively:

```bash
mitmdump -w admin.flows                        # browse as admin, then stop
mitmdump -nr admin.flows --set hardump=admin.har
```

On older versions the same thing needs the bundled example script: `mitmdump -nr admin.flows -s har_dump.py --set hardump=admin.har`.

## HAR files contain live credentials

A HAR file is a verbatim recording of an authenticated session. It contains your session cookies, bearer tokens, API keys, CSRF tokens, and whatever was in the bodies of the requests you made — frequently including passwords, from the login request you captured on the way in.

**Treat every capture as a secret.** Do not commit them, do not attach them to a ticket, do not paste them into a chat client or an LLM, and delete them when the engagement is over. The `.gitignore` in this repository ignores `*.har` for that reason.

har-diff redacts by default, in three layers:

1. **Structural** — credential headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key` and friends), cookie values, and query parameters and body fields whose name marks them as credentials (`password`, `access_token`, `client_secret`, `session`, `sig`, …) are replaced before they are put into an output object.
2. **Literal** — every credential-shaped string seen while parsing is recorded and removed from the rendered output by exact match, including its percent-encoded form. This is the backstop: it holds even if a value escapes layer 1.
3. **Pattern** — a final sweep of the finished document for high-confidence token shapes: JWTs, `Bearer`/`Basic` header values, AWS access key ids, Stripe, GitHub, Slack, Google and npm key prefixes, and PEM private key blocks.

Layer 3 is deliberately limited to distinctive prefixes. A broad "anything long and random" sweep would also destroy the object references the tool exists to report.

Response bodies are never rendered, and neither is a request body in `parse`, `diff` or `objects` — only its content type, size and parameter names. A request body *is* rendered in the `plan` command's `curl`, because a replay that omits the body does not reproduce the request. It goes through a structural redaction first: JSON leaves, form fields and `multipart/form-data` parts whose name reads as a credential have their value replaced with `[REDACTED]`, and the rest of the body is left byte for byte. `Referer` and `Origin` are URLs and get the same query-parameter treatment as the request's own URL. Emitted `curl` commands carry `$HARDIFF_<LABEL>_TOKEN` / `$HARDIFF_<LABEL>_COOKIE` placeholders, never a real credential.

Redaction is name-driven, so a credential in a field named like an identifier survives it. That is why `plan` output is still capture-derived material: review it before pasting it anywhere.

`--unsafe-show-secrets` disables all of it. It prints a warning to stderr first, and you should not use it on anything you intend to share.

The test suite asserts this rather than asking you to trust it: it renders all four commands in all three formats against fixtures whose credentials are known strings, and fails if any of those strings — or even the substring `FIXTURE` — survives into any output.

## Authorised use only

har-diff is for testing applications you own or have written permission to test: your own systems, a client engagement with a signed scope, or a bug bounty programme whose policy covers the target and the technique.

It produces candidates, not requests. The moment you run one of the emitted `curl` commands you are sending traffic to a live system, and that is on you. Two-account authorisation testing also means handling another account's data: when a candidate confirms, record only what you need to demonstrate the finding, and do not go further into the data than the proof requires. Multi-tenant SaaS programmes usually have explicit rules about this. Read them.

## Limitations

These are real, and worth knowing before you rely on the output.

- **It finds candidates. It does not confirm anything.** Every item in the plan is a hypothesis about an authorisation decision the server might get wrong. Confirmation is replaying the request and reading the response. There is no shortcut.
- **A 200 is not a finding.** A `200` with an empty list, a null body, or a generic "not found" payload is how plenty of correct implementations answer an unauthorised read. Confirm the response actually discloses the other account's data before you write it up.
- **It cannot model business rules.** A manager who is *supposed* to read their reports' records will look exactly like a BOLA finding. So will a deliberately public endpoint. har-diff has no idea what your authorisation model is meant to be; only you do.
- **It only knows what you captured.** An endpoint the privileged session never touched does not appear. Coverage of the diff is exactly the coverage of your browsing, which is the single biggest determinant of how useful the output is.
- **Absence from the low-privilege capture means nothing on its own.** The user session not calling `/admin/audit-log` is a fact about the UI, not about the server's authorisation. That is why it is a candidate.
- **Path templating is a heuristic.** Identifier-shaped segments are templated; slugs are not, unless you pass `--template-slugs`. A route whose segments are English words (`/account/settings/billing`) is indistinguishable from a path containing a slug id, and getting this wrong in either direction either over-groups distinct endpoints or reports one endpoint as two.
- **Object shape classification is a heuristic too.** A 20-character mixed-case string could be an opaque object id or an unmarked API token. Values in credential positions are flagged sensitive and masked; values that are not are shown. Treat the capture as a secret regardless.
- **Response size comparison is crude.** Sizes are compared as medians per capture, differing when they vary by at least 10% and 32 bytes. It flags "look at this", not "this is wrong".
- **GraphQL is handled only as HTTP.** Every GraphQL request collapses into one `POST /graphql` signature. The query document is not parsed, so distinct operations are not separated and field-level differences are invisible. Body parameter names do come through — `operationName`, `query`, `variables.*` — so a variable one role sends and another does not will show up in the parameter diff; which *operations* each role called will not.
- **No request is ever sent.** By design. har-diff does not replay, does not follow redirects, does not retry, and has no network code.

## Programmatic API

All four stages are exported and typed.

```ts
import { parseHarFile, extractObjects, diffCaptures, buildPlan, Redactor, renderPlan } from 'har-diff';

const admin = await parseHarFile('admin.har', { label: 'admin' });
const user = await parseHarFile('user.har', { label: 'user' });

const objects = extractObjects([admin, user]);
const diff = diffCaptures([admin, user], { objects, privilegedLabel: 'admin' });
const plan = buildPlan([admin, user], diff, { limitPerKind: 20 });

// Build the redactor from every secret the captures reported, then pass all
// output through it.
const redactor = new Redactor([...admin.secrets, ...user.secrets]);
console.log(renderPlan(plan, 'markdown', redactor));

for (const candidate of plan.candidates) {
  if (candidate.kind === 'object-reference-substitution') {
    console.log(candidate.id, candidate.replayAs, candidate.substitutions);
  }
}
```

| Function | Returns |
| --- | --- |
| `parseHar(jsonOrObject, options)` / `parseHarFile(path, options)` | `Capture` — canonical requests, parse warnings, and the credential values seen |
| `extractObjects(captures, options)` | `ObjectIndex` — classified object references and enumerable integer slots |
| `diffCaptures(captures, options)` | `DiffResult` — exclusive endpoints, parameter diffs, response diffs, capture-exclusive object references |
| `buildPlan(captures, diff, options)` | `TestPlan` — ordered candidates with replay instructions and `curl` commands |
| `Redactor` | Credential stripping for any rendered output |
| `renderParse` / `renderDiff` / `renderObjects` / `renderPlan` | `string` in `text`, `json` or `markdown` |

Lower-level helpers are exported too — `templatePath`, `classifyIdentifier`, `groupBySignature`, `walkJson`, `applySubstitution`, `findSequentialSlots` — if you want to build something else on the same primitives.

## Development

```bash
npm install          # typescript + @types/node, nothing else
npm run build        # tsc --build, strict
npm test             # build, then node:test over dist/test
npm run typecheck    # tsc --noEmit
```

The test suite covers path templating (including every identifier shape and multi-segment paths), signature grouping, exclusive-endpoint and parameter-difference detection, object extraction and classification for each shape, sequential-integer detection, plan generation and substitution, CLI argument parsing, and the redaction guarantee across every command and format.

`test/fixtures/` holds two small synthetic HAR files of a toy API, written for this suite. Their credentials are visibly fake placeholders containing the string `FIXTURE`, and the redaction tests depend on that — see `test/fixtures/README.md`.

## License

MIT. Copyright (c) 2026 David Nichols.
