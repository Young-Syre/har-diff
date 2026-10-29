# Test fixtures

`admin.har` and `user.har` are **synthetic** HAR 1.2 captures of a toy API at
`https://api.shopfront.test`, written for har-diff's test suite. No real host,
account or session is involved.

Every credential in them is a visibly fake placeholder:

- bearer tokens are JWTs whose signature segment is the literal string
  `FIXTURE-SIGNATURE-NOT-REAL` and whose payload says
  `"note": "fake token for tests only"`;
- cookie values begin with `FIXTURE`.

They exist so the test suite can assert that none of those values ever appears
in har-diff's output. If you change them, keep the `FIXTURE` prefixes - the
redaction tests look for them.

## What the two captures contain

| | `admin.har` | `user.har` |
| --- | --- | --- |
| numeric-id endpoint | `GET /api/v1/users/8123`, `/8124`, `/8125` | `GET /api/v1/users/9001` |
| UUID endpoint | `GET /api/v1/documents/9f2b4c6d-…` | `GET /api/v1/documents/4c1d8e52-…` |
| admin-only endpoint | `GET /api/v1/admin/audit-log` | — |
| shared endpoint, extra parameter | `PATCH /api/v1/users/8124` with `role` and `org_id` | `PATCH /api/v1/users/9001` with `display_name` only |
| shared endpoint, divergent response | `GET /api/v1/users` (3 users) | `GET /api/v1/users` (1 user) |
| low-privilege-only endpoints | — | `GET /api/v1/notifications`, `GET /api/v1/invites/accept`, `GET /api/v1/admin/settings` (403) |

Other identifier shapes are spread across the admin capture so that every
branch of the classifier is exercised: ULID (`/api/v1/events?cursor=…`),
MongoDB ObjectId (`/api/v1/orders/…`), 32-character hex
(`/api/v1/exports/…`), opaque base64url (`/api/v1/attachments/…`), slug
(`/api/v1/projects/acme-corp`), email addresses in response bodies, and a JWT
in a query parameter in the user capture (`invite_token`).
