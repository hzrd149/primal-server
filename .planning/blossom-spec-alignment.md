# Blossom Spec Alignment Backlog

Source spec reviewed: https://github.com/hzrd149/blossom, current `master` BUD-01 through BUD-12.

Implementation reviewed: `src/blossom.jl` plus related media/storage code.

## Current State

The server implements a compact Blossom HTTP surface in `src/blossom.jl`:

- `GET /<sha256>[.<ext>]`
- `HEAD /<sha256>[.<ext>]`
- `PUT /upload`
- `HEAD /upload`
- `PUT /mirror`
- `PUT /media`
- `HEAD /media`
- `GET /list/<pubkey>`
- `DELETE /<sha256>`

The implementation broadly matches the intended endpoint shape, but it is not fully aligned with the latest Blossom BUDs. The most important gaps are around authorization semantics, mirror hash validation, status codes, and list pagination.

## Fix Order

Work these one at a time. The first two are security/behavior correctness issues and should be handled before polish or optional features.

1. Fix mirror hash authorization. Implementation pass complete; full Julia load verification is blocked by local environment setup noted below.
2. Bring BUD-11 authorization validation in line with spec.
3. Enforce upload/media `X-SHA-256` mismatch handling.
4. Fix delete missing-blob behavior.
5. Correct `/media` auth action from `upload` to `media`.
6. Improve upload/mirror/media success status codes.
7. Add BUD-12 list pagination and sorting.
8. Decide and implement retrieval redirect strategy.
9. Decide whether to restore or remove unreachable `find_blob` fallback.
10. Add focused regression tests or verification scripts.

## Issues And Proposed Fixes

### 1. Mirror Authorizes URL Hash Instead Of Downloaded Blob Hash

Severity: high.

Spec references: BUD-04, BUD-11.

Current code: `src/blossom.jl:263-268`.

Problem:

- `PUT /mirror` parses the first 64-hex value from the submitted URL.
- It validates the auth event `x` tag against that URL-derived hash.
- It then downloads the URL and imports whatever bytes are returned.
- If the origin returns bytes with a different SHA-256, the server can store a blob the user did not authorize.

Fix:

- Parse and validate the mirror request body first.
- Download the remote bytes.
- Compute `SHA.sha256(data)`.
- Validate `check_action(req, "upload"; x_tag_hash=actual_hash)` after the actual hash is known.
- If an expected hash was extracted from the URL and it does not match actual bytes, return `409 Conflict` or another clear spec-aligned rejection.
- Map origin fetch/body/URL failures to `400` or `502` instead of falling through to generic `500`.

Acceptance checks:

- Mirroring a URL whose path hash differs from returned bytes is rejected.
- Mirroring valid bytes with matching auth `x` succeeds.
- A malformed JSON body returns `400`.
- An unreachable origin returns `502`.

Implementation note:

- Updated `PUT /mirror` to parse the request body defensively, require a SHA-256 in the mirror URL, pre-authorize the auth `x` tag against that URL hash before downloading, compute the SHA-256 of downloaded bytes, reject content mismatches with `409`, and import only after the actual bytes match the pre-authorized hash.
- Added mirror SSRF guardrails before fetching: mirror URLs must parse as `https`, must have a resolvable non-private/non-loopback/non-link-local host, crafted hostnames that spoof Primal direct-fetch substrings are rejected, and the SHA-256 is extracted from the parsed URL path instead of the raw URL string.
- Consolidated `x` tag validation through `check_x_tag` so `check_action(...; x_tag_hash=...)` and mirror validation use the same tag matching behavior.
- Full load verification was attempted with `nix --extra-experimental-features 'nix-command flakes' develop -c julia --project -e 'import PrimalServer'`, but the environment failed before import because `bech32/ref/c/segwit_addr.c` is missing and Julia could not resolve `TimeZones`.

### 2. BUD-11 Authorization Validation Is Incomplete

Severity: high.

Spec reference: BUD-11.

Current code: `src/blossom.jl:160-187`.

Problems:

- Uses normal base64 decode, while BUD-11 requires base64url without padding.
- Allows auth events without an `expiration` tag, but spec requires it.
- Does not enforce `created_at` in the past; the check is commented out.
- Ignores `server` tags, so server-scoped tokens are not enforced.
- Does not validate `server` tag domain format.
- Mostly returns `400` for auth failures, while spec expects `401 Unauthorized` for missing/invalid auth.
- Does not distinguish malformed token input from valid-but-unauthorized action clearly.

Fix:

- Decode `Authorization: Nostr <base64url-no-padding-json-event>` correctly.
- Require event kind `24242`.
- Verify Nostr event id and signature.
- Require `created_at <= now`.
- Require at least one valid future `expiration` tag.
- Require a matching `t` tag.
- If any `server` tags exist, require one to match the current server domain from `Host` or configured `BASE_URL` domain.
- For endpoints requiring a hash, require a matching lowercase hex `x` tag.
- Return `401` for missing/invalid auth.

Acceptance checks:

- Missing auth returns `401`.
- Expired token returns `401`.
- Token without expiration returns `401`.
- Future `created_at` returns `401`.
- Valid server-scoped token for this host succeeds.
- Valid server-scoped token for another host fails.

Implementation note:

- Updated `check_action` to decode `Authorization: Nostr` tokens as base64url, with padded base64url and legacy standard base64 accepted for backward compatibility. Malformed token input now maps to `401`; auth validation requires kind `24242`, valid event id/signature, non-future `created_at`, at least one future `expiration` tag, matching `t` tags, valid and matching `server` tag domain scope, and exact lowercase hex `x` tag matches when a hash is required.
- Full load verification remains blocked by local environment setup: `nix --extra-experimental-features 'nix-command flakes' develop -c julia --project -e 'import PrimalServer'` fails before import because `bech32/ref/c/segwit_addr.c` is missing and Julia cannot resolve `TimeZones`.

### 3. `X-SHA-256` Mismatch Is Not Enforced On Upload Or Media

Severity: medium-high.

Spec references: BUD-02, BUD-05.

Current code: `src/blossom.jl:269-273`.

Problem:

- `PUT /upload` and `PUT /media` compute SHA-256 from the request body and validate auth against that.
- If the client supplies `X-SHA-256` and it does not match the body, the spec says the server should return `409 Conflict`.
- Current implementation ignores mismatch semantics.

Fix:

- Read optional `X-SHA-256` header.
- If present, parse as lowercase hex SHA-256.
- If malformed, return `400`.
- If parsed value does not equal `SHA.sha256(data)`, return `409`.
- Use the body hash for storage and auth hash validation.

Acceptance checks:

- Upload with matching `X-SHA-256` succeeds.
- Upload with mismatched `X-SHA-256` returns `409`.
- Upload with malformed `X-SHA-256` returns `400`.
- Same behavior applies to `/media`.

### 4. Delete Missing Blob Can Become A 500

Severity: medium.

Spec reference: BUD-12.

Current code: `src/blossom.jl:251-258`.

Problem:

- `r = find_upload(req.target)` can return `nothing`.
- The next line calls `r.sha256` before checking `r`.
- Deleting a nonexistent blob can throw and return a generic `500`.

Fix:

- Check `isnothing(r)` immediately after lookup.
- Return `404 Not Found` before calling `check_action` if the blob is unavailable for deletion.
- Keep owner check after auth validation.

Acceptance checks:

- `DELETE /<missing-sha256>` returns `404` without internal exception.
- Deleting an existing blob with invalid auth returns `401`.
- Deleting another user's blob returns `404` or `403`, depending on desired policy.

Implementation note:

- `DELETE` now returns `404` immediately when `find_upload` returns `nothing`, before reading `r.sha256`, and the leftover `@show` debug print was removed from the purge path.

### 5. `/media` Uses Upload Auth Action Instead Of Media Auth Action

Severity: medium.

Spec references: BUD-05, BUD-11.

Current code: `src/blossom.jl:236-241`, `src/blossom.jl:269-273`.

Problem:

- `HEAD /media` and `PUT /media` currently call `check_action(req, "upload"; ...)`.
- BUD-11 says `/media` requires `t=media`.

Fix:

- Use `action = req.target == "/media" ? "media" : "upload"` for upload/media routes.
- Keep `/mirror` on `upload`.

Acceptance checks:

- `/media` with `t=media` succeeds.
- `/media` with only `t=upload` fails.
- `/upload` still requires `t=upload`.

### 6. Upload, Mirror, And Media Always Return 200

Severity: medium.

Spec references: BUD-02, BUD-04, BUD-05.

Current code: `src/blossom.jl:281-299`.

Problem:

- `import_blob` always returns `200 OK`.
- BUD-02 and BUD-04 require `201 Created` for newly stored blobs and `200 OK` for already existing blobs.
- BUD-05 allows either `200` or `201`, but distinguishing new/existing is still useful.

Fix:

- Determine whether the blob already existed before import, likely by checking `media_uploads` or `media_storage` by SHA-256 before calling import.
- Return `201` when newly stored and `200` when pre-existing.
- If the existing import pipeline cannot safely report this yet, document the limitation and keep `200` until storage semantics are clearer.

Acceptance checks:

- First upload of a blob returns `201`.
- Re-upload of same blob returns `200`.
- Mirror follows the same behavior.

### 7. `/list/<pubkey>` Lacks BUD-12 Pagination And Sorting

Severity: medium.

Spec reference: BUD-12.

Current code: `src/blossom.jl:205-220`.

Problems:

- Does not support `cursor` query parameter.
- Does not support `limit` query parameter.
- Does not sort by `uploaded` descending.
- Does not exclude the cursor blob from the returned page.
- Does not validate malformed query params.
- Currently list is public; BUD-11 defines `t=list` if auth is required, but auth is optional by spec.

Fix:

- Parse URL query parameters.
- Add `ORDER BY created_at DESC`.
- Add bounded `limit` with a server default and maximum.
- Implement cursor lookup by SHA-256 and exclude the cursor item.
- Return `400` for malformed cursor or limit.
- Decide whether list should remain public or require `t=list` auth.

Acceptance checks:

- Results are ordered newest first.
- `limit=2` returns at most two items.
- `cursor=<sha256>` excludes the cursor blob and returns the next page.
- Malformed cursor returns `400`.

### 8. Retrieval Redirect Uses 302 Instead Of Current Spec Redirect Codes

Severity: medium-low.

Spec reference: BUD-01.

Current code: `src/blossom.jl:222-229`.

Problem:

- `GET /<sha256>` returns `302` redirect.
- BUD-01 redirect guidance names `307` or `308` and requires redirect URLs to contain the same SHA-256.
- Destination responses must include CORS, content type, and content length.
- Current redirect target is `r.media_url`, which may or may not include the SHA-256 depending on storage provider/path.

Fix options:

- Prefer `307 Temporary Redirect` if the redirect target is stable enough and includes the same SHA-256.
- Use `308 Permanent Redirect` only if the CDN/object URL is intended to be permanent.
- Alternatively proxy bytes through Blossom and return `200`, with `Content-Type`, `Content-Length`, and range support handled by this server.

Acceptance checks:

- Redirect URL contains the same SHA-256.
- Response uses chosen spec-aligned status code.
- Destination URL serves with compatible CORS and metadata headers, or server proxies those headers itself.

### 9. `find_blob` Has Unreachable Fallback Logic

Severity: low-medium.

Spec reference: BUD-01 behavior coverage.

Current code: `src/blossom.jl:102-127`.

Problem:

- `find_blob` immediately returns `find_upload(req_target)`.
- The later `media_storage` fallback code is unreachable.
- Effective behavior only serves blobs known through `media_uploads`.

Fix options:

- Remove the unreachable fallback if serving only user uploads is intentional.
- Or restore fallback by changing the early return to `isnothing(r) || return r`.
- If restored, verify moderation/block filtering and returned descriptor fields are correct.

Acceptance checks:

- Intentional lookup behavior is documented in code or tests.
- No unreachable code remains.
- Moderation/blocking semantics are preserved.

Implementation note:

- Removed the unreachable `media_storage` fallback after the early `find_upload` return. Current runtime behavior remains limited to upload-backed blobs.

### 10. Missing Focused Regression Tests

Severity: medium.

Spec references: all implemented BUDs.

Problem:

- The current implementation is behavior-heavy and security-sensitive but lacks obvious focused Blossom tests.

Fix:

- Add focused tests or a lightweight verification script for Blossom handler behavior.
- Prefer handler-level tests where possible to avoid requiring a full server and media import pipeline for every case.

Suggested coverage:

- Auth decoding and validation.
- Upload `X-SHA-256` match/mismatch.
- Mirror actual hash validation.
- `/media` `t=media` action.
- Delete missing blob.
- List pagination.
- CORS preflight headers.

## Non-Goals For Initial Pass

- Payment required behavior from BUD-07.
- Blob reports from BUD-09.
- Blossom URI support from BUD-10.
- Full byte-range proxying unless retrieval is changed from redirect to direct serving.
- NIP-89 discovery; the current Blossom spec does not require it.
