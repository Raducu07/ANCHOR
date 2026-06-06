---
name: anchor-backend-safety-review
description: Review a backend diff or PR for ANCHOR-specific safety regressions before merge. Use on any change touching app/, migrations/, tests/, auth, RLS, receipts, exports, or LLM-call paths.
---

# ANCHOR Backend Safety Review

Read-only review of a backend diff. Produce findings; do not edit.

## What to check

### Tenant safety
- New endpoint: has explicit auth dependency + uses request-scoped tenant context.
- New table: RLS enabled + FORCED + policy has `USING` *and* `WITH CHECK`.
- New query against tenant tables: relies on RLS, does not bypass via service-role-like access.
- No new code path sets `app.clinic_id` from untrusted input.

### Auth
- No change to clinic auth, admin auth, invite flow, or setup-token logic unless the engineering brief explicitly asks for it. If touched, flag for founder review.
- No new admin endpoint without admin-auth dependency.
- No new JWT logic without algorithm pinning and aud/iss checks.

### Metadata-only doctrine
- No new column stores raw prompts, outputs, drafts, transcripts, or clinical content.
- Hashes only for identifier-shaped data; hashed at write time, not read time.

### Live LLM path
- If the diff touches the Workspace live generation path: verify it is gated off in production and the hard-refusal boundary (diagnosis/treatment/prescribing) is preserved.
- If a new provider is wired in: flag — subprocessor implications.

### Migrations
- New migration only if unavoidable.
- Never edits an existing migration retroactively.
- Includes RLS + FORCE RLS + `USING`/`WITH CHECK` for tenant tables.
- Reversible or documented as forward-only with rationale.

### Code hygiene
- No new `# type: ignore`, no new `Any`, no new suppression comments without same-change justification.
- No regression to Pydantic v1-style configs (M6.6.1 cleanup must hold).
- App import check (`python -c "from app.main import app"`) noted as required for the change.
- Existing Assistant evaluation suite not refactored (only additive changes allowed).

### Wording in responses
- Any new error message or API response string is checked against Readiness Map v1.1 §2.
- No compliance/certification/RCVS-approval claims.
- No clinical decision-making framing.

## Output format

```
BACKEND SAFETY REVIEW
Files reviewed: [paths]
Findings:
  BLOCK:  [reasons — must fix before merge]
  FIX:    [should fix in this change]
  NIT:    [optional]
Doctrine preserved: yes/no/explain
Tenant safety, RLS, auth preserved: yes/no/explain
Tests required before merge: [list]
```
