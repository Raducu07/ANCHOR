---
name: anchor-security-audit
description: Run a release-candidate security audit pass on the ANCHOR backend. Use when the user asks for a security audit, RC hardening pass, pre-release check, or wants to verify auth/RLS/exports/rate-limits/secrets before a release window.
---

# ANCHOR Security Audit

Scope set by CLAUDE.md "Next backend tasks (RC hardening)". Read-only audit; produce findings, do not patch.

## Audit checklist

### 1. Auth surfaces
- Clinic auth: token issuance, refresh, revocation, expiry, replay resistance.
- Admin auth: admin token storage, rotation posture, scope of admin endpoints.
- Invite flow and setup-token logic: single-use, time-bound, tenant-bound.
- JWT: signing algorithm pinned (no `none`, no alg confusion), kid handling, audience/issuer checked, clock skew bounded.

### 2. Tenant isolation
- Every tenant-scoped table has RLS enabled *and* FORCED.
- Every RLS policy has both `USING` and `WITH CHECK`.
- `current_setting('app.clinic_id')` set on every request path; verify there is no code path that hits tenant tables without the context being set.
- No endpoint accepts a tenant id from the client and trusts it.

### 3. Route protection / RBAC
- Every router has an explicit auth dependency; flag any route missing one.
- Admin-only routes are gated by admin auth, not just by being unlinked from the UI.
- Clinic-staff vs clinic-owner role boundaries enforced server-side.

### 4. Exports and receipts
- Export endpoints are tenant-scoped, rate-limited, and audit-logged.
- Receipt fetch endpoints reject cross-tenant ids and do not leak existence via differential error codes.
- No export path returns raw prompts/outputs/drafts; metadata-only doctrine preserved.

### 5. CORS and rate limiting
- CORS allow-list is explicit (no wildcard with credentials).
- Rate limits exist on auth endpoints, export endpoints, and any endpoint that triggers external API calls.

### 6. Secrets and dependencies
- No secrets in repo; scan for accidental commits (.env, keys, tokens).
- Dependency scan for known CVEs in pinned versions.
- Anthropic API key (if present) is staging/local only; not wired to a production code path.

### 7. Operational resilience (flag, do not test)
- Backups configured on Render Postgres; restore tested.
- Migration rollback posture documented.

### 8. Metadata-only doctrine
- No new column on a tenant table stores raw prompt/output/draft/transcript/clinical content.
- Identifier-shaped data (IPs, user agents) hashed at write time.

## Output format

```
SECURITY AUDIT — ANCHOR backend
Findings by severity:
  CRITICAL: [...]
  HIGH:     [...]
  MEDIUM:   [...]
  LOW / INFO: [...]
Deferred / out-of-scope (flagged for awareness): [...]
Doctrine preserved: yes/no/explain
Tenant safety, RLS, auth preserved: yes/no/explain
```

Never patch from this skill. Report only. The user will decide whether to spawn a fix task.
