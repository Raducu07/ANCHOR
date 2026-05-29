# ANCHOR Phase 2A-1 — Claude Code Engineering Brief

**Feature**: CPD-Recordable AI Literacy (standalone)
**Version**: v1.1 (approved; buyer conversations run in parallel, not blocking)
**Date**: 25 May 2026
**Owner**: Founder / Product Owner
**Linked documents**:
- `docs/canonical/ANCHOR_Roadmap_v2_5_May_2026.docx` (§1 doctrine; §4 M6 as-built)
- `docs/canonical/ANCHOR_RCVS_EU_AI_Act_Readiness_Map_v1.docx` (§2 wording; §3 RCVS; §4 EU AI Act)
- `docs/canonical/ANCHOR_Phase_2A_Build_Order_Decision_Memo_v1_1.docx` (§5 scope authority)
- `CLAUDE.md` at each repo root (per-session guardrails)

---

## How to use this brief

This is the implementation contract for Phase 2A-1. It is consumed by Claude Code across separate backend and frontend sessions.

- **One Claude Code session per repo.** Backend session first (migrations, endpoints, tests), then frontend session (pages, components, copy).
- **Quote sections, do not paste the whole brief.** Each Claude Code prompt should reference the specific section(s) being worked on (e.g. "Implement §2.1 schema and §2.2 RLS policies").
- **CLAUDE.md is the persistent guardrail.** This brief is the task; CLAUDE.md is the doctrine. Do not paste doctrine into prompts — it is already loaded by Claude Code automatically.
- **Buyer listening cadence.** M5.6 buyer conversations continue in parallel and may trigger an in-flight scope revision, but they no longer block substantive Phase 2A-1 implementation. Public copy audit and retention/memory-consent documentation remain mandatory before external use.

---

## §1 — Doctrine quick-check (must be true at all times)

Before declaring any change complete, Claude Code must confirm:

- **Metadata-only**: no raw learning content stored in database; `learning_modules.content_reference` is a URL or relative path; no quiz answers; no clinical content
- **RLS + FORCE RLS**: on all clinic-scoped tables, with `USING` AND `WITH CHECK` clauses
- **Tenant isolation**: all completion and export queries use `current_setting('app.clinic_id')::UUID`
- **Wording controls**: all clinic-facing copy passes Readiness Map §2 wording table
- **Aligned, not compliant**: no copy claims RCVS approval, EU AI Act compliance, certification, or regulator endorsement
- **No backend↔frontend co-changes**: one repo per session

---

## §2 — Backend scope (repo: `C:\Users\rggal\ANCHOR`)

### §2.1 — Database schema

Four new tables/views. One is the global catalogue (not tenant-isolated); the others are clinic-scoped with RLS.

**Migration discipline**: create a single new migration file following the repo's existing naming convention. Do not retroactively edit any existing migration. Include `ALTER TABLE … ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` on every clinic-scoped table.

```sql
-- 2A-1.a — learning_modules: ANCHOR-curated global catalogue (NOT clinic-scoped)
CREATE TABLE learning_modules (
    module_id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    module_slug            TEXT        NOT NULL UNIQUE,
    version                TEXT        NOT NULL,                              -- semantic, e.g. '1.0.0'
    title                  TEXT        NOT NULL,
    summary                TEXT        NOT NULL,
    learning_objectives    TEXT[]      NOT NULL,
    role_applicability     TEXT[]      NOT NULL,                              -- subset of {vet, nurse, practice_manager, admin, reception, locum}
    cpd_minutes            INTEGER     NOT NULL CHECK (cpd_minutes > 0),
    category               TEXT        NOT NULL,                              -- one of {literacy, bias_detection, ethical_use, confidentiality, transparency, preparation_for_practice}
    rcvs_principle_mappings    TEXT[]  NOT NULL,
    eu_ai_act_article_mappings TEXT[]  NOT NULL,
    content_reference      TEXT        NOT NULL,                              -- URL or relative path; NO raw content in DB
    is_active              BOOLEAN     NOT NULL DEFAULT true,
    superseded_by          UUID        REFERENCES learning_modules(module_id),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_learning_modules_active ON learning_modules(is_active);
CREATE INDEX idx_learning_modules_category ON learning_modules(category);

-- 2A-1.b — learning_completions: per-user per-clinic records
CREATE TABLE learning_completions (
    completion_id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    clinic_id                UUID        NOT NULL,
    user_id                  UUID        NOT NULL,
    module_id                UUID        NOT NULL REFERENCES learning_modules(module_id),
    module_version           TEXT        NOT NULL,           -- snapshot at completion time
    completed_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledgement_provided BOOLEAN     NOT NULL DEFAULT false,
    cpd_minutes_credited     INTEGER     NOT NULL CHECK (cpd_minutes_credited > 0),  -- snapshot
    is_voided                BOOLEAN     NOT NULL DEFAULT false,
    void_reason              TEXT,
    voided_at                TIMESTAMPTZ,
    voided_by_user_id        UUID,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT learning_completions_unique UNIQUE (clinic_id, user_id, module_id, module_version)
);

ALTER TABLE learning_completions ENABLE ROW LEVEL SECURITY;
ALTER TABLE learning_completions FORCE ROW LEVEL SECURITY;

CREATE POLICY learning_completions_tenant_isolation ON learning_completions
    FOR ALL
    USING (clinic_id = current_setting('app.clinic_id')::UUID)
    WITH CHECK (clinic_id = current_setting('app.clinic_id')::UUID);

CREATE INDEX idx_learning_completions_user ON learning_completions(clinic_id, user_id);
CREATE INDEX idx_learning_completions_module ON learning_completions(clinic_id, module_id);

-- 2A-1.c — v_cpd_records: per-user CPD record (derived view; founder decision confirmed in §4.3)
CREATE VIEW v_cpd_records AS
SELECT
    clinic_id,
    user_id,
    COUNT(*)                              AS total_modules_completed,
    SUM(cpd_minutes_credited)             AS total_cpd_minutes,
    MIN(completed_at)                     AS first_completion_at,
    MAX(completed_at)                     AS most_recent_completion_at,
    bool_or(acknowledgement_provided)     AS any_acknowledgement_provided
FROM learning_completions
WHERE is_voided = false
GROUP BY clinic_id, user_id;

-- 2A-1.d — cpd_exports: immutable export artefacts
CREATE TABLE cpd_exports (
    export_id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    clinic_id              UUID        NOT NULL,
    user_id                UUID        NOT NULL,                              -- the user the export is FOR
    generated_by_user_id   UUID        NOT NULL,                              -- the user who triggered generation
    export_version         TEXT        NOT NULL,                              -- export format version, e.g. 'v1'
    export_hash            TEXT        NOT NULL,                              -- SHA-256 hex digest of export_payload
    export_payload         JSONB       NOT NULL,                              -- immutable snapshot
    generated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE cpd_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE cpd_exports FORCE ROW LEVEL SECURITY;

CREATE POLICY cpd_exports_tenant_isolation ON cpd_exports
    FOR ALL
    USING (clinic_id = current_setting('app.clinic_id')::UUID)
    WITH CHECK (clinic_id = current_setting('app.clinic_id')::UUID);

CREATE INDEX idx_cpd_exports_user ON cpd_exports(clinic_id, user_id);
```

**Doctrine rationale**:

- `learning_modules` is NOT clinic-scoped because the catalogue is ANCHOR-curated and shared across clinics. Custom per-clinic modules are out of scope for 2A-1 (deferred to M4.6 Learn Maturity).
- `cpd_minutes_credited` is snapshotted at completion so future module changes do not retroactively alter records. This is an EU AI Act Article 12 record-keeping requirement.
- `module_version` is snapshotted similarly. A user who completes v1.0 and then v1.1 of the same module has two completion rows.
- `cpd_exports` is immutable: never UPDATE or DELETE rows. The `export_hash` lets downstream consumers verify integrity.
- `learning_completions` are not silently deleted or overwritten. Corrections use the void-with-reason fields so the evidence trail remains reviewable.

### §2.2 — Pydantic models

Add to `app/models/learn.py` (or repo equivalent location):

```python
# Public-facing module catalogue
class LearningModule(BaseModel):
    module_id: UUID
    module_slug: str
    version: str
    title: str
    summary: str
    learning_objectives: list[str]
    role_applicability: list[str]
    cpd_minutes: int
    category: str
    rcvs_principle_mappings: list[str]
    eu_ai_act_article_mappings: list[str]
    content_reference: str
    is_active: bool

# Completion record
class LearningCompletion(BaseModel):
    completion_id: UUID
    user_id: UUID
    module_id: UUID
    module_version: str
    completed_at: datetime
    acknowledgement_provided: bool
    cpd_minutes_credited: int
    is_voided: bool
    void_reason: str | None = None
    voided_at: datetime | None = None
    voided_by_user_id: UUID | None = None

class LearningCompletionCreate(BaseModel):
    module_id: UUID
    acknowledgement_provided: bool = False

class LearningCompletionVoid(BaseModel):
    void_reason: str

# Per-user CPD record (derived)
class CPDRecord(BaseModel):
    user_id: UUID
    total_modules_completed: int
    total_cpd_minutes: int
    first_completion_at: datetime | None
    most_recent_completion_at: datetime | None
    completions: list[LearningCompletion]

# Export artefact
class CPDExport(BaseModel):
    export_id: UUID
    user_id: UUID
    generated_by_user_id: UUID
    export_version: str
    export_hash: str
    generated_at: datetime
    # NB: export_payload is NOT exposed in the response model — it's served separately via GET .../exports/{export_id}/payload

# Trust Pack aggregate
class TrustPackLearningDelta(BaseModel):
    total_staff_with_completions: int
    total_cpd_minutes_delivered: int
    completion_rate_by_role: dict[str, float]   # role → percentage
    bias_detection_completions: int             # category == 'bias_detection'
    module_catalogue_count: int
    last_completion_at: datetime | None
```

### §2.3 — API endpoints

Add new router at `app/routers/learn_v1.py` (or repo equivalent). All endpoints follow existing FastAPI patterns: dependency injection for tenant context, structured error responses, OpenAPI annotations.

```
GET    /v1/learn/modules                          # List active modules, optionally filtered by role or category
GET    /v1/learn/modules/{module_id}              # Module detail

POST   /v1/learn/completions                      # Record a completion (current user only)
POST   /v1/learn/completions/{completion_id}/void # Void a completion with reason (clinic-admin only; no silent delete)
GET    /v1/learn/completions/me                   # Current user's completions
GET    /v1/learn/completions/users/{user_id}      # Specific user's completions (clinic-admin only)

GET    /v1/learn/cpd/me                           # Current user's CPD record
GET    /v1/learn/cpd/users/{user_id}              # Specific user's CPD record (clinic-admin only)

POST   /v1/learn/cpd/users/{user_id}/exports      # Generate a new immutable export for a user
GET    /v1/learn/cpd/users/{user_id}/exports      # List exports for a user
GET    /v1/learn/cpd/exports/{export_id}          # Retrieve export metadata
GET    /v1/learn/cpd/exports/{export_id}/payload  # Retrieve the immutable JSON payload

GET    /v1/trust/posture/learning-delta           # Aggregated learning evidence for Trust Pack
```

**Authorisation discipline**:
- `me` endpoints: current user from auth context
- `users/{user_id}`, `exports`, and completion-void endpoints: require clinic-admin role; user_id/completion_id must belong to the same clinic_id as the requester
- All endpoints set `current_setting('app.clinic_id')` from the existing tenant-context middleware before any database query

**Response envelope**: follow existing repo convention.

### §2.4 — Initial module catalogue seed

Seed at least these modules via a data migration (separate from the schema migration):

| Slug | Title | Category | CPD min | RCVS themes | EU AI Act |
|---|---|---|---|---|---|
| `ai-literacy-foundations-v1` | AI Literacy Foundations for Veterinary Teams | literacy | 30 | accountability, ai_literacy, preparation_for_practice | article_4 |
| `bias-detection-in-ai-outputs-v1` | Recognising Biased, Inaccurate, or Misleading AI Outputs | bias_detection | 25 | ai_literacy, bias_detection | article_4 |
| `ethical-and-safe-ai-use-v1` | Ethical and Safe Use of AI in Clinical Workflows | ethical_use | 20 | ethical_safe_use, academic_integrity | article_4 |
| `confidentiality-and-ai-v1` | Confidentiality and Data Protection When Using AI | confidentiality | 20 | confidentiality_data_protection | article_4 |
| `explaining-ai-to-clients-v1` | Explaining AI Use to Pet Owners | transparency | 15 | explainability | article_4, article_50 |

`role_applicability` for all: `{vet, nurse, practice_manager, admin, reception, locum}` initially. Refinement is a follow-on, not 2A-1 scope.

`content_reference` for each: a relative path to a markdown file in `docs/learn/modules/<slug>.md` in the repo. Markdown files are NOT a database concern — they ship with the deploy. This preserves metadata-only doctrine.

The actual content of the markdown files is OUT of this brief's scope — write placeholder stubs only ("Module content to be written. See engineering brief §2.4."). Real module copy is a separate content task, not engineering.

### §2.5 — Backend test scope

Create `tests/test_learn_v1.py`. Required tests:

| Test | What it verifies |
|---|---|
| `test_list_modules_returns_only_active` | `is_active=false` modules are excluded from list endpoint |
| `test_list_modules_filter_by_category` | Category filter works |
| `test_list_modules_filter_by_role` | Role applicability filter works |
| `test_module_detail_returns_full_record` | Module detail endpoint returns all fields |
| `test_record_completion_creates_row` | POST /completions inserts a row |
| `test_record_completion_snapshots_version_and_minutes` | Completion stores `module_version` and `cpd_minutes_credited` from the module at insert time |
| `test_record_completion_duplicate_same_version_rejected` | UNIQUE constraint rejects duplicate `(clinic_id, user_id, module_id, module_version)` |
| `test_record_completion_new_version_allowed` | Different `module_version` for the same module is allowed |
| `test_tenant_isolation_completions` | Clinic A cannot read Clinic B's completions; RLS blocks |
| `test_rls_with_check_blocks_wrong_clinic_id` | Attempting to insert a completion with a different `clinic_id` than the session context fails |
| `test_cpd_record_aggregation` | `/cpd/me` returns correct totals |
| `test_void_completion_requires_reason_and_preserves_row` | Completion can be voided with reason; row remains for audit trail |
| `test_voided_completion_excluded_from_cpd_record` | Voided completions are excluded from CPD record aggregation |
| `test_cpd_record_admin_view` | Clinic admin can see another user's record; non-admin cannot |
| `test_create_export_is_immutable` | After creation, the export's `export_hash` matches `sha256(export_payload)` |
| `test_export_payload_does_not_change_after_completion_added` | New completion does not retroactively alter an existing export |
| `test_trust_pack_delta_aggregates` | `/trust/posture/learning-delta` returns expected counts and rates |
| `test_trust_pack_delta_bias_detection_count` | Bias-detection category completions counted distinctly |

Run after implementation:
- New test suite: `pytest tests/test_learn_v1.py -v`
- Existing Assistant test suite: `pytest tests/test_assistant_*.py -v` (must remain passing)
- App import check: `python -c "from app.main import app"` (must succeed)

### §2.6 — Backend reporting expectations

Match CLAUDE.md §"Reporting expectations after each session." Specifically confirm:

1. **Files changed** — full paths
2. **Migrations added** — list new migration files; confirm no existing migrations edited
3. **Tables created** — names; RLS + FORCE RLS enabled; `WITH CHECK` present on every policy
4. **Endpoints added** — full path list
5. **Tests run** — counts and pass/fail
6. **App import check** — pass/fail
7. **Metadata-only doctrine preserved** — yes/no; specifically: no raw content stored, content references only
8. **Tenant safety preserved** — yes/no; specifically: RLS enabled, `WITH CHECK` on all policies, tenant isolation tests pass
9. **Deferred items / scope cuts** — explicit list

---

## §3 — Frontend scope (repo: `C:\Users\rggal\anchor-portal`)

### §3.1 — Pages to add or modify

| Route | Status | Scope |
|---|---|---|
| `/learn` | Modify | Module catalogue. Filter by role and category. Show completion state for logged-in user. Preserve existing Learn baseline content as a separate section. |
| `/learn/[moduleSlug]` | Add | Module detail. Render module content from `content_reference` (server-fetched markdown). "Mark complete" CTA. Optional acknowledgement checkbox. Confirmation state after completion. |
| `/learn/cpd` | Add | Current user's CPD record. Total stats. Module list with completion dates. Export button. |
| `/learn/cpd/[userId]` | Add (admin) | Clinic-admin view of a specific user's CPD record. Same layout as `/learn/cpd` but with user context. |
| `/trust/posture` | Modify | Add a "Learning evidence" section with new tiles. Preserve existing Assistant receipt evidence card. |

### §3.2 — Components to add

| Component | Purpose |
|---|---|
| `ModuleCard` | Catalogue card: title, summary, CPD minutes, category, completion state |
| `ModuleDetailHeader` | Title, summary, learning objectives, role chips, CPD minutes, RCVS/EU AI Act mapping badges |
| `CompletionStateBadge` | "Not started" / "Completed dd/mm/yyyy" |
| `AcknowledgementCheckbox` | Optional acknowledgement before marking complete |
| `MarkCompleteButton` | Triggers `POST /v1/learn/completions` |
| `CPDRecordSummary` | Total modules, total minutes, last completion |
| `CPDExportButton` | Triggers `POST /v1/learn/cpd/users/{userId}/exports`; offers download |
| `LearningEvidenceTile` (for Trust posture) | Reads `/v1/trust/posture/learning-delta`; renders aggregates |
| `BiasDetectionBadge` | Visual identifier on cards where `category === 'bias_detection'` (RCVS Theme 8 trackable signal) |

### §3.3 — API client additions

Add to existing API client file (e.g. `lib/api/learn.ts`). Functions:

```typescript
listModules(opts?: { role?: string; category?: string }): Promise<LearningModule[]>
getModule(moduleId: string): Promise<LearningModule>
recordCompletion(input: { moduleId: string; acknowledgementProvided: boolean }): Promise<LearningCompletion>
listMyCompletions(): Promise<LearningCompletion[]>
listUserCompletions(userId: string): Promise<LearningCompletion[]>     // admin
getMyCpdRecord(): Promise<CPDRecord>
getUserCpdRecord(userId: string): Promise<CPDRecord>                   // admin
createCpdExport(userId: string): Promise<CPDExport>                    // admin
listCpdExports(userId: string): Promise<CPDExport[]>
getCpdExportPayload(exportId: string): Promise<unknown>                // JSON download
getTrustPackLearningDelta(): Promise<TrustPackLearningDelta>
```

TypeScript types must mirror the backend Pydantic models in §2.2.

### §3.4 — Copy controls (specific)

**EU AI Act citation discipline**: any reference to Regulation (EU) 2024/1689, Article 4, Article 113, or any other EU AI Act provision must follow `docs/canonical/Official_EU_AI_Act_Source_Note_v1.md`. EUR-Lex is the only acceptable primary source, and Article 113 must be cited for all applicability dates.

Use this language verbatim where applicable. Do not paraphrase into stronger claims.

| Surface | Use this | Never |
|---|---|---|
| Page header (`/learn`) | "AI literacy for your team" | "RCVS-certified training" |
| CPD record header | "Your CPD-recordable AI literacy activity" | "Your RCVS-accredited CPD" |
| Export confirmation | "This is a metadata-only record of completed AI literacy modules. It is not RCVS-accredited CPD unless your professional body explicitly recognises ANCHOR Learn modules." | "This is your official CPD record." |
| Completion confirmation | "Completion recorded. This activity is logged as evidence of AI literacy practice." | "You are now compliant with EU AI Act Article 4." |
| Bias-detection module description | "Helps you recognise biased, inaccurate, or misleading AI outputs." | "Guarantees you can detect AI bias." |
| Trust posture tile | "Aligned with RCVS AI literacy expectations and EU AI Act Article 4 readiness." | "Compliant with RCVS and EU AI Act." |

Cross-check all other copy against Readiness Map §2.

### §3.5 — Visual direction

- Use existing component patterns and design tokens. Do not introduce new colour systems, typography, or layouts.
- Module cards should match the visual language of existing Receipts cards and Trust posture tiles. Borrow patterns; do not invent new ones.
- Bias-detection modules get a distinct but small visual marker (`BiasDetectionBadge`) — not a different card style.
- Do not "fix" the AppShell custom-font warning while in this scope.

### §3.6 — Frontend test, build, lint expectations

- `npm run build` — must pass
- `npm run lint` — must remain 0 errors; warning count must remain at 1 (AppShell font warning only)
- If lint introduces new warnings, stop and report; do not suppress
- No `any`, no `@ts-nocheck`, no `// eslint-disable` without documented justification

### §3.7 — Frontend reporting expectations

Match CLAUDE.md §"Reporting expectations after each session." Specifically confirm:

1. **Files changed** — full paths
2. **Pages added / modified** — list of routes
3. **Components added** — list with file paths
4. **Build result** — pass/fail
5. **Lint result** — error count (must be 0); warning count (must be 1; identify which warning if not AppShell)
6. **Metadata-only doctrine preserved** — yes/no; specifically: no raw learning content displayed/stored client-side beyond what backend returns
7. **Visual direction preserved** — yes/no; specifically: no new design tokens, no redesigns
8. **Wording controls applied** — confirm copy passes Readiness Map §2 and this brief §3.4
9. **Deferred items / scope cuts** — explicit list

---

## §4 — Cross-cutting requirements

### §4.1 — Doctrine preservation final-review checklist

Before either session declares Phase 2A-1 complete, both must pass:

- [ ] No raw learning content stored in database (backend)
- [ ] No raw learning content held in client state beyond rendered display (frontend)
- [ ] All clinic-scoped tables have RLS enabled and FORCE RLS enabled
- [ ] All RLS policies have both `USING` and `WITH CHECK`
- [ ] Tenant-isolation tests pass (backend `test_tenant_isolation_completions`, `test_rls_with_check_blocks_wrong_clinic_id`)
- [ ] All clinic-facing copy passes Readiness Map §2 wording table
- [ ] No copy claims compliance, certification, or regulator endorsement
- [ ] Trust Pack delta surfaces aggregates only, no per-user data
- [ ] Bias-detection completions are independently trackable (RCVS Theme 8)
- [ ] Existing Assistant evidence loop is unaffected (backend Assistant test suite still passes; frontend `/assistant`, `/receipts`, `/intelligence`, `/trust/posture` Assistant card still render correctly)

### §4.2 — Out of scope for Phase 2A-1 (deferred)

Hard "do not touch" list. If any of these come up mid-implementation, stop and report.

| Item | Deferred to |
|---|---|
| Staff Attestation Layer | Phase 2A-2 |
| Governance Policy Library | Phase 2A-2 |
| Quiz grading / assessment scoring | M4.6 Learn Maturity |
| Role-based learning paths | M4.6 |
| Scenario-based onboarding | M4.6 |
| Adaptive recommendations from governance metadata patterns | M4.6 |
| Leadership dashboards on training uptake (per-user views) | M4.6 |
| External LMS integration | Future |
| Per-clinic custom modules | M4.6 |
| Formal CPD body accreditation integration | Out of doctrine scope unless explicitly achieved |
| Why-flagged → Learn deep linking | Parallel work; fold in only if 2A-1 scope permits; otherwise separate task |

### §4.3 — Confirmed implementation decisions (founder-approved)

These decisions are now baked into v1.1 and are no longer blockers for substantive build. Claude Code must implement them as stated unless explicitly instructed otherwise.

| Decision | Confirmed choice |
|---|---|
| `cpd_records` as table or view? | **View.** `learning_completions` remains the source of truth; `cpd_exports` provides immutable export snapshots. |
| Module content location | **Markdown in `docs/learn/modules/`.** The database stores only metadata and `content_reference`. |
| Completion irreversibility | **Void with reason.** Do not silently delete or overwrite completions; use `is_voided`, `void_reason`, `voided_at`, and `voided_by_user_id`. |
| Bias-detection representation | **Category.** Use `category = 'bias_detection'` for filtering and aggregate queries. |
| Export payload format v1 | **Pure JSON.** PDF generation is a later follow-on. |
| User role taxonomy | **Inspect and reuse/reconcile with the existing repo enum before migration.** Do not invent a parallel role taxonomy. |

### §4.4 — Scoping and audit work that may proceed in parallel

Scoping and audit work may proceed at any time and may also run alongside substantive build:

- Schema review: Claude Code reads §2.1 and proposes refinements or flags conflicts with existing tables
- File impact analysis: Claude Code lists every file that would change without editing any of them
- Existing-code audit: Claude Code reads existing `/learn` page and reports its current state, fields, and patterns
- Wording audit of existing `/learn` page against Readiness Map §2 (report-only)
- Test scaffolding: Claude Code drafts `tests/test_learn_v1.py` with test stubs but no implementation
- TypeScript type drafts: Claude Code drafts the API client types matching §2.2 Pydantic models

None of the above touches production code or database state. All are reversible without consequence.

---

## §5 — Session kickoff prompt templates

### §5.1 — Backend session kickoff

Paste this as the first message in a Claude Code session opened in `C:\Users\rggal\ANCHOR`:

> Read `CLAUDE.md` and `docs/canonical/Phase_2A_1_Engineering_Brief_v1_1.md`. Confirm in one paragraph:
> 1. What ANCHOR's doctrine requires.
> 2. The Phase 2A-1 backend scope (§2 of the brief).
> 3. The database schema you plan to implement (§2.1).
> 4. The confirmed implementation decisions (§4.3) that you must apply during build.
> 5. What is out of scope (§4.2).
>
> Then wait for my next instruction. Do not write any code yet.

### §5.2 — Frontend session kickoff

Paste this as the first message in a Claude Code session opened in `C:\Users\rggal\anchor-portal`:

> Read `CLAUDE.md` and `docs/canonical/Phase_2A_1_Engineering_Brief_v1_1.md`. Confirm in one paragraph:
> 1. What ANCHOR's doctrine requires for frontend work.
> 2. The Phase 2A-1 frontend scope (§3 of the brief).
> 3. The pages and components you plan to add or modify (§3.1, §3.2).
> 4. The copy controls (§3.4) and where you will apply them.
> 5. What is out of scope (§4.2).
>
> Then wait for my next instruction. Do not write any code yet.

### §5.3 — Parallel scoping prompt

> Read `CLAUDE.md` and `docs/canonical/Phase_2A_1_Engineering_Brief_v1_1.md` §4.4. Perform the pre-build scoping work listed there: schema review, file impact analysis, existing-code audit, wording audit, test scaffolding (stubs only), TypeScript type drafts. Do not edit any production code or run any migrations. Report findings.

### §5.4 — Per-section implementation prompt template

After kickoff, implement one section at a time:

> Implement §2.1 (database schema) and §2.5 test cases `test_record_completion_creates_row` and `test_tenant_isolation_completions` from the engineering brief. Do not implement endpoints yet. Run the new tests and the existing Assistant test suite. Report per the format in CLAUDE.md.

### §5.5 — End-of-session reporting prompt

> Report per the format in CLAUDE.md: files changed, migrations added, tables created (with RLS confirmation), endpoints added, tests run with counts and results, app import check, metadata-only doctrine preserved, tenant safety preserved, deferred items.

---

## §6 — Sign-off

This brief v1.1 is approved as the implementation contract for Phase 2A-1 once founder confirms the file has been installed in both repositories.

Substantive Phase 2A-1 build may proceed without waiting for the M5.6 buyer-conversation gate. Buyer conversations remain valuable and should continue in parallel; findings may trigger an in-flight scope revision if a stronger first wedge is signalled.

Before external use or clinic onboarding, the following remain mandatory:

1. Public copy audit against Readiness Map §2 and Decision Memo wording controls.
2. Retention and memory-consent rules documented in Trust Pack and Privacy/Policy surfaces.

Implementation decisions in §4.3 are confirmed and must be applied. No additional founder decision is required on those six points unless repository inspection reveals a conflict, especially around existing user-role taxonomy.

---

*Brief v1.1 — updated 25 May 2026 — buyer-conversation gate removed; implementation decisions confirmed; public copy audit and retention/memory-consent documentation remain mandatory before external use.*



