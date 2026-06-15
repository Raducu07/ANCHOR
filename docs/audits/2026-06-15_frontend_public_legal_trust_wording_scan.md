# ANCHOR Frontend Public Legal + Trust Wording Scan v1

*Date: 15 June 2026 · Owner: Founder / Product Owner · Phase: 2A-D release-candidate hardening*

## 1. Status and purpose

This is an **internal frontend / public-copy audit artefact**. It is the frontend/public-site counterpart to the backend-held final RC wording scan.

It is **not** legal advice, **not** solicitor review, **not** final release-candidate sign-off, and **not** authorisation for paid pilots, real clinic data, billing, Stripe, or live Workspace generation. It records the current wording posture of public-facing ANCHOR copy so that issues can be corrected (in a later patch) before any external reliance. No page or copy was modified to produce this artefact.

## 2. Scope reviewed

Public route/content areas inspected against the current repository state:

**Public marketing**
- Home (`app/page.tsx` → `components/marketing/PublicWebsite.tsx`) and `app/marketing/page.tsx`
- Public header/footer/CTA (`components/marketing/MarketingShell.tsx`; footer renders `LEGAL_FOOTER_GROUPS`)
- Public marketing assistant copy (`lib/anchorAssistantContent.ts`, `lib/anchorAssistant.ts`)
- `/demo` (`components/marketing/DemoRequestForm.tsx`), `/demo/thanks`
- `/start` (`components/marketing/StartRequestForm.tsx`), `/start/thanks`
- `/plans` (pricing-tier marketing copy)

**Legal Centre** (`app/legal/*`, content via `lib/legal/legalContent.ts`)
- `/legal` (index), `/legal/terms`, `/legal/privacy`, `/legal/data-processing`, `/legal/acceptable-use`, `/legal/ai-governance-boundary`, `/legal/security`, `/legal/security/toms`, `/legal/subprocessors`, `/legal/data-retention`, `/legal/data-roles`, `/legal/data-classification`, `/legal/ai-data-use`, `/legal/ai-providers`, `/legal/customer-responsibilities`, `/legal/offboarding`, `/legal/versions`, `/legal/cookies`, `/legal/pilot-terms`

**Trust Centre** (`app/trust-center/*`)
- `/trust-center`, `/trust-center/security`, `/trust-center/privacy`, `/trust-center/ai-governance`, `/trust-center/procurement`, `/trust-center/request-access`

**Security disclosure**
- `/security/vulnerability-disclosure`

**Contact / commercial posture**
- Contact routes (Trust Centre contact card, request-access, vulnerability-disclosure, privacy/terms/data-processing contact lines)
- Stripe / billing posture (`/legal/subprocessors`, `/legal/data-classification`)

**Intentionally not reviewed (out of public scope):**
- `/security` (no index route exists; only `/security/vulnerability-disclosure` is present).
- Authenticated portal surfaces behind `AppShell` — `app/trust/**` (Trust posture / Trust Pack), `app/dashboard`, `app/learn/**` (Learn/CPD), `app/workspace*`, `app/receipts`, `app/settings/**`, `app/governance-events`, `app/privacy-policy`, `app/support`, `app/ops/**`. These are not public marketing/legal surfaces; public-facing trust language lives in `/trust-center` and was reviewed. They were spot-checked only for clinical-boundary doctrine (see §10).
- Backend repository (the final backend-held RC wording scan is separate).

## 3. Legal skill / review method

A Claude legal skill **was found and used**: `.claude/skills/anchor-legal-prep/SKILL.md` (invoked for this audit). The scan applied that skill's §4 prohibited-claims list, §5 safer-wording set, §6 legal-gate rules, §7 Article 4 rule, and §8 Anthropic/provider rule. It was cross-checked against repo `CLAUDE.md`, `CODEX_GUARDRAILS.md`, and the operative canonical set (Roadmap v2.6, Readiness Map v1.1 §2 wording controls, Addendum v1.3). Related skills present but not primary for this artefact: `anchor-doctrine-check`, `anchor-security-audit`, `anchor-frontend-visual-review`.

## 4. Executive result

**PASS WITH WATCH ITEMS.**

- **No BLOCKERS.** No public copy authorises a gated activity (paid pilots, real clinic data, billing, Stripe, live generation) or materially misrepresents ANCHOR.
- **No ISSUES** in the prohibited-claim families: every risky term appears only in negation, "is-not", prohibited-use, or "not a certification/guarantee" framing.
- **WATCH items** exist, the most notable being Slice 2 status labels that assert "solicitor reviewed" / "Founder-approved public summary" (§5 row 14, §8, §11). These were a recorded founder framing but should be confirmed (or softened to "prepared for solicitor review") before binding external legal reliance.

Conservative reading: safe for **current public informational use** and for **founder/solicitor review**; **not** safe for binding commercial/external legal reliance until solicitor review is confirmed and the standing gates close.

## 5. Non-claim scan results

| Phrase / claim family | Result | Location(s) | Notes | Required action |
| --- | --- | --- | --- | --- |
| RCVS approved / RCVS compliant / regulator endorsed | PASS | `legalContent.ts` non-claim notice + `ai-governance-boundary` is-not list; `trust-center/ai-governance` | Only as negations ("does not make a clinic compliant"; "not a regulator-approved product") | None |
| certified / certification | PASS | `legalContent.ts` security entry; `legal/security/toms`; `trust-center/security`; procurement card | Always "not a certification" / "not SOC 2, ISO, penetration-test" | None |
| compliance guarantee / guarantees / guaranteed | PASS | `legalContent.ts` (terms "No guarantees", security); `trust-center/security`; `toms` | Negated: "does not guarantee…", "not guarantees", "does not constitute a guarantee" | None |
| GDPR compliant / EU AI Act compliant / Article 4 compliant | PASS | `trust-center/ai-governance` (Article 4 as readiness theme); privacy pages | Not asserted; Article 4 framed "subject to legal review and amendment watch"; UK applicability not assumed | None |
| fine-proof / breach-proof | PASS | `trust-center/security`; `legalContent.ts` security | Negated: "not breach-proof or secure by guarantee" | None |
| clinical decision support / diagnosis / prescribing / treatment planning / autonomous triage / ambient scribe / EHR / PMS | PASS | `ai-governance-boundary` & `acceptable-use` (is-not / prohibited-use lists); `trust-center/ai-governance`; `pilot-terms`; assistant clinical-boundary refusals (`lib/anchorAssistant.ts`, `lib/anchorAssistantContent.ts`) | Only as exclusions / prohibited uses / hard refusals | None |
| clinical record / patient record | PASS | `acceptable-use` (prohibited use); `ai-data-use`/`privacy`/`pilot-terms` (do-not-upload); `ClientTransparencyAdminPage` ("not a clinical record") | Never claimed as a capability | None |
| clinical correctness / patient safety / proof of competence | PASS | `ai-governance-boundary`; `trust-center/ai-governance` | Negated: receipts "do not prove clinical correctness, patient safety, professional competence, or regulatory compliance" | None |
| RCVS-accredited CPD / certified CPD | PASS | `acceptable-use`; `trust-center/ai-governance` | Uses "CPD-recordable AI literacy activity"; explicit "not RCVS-accredited CPD unless… achieved" | None |
| vendor-neutral / provider-agnostic (present tense) | PASS | `ai-providers`; `ai-data-use`; `ai-governance-boundary`; `lib/anchorAssistantContent.ts` | Future-tense only ("architected for vendor-neutrality / vendor-neutral over time") with explicit "present-tense vendor-neutrality is not claimed while a single provider is wired" | None |
| live generation active | PASS | `ai-providers`; `ai-data-use`; `subprocessors`; `ai-governance-boundary` | Consistently "production-off"; "deterministic governed generation today" | None |
| Stripe active / payment processor active / billing live | PASS | `subprocessors` (status "future candidate"); `data-classification` | "Not active"; "no active payment processor"; activation gated | None |
| paid pilot authorised / real clinic data authorised | PASS | `pilot-terms`; `request-access`; `security`; `ai-data-use` | Gated: "before any paid pilot or real clinic data"; "not authorisation to start a paid pilot…" | None |
| solicitor reviewed / Founder-approved public summary | WATCH | `legalContent.ts` `SLICE2_PAGES` stage labels; `/legal/versions` register | Slice 2 pages assert "Public informational - solicitor reviewed" / "Founder-approved public summary" per a recorded founder decision; cannot be verified from the repo | Confirm solicitor review actually occurred; if not yet complete, soften to "prepared for solicitor review" before external reliance |
| externally effective / final legal document | PASS | `/legal/versions` ("Not externally effective"); terms/privacy ("not a final…", "not in force") | Only as negations | None |
| legal advice | PASS | shared non-claim notice; `legal`/`data-processing` contact lines | Always "not legal advice" / "does not provide legal advice" | None |
| billing@ as public support route | PASS | `data-classification` only | "Reserved, founder-monitored… not currently advertised as a public support route"; absent from contact card/footer | Keep out of public contact card/footer |
| contact routes imply teams / SLA / 24-7 / staffed desk | PASS | `trust-center` contact card; `request-access`; `vulnerability-disclosure`; `start/thanks` | Explicitly negated: "not separate teams, a support desk, SLA, emergency channel, legal-advice service, DPO service, or regulator contact route"; "founder-operated" | None |

## 6. Gated-activity scan results

| Gated activity | Result | Notes |
| --- | --- | --- |
| Paid pilots | PASS | Not authorised anywhere; `pilot-terms`/`request-access` state the security-audit + operational-resilience + solicitor-reviewed-pack gate must complete first. |
| Real clinic data | PASS | Not authorised; "do not send/upload clinic, client, or patient data" caveats throughout; metadata-only by default. |
| Live Workspace generation | PASS | Consistently "production-off pending local/staging safety gate"; no "live generation active" claim. |
| Stripe / payment / billing | PASS | Stripe "future candidate / not active"; no active payment processor; no live billing/subscription/invoice/refund/VAT claim; `billing@` reserved/not public. |
| Solicitor-approved / final legal status | WATCH | No page is marked "final" or "in force"; however Slice 2 stage labels assert "solicitor reviewed" (see §5 / §11). Not marked solicitor-*approved*, but "solicitor reviewed" should be confirmed or softened. |
| External connectors / runtime ingestion | PASS | No connector/runtime-ingestion capability claimed; no MCP/connector copy on public surfaces. |
| Anthropic / live AI provider subprocessor posture | PASS | "Anthropic becomes a subprocessor when live generation is enabled"; production-off by default; subprocessor docs required before pilots/real data. |
| billing@ public promotion | PASS | Present only in the data-classification audit register, marked reserved and not advertised; not in the Trust Centre contact card, footer, `/demo`, `/start`, or `/request-access`. |

## 7. Public Legal Centre scan

**Status: PASS** (with the single cross-cutting WATCH on Slice 2 "solicitor reviewed" labelling). All 19 Legal Centre routes render with conservative, doctrine-aligned copy: every page carries the shared non-claim notice ("not legal advice"; "does not make a clinic compliant…"); Slice 1 documents are labelled draft / not in force; Slice 2 procurement/contract summaries defer to signed agreements ("the signed agreement and any data processing agreement control"). Security, TOMs, subprocessors, AI Providers, AI Data Use, AI Governance Boundary, Data Roles/Classification, Pilot Terms, and Cookies all use negated or gated wording. No ISSUE/BLOCKER.

## 8. Public Trust Centre scan

**Status: PASS** (same Slice 2 WATCH). `/trust-center` and its five sub-pages present procurement-friendly summaries that consistently state "not a certification", "not a compliance or certification claim", and route everything to signed agreements. The contact card lists six founder-monitored routes with a full negating caveat (not teams/desk/SLA/emergency/legal-advice/DPO/regulator). `/trust-center/request-access` keeps the no-form / no-data-submission / not-an-authorisation caveats. The Slice 2 stage labels here also assert "solicitor reviewed" / "Founder-approved public summary" → WATCH per §5/§11.

## 9. Public marketing / contact / CTA scan

**Status: PASS.** Home/marketing copy ("Governed AI workflows for veterinary clinics", "governance, trust, learning, and accountability", explicit "Clear product boundaries… without overstating what the product is") carries no prohibited claims. The public assistant content frames vendor-neutrality as future-tense and refuses clinical questions. `/demo` is provider-agnostic email-preparation (no auto-send, no backend POST, no fake success); `/start` remains structured backend intake with a genuine post-success state and softened, founder-operated response-time wording. Footer renders grouped legal/trust links only — **no contact addresses, no `billing@`, no Stripe**. CTAs are "Request a walkthrough" / "Start with ANCHOR" / "Compare plans" — no SLA, paid-pilot, or onboarding-guarantee language. No ISSUE/BLOCKER.

## 10. Product / trust-surface copy scan

**Status: PASS (public-relevant copy).** Public-facing trust language lives in `/trust-center` (covered in §8). The authenticated portal Trust posture / Trust Pack / Learn / CPD / Dashboard surfaces sit behind `AppShell` auth and are **not public**; they were not part of this public scan beyond a clinical-boundary spot-check, which confirmed the assistant and client-transparency surfaces use hard refusals and "not a clinical record / not legal advice" framing. No pricing/billing/Stripe references appear on public surfaces other than the conservative future-candidate/reserved notes in `/legal/subprocessors` and `/legal/data-classification`. Any future change to authenticated Trust Pack export copy intended for external sharing should be re-scanned before external distribution.

## 11. Open watch items

- **Solicitor review not confirmed.** Slice 2 stage labels assert "solicitor reviewed" / "Founder-approved public summary". This is a recorded founder framing, not a verified fact in-repo. Before binding external reliance, confirm solicitor review actually occurred, or soften to "prepared for solicitor review".
- **Live Workspace generation safety gate still blocked** — copy correctly states production-off; keep until the local/staging safety gate passes.
- **No paid-pilot / real-clinic-data authorisation** — gates correctly stated; must remain until security audit + operational resilience + solicitor-reviewed legal/commercial pack complete.
- **`billing@anchorvet.co.uk` reserved / not public** — keep out of public contact card and footer.
- **Stripe future-candidate only** — keep "not active" until money can actually move / payment data is processed; then list as an active subprocessor with region/transfer detail.
- **Accountant / VAT / payment treatment not complete** — no public copy implies otherwise; confirm before any billing activation.
- **Subprocessor specifics unconfirmed** — database provider, analytics provider, and hosting regions/transfers remain "to be confirmed"; finalise in the DPA before external reliance.
- **EU AI Act wording** — Article 4 kept as a readiness theme with amendment watch; re-check at each Readiness Map review.
- **Routes likely to need updates after legal review** — terms, privacy, data-processing, TOMs, subprocessors, pilot-terms (status labels and any final-position wording).

## 12. Required follow-up

- **No correction patch is required to keep current public copy safe for informational use** — there are no ISSUES or BLOCKERS.
- **Smallest recommended follow-up (optional, before external/binding use):** a tiny wording patch to change Slice 2 stage labels from "solicitor reviewed" / "Founder-approved public summary" to "prepared for solicitor review" **unless** the founder can confirm solicitor review actually occurred. This is the only copy-level item the conservative posture would change before external legal reliance.
- Otherwise: record that frontend public wording is **ready for founder/solicitor review**, not for external legal reliance.

## 13. Conclusion

- **Safe for current public informational use:** Yes. Public copy is conservative, doctrine-aligned, and free of prohibited claims; gated activities are not authorised.
- **Safe for founder / solicitor review:** Yes. The surface is in good shape to hand to a solicitor for the legal/commercial pack.
- **Safe for binding commercial / external legal reliance:** No — not yet. It is not legal advice and not solicitor-approved; the "solicitor reviewed" stage labels need confirmation or softening, solicitor review of the legal/commercial pack must complete, and the standing gates (live generation safety, paid pilots, real clinic data, billing/Stripe) remain closed.

*This artefact records findings only. No existing page or copy was modified. Aligned, not compliant.*
