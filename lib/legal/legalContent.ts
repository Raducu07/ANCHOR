// lib/legal/legalContent.ts
//
// Typed static content registry for the ANCHOR Legal & Trust Centre (Slice 1, Patch A).
//
// Doctrine: copy here is metadata-only aware, "aligned, not compliant", and prepared for
// solicitor review / public transparency. It must not claim compliance, certification,
// regulator approval, present-tense vendor-neutrality, or that live generation is active.
// See .claude/skills/anchor-legal-prep/SKILL.md and Readiness Map v1.1 Section 2.

export type LegalSection = {
  heading: string;
  body?: string[];
  bullets?: string[];
};

export type LegalRelatedLink = {
  href: string;
  label: string;
};

export type LegalPage = {
  slug: string;
  title: string;
  subtitle: string;
  version: string;
  statusLabel: string;
  stage: string;
  lastUpdated: string;
  summary: string;
  sections: LegalSection[];
  related?: LegalRelatedLink[];
};

// Shared non-claim notice rendered on every legal page and the Legal Centre index.
export const LEGAL_NON_CLAIM_NOTICE =
  "ANCHOR helps clinics evidence responsible AI governance practices. It does not make a clinic compliant with any law or professional standard, and it does not replace veterinary judgement. These pages are prepared for transparency and solicitor review and are not legal advice.";

// Slice 1 pages planned but not yet published (shown as non-links on the index).
export const PLANNED_LEGAL_PAGES: string[] = [
  "Terms of Service",
  "Privacy Notice",
  "Acceptable Use Policy",
  "Security Overview",
  "Data Retention",
  "Data Classification",
  "Offboarding and Data Export",
  "Document Versions",
  "Vulnerability Disclosure",
  "Trust Centre",
];

const COMMON_VERSION = "v0.1 (draft)";
const COMMON_STATUS = "Draft";
const COMMON_STAGE = "Prepared for solicitor review - not in force";
const COMMON_LAST_UPDATED = "15 June 2026";

const LEGAL_PAGES: Record<string, LegalPage> = {
  "ai-governance-boundary": {
    slug: "ai-governance-boundary",
    title: "AI Governance Boundary",
    subtitle: "What ANCHOR is, what it is not, and what governance receipts do and do not show.",
    version: COMMON_VERSION,
    statusLabel: COMMON_STATUS,
    stage: COMMON_STAGE,
    lastUpdated: COMMON_LAST_UPDATED,
    summary:
      "This page sets out the boundary of what ANCHOR does. ANCHOR is governance and readiness infrastructure for safe AI use in veterinary clinics. It is deliberately not a clinical system, and its evidence is governance metadata, not proof of clinical or regulatory outcomes.",
    sections: [
      {
        heading: "What ANCHOR is",
        body: [
          "ANCHOR is governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics.",
        ],
        bullets: [
          "Metadata-only by default.",
          "Human-review based: AI-supported outputs remain subject to professional judgement before operational use.",
          "Receipt-backed: governed activity is explainable through governance metadata.",
          "Trust-surface oriented and multi-tenant, with clinic-scoped separation.",
          "Standalone now, and architected for vendor-neutrality / vendor-neutral over time.",
        ],
      },
      {
        heading: "What ANCHOR is not",
        body: [
          "ANCHOR is not a clinical product and must not be used as one. In particular, ANCHOR is not:",
        ],
        bullets: [
          "diagnostic AI",
          "prescribing AI",
          "treatment-planning AI",
          "autonomous triage",
          "an ambient scribe",
          "an EHR or PMS",
          "a clinical decision-support product",
          "a GPAI (general-purpose AI) model provider",
          "a compliance guarantee",
          "a regulator-approved product",
          "a replacement for veterinary judgement",
        ],
      },
      {
        heading: "What governance receipts are",
        body: [
          "Governance receipts are governance evidence only. They record metadata about governed activity, for example identifiers, timestamps, policy version, and review state, so that AI use can be reviewed and accounted for.",
        ],
      },
      {
        heading: "What governance receipts do not prove",
        body: [
          "A governance receipt does not prove clinical correctness, patient safety, professional competence, or regulatory compliance. It evidences that a governance process took place; it does not validate the clinical content or outcome of any underlying work.",
        ],
      },
      {
        heading: "Generation posture",
        body: [
          "ANCHOR provides deterministic governed generation today. Live Workspace generation remains production-off pending a local/staging safety gate. See the AI Data Use page for how AI providers and data are handled.",
        ],
      },
    ],
    related: [{ href: "/legal/ai-data-use", label: "AI Data Use" }],
  },

  "ai-data-use": {
    slug: "ai-data-use",
    title: "AI Data Use",
    subtitle: "How AI is used in ANCHOR, and how data is and is not used.",
    version: COMMON_VERSION,
    statusLabel: COMMON_STATUS,
    stage: COMMON_STAGE,
    lastUpdated: COMMON_LAST_UPDATED,
    summary:
      "This page explains ANCHOR's current position on AI data use. It describes what ANCHOR does not do with customer data, the current generation posture, and the responsibilities clinics retain when submitting material.",
    sections: [
      {
        heading: "Training of AI models",
        body: [
          "ANCHOR does not use customer governance records, learning records, Trust Pack materials, clinic metadata, or account data to train public general-purpose AI models.",
        ],
      },
      {
        heading: "Current generation posture",
        bullets: [
          "Live Workspace generation is production-off.",
          "The current live Workspace generation path has been built against Anthropic, but it remains production-off.",
          "Anthropic becomes a subprocessor when live generation is enabled.",
          "ANCHOR is presented as deterministic governed generation today and is architected for vendor-neutrality / vendor-neutral over time; present-tense vendor-neutrality is not claimed while a single provider is wired.",
        ],
      },
      {
        heading: "What this page does not claim",
        body: [
          "This page does not claim that no AI provider ever sees data, and it does not claim that data never leaves the UK. Those positions depend on technical and contractual arrangements that must be confirmed, including in the subprocessor and data-processing documentation prepared for solicitor review, before any paid pilot or real clinic data.",
        ],
      },
      {
        heading: "Customer data submission",
        body: [
          "Customers must not upload raw clinical records or identifiable client or patient material unless a specific authorised product flow and a corresponding agreement permit it. ANCHOR is metadata-only by default and is not intended to receive raw clinical content.",
        ],
      },
      {
        heading: "Status",
        body: [
          "Live generation remains production-off until the local/staging safety gate passes, and legal and subprocessor documentation must be complete before any paid pilot or real clinic data.",
        ],
      },
    ],
    related: [
      { href: "/legal/ai-governance-boundary", label: "AI Governance Boundary" },
      { href: "/legal/customer-responsibilities", label: "Customer Responsibilities" },
    ],
  },

  "data-roles": {
    slug: "data-roles",
    title: "Data Roles",
    subtitle: "Draft data-protection roles, and what may still be personal data.",
    version: COMMON_VERSION,
    statusLabel: COMMON_STATUS,
    stage: COMMON_STAGE,
    lastUpdated: COMMON_LAST_UPDATED,
    summary:
      "This page describes ANCHOR's draft assumptions about data-protection roles. These assumptions are not final and are subject to solicitor review.",
    sections: [
      {
        heading: "Metadata-only does not mean no personal data",
        body: [
          "ANCHOR is metadata-only by default, but metadata-only does not mean no personal data is involved.",
        ],
      },
      {
        heading: "Information that may still be personal data",
        body: ["Depending on context, the following may still be personal data:"],
        bullets: [
          "staff identifiers",
          "reviewer attribution",
          "learning records",
          "audit events",
          "public intake submissions",
          "governance metadata",
        ],
      },
      {
        heading: "Draft controller and processor assumptions",
        body: [
          "Intended controller and processor assumptions are draft and subject to solicitor review. Nothing on this page is a final determination of data-protection roles, and it is not legal advice.",
        ],
      },
      {
        heading: "Clinic responsibilities",
        body: [
          "Clinic responsibilities remain in place, including for lawful basis, providing a privacy notice to data subjects, managing staff access, and ensuring that only appropriate data is submitted to ANCHOR.",
        ],
      },
    ],
    related: [{ href: "/legal/customer-responsibilities", label: "Customer Responsibilities" }],
  },

  "customer-responsibilities": {
    slug: "customer-responsibilities",
    title: "Customer Responsibilities",
    subtitle: "What your clinic remains responsible for when using ANCHOR.",
    version: COMMON_VERSION,
    statusLabel: COMMON_STATUS,
    stage: COMMON_STAGE,
    lastUpdated: COMMON_LAST_UPDATED,
    summary:
      "ANCHOR supports governance evidence. It does not take on clinical or professional duties. This page sets out the responsibilities that remain with the clinic.",
    sections: [
      {
        heading: "Responsibilities that remain with the clinic",
        body: ["Clinics remain responsible for:"],
        bullets: [
          "clinical judgement",
          "professional standards",
          "staff supervision",
          "client communication",
          "lawful processing of personal data",
          "safe use of AI tools",
        ],
      },
      {
        heading: "ANCHOR's supporting role",
        body: [
          "ANCHOR supports governance evidence and readiness. It does not transfer clinical or professional duties away from the clinic, and it does not replace veterinary judgement.",
        ],
      },
      {
        heading: "Appropriate use of content",
        body: [
          "Clinics must avoid inappropriate uploads of raw clinical or client content, consistent with ANCHOR's metadata-only design and the AI Data Use page.",
        ],
      },
      {
        heading: "Human review before operational use",
        body: [
          "Clinics must review AI-supported outputs before operational use. AI output is assistive, not authoritative.",
        ],
      },
      {
        heading: "Access management",
        body: ["Clinics must manage staff and administrator access to ANCHOR appropriately."],
      },
    ],
    related: [{ href: "/legal/ai-data-use", label: "AI Data Use" }],
  },
};

export function getLegalPage(slug?: string | null): LegalPage | undefined {
  if (!slug) return undefined;
  return LEGAL_PAGES[slug];
}

export function listLegalPages(): LegalPage[] {
  return Object.values(LEGAL_PAGES);
}
