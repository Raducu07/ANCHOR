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
// All Slice 1 pages are now published; this list is empty and the index hides
// the "Planned pages" block when it is empty.
export const PLANNED_LEGAL_PAGES: string[] = [];

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

  terms: {
    slug: "terms",
    title: "Terms of Service",
    subtitle: "Public terms of service - solicitor-preparation draft.",
    version: COMMON_VERSION,
    statusLabel: COMMON_STATUS,
    stage: COMMON_STAGE,
    lastUpdated: COMMON_LAST_UPDATED,
    summary:
      "This is a draft of ANCHOR's public terms of service, prepared for solicitor review. It is not final and is not currently in force.",
    sections: [
      {
        heading: "Status of these terms",
        bullets: [
          "This is not a final Terms of Service.",
          "These terms are not currently in force unless and until they are incorporated into a signed agreement or formal launch terms.",
          "A signed agreement, pilot agreement, data processing agreement, or order form may supersede this public wording.",
        ],
      },
      {
        heading: "What ANCHOR is",
        body: [
          "ANCHOR is governance and readiness infrastructure for safe AI use in veterinary clinics. It is not clinical decision-making AI, and it does not diagnose, prescribe, plan treatment, or replace veterinary judgement.",
        ],
      },
      {
        heading: "Customer responsibilities",
        body: [
          "Clinics remain responsible for professional judgement, lawful processing of personal data, staff supervision, and safe use of AI tools. See the Customer Responsibilities page.",
        ],
      },
      {
        heading: "No guarantees",
        body: [
          "ANCHOR does not guarantee compliance with any law or professional standard, and does not guarantee safety, clinical correctness, or uninterrupted service.",
        ],
      },
      {
        heading: "Draft note on operative terms",
        body: [
          "Liability, limitation, and other operative contract terms are not set out here as a final legal position. They will be addressed in the legal and commercial pack and confirmed through solicitor review before any agreement is offered.",
        ],
      },
      {
        heading: "Legal and commercial document enquiries",
        body: [
          "Legal and commercial document enquiries may be sent to legal@anchorvet.co.uk. This mailbox forwards to and is monitored by the founder; it is a contact route only and does not provide legal advice. Signed agreements and solicitor-reviewed documents control.",
        ],
      },
    ],
    related: [
      { href: "/legal/customer-responsibilities", label: "Customer Responsibilities" },
      { href: "/legal/acceptable-use", label: "Acceptable Use Policy" },
    ],
  },

  privacy: {
    slug: "privacy",
    title: "Privacy Notice",
    subtitle: "Draft privacy notice - solicitor review pending.",
    version: COMMON_VERSION,
    statusLabel: COMMON_STATUS,
    stage: COMMON_STAGE,
    lastUpdated: COMMON_LAST_UPDATED,
    summary:
      "This is a draft privacy notice prepared for solicitor review. Final positions depend on the legal documents and are not yet in force.",
    sections: [
      {
        heading: "Status",
        body: [
          "This is a draft privacy notice prepared for solicitor review. It is not a final privacy notice and is not legal advice.",
        ],
      },
      {
        heading: "Metadata-only does not mean no personal data",
        body: [
          "ANCHOR is metadata-only by default, but metadata-only does not mean no personal data is involved.",
        ],
      },
      {
        heading: "Personal data that may be processed",
        body: ["Depending on context, personal data may include:"],
        bullets: [
          "account data",
          "staff identifiers",
          "reviewer attribution",
          "learning records",
          "audit events",
          "public intake submissions",
          "governance metadata",
          "support communications",
        ],
      },
      {
        heading: "Raw clinical content",
        body: [
          "Raw clinical, client, or patient content is not expected by default and should not be submitted unless an authorised product flow and a corresponding agreement permit it.",
        ],
      },
      {
        heading: "Roles and documentation",
        body: [
          "Final controller and processor positions are subject to the legal documents and solicitor review. International-transfer and subprocessor positions are not confirmed here and must be set out in the data-processing and subprocessor documentation before any paid pilot or real clinic data.",
        ],
      },
      {
        heading: "Privacy and data-protection contact",
        body: [
          "Privacy and data-protection questions may be sent to privacy@anchorvet.co.uk. This mailbox forwards to and is monitored by the founder; it is a contact route, not a Data Protection Officer appointment. Please do not send raw clinic, client, or patient data unless an authorised agreement and product flow permit it.",
        ],
      },
    ],
    related: [{ href: "/legal/data-roles", label: "Data Roles" }],
  },

  "acceptable-use": {
    slug: "acceptable-use",
    title: "Acceptable Use Policy",
    subtitle: "Draft acceptable use policy - solicitor review pending.",
    version: COMMON_VERSION,
    statusLabel: COMMON_STATUS,
    stage: COMMON_STAGE,
    lastUpdated: COMMON_LAST_UPDATED,
    summary:
      "This draft sets out how ANCHOR may and may not be used. It is prepared for solicitor review and is not yet in force.",
    sections: [
      {
        heading: "Permitted use",
        body: ["ANCHOR is intended to support:"],
        bullets: [
          "governance evidence",
          "AI-use policy support",
          "learning and CPD-recordable AI literacy evidence",
          "client transparency support",
          "incident and near-miss governance metadata",
          "Trust Pack and readiness evidence",
        ],
      },
      {
        heading: "Prohibited use",
        body: ["ANCHOR must not be used for:"],
        bullets: [
          "diagnostic use",
          "prescribing use",
          "treatment-planning use",
          "autonomous triage",
          "replacing veterinary judgement",
          "use as an EHR, PMS, or clinical record",
          "uploading raw clinical records or identifiable client or patient material unless expressly permitted by an authorised product flow and agreement",
          "attempting to bypass tenant or access controls",
          "using outputs without human review",
          "any unlawful, harmful, misleading, abusive, or security-invasive use",
        ],
      },
      {
        heading: "Enforcement note",
        body: [
          "These boundaries describe expected use. ANCHOR's controls support safe use but do not perfectly police or prevent all possible misuse; responsibility for appropriate use remains with the clinic and its staff.",
        ],
      },
    ],
    related: [
      { href: "/legal/ai-governance-boundary", label: "AI Governance Boundary" },
      { href: "/legal/customer-responsibilities", label: "Customer Responsibilities" },
    ],
  },

  security: {
    slug: "security",
    title: "Security Posture",
    subtitle: "High-level security posture - not a security certification.",
    version: COMMON_VERSION,
    statusLabel: COMMON_STATUS,
    stage: COMMON_STAGE,
    lastUpdated: COMMON_LAST_UPDATED,
    summary:
      "This page describes ANCHOR's security posture at a high level. It is not a security certification and is prepared for solicitor and buyer review.",
    sections: [
      {
        heading: "Scope of this page",
        body: [
          "This is a high-level description of security posture only. It is not a security certification and does not constitute a guarantee.",
        ],
      },
      {
        heading: "Tenant isolation and access",
        bullets: [
          "Multi-tenant separation using row-level security (RLS), including FORCE RLS, and request-scoped tenant context as part of the platform's isolation model.",
          "Authentication and access control for clinic and administrator users.",
          "Clinic-scoped access so views remain limited to a single tenant.",
        ],
      },
      {
        heading: "Logging and audit",
        body: [
          "Administrative actions are recorded through audit logging, supporting an admin audit posture for review.",
        ],
      },
      {
        heading: "Data discipline",
        body: [
          "Storage is metadata-only by default; raw prompt and output content are not stored in the current product doctrine.",
        ],
      },
      {
        heading: "Operational resilience and security audit",
        body: [
          "A security audit and operational-resilience evidence are a mandatory release-candidate gate before paid pilots or real clinic data. This work includes dependency and vulnerability scanning, backup and tested restore, and a breach and incident-response runbook. These are operational practices and planned controls, not guarantees.",
        ],
      },
      {
        heading: "What this page does not claim",
        body: [
          "This page does not claim SOC 2, ISO, penetration-test, or other security certification, and it does not claim that the platform is breach-proof or secure by guarantee. Specific encryption and hosting-region details are not asserted here and must be confirmed in the security and legal documentation.",
        ],
      },
    ],
  },

  "data-retention": {
    slug: "data-retention",
    title: "Data Retention",
    subtitle: "Retention and deletion - draft, subject to solicitor review.",
    version: COMMON_VERSION,
    statusLabel: COMMON_STATUS,
    stage: COMMON_STAGE,
    lastUpdated: COMMON_LAST_UPDATED,
    summary:
      "This page describes ANCHOR's draft approach to data retention and deletion. Retention periods are not yet fixed and are subject to the legal and commercial pack and solicitor review.",
    sections: [
      {
        heading: "Status",
        body: [
          "The retention schedule is subject to the legal and commercial pack and solicitor review. Specific retention periods are not fixed here.",
        ],
      },
      {
        heading: "Records with potentially different retention",
        body: ["Different categories of record may have different retention periods, including:"],
        bullets: [
          "governance metadata",
          "learning records",
          "audit logs",
          "incident records",
          "public intake submissions",
          "support records",
        ],
      },
      {
        heading: "Survival after closure",
        body: [
          "Some records may survive account closure for legal, billing, security, dispute-handling, backup, audit, or agreed governance-evidence purposes.",
        ],
      },
      {
        heading: "Backups and export",
        bullets: [
          "Backup deletion lag may apply, so data may persist in backups for a period after deletion from active systems.",
          "Where applicable, customers should export relevant records before closure.",
        ],
      },
    ],
    related: [{ href: "/legal/offboarding", label: "Offboarding and Data Deletion" }],
  },

  "data-classification": {
    slug: "data-classification",
    title: "Data Classification Register",
    subtitle: "Draft register of customer data classes - subject to solicitor review.",
    version: COMMON_VERSION,
    statusLabel: COMMON_STATUS,
    stage: COMMON_STAGE,
    lastUpdated: COMMON_LAST_UPDATED,
    summary:
      "This draft register lists the classes of data ANCHOR may handle and notes expectations for personal data and raw clinical content. It is prepared for solicitor review.",
    sections: [
      {
        heading: "Data classes",
        body: ["ANCHOR may handle the following classes of data:"],
        bullets: [
          "public website data",
          "account and authentication data",
          "clinic and tenant administration data",
          "governance metadata",
          "Assistant and governed-workflow metadata",
          "learning and CPD metadata",
          "policy and attestation metadata",
          "Trust Pack and self-assessment metadata",
          "incident and near-miss metadata",
          "public intake data",
          "billing data, if and when billing is enabled",
          "support communications",
          "AI-provider transient routing data, if live generation is enabled",
          "system logs and audit logs",
        ],
      },
      {
        heading: "Raw clinical content",
        body: ["Raw clinical content is not expected and is prohibited by default."],
      },
      {
        heading: "Personal data",
        body: [
          "Personal data is possible for several of these classes, for example account data, staff identifiers, reviewer attribution, public intake data, and support communications.",
        ],
      },
      {
        heading: "Sensitive or special-category data",
        body: [
          "Sensitive or special-category data is not expected and is prohibited by default, unless a specific authorised product flow and a corresponding agreement permit it.",
        ],
      },
      {
        heading: "Billing and payment data",
        body: [
          "There is no active payment processor and no live customer billing workflow. ANCHOR does not currently operate subscription, invoice, payment, refund, or customer billing processes, so no customer payment data is processed today.",
          "Stripe is the intended future candidate payment processor for the M5.8 billing and payment foundations, subject to security, legal and commercial, pricing, VAT and accounting, cancellation and refund, and founder-approval gates. Until activated, Stripe is not treated as processing ANCHOR customer payment data.",
          "billing@anchorvet.co.uk is a reserved, founder-monitored route for future billing and payment enquiries. It is not currently advertised as a public support route.",
        ],
      },
      {
        heading: "Draft note",
        body: [
          "Retention periods and any subprocessors for these classes are not confirmed here and are subject to the legal and commercial pack and solicitor review.",
        ],
      },
    ],
    related: [
      { href: "/legal/data-roles", label: "Data Roles" },
      { href: "/legal/data-retention", label: "Data Retention" },
    ],
  },

  offboarding: {
    slug: "offboarding",
    title: "Offboarding and Data Deletion",
    subtitle: "Offboarding, deletion, and survival - draft, subject to solicitor review.",
    version: COMMON_VERSION,
    statusLabel: COMMON_STATUS,
    stage: COMMON_STAGE,
    lastUpdated: COMMON_LAST_UPDATED,
    summary:
      "This page describes ANCHOR's draft approach to offboarding, data deletion, and which records may survive closure. It is prepared for solicitor review and is not yet in force.",
    sections: [
      {
        heading: "Before closure",
        bullets: [
          "Where applicable, export relevant records before closure.",
          "Account deactivation can be requested as part of offboarding.",
        ],
      },
      {
        heading: "Deletion",
        body: [
          "A specific deletion-request route is to be confirmed in the legal and commercial pack and is subject to solicitor review.",
        ],
      },
      {
        heading: "What may survive closure",
        body: [
          "Some records may survive closure for legal, billing, security, dispute-handling, backup, audit, or agreed governance-evidence purposes. ANCHOR does not represent that all data is deleted immediately or that nothing survives closure.",
        ],
      },
      {
        heading: "Backups and subprocessors",
        bullets: [
          "Backup deletion lag may apply.",
          "Deletion may depend on subprocessor deletion timelines where subprocessors are involved.",
        ],
      },
      {
        heading: "Clinic responsibility",
        body: [
          "Clinics remain responsible for any local copies of exported or downloaded material.",
        ],
      },
    ],
    related: [{ href: "/legal/data-retention", label: "Data Retention" }],
  },
};

export function getLegalPage(slug?: string | null): LegalPage | undefined {
  if (!slug) return undefined;
  return LEGAL_PAGES[slug];
}

export function listLegalPages(): LegalPage[] {
  return Object.values(LEGAL_PAGES);
}

// Display order for the Legal Centre index and registry-backed listings
// (Patch A + Patch B document pages). The explicit /legal/versions register
// is listed separately by the pages that render it.
export const LEGAL_PAGE_ORDER: string[] = [
  "terms",
  "privacy",
  "acceptable-use",
  "ai-governance-boundary",
  "security",
  "data-retention",
  "data-roles",
  "data-classification",
  "ai-data-use",
  "customer-responsibilities",
  "offboarding",
];

// Returns the registry pages in display order (skips any unknown slug).
export function listLegalPagesInOrder(): LegalPage[] {
  return LEGAL_PAGE_ORDER.map((slug) => LEGAL_PAGES[slug]).filter(
    (page): page is LegalPage => Boolean(page),
  );
}

// ---------------------------------------------------------------------------
// Slice 2 (procurement / contract-adjacent public summaries)
//
// Founder/solicitor confirmation is treated as available for completing the
// public-facing view, so these are published "public summaries" rather than
// drafts. Wording remains conservative: no compliance, certification, security
// assurance, legal-effectiveness, or clinical claims. Signed agreements, DPA,
// pilot agreement, order form, or final legal terms control over these summaries.
// ---------------------------------------------------------------------------

export type Slice2PageMeta = {
  href: string;
  title: string;
  subtitle: string;
  version: string;
  lastUpdated: string;
  statusLabel: string;
  stage: string;
};

const SLICE2_VERSION = "v1.0";
const SLICE2_LAST_UPDATED = "15 June 2026";
const SLICE2_STATUS_BADGE = "Public summary";

export const SLICE2_PAGES: Record<string, Slice2PageMeta> = {
  "trust-security": {
    href: "/trust-center/security",
    title: "Trust Centre: Security",
    subtitle: "Procurement-friendly overview of ANCHOR's security posture.",
    version: SLICE2_VERSION,
    lastUpdated: SLICE2_LAST_UPDATED,
    statusLabel: SLICE2_STATUS_BADGE,
    stage: "Procurement summary - not a certification",
  },
  "trust-privacy": {
    href: "/trust-center/privacy",
    title: "Trust Centre: Privacy",
    subtitle: "Procurement-friendly overview of ANCHOR's privacy posture.",
    version: SLICE2_VERSION,
    lastUpdated: SLICE2_LAST_UPDATED,
    statusLabel: SLICE2_STATUS_BADGE,
    stage: "Public informational - solicitor reviewed",
  },
  "trust-ai-governance": {
    href: "/trust-center/ai-governance",
    title: "Trust Centre: AI Governance",
    subtitle: "Procurement-friendly overview of how ANCHOR governs AI use.",
    version: SLICE2_VERSION,
    lastUpdated: SLICE2_LAST_UPDATED,
    statusLabel: SLICE2_STATUS_BADGE,
    stage: "Public informational - solicitor reviewed",
  },
  "trust-procurement": {
    href: "/trust-center/procurement",
    title: "Trust Centre: Procurement Pack",
    subtitle: "An index of ANCHOR's legal, security, privacy, and AI-governance materials for buyers.",
    version: SLICE2_VERSION,
    lastUpdated: SLICE2_LAST_UPDATED,
    statusLabel: SLICE2_STATUS_BADGE,
    stage: "Procurement summary - not a certification",
  },
  "trust-request-access": {
    href: "/trust-center/request-access",
    title: "Trust Centre: Request Access",
    subtitle: "How to request procurement, security, and legal review materials.",
    version: SLICE2_VERSION,
    lastUpdated: SLICE2_LAST_UPDATED,
    statusLabel: SLICE2_STATUS_BADGE,
    stage: "Public informational - solicitor reviewed",
  },
  toms: {
    href: "/legal/security/toms",
    title: "Technical and Organisational Measures",
    subtitle: "A contract-adjacent summary of ANCHOR's technical and organisational measures.",
    version: SLICE2_VERSION,
    lastUpdated: SLICE2_LAST_UPDATED,
    statusLabel: SLICE2_STATUS_BADGE,
    stage: "Contract-adjacent summary - agreement controls",
  },
  subprocessors: {
    href: "/legal/subprocessors",
    title: "Subprocessors",
    subtitle: "Public summary of the subprocessors ANCHOR may use.",
    version: SLICE2_VERSION,
    lastUpdated: SLICE2_LAST_UPDATED,
    statusLabel: SLICE2_STATUS_BADGE,
    stage: "Contract-adjacent summary - agreement controls",
  },
  "ai-providers": {
    href: "/legal/ai-providers",
    title: "AI Providers",
    subtitle: "How ANCHOR works with AI providers, and what that means for data.",
    version: SLICE2_VERSION,
    lastUpdated: SLICE2_LAST_UPDATED,
    statusLabel: SLICE2_STATUS_BADGE,
    stage: "Founder-approved public summary",
  },
  "data-processing": {
    href: "/legal/data-processing",
    title: "Data Processing Summary",
    subtitle: "A public summary of how ANCHOR processes data on behalf of clinics.",
    version: SLICE2_VERSION,
    lastUpdated: SLICE2_LAST_UPDATED,
    statusLabel: SLICE2_STATUS_BADGE,
    stage: "Contract-adjacent summary - agreement controls",
  },
  "pilot-terms": {
    href: "/legal/pilot-terms",
    title: "Pilot Terms Summary",
    subtitle: "A public summary of how ANCHOR pilots are intended to work.",
    version: SLICE2_VERSION,
    lastUpdated: SLICE2_LAST_UPDATED,
    statusLabel: SLICE2_STATUS_BADGE,
    stage: "Contract-adjacent summary - agreement controls",
  },
  cookies: {
    href: "/legal/cookies",
    title: "Cookie Notice",
    subtitle: "How ANCHOR uses cookies, based on the current frontend.",
    version: SLICE2_VERSION,
    lastUpdated: SLICE2_LAST_UPDATED,
    statusLabel: SLICE2_STATUS_BADGE,
    stage: "Public informational - solicitor reviewed",
  },
};

export function getSlice2Page(key: string): Slice2PageMeta {
  const page = SLICE2_PAGES[key];
  if (!page) {
    throw new Error(`Unknown Slice 2 page: ${key}`);
  }
  return page;
}

// Grouped footer navigation across Slice 1 + Slice 2 (kept readable in columns).
export type LegalFooterLink = { href: string; label: string };
export type LegalFooterGroup = { heading: string; links: LegalFooterLink[] };

export const LEGAL_FOOTER_GROUPS: LegalFooterGroup[] = [
  {
    heading: "Legal",
    links: [
      { href: "/legal", label: "Legal Centre" },
      { href: "/legal/terms", label: "Terms of Service" },
      { href: "/legal/acceptable-use", label: "Acceptable Use" },
      { href: "/legal/data-processing", label: "Data Processing" },
      { href: "/legal/pilot-terms", label: "Pilot Terms" },
      { href: "/legal/cookies", label: "Cookies" },
      { href: "/legal/versions", label: "Version History" },
    ],
  },
  {
    heading: "Data & AI",
    links: [
      { href: "/legal/privacy", label: "Privacy Notice" },
      { href: "/legal/data-roles", label: "Data Roles" },
      { href: "/legal/data-classification", label: "Data Classification" },
      { href: "/legal/data-retention", label: "Data Retention" },
      { href: "/legal/offboarding", label: "Offboarding" },
      { href: "/legal/ai-governance-boundary", label: "AI Governance Boundary" },
      { href: "/legal/ai-data-use", label: "AI Data Use" },
      { href: "/legal/ai-providers", label: "AI Providers" },
      { href: "/legal/customer-responsibilities", label: "Customer Responsibilities" },
    ],
  },
  {
    heading: "Trust & Security",
    links: [
      { href: "/trust-center", label: "Trust Centre" },
      { href: "/trust-center/security", label: "Trust Centre: Security" },
      { href: "/trust-center/privacy", label: "Trust Centre: Privacy" },
      { href: "/trust-center/ai-governance", label: "Trust Centre: AI Governance" },
      { href: "/trust-center/procurement", label: "Procurement Pack" },
      { href: "/trust-center/request-access", label: "Request Access" },
      { href: "/legal/security", label: "Security Posture" },
      { href: "/legal/security/toms", label: "TOMs" },
      { href: "/legal/subprocessors", label: "Subprocessors" },
      { href: "/security/vulnerability-disclosure", label: "Vulnerability Disclosure" },
    ],
  },
];
