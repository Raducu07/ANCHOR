// lib/learnCards.ts

export type LearnCard = {
  slug: string;
  title: string;
  summary: string;
  whyThisMatters: string;
  actions: string[];
  relatedModes?: string[];
  relatedReasonCodes?: string[];
};

const LEARN_CARDS: Record<string, LearnCard> = {
  "privacy-safe-ai-use": {
    slug: "privacy-safe-ai-use",
    title: "Privacy-safe AI use",
    summary:
      "Reinforce safer day-to-day AI usage when privacy warnings or handling concerns appear in governance activity.",
    whyThisMatters:
      "This learning item helps staff understand how to use AI tools without exposing personal, confidential, or unnecessary identifying information. It supports safer operational use while preserving clinic privacy expectations.",
    actions: [
      "Do not paste unnecessary personal or confidential information into AI tools.",
      "Reduce identifiable detail to the minimum needed for the task.",
      "Check whether the workflow requires anonymisation before AI use.",
      "Treat AI output as assistive, not authoritative.",
      "Follow clinic policy for privacy-aware AI handling.",
    ],
    relatedModes: ["client_comm", "internal_summary"],
    relatedReasonCodes: ["privacy_warning", "pii_warned"],
  },

  "governance-basics": {
    slug: "governance-basics",
    title: "Governance basics",
    summary:
      "Understand how ANCHOR applies governance controls, receipts, and metadata-only accountability to AI-assisted workflows.",
    whyThisMatters:
      "Governance understanding helps staff use AI more confidently and safely while preserving policy adherence, traceability, and trust.",
    actions: [
      "Understand what a governance receipt represents.",
      "Know that ANCHOR stores metadata, not raw prompt/output content.",
      "Use governance events to spot recurring friction areas.",
      "Use Learn surfaces to reinforce safe practice patterns.",
    ],
    relatedModes: ["clinical_note", "client_comm", "internal_summary"],
    relatedReasonCodes: ["allowed", "replaced", "modified"],
  },
};

const LEARN_ALIASES: Record<string, string> = {
  // recommendation ids / labels / legacy variants
  privacy_training: "privacy-safe-ai-use",
  "privacy-training": "privacy-safe-ai-use",
  privacy_safe_ai_use: "privacy-safe-ai-use",
  "privacy-safe-ai-use": "privacy-safe-ai-use",
  privacy: "privacy-safe-ai-use",

  governance: "governance-basics",
  "governance-basics": "governance-basics",
};

export function normalizeLearnSlug(input?: string | null): string {
  const raw = String(input ?? "").trim().toLowerCase();

  if (!raw) return "governance-basics";

  if (LEARN_CARDS[raw]) return raw;
  if (LEARN_ALIASES[raw]) return LEARN_ALIASES[raw];

  const normalized = raw.replace(/\s+/g, "-").replace(/_/g, "-");
  if (LEARN_CARDS[normalized]) return normalized;
  if (LEARN_ALIASES[normalized]) return LEARN_ALIASES[normalized];

  return "governance-basics";
}

export function getLearnCard(input?: string | null): LearnCard {
  const slug = normalizeLearnSlug(input);
  return LEARN_CARDS[slug] ?? LEARN_CARDS["governance-basics"];
}

export function getLearnHref(input?: string | null): string {
  const slug = normalizeLearnSlug(input);
  return `/learn/cards/${slug}`;
}

export function listLearnCards(): LearnCard[] {
  return Object.values(LEARN_CARDS);
}