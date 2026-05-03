export type AnchorAssistantTopic = {
  id: string;
  title: string;
  category: "overview" | "workflow" | "boundary" | "commercial" | "trust";
  keywords: readonly string[];
  answer: string;
  suggestedCta?: {
    label: string;
    href: string;
  };
  confidence: "high" | "medium";
};

export const anchorAssistantQuickPrompts = [
  "What does ANCHOR do?",
  "Is this a clinical AI product?",
  "How do clinics get started?",
  "What happens in a walkthrough?",
  "Does ANCHOR store raw content?",
] as const;

export const anchorAssistantTopics: readonly AnchorAssistantTopic[] = [
  {
    id: "what-is-anchor",
    title: "What is ANCHOR?",
    category: "overview",
    keywords: ["what is anchor", "what does anchor do", "anchor platform", "anchor product"],
    answer:
      "ANCHOR is governance, trust, learning, and intelligence infrastructure for safe AI use in veterinary clinics. It helps clinics move from informal AI use into governed workflows with visible accountability, receipt-backed review, and practical oversight.",
    suggestedCta: { label: "Request a walkthrough", href: "/demo" },
    confidence: "high",
  },
  {
    id: "governed-workflow",
    title: "How the governed workflow works",
    category: "workflow",
    keywords: ["workflow", "governed workflow", "how does it work", "review settings", "receipt preview"],
    answer:
      "The governed workflow lets a clinic define the task, add source material, set review boundaries, generate a governed result, and keep accountability visible through receipts, trust surfaces, and follow-up guidance.",
    suggestedCta: { label: "Request a walkthrough", href: "/demo" },
    confidence: "high",
  },
  {
    id: "who-is-it-for",
    title: "Who ANCHOR is for",
    category: "commercial",
    keywords: ["who is it for", "practice managers", "clinic owners", "operations leads", "multi-site"],
    answer:
      "ANCHOR is designed for practice managers, clinic owners, clinical directors, operations leads, and multi-site groups that want safer day-to-day AI use with clearer review, oversight, and onboarding discipline.",
    suggestedCta: { label: "View plans", href: "/plans" },
    confidence: "high",
  },
  {
    id: "not-clinical-ai",
    title: "Not a clinical decision-making system",
    category: "boundary",
    keywords: ["clinical ai", "clinical decision", "diagnosis", "treatment", "medical advice"],
    answer:
      "No. ANCHOR is not a clinical decision-making AI system. It governs workflows around AI use in veterinary clinics and keeps human review visible before operational use.",
    suggestedCta: { label: "Request a walkthrough", href: "/demo" },
    confidence: "high",
  },
  {
    id: "raw-content-storage",
    title: "Raw prompt and output storage",
    category: "boundary",
    keywords: ["store raw prompts", "store raw outputs", "raw content", "archive prompts", "archive outputs"],
    answer:
      "ANCHOR is metadata-only by default for governed operational accountability. It is designed to keep receipts, traceability, and oversight visible without normalising broad raw prompt and output retention.",
    suggestedCta: { label: "Request a walkthrough", href: "/demo" },
    confidence: "high",
  },
  {
    id: "receipts",
    title: "What receipts are",
    category: "trust",
    keywords: ["receipts", "receipt-backed", "accountability", "traceability"],
    answer:
      "Receipts are request-level accountability records that keep governance evidence, decision traceability, and policy context visible without turning ANCHOR into a raw-content archive.",
    suggestedCta: { label: "Request a walkthrough", href: "/demo" },
    confidence: "high",
  },
  {
    id: "trust-surfaces",
    title: "What trust surfaces are",
    category: "trust",
    keywords: ["trust surfaces", "trust center", "leadership visibility", "trust posture"],
    answer:
      "Trust surfaces package governance posture, communication boundaries, and exportable trust artifacts so clinic leaders can review AI use more clearly and credibly.",
    suggestedCta: { label: "Request a walkthrough", href: "/demo" },
    confidence: "high",
  },
  {
    id: "walkthrough",
    title: "What happens in a walkthrough",
    category: "commercial",
    keywords: ["walkthrough", "demo", "what happens in a walkthrough"],
    answer:
      "In a walkthrough, ANCHOR shows the governed workflow, receipt-backed accountability, trust, learning, and intelligence surfaces, plus the onboarding and subscription path that fits the clinic.",
    suggestedCta: { label: "Request a walkthrough", href: "/demo" },
    confidence: "high",
  },
  {
    id: "plans",
    title: "Start, Grow, and Group plans",
    category: "commercial",
    keywords: ["plans", "start plan", "grow plan", "group plan", "pricing"],
    answer:
      "ANCHOR currently frames three starting paths: Start for clinics beginning governed AI use, Grow for clinics operationalising AI more consistently, and Group for larger or multi-site rollout discussions. If you need exact commercial guidance, the safest next step is a walkthrough.",
    suggestedCta: { label: "View plans", href: "/plans" },
    confidence: "medium",
  },
  {
    id: "getting-started",
    title: "How clinics get started",
    category: "commercial",
    keywords: ["get started", "start with anchor", "onboarding", "setup"],
    answer:
      "Clinics usually start by choosing the right entry path, sharing their setup context, and moving into assisted onboarding for clinic details, first admin setup, and first governed workflow activation.",
    suggestedCta: { label: "Start with ANCHOR", href: "/start" },
    confidence: "high",
  },
  {
    id: "multi-site",
    title: "Multi-site support",
    category: "commercial",
    keywords: ["multi-site", "group", "multiple clinics", "rollout"],
    answer:
      "Yes. ANCHOR can support larger clinics and multi-site groups through the Group path, which is designed for rollout discussion, assisted onboarding, and a higher-touch implementation conversation.",
    suggestedCta: { label: "Start with ANCHOR", href: "/start" },
    confidence: "high",
  },
  {
    id: "human-review",
    title: "Human review remains visible",
    category: "boundary",
    keywords: ["human review", "replace human review", "operational use", "before use"],
    answer:
      "ANCHOR does not replace human review. It is designed so review remains visible before operational use, with governance and accountability layered around AI-assisted workflows.",
    suggestedCta: { label: "Request a walkthrough", href: "/demo" },
    confidence: "high",
  },
  {
    id: "vendor-neutral",
    title: "Vendor-neutral over time",
    category: "overview",
    keywords: ["vendor neutral", "model neutral", "llm neutral", "provider neutral"],
    answer:
      "ANCHOR is designed as governance-first infrastructure rather than a single-model product. That supports a more vendor-neutral direction over time, although exact provider and implementation choices depend on the clinic’s rollout path.",
    suggestedCta: { label: "Request a walkthrough", href: "/demo" },
    confidence: "medium",
  },
  {
    id: "privacy",
    title: "How ANCHOR handles privacy",
    category: "boundary",
    keywords: [
      "privacy",
      "data privacy",
      "pii",
      "privacy posture",
      "how does anchor handle privacy",
      "privacy aware",
      "personally identifiable",
    ],
    answer:
      "ANCHOR is privacy-aware by default. It is metadata-only by default for governed operational accountability, does not normalise raw prompt or output storage, and keeps governance receipts, traceability, and human review visible so accountability stays clear without turning ANCHOR into a content archive.",
    suggestedCta: { label: "Request a walkthrough", href: "/demo" },
    confidence: "high",
  },
  {
    id: "practice-types",
    title: "Practice and clinic-type support",
    category: "commercial",
    keywords: [
      "dog only",
      "cat only",
      "small animal",
      "small animal clinic",
      "mixed practice",
      "referral practice",
      "practice type",
      "clinic type",
      "veterinary practice",
    ],
    answer:
      "ANCHOR is designed for veterinary clinics generally, including small-animal, dog/cat, mixed, referral, and multi-site teams. It governs AI use across these contexts but does not provide clinical advice itself — human review remains visible before any operational use.",
    suggestedCta: { label: "Request a walkthrough", href: "/demo" },
    confidence: "high",
  },
  {
    id: "route-choice",
    title: "Choosing demo, start, or plans",
    category: "commercial",
    keywords: [
      "which route",
      "which path",
      "demo or start",
      "demo or plans",
      "start or plans",
      "route should i",
      "path should i",
      "should i choose",
      "where do i start",
      "what should i pick",
    ],
    answer:
      "Pick /demo for a walkthrough if you want a guided product tour, /start to share clinic context for assisted onboarding, or /plans to compare the Start, Grow, and Group entry paths. If you’re unsure, a walkthrough is usually the safest first step.",
    suggestedCta: { label: "Request a walkthrough", href: "/demo" },
    confidence: "high",
  },
] as const;
