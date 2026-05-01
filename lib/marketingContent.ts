export const homepageWhyItems = [
  {
    title: "Privacy-sensitive details need careful handling",
    text: "Ensure sensitive clinical and client data is detected and managed before reaching AI models.",
  },
  {
    title: "Human review should stay visible before operational use",
    text: "Establish mandatory human review checkpoints before AI outputs are used operationally.",
  },
  {
    title: "Leadership needs oversight without normalising raw-content storage",
    text: "Rely on receipt-backed traceability to maintain a record of safe use without storing raw operational material.",
  },
  {
    title: "Safe adoption depends on practical workflows, not vague policy",
    text: "Provide clinic leaders and practice managers with leadership visibility into AI usage through governed workflows.",
  },
] as const;

export const homepageWorkflowSteps = [
  {
    step: "01",
    title: "Define the workflow",
    text: "Staff select the task, add source material, and set the instruction inside a clinic-scoped governed workflow.",
    image: "/anchor-public/workspace-review-settings.png",
    alt: "Workspace review settings for a governed workflow",
    reverse: false,
    crop: "object-top",
  },
  {
    step: "02",
    title: "Generate the governed result",
    text: "ANCHOR produces a governed output with privacy-aware handling, operational context, and receipt-backed accountability.",
    image: "/anchor-public/workspace-receipt-preview.png",
    alt: "Workspace receipt preview and governed output actions",
    reverse: true,
    crop: "object-top",
  },
  {
    step: "03",
    title: "Keep accountability visible",
    text: "Receipts, traceability, trust surfaces, and learning cues remain available without turning the product into a raw-content archive.",
    image: "/anchor-public/receipts-loaded-receipt.png",
    alt: "Receipts view showing request-level accountability",
    reverse: false,
    crop: "object-top",
  },
] as const;

export const homepagePlatformCards = [
  {
    title: "Dashboard",
    text: "View leadership-facing governance posture, activity, learning signals, and operational next steps.",
    image: "/anchor-public/dashboard-overview.png",
    alt: "Dashboard overview showing operational governance metrics",
  },
  {
    title: "Receipts",
    text: "Inspect request-level accountability, policy traceability, and metadata-backed governance evidence.",
    image: "/anchor-public/receipts-loaded-receipt.png",
    alt: "Receipts page showing governance receipt details",
  },
  {
    title: "Governance Events",
    text: "Review recent clinic-scoped activity, identify friction patterns, and move directly into follow-up surfaces.",
    image: "/anchor-public/governance-events-overview.png",
    alt: "Governance Events page overview",
  },
  {
    title: "Learn",
    text: "Turn governance signals into practical staff guidance for safer day-to-day AI use.",
    image: "/anchor-public/learn-overview.png",
    alt: "Learn surface overview",
  },
  {
    title: "Trust",
    text: "Package trust posture, communication boundaries, and exportable leadership-facing artifacts.",
    image: "/anchor-public/trust-center-overview.png",
    alt: "Trust Center overview",
  },
  {
    title: "Intelligence",
    text: "Surface governance hotspots, recurring patterns, and recommended next actions from metadata signals.",
    image: "/anchor-public/dashboard-receipts-learning-actions.png",
    alt: "Dashboard learning and intelligence actions surface",
  },
] as const;

export const trustStripItems = [
  "Metadata-only accountability by default",
  "Receipt-backed review",
  "Policy traceability at request level",
  "Human review before operational use",
  "Clinic-scoped trust surfaces",
] as const;

export const homepageBoundaryCards = [
  {
    title: "Not clinical decision-making AI",
    text: "ANCHOR governs workflows around AI use in veterinary clinics. It does not replace professional clinical judgment.",
  },
  {
    title: "Not a raw-content archive",
    text: "ANCHOR is built around metadata-only accountability by default rather than normalising broad prompt and output retention.",
  },
  {
    title: "Not a replacement for human review",
    text: "Staff remain responsible for checking appropriateness, context, and operational use before acting on AI-assisted outputs.",
  },
] as const;

export const demoWhatWeWillShow = [
  "The governed workflow",
  "Receipt-backed accountability",
  "Trust, learning, and intelligence surfaces",
  "How clinics get started",
] as const;

export const demoAudience = [
  "Practice managers",
  "Clinic owners",
  "Clinical directors",
  "Operations leads",
  "Teams already using AI informally",
  "Multi-site groups preparing for more consistent AI use",
] as const;

export const demoReasons = [
  "AI use is already happening informally",
  "Privacy-sensitive details need better handling",
  "Leadership wants visibility without normalising raw-content retention",
  "They need a workflow, not just policy",
] as const;

export const planCards = [
  {
    name: "Start",
    audience: "For clinics beginning governed AI use",
    features: [
      "Governed workflow access",
      "Request-level receipts",
      "Metadata-only accountability by default",
      "Core dashboard visibility",
      "Basic trust and review surfaces",
    ],
  },
  {
    name: "Grow",
    audience: "For clinics operationalising AI more consistently",
    features: [
      "Everything in Start",
      "Expanded governance visibility",
      "Learn and guidance surfaces",
      "Intelligence recommendations",
      "Stronger operational review flow",
    ],
  },
  {
    name: "Group",
    audience: "For larger clinics or multi-site rollout",
    features: [
      "Everything in Grow",
      "Multi-site rollout discussion",
      "Assisted onboarding",
      "Higher-touch setup path",
      "Commercial and implementation discussion",
    ],
  },
] as const;

export const planChoiceGuidance = [
  {
    title: "Start when governed AI use is just beginning",
    text: "Choose Start if the clinic needs one calm path into governed workflows, request-level receipts, and the core visibility surfaces.",
  },
  {
    title: "Grow when AI use is becoming operational",
    text: "Choose Grow when governance review, staff guidance, and intelligence recommendations need to support more consistent day-to-day use.",
  },
  {
    title: "Group when rollout needs coordination",
    text: "Choose Group when a larger clinic or multi-site organisation needs a higher-touch onboarding and implementation discussion.",
  },
] as const;

export const productDoctrineItems = [
  "Governance-first workflow support",
  "Metadata-only accountability by default",
  "Human review before operational use",
  "Clinic-scoped accountability surfaces",
  "Clear separation from clinical decision-making AI",
] as const;

export const onboardingOverviewSteps = [
  "Clinic details",
  "First admin",
  "Plan selection",
  "Billing",
  "Confirmation",
  "First-use setup",
] as const;

export const plansFaqs = [
  {
    question: "Does ANCHOR include clinical decision-making AI?",
    answer:
      "No. ANCHOR is governance, trust, learning, and intelligence infrastructure around AI use in veterinary clinics. It is not a clinical decision-making system.",
  },
  {
    question: "Does ANCHOR store raw prompts and outputs by default?",
    answer:
      "No. ANCHOR preserves metadata-only accountability by default so clinics can keep review and traceability visible without normalising raw-content retention.",
  },
  {
    question: "Can a clinic begin with a smaller rollout and expand later?",
    answer:
      "Yes. Start is designed for clinics beginning governed AI use, with Grow and Group providing a clearer path into broader operational rollout.",
  },
  {
    question: "Can we request a walkthrough before deciding how to start?",
    answer:
      "Yes. The walkthrough route is there to help clinics understand the governed workflow, trust surfaces, and onboarding path before moving into setup.",
  },
  {
    question: "Is billing live on this page today?",
    answer:
      "Not yet. The plans page explains commercial entry clearly, while live billing and onboarding wiring can be connected later without changing the starting flow.",
  },
] as const;

export const demoRoleOptions = [
  "Practice manager",
  "Clinic owner",
  "Clinical director",
  "Operations lead",
  "Veterinary surgeon",
  "Practice administrator",
  "Technology / digital lead",
  "Other",
] as const;

export const demoCurrentAiUseOptions = [
  "No current AI use yet",
  "Small informal use across a few staff",
  "Regular drafting and summarisation use",
  "Clinic-wide experimentation",
  "Multi-site or coordinated operational use",
] as const;

export const demoPrimaryInterestOptions = [
  "Governed workflow",
  "Receipt-backed accountability",
  "Trust surfaces",
  "Learning and staff guidance",
  "Operational intelligence",
  "Commercial rollout discussion",
] as const;

export const demoBiggestConcernOptions = [
  "Privacy-sensitive details",
  "Leadership visibility",
  "Lack of workflow consistency",
  "Human review discipline",
  "Trust and external communication",
  "Scaling AI use safely",
] as const;

export const demoClinicSizeOptions = [
  "1 site",
  "2-5 sites",
  "6-10 sites",
  "11+ sites",
] as const;

export const startPreferredPlanOptions = [
  "Start",
  "Grow",
  "Group",
  "Not sure yet",
] as const;

export const startClinicSizeOptions = [
  "1 site",
  "2-5 sites",
  "6-10 sites",
  "11+ sites",
] as const;

export const startCurrentAiUseOptions = [
  "Not using AI yet",
  "Exploring informally",
  "Used by a few staff",
  "Already part of workflows",
] as const;

export const startRolloutTimingOptions = [
  "As soon as possible",
  "This month",
  "Next 1–3 months",
  "Just exploring for now",
] as const;
