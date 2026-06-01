// lib/assistantLearnGuidance.tsx
//
// Why-flagged -> Learn linkage (frontend-only, static mapping v1).
//
// Doctrine:
//   * Educational guidance only. Not clinical advice.
//   * Clicking a link is navigation-only. It must NOT call POST
//     /v1/learn/completions or otherwise record CPD activity.
//   * Learn guidance must not be presented as proof of professional
//     competence, certified or accredited CPD, approval by the RCVS, a
//     clinical-safety guarantee, or a regulatory outcome.
//   * Human review of AI-assisted work remains required.
//
// Implementation note:
//   The specific strings inside Assistant `refusal_reason_codes[]` and
//   `safety_flags[]` are treated as opaque on the frontend (no enum is
//   shared by lib/types.ts). Mapping uses conservative substring keyword
//   matching against a small known cue set and a generic fallback. New
//   backend codes therefore fall through to the generic "ethical and
//   safe AI use" / governance fallback rather than misclassifying.
//   When the backend later provides a real `learn_links` field on the
//   run/receipt response, this helper can be replaced by passing those
//   through directly.

import Link from "next/link";

export type AssistantLearnBadge =
  | "PII"
  | "Refusal"
  | "Safety flag"
  | "Output blocked"
  | "Mode"
  | "Governance"
  | "Explainer";

export type AssistantLearnLink = {
  key: string;
  title: string;
  description: string;
  href: string;
  badge: AssistantLearnBadge;
  priority: number;
};

export type AssistantLearnSignals = {
  pii_detected?: boolean;
  pii_types?: string[];
  safety_flags?: string[];
  refusal_reason_codes?: string[];
  run_status?: string | null;
  review_status?: string | null;
  mode?: string | null;
};

// Destinations confirmed to exist by the M6 / Phase 2A polish audit.
// Centralised so a future module re-version is a one-stop change.
const HREF = {
  privacyCard: "/learn/cards/privacy-safe-ai-use",
  confidentialityModule: "/learn/confidentiality-and-ai-v1",
  ethicalUseModule: "/learn/ethical-and-safe-ai-use-v1",
  biasDetectionModule: "/learn/bias-detection-in-ai-outputs-v1",
  explainingToClientsModule: "/learn/explaining-ai-to-clients-v1",
  governanceCard: "/learn/cards/governance-basics",
  explainersPage: "/learn/explainers",
} as const;

const CLINICAL_BOUNDARY_KEYWORDS = [
  "diagnos",
  "prescrib",
  "treatment",
  "triage",
  "dosing",
];
const BIAS_KEYWORDS = [
  "bias",
  "mislead",
  "unsupported",
  "inaccurate",
  "hallucinat",
];

function lower(values: string[] | undefined): string[] {
  return (values ?? []).map((v) => (typeof v === "string" ? v.toLowerCase() : ""));
}

function anyContains(values: string[], needles: string[]): boolean {
  return values.some((v) => needles.some((n) => v.includes(n)));
}

// Priority ordering (lower number = higher priority). Used to keep the
// most pertinent links when capping to 3.
const PRIORITY = {
  pii: 10,
  refusalClinical: 20,
  safetyClinical: 25,
  bias: 30,
  outputBlocked: 35,
  refusalGeneric: 40,
  mode: 60,
  governance: 70,
  explainers: 80,
} as const;

export function getAssistantLearnLinks(
  signals: AssistantLearnSignals,
): AssistantLearnLink[] {
  const refusalCodes = lower(signals.refusal_reason_codes);
  const safetyFlags = lower(signals.safety_flags);
  const runStatus = (signals.run_status ?? "").toLowerCase();
  const mode = (signals.mode ?? "").toLowerCase();

  const hasPii =
    signals.pii_detected === true ||
    (Array.isArray(signals.pii_types) && signals.pii_types.length > 0);

  const refusalHasClinical = anyContains(refusalCodes, CLINICAL_BOUNDARY_KEYWORDS);
  const safetyHasClinical = anyContains(safetyFlags, CLINICAL_BOUNDARY_KEYWORDS);
  const flagsHaveBias =
    anyContains(refusalCodes, BIAS_KEYWORDS) ||
    anyContains(safetyFlags, BIAS_KEYWORDS);

  const isOutputBlocked = runStatus === "output_blocked";
  const isRefused = runStatus === "generation_refused";

  const anySignalPresent =
    hasPii ||
    refusalCodes.length > 0 ||
    safetyFlags.length > 0 ||
    isOutputBlocked ||
    isRefused;

  const links: AssistantLearnLink[] = [];

  if (hasPii) {
    links.push({
      key: "pii-card",
      title: "Privacy-safe AI use",
      description:
        "Short card on reducing identifiable detail in AI-assisted workflows.",
      href: HREF.privacyCard,
      badge: "PII",
      priority: PRIORITY.pii,
    });
    links.push({
      key: "pii-module",
      title: "Confidentiality and data protection when using AI",
      description:
        "Deeper module on confidentiality expectations when using AI tools.",
      href: HREF.confidentialityModule,
      badge: "PII",
      priority: PRIORITY.pii + 1,
    });
  }

  if (refusalHasClinical) {
    links.push({
      key: "ethical-from-refusal",
      title: "Ethical and safe AI use in clinical workflows",
      description:
        "Why ANCHOR will not provide diagnosis, prescribing, dosing, or triage decisions.",
      href: HREF.ethicalUseModule,
      badge: "Refusal",
      priority: PRIORITY.refusalClinical,
    });
  } else if (safetyHasClinical) {
    links.push({
      key: "ethical-from-safety",
      title: "Ethical and safe AI use in clinical workflows",
      description:
        "How ANCHOR keeps clinical-decision requests outside automated handling.",
      href: HREF.ethicalUseModule,
      badge: "Safety flag",
      priority: PRIORITY.safetyClinical,
    });
  }

  if (flagsHaveBias) {
    links.push({
      key: "bias-module",
      title: "Recognising biased, inaccurate, or misleading AI outputs",
      description:
        "Helps your team spot unsupported or biased material in AI output.",
      href: HREF.biasDetectionModule,
      badge: "Safety flag",
      priority: PRIORITY.bias,
    });
  }

  if (isOutputBlocked) {
    links.push({
      key: "blocked-ethical",
      title: "Ethical and safe AI use in clinical workflows",
      description:
        "Context on why ANCHOR blocks certain outputs before they reach the user.",
      href: HREF.ethicalUseModule,
      badge: "Output blocked",
      priority: PRIORITY.outputBlocked,
    });
  }

  if (isRefused) {
    links.push({
      key: "refused-ethical",
      title: "Ethical and safe AI use in clinical workflows",
      description:
        "Background on the safety boundaries ANCHOR enforces on refusals.",
      href: HREF.ethicalUseModule,
      badge: "Refusal",
      priority: PRIORITY.refusalGeneric,
    });
  }

  if (anySignalPresent && mode === "client_communication") {
    links.push({
      key: "mode-client-communication",
      title: "Explaining AI use to pet owners",
      description:
        "Module on talking to clients about AI-assisted communications.",
      href: HREF.explainingToClientsModule,
      badge: "Mode",
      priority: PRIORITY.mode,
    });
  }

  // Generic governance fallback only if a signal was present but nothing
  // else matched yet.
  if (anySignalPresent && links.length === 0) {
    links.push({
      key: "governance-card",
      title: "Governance basics",
      description:
        "What ANCHOR receipts, flags, and metadata-only governance mean.",
      href: HREF.governanceCard,
      badge: "Governance",
      priority: PRIORITY.governance,
    });
  }

  // Explainer page as a low-priority fallback when there's room.
  if (anySignalPresent && links.length < 3) {
    links.push({
      key: "explainers",
      title: "Why was this flagged?",
      description: "Plain-language explainers for common governance signals.",
      href: HREF.explainersPage,
      badge: "Explainer",
      priority: PRIORITY.explainers,
    });
  }

  // Dedupe by href (keep first occurrence at lowest priority position).
  const seen = new Set<string>();
  const deduped: AssistantLearnLink[] = [];
  for (const link of links) {
    if (seen.has(link.href)) continue;
    seen.add(link.href);
    deduped.push(link);
  }

  // Stable sort by priority then by original index (preserved because
  // sort is stable in modern JS engines).
  deduped.sort((a, b) => a.priority - b.priority);

  return deduped.slice(0, 3);
}

// ---------------------------------------------------------------------
// Render component
// ---------------------------------------------------------------------

const BADGE_TONE: Record<AssistantLearnBadge, string> = {
  PII: "border-amber-200 bg-amber-50 text-amber-700",
  Refusal: "border-rose-200 bg-rose-50 text-rose-700",
  "Safety flag": "border-amber-200 bg-amber-50 text-amber-700",
  "Output blocked": "border-rose-200 bg-rose-50 text-rose-700",
  Mode: "border-slate-200 bg-white text-slate-600",
  Governance: "border-slate-200 bg-white text-slate-600",
  Explainer: "border-slate-200 bg-white text-slate-600",
};

export function RelevantLearnGuidance({
  links,
}: {
  links: AssistantLearnLink[];
}) {
  if (!links || links.length === 0) return null;

  return (
    <div className="mt-4 rounded-xl border border-slate-200 bg-white p-4">
      <p className="text-sm font-semibold text-slate-900">
        Relevant Learn guidance
      </p>
      <p className="mt-1 text-xs leading-5 text-slate-600">
        These links may help your team understand the governance signal. Human
        review remains required.
      </p>

      <ul className="mt-3 space-y-2">
        {links.map((link) => (
          <li
            key={link.key}
            className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2"
          >
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={[
                  "inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
                  BADGE_TONE[link.badge],
                ].join(" ")}
              >
                {link.badge}
              </span>
              <Link
                href={link.href}
                className="text-sm font-semibold text-slate-900 underline underline-offset-4 hover:text-slate-700"
              >
                {link.title}
              </Link>
            </div>
            <p className="mt-1 text-xs leading-5 text-slate-600">
              {link.description}
            </p>
          </li>
        ))}
      </ul>

      <p className="mt-3 text-[11px] leading-5 text-slate-500">
        Educational guidance only. Not clinical advice. Opening a link does not
        complete a Learn module or record CPD activity.
      </p>
    </div>
  );
}
