import type { Metadata } from "next";
import { LegalPageShell } from "@/components/legal/LegalPageShell";
import { LegalSections } from "@/components/legal/LegalSections";
import type { LegalSection } from "@/lib/legal/legalContent";
import { getSlice2Page } from "@/lib/legal/legalContent";

const meta = getSlice2Page("ai-providers");

export const metadata: Metadata = {
  title: `${meta.title} | ANCHOR`,
  description: meta.subtitle,
};

const sections: LegalSection[] = [
  {
    heading: "Current posture",
    body: [
      "The current live Workspace generation path has been built against Anthropic, but it remains production-off unless explicitly enabled. ANCHOR is presented as deterministic governed generation today.",
    ],
  },
  {
    heading: "ANCHOR is not a GPAI model provider",
    body: [
      "ANCHOR is not a provider of a general-purpose AI model. It is governance infrastructure around the AI tools that clinics use.",
    ],
  },
  {
    heading: "Training of AI models",
    body: [
      "ANCHOR does not use customer governance records, learning records, Trust Pack materials, clinic metadata, or account data to train public general-purpose AI models.",
    ],
  },
  {
    heading: "Raw content",
    body: [
      "No raw clinical, client, or patient content is processed by default. Such content should not be submitted unless an authorised product flow and a corresponding agreement permit it.",
    ],
  },
  {
    heading: "Vendor-neutrality posture",
    body: [
      "ANCHOR is architected for vendor-neutrality and is vendor-neutral over time. This is an architectural and future posture, not present-state operation of multiple providers; present-tense vendor-neutrality is not claimed while a single provider is wired.",
    ],
  },
  {
    heading: "Provider routing",
    body: [
      "Any AI-provider routing occurs only under authorised flows and once the relevant legal and subprocessor documentation is in place. Anthropic becomes a subprocessor only when live generation is enabled.",
    ],
  },
  {
    heading: "What this page does not claim",
    body: [
      "This page does not claim that no AI provider ever sees data. The accurate position is that live generation is production-off by default and that provider involvement is governed by the relevant agreements when it is enabled.",
    ],
  },
];

export default function AiProvidersPage() {
  return (
    <LegalPageShell
      title={meta.title}
      subtitle={meta.subtitle}
      meta={{ version: meta.version, statusLabel: meta.statusLabel, stage: meta.stage, lastUpdated: meta.lastUpdated }}
    >
      <p className="text-base leading-7 text-slate-700">
        This summary explains how ANCHOR works with AI providers and what that means for data. It is a founder-approved
        public summary, not legal advice.
      </p>
      <LegalSections sections={sections} />
    </LegalPageShell>
  );
}
