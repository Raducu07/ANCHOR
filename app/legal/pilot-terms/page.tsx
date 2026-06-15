import type { Metadata } from "next";
import { LegalPageShell } from "@/components/legal/LegalPageShell";
import { LegalSections } from "@/components/legal/LegalSections";
import type { LegalSection } from "@/lib/legal/legalContent";
import { getSlice2Page } from "@/lib/legal/legalContent";

const meta = getSlice2Page("pilot-terms");

export const metadata: Metadata = {
  title: `${meta.title} | ANCHOR`,
  description: meta.subtitle,
};

const sections: LegalSection[] = [
  {
    heading: "Status",
    body: [
      "Pilot terms are founder and solicitor controlled. A signed pilot agreement or order form controls. This public page alone does not authorise a pilot.",
    ],
  },
  {
    heading: "Gate",
    body: [
      "No paid pilot or real clinic data is permitted unless a security audit, operational-resilience evidence, and a solicitor-reviewed legal and commercial pack are complete.",
    ],
  },
  {
    heading: "Pilot scope",
    body: [
      "A pilot is a governed, metadata-only evaluation of ANCHOR's governance, trust, learning, and readiness surfaces.",
    ],
  },
  {
    heading: "No clinical decision-making use",
    body: [
      "A pilot does not include diagnostic, prescribing, treatment-planning, or autonomous-triage use, and ANCHOR does not replace veterinary judgement.",
    ],
  },
  {
    heading: "Data boundaries",
    body: [
      "ANCHOR is metadata-only by default. No raw clinical, client, or patient content should be uploaded unless expressly authorised by an agreed product flow and the pilot agreement.",
    ],
  },
  {
    heading: "Support and incident route",
    body: ["A support and incident route is agreed as part of the pilot."],
  },
  {
    heading: "Exit and offboarding",
    body: ["Exit and offboarding follow the approach summarised on the Offboarding page and the pilot agreement."],
  },
  {
    heading: "Feedback and evaluation",
    body: ["A pilot may include feedback and evaluation activities agreed with the clinic."],
  },
  {
    heading: "Controlling documents",
    body: [
      "The signed pilot agreement or order form controls. Nothing on this public page authorises a pilot, onboarding, or the processing of real clinic data on its own.",
    ],
  },
];

export default function PilotTermsPage() {
  return (
    <LegalPageShell
      title={meta.title}
      subtitle={meta.subtitle}
      meta={{ version: meta.version, statusLabel: meta.statusLabel, stage: meta.stage, lastUpdated: meta.lastUpdated }}
    >
      <p className="text-base leading-7 text-slate-700">
        This summary explains how ANCHOR pilots are intended to work. It is a contract-adjacent summary; a signed pilot
        agreement or order form controls.
      </p>
      <LegalSections sections={sections} />
    </LegalPageShell>
  );
}
