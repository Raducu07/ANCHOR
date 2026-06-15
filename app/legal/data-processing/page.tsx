import type { Metadata } from "next";
import { LegalPageShell } from "@/components/legal/LegalPageShell";
import { LegalSections } from "@/components/legal/LegalSections";
import type { LegalSection } from "@/lib/legal/legalContent";
import { getSlice2Page } from "@/lib/legal/legalContent";

const meta = getSlice2Page("data-processing");

export const metadata: Metadata = {
  title: `${meta.title} | ANCHOR`,
  description: meta.subtitle,
};

const sections: LegalSection[] = [
  {
    heading: "Status",
    body: [
      "This is a public summary only. A signed data processing agreement and the customer agreement control over this summary.",
    ],
  },
  {
    heading: "Roles",
    body: [
      "Controller and processor roles are subject to the agreement, the configuration, and the data submitted. A clinic is likely the controller for its clinic-governance data, and ANCHOR is likely the processor for clinic-governance processing where it is configured that way.",
    ],
  },
  {
    heading: "Categories of data",
    body: ["Processing may involve:"],
    bullets: [
      "account and authentication data",
      "staff identifiers and reviewer attribution",
      "governance metadata",
      "learning and CPD metadata",
      "policy and attestation metadata",
      "incident and near-miss metadata",
      "public intake submissions",
      "support communications",
    ],
  },
  {
    heading: "Processing purposes",
    body: ["Processing supports:"],
    bullets: [
      "providing governance and readiness infrastructure",
      "metadata-only governance evidence and receipts",
      "human-review workflows",
      "trust, learning, and readiness surfaces",
      "operating, securing, and supporting the service",
    ],
  },
  {
    heading: "Subprocessors",
    body: [
      "Subprocessors are summarised on the Subprocessors page. Their use is controlled by the data processing agreement.",
    ],
  },
  {
    heading: "International transfers and regions",
    body: [
      "International-transfer and hosting-region positions are not asserted here unless confirmed, and are addressed in the data processing agreement.",
    ],
  },
  {
    heading: "Retention and deletion",
    body: [
      "Retention and deletion are summarised on the Data Retention and Offboarding pages and are subject to the agreement.",
    ],
  },
  {
    heading: "Data subject assistance",
    body: [
      "Where applicable, ANCHOR can assist the clinic, as controller, in responding to data-subject requests.",
    ],
  },
  {
    heading: "Incident and breach assistance",
    body: ["Where applicable, ANCHOR can assist the clinic with incident and breach handling, as set out in the agreement."],
  },
  {
    heading: "Audit and information rights",
    body: [
      "Audit and information rights are summarised here and are addressed in detail in the data processing agreement.",
    ],
  },
  {
    heading: "Not legal advice",
    body: ["This is a public summary and is not legal advice. The signed documents control."],
  },
];

export default function DataProcessingPage() {
  return (
    <LegalPageShell
      title={meta.title}
      subtitle={meta.subtitle}
      meta={{ version: meta.version, statusLabel: meta.statusLabel, stage: meta.stage, lastUpdated: meta.lastUpdated }}
    >
      <p className="text-base leading-7 text-slate-700">
        This summary describes how ANCHOR processes data on behalf of clinics. It is a contract-adjacent summary; the
        signed data processing agreement and customer agreement control.
      </p>
      <LegalSections sections={sections} />
    </LegalPageShell>
  );
}
