import type { Metadata } from "next";
import { LegalPageShell } from "@/components/legal/LegalPageShell";
import { LegalSections } from "@/components/legal/LegalSections";
import type { LegalSection } from "@/lib/legal/legalContent";
import { getSlice2Page } from "@/lib/legal/legalContent";

const meta = getSlice2Page("trust-privacy");

export const metadata: Metadata = {
  title: `${meta.title} | ANCHOR`,
  description: meta.subtitle,
};

const sections: LegalSection[] = [
  {
    heading: "Overview",
    body: [
      "ANCHOR is metadata-only by default. This page summarises its privacy posture for procurement review and points to the controlling documents.",
    ],
  },
  {
    heading: "Metadata can still be personal data",
    body: [
      "Metadata-only does not mean no personal data is involved. Some governance metadata may still relate to identifiable individuals.",
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
    heading: "Clinic responsibilities",
    body: [
      "Clinics remain responsible for their lawful basis for processing, for providing a privacy notice to data subjects, and for managing staff access.",
    ],
  },
  {
    heading: "Controlling documents",
    body: [
      "A data processing agreement, the public Privacy Notice, and the legal pages may control. Final controller and processor positions are subject to the agreement and to solicitor review. International-transfer and hosting-region positions are not asserted here and are addressed in the data-processing and subprocessor documentation.",
    ],
  },
];

export default function TrustCenterPrivacyPage() {
  return (
    <LegalPageShell
      title={meta.title}
      subtitle={meta.subtitle}
      backHref="/trust-center"
      backLabel="Back to Trust Centre"
      meta={{ version: meta.version, statusLabel: meta.statusLabel, stage: meta.stage, lastUpdated: meta.lastUpdated }}
    >
      <p className="text-base leading-7 text-slate-700">
        This overview summarises how ANCHOR approaches privacy for buyer and procurement review. It is a summary and is
        not a final privacy notice or legal advice.
      </p>
      <LegalSections sections={sections} />
    </LegalPageShell>
  );
}
