import type { Metadata } from "next";
import { LegalPageShell } from "@/components/legal/LegalPageShell";
import { LegalSections } from "@/components/legal/LegalSections";
import type { LegalSection } from "@/lib/legal/legalContent";
import { getSlice2Page } from "@/lib/legal/legalContent";

const meta = getSlice2Page("trust-ai-governance");

export const metadata: Metadata = {
  title: `${meta.title} | ANCHOR`,
  description: meta.subtitle,
};

const sections: LegalSection[] = [
  {
    heading: "What ANCHOR governs",
    body: [
      "ANCHOR governs workflows around AI use. It is not diagnostic, prescribing, or treatment-planning AI, and it does not perform autonomous triage.",
    ],
  },
  {
    heading: "Human review",
    body: [
      "Human review is visible and required. AI-supported outputs remain subject to professional judgement before operational use.",
    ],
  },
  {
    heading: "Governance receipts",
    body: [
      "Governed activity is explainable through governance receipts, which are metadata governance evidence. They do not prove clinical correctness, patient safety, professional competence, or regulatory compliance.",
    ],
  },
  {
    heading: "Governance surfaces",
    body: ["ANCHOR brings together governance surfaces, including:"],
    bullets: [
      "Trust Pack and readiness evidence",
      "RCVS-themed self-assessment",
      "ANCHOR Learn",
      "client transparency",
      "incident and near-miss governance metadata",
    ],
  },
  {
    heading: "AI literacy",
    body: [
      "Learning activity is described as CPD-recordable AI literacy activity. It is not RCVS-accredited CPD unless a formal accreditation has actually been achieved.",
    ],
  },
  {
    heading: "EU AI Act readiness",
    body: [
      "Where the EU AI Act is referenced, Article 4 is treated only as an AI-literacy readiness theme, subject to legal review and an amendment watch. UK applicability depends on EU nexus and legal analysis and is not assumed.",
    ],
  },
  {
    heading: "No compliance guarantee",
    body: [
      "ANCHOR helps clinics evidence responsible AI governance practices aligned with emerging professional expectations. It does not make a clinic compliant with any law or professional standard.",
    ],
  },
];

export default function TrustCenterAiGovernancePage() {
  return (
    <LegalPageShell
      title={meta.title}
      subtitle={meta.subtitle}
      backHref="/trust-center"
      backLabel="Back to Trust Centre"
      meta={{ version: meta.version, statusLabel: meta.statusLabel, stage: meta.stage, lastUpdated: meta.lastUpdated }}
    >
      <p className="text-base leading-7 text-slate-700">
        This overview summarises how ANCHOR governs AI use for buyer and procurement review. It is a summary and is not
        a compliance or certification claim.
      </p>
      <LegalSections sections={sections} />
    </LegalPageShell>
  );
}
