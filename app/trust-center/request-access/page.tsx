import type { Metadata } from "next";
import { LegalPageShell } from "@/components/legal/LegalPageShell";
import { LegalSections } from "@/components/legal/LegalSections";
import type { LegalSection } from "@/lib/legal/legalContent";
import { getSlice2Page } from "@/lib/legal/legalContent";

const meta = getSlice2Page("trust-request-access");

export const metadata: Metadata = {
  title: `${meta.title} | ANCHOR`,
  description: meta.subtitle,
};

const sections: LegalSection[] = [
  {
    heading: "How to request materials",
    body: [
      "Procurement, security, and legal review materials may be requested through a founder-approved commercial or onboarding route.",
    ],
  },
  {
    heading: "No live form in this view",
    body: [
      "There is no live request form in this view, and no data is submitted on this page. It is static guidance only.",
    ],
  },
  {
    heading: "Do not upload data here",
    body: [
      "Do not upload clinic, client, or patient data on this page or as part of an access request. ANCHOR is metadata-only by default and does not expect raw clinical content.",
    ],
  },
  {
    heading: "Request route and contact",
    body: [
      "Procurement, security, and legal review material requests may be sent to procurement@anchorvet.co.uk. For general enquiries you can also use hello@anchorvet.co.uk. These mailboxes forward to and are monitored by the founder; they are contact routes, not separate teams, a support desk, or an SLA. Please do not include clinic, client, patient, or other unnecessary personal data in a request.",
    ],
  },
  {
    heading: "Not an authorisation",
    body: [
      "Requesting materials is not authorisation to start a paid pilot, onboard a real clinic, or submit real clinic data. Those steps require a completed security audit, operational-resilience evidence, and a solicitor-reviewed legal and commercial pack.",
    ],
  },
];

export default function TrustCenterRequestAccessPage() {
  return (
    <LegalPageShell
      title={meta.title}
      subtitle={meta.subtitle}
      backHref="/trust-center"
      backLabel="Back to Trust Centre"
      meta={{ version: meta.version, statusLabel: meta.statusLabel, stage: meta.stage, lastUpdated: meta.lastUpdated }}
    >
      <p className="text-base leading-7 text-slate-700">
        This page explains how to request ANCHOR&apos;s procurement, security, and legal review materials. It is static
        guidance and does not collect any data.
      </p>
      <LegalSections sections={sections} />
    </LegalPageShell>
  );
}
