import type { Metadata } from "next";
import { LegalPageShell } from "@/components/legal/LegalPageShell";
import { LegalSections } from "@/components/legal/LegalSections";
import type { LegalSection } from "@/lib/legal/legalContent";
import { getSlice2Page } from "@/lib/legal/legalContent";

const meta = getSlice2Page("trust-security");

export const metadata: Metadata = {
  title: `${meta.title} | ANCHOR`,
  description: meta.subtitle,
};

const sections: LegalSection[] = [
  {
    heading: "Scope of this page",
    body: [
      "This is a high-level, procurement-friendly summary of ANCHOR's security posture. It is not a security certification and does not constitute a guarantee.",
    ],
  },
  {
    heading: "Authentication and access control",
    bullets: [
      "Authentication for clinic and administrator users.",
      "Role-aware access control for administrative functions.",
      "Clinic-scoped access so views remain limited to a single tenant.",
    ],
  },
  {
    heading: "Tenant isolation",
    body: [
      "ANCHOR uses multi-tenant separation with row-level security (RLS), including FORCE RLS, and request-scoped tenant context as part of its isolation model.",
    ],
  },
  {
    heading: "Audit logging",
    body: [
      "Administrative actions are recorded through audit logging and admin audit events, supporting reviewable accountability.",
    ],
  },
  {
    heading: "Metadata-only storage discipline",
    body: [
      "Storage is metadata-only by default. Raw prompt and output content are not stored in the current product doctrine.",
    ],
  },
  {
    heading: "Dependency and vulnerability management",
    body: [
      "Dependency and vulnerability (CVE) review is part of the security-audit posture. The formal security audit is a mandatory release-candidate gate before paid pilots or real clinic data.",
    ],
  },
  {
    heading: "Backup, restore, and operational resilience",
    body: [
      "Backup, restore, and operational-resilience practices, including tested restore, are being prepared as part of the same release-candidate gate. These are operational practices, not guarantees.",
    ],
  },
  {
    heading: "Incident response",
    body: [
      "An incident-response posture, including a breach and incident-response runbook, is part of the operational-resilience gate.",
    ],
  },
  {
    heading: "Secure development and change management",
    body: [
      "Changes are managed through version control and review. Secure-development and change-management practices form part of the operating posture.",
    ],
  },
  {
    heading: "What this page does not claim",
    body: [
      "This page does not claim SOC 2, ISO, or penetration-test certification unless such a certification is actually held, and it does not claim that the platform is breach-proof or secure by guarantee. Specific encryption and hosting-region details are confirmed in the security and legal documentation and any data processing agreement.",
    ],
  },
];

export default function TrustCenterSecurityPage() {
  return (
    <LegalPageShell
      title={meta.title}
      subtitle={meta.subtitle}
      backHref="/trust-center"
      backLabel="Back to Trust Centre"
      meta={{ version: meta.version, statusLabel: meta.statusLabel, stage: meta.stage, lastUpdated: meta.lastUpdated }}
    >
      <p className="text-base leading-7 text-slate-700">
        This overview summarises how ANCHOR approaches security for buyer and procurement review. It is a summary, not a
        certification or guarantee.
      </p>
      <LegalSections sections={sections} />
    </LegalPageShell>
  );
}
