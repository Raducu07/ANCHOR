import type { Metadata } from "next";
import { LegalPageShell } from "@/components/legal/LegalPageShell";
import { LegalSections } from "@/components/legal/LegalSections";
import type { LegalSection } from "@/lib/legal/legalContent";
import { getSlice2Page } from "@/lib/legal/legalContent";

const meta = getSlice2Page("toms");

export const metadata: Metadata = {
  title: `${meta.title} | ANCHOR`,
  description: meta.subtitle,
};

const sections: LegalSection[] = [
  {
    heading: "Access control",
    body: ["Access to ANCHOR functions is controlled and role-aware, with administrative functions gated accordingly."],
  },
  {
    heading: "Authentication",
    body: ["Clinic and administrator users authenticate before accessing clinic-scoped surfaces."],
  },
  {
    heading: "Tenant isolation",
    body: ["Clinic data is separated by tenant, with request-scoped tenant context applied to access."],
  },
  {
    heading: "Row-level security (RLS) and FORCE RLS",
    body: ["Multi-tenant separation uses row-level security, including FORCE RLS, as part of the isolation model."],
  },
  {
    heading: "Audit logging",
    body: ["Administrative actions are recorded through audit logging and admin audit events for reviewability."],
  },
  {
    heading: "Metadata-only storage discipline",
    body: ["Storage is metadata-only by default; raw prompt and output content are not stored in the current doctrine."],
  },
  {
    heading: "Backup and restore",
    body: [
      "Backup and tested-restore practices are being prepared as part of the operational-resilience gate. They are operational practices, not guarantees.",
    ],
  },
  {
    heading: "Retention and deletion",
    body: [
      "Retention and deletion are summarised on the Data Retention and Offboarding pages and are subject to the agreement and data processing agreement.",
    ],
  },
  {
    heading: "Incident response",
    body: ["An incident-response posture, including a breach and incident-response runbook, is part of the same gate."],
  },
  {
    heading: "Dependency and vulnerability management",
    body: ["Dependency and vulnerability (CVE) review forms part of the security-audit posture."],
  },
  {
    heading: "Secure development and change management",
    body: ["Changes are managed through version control and review, supporting secure-development and change-management practices."],
  },
  {
    heading: "Subprocessor management",
    body: [
      "Subprocessors are summarised on the Subprocessors page. The signed data processing agreement and customer agreement control subprocessor use.",
    ],
  },
  {
    heading: "Operational resilience and business continuity",
    body: [
      "Operational-resilience and business-continuity practices are part of the release-candidate gate before paid pilots or real clinic data.",
    ],
  },
  {
    heading: "Personnel, founder, and operator access",
    body: [
      "Operator access is limited to what is needed to run and support the platform. Founder and operator access follows the same metadata-only discipline.",
    ],
  },
  {
    heading: "What this page is not",
    body: [
      "This is a contract-adjacent summary only. It is not a SOC 2 report, an ISO certification, a penetration-test report, or a security guarantee. The agreement and any data processing agreement control the final contractual technical and organisational measures.",
    ],
  },
];

export default function TomsPage() {
  return (
    <LegalPageShell
      title={meta.title}
      subtitle={meta.subtitle}
      meta={{ version: meta.version, statusLabel: meta.statusLabel, stage: meta.stage, lastUpdated: meta.lastUpdated }}
    >
      <p className="text-base leading-7 text-slate-700">
        This summary describes ANCHOR&apos;s technical and organisational measures at a high level for review. It is a
        contract-adjacent summary; the signed agreement and any data processing agreement control.
      </p>
      <LegalSections sections={sections} />
    </LegalPageShell>
  );
}
