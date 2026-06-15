import type { Metadata } from "next";
import { LegalPageShell } from "@/components/legal/LegalPageShell";
import { LegalSections } from "@/components/legal/LegalSections";
import type { LegalSection } from "@/lib/legal/legalContent";
import { getSlice2Page } from "@/lib/legal/legalContent";

const meta = getSlice2Page("cookies");

export const metadata: Metadata = {
  title: `${meta.title} | ANCHOR`,
  description: meta.subtitle,
};

const sections: LegalSection[] = [
  {
    heading: "Current posture",
    body: [
      "This notice reflects a review of the current ANCHOR frontend. It describes the cookie and storage posture observed at the time of writing and is subject to deployment and provider confirmation.",
    ],
  },
  {
    heading: "Strictly necessary cookies",
    body: [
      "Strictly necessary cookies may be used where required for core functionality. The internal operator and administrator area uses a session cookie, and a short-lived flash cookie, for sign-in. These are operational, not marketing.",
    ],
  },
  {
    heading: "Authentication and session",
    body: [
      "In the current frontend, the clinic portal holds its session token in browser local storage rather than in cookies. Local storage is used to keep a signed-in session and is not used for marketing.",
    ],
  },
  {
    heading: "Analytics and marketing cookies",
    body: [
      "No marketing or analytics cookies were identified in this frontend review, subject to deployment and provider confirmation.",
    ],
  },
  {
    heading: "Preferences and change route",
    body: [
      "A cookie-preference or change route can be added here if and when cookie-based analytics or similar features are introduced.",
    ],
  },
  {
    heading: "Status",
    body: [
      "This is not a final cookie policy unless it has been solicitor-reviewed. It will be updated if the cookie or analytics posture changes.",
    ],
  },
];

export default function CookiesPage() {
  return (
    <LegalPageShell
      title={meta.title}
      subtitle={meta.subtitle}
      meta={{ version: meta.version, statusLabel: meta.statusLabel, stage: meta.stage, lastUpdated: meta.lastUpdated }}
    >
      <p className="text-base leading-7 text-slate-700">
        This notice summarises how ANCHOR uses cookies and similar storage, based on the current frontend.
      </p>
      <LegalSections sections={sections} />
    </LegalPageShell>
  );
}
