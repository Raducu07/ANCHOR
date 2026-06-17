import type { ReactNode } from "react";
import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://anchorvet.co.uk"),
  title: "ANCHOR | AI Governance Infrastructure for Veterinary Clinics",
  description:
    "Governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics.",
  openGraph: {
    siteName: "ANCHOR",
    type: "website",
    url: "/",
    title: "ANCHOR | AI Governance Infrastructure for Veterinary Clinics",
    description:
      "Governance, trust, learning, intelligence, and readiness infrastructure for safe AI use in veterinary clinics.",
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-slate-50 text-slate-900 antialiased">{children}</body>
    </html>
  );
}
