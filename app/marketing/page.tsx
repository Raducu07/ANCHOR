import type { Metadata } from "next";
import { PublicWebsite } from "@/components/marketing/PublicWebsite";

// /marketing renders the same public homepage as /. Mark / as canonical and
// keep /marketing out of the index so the duplicate route is not indexed
// separately. UI and copy are unchanged.
export const metadata: Metadata = {
  alternates: { canonical: "/" },
  robots: { index: false, follow: true },
};

export default function MarketingPage() {
  return <PublicWebsite />;
}
