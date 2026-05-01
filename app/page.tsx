import type { Metadata } from "next";
import { PublicWebsite } from "@/components/marketing/PublicWebsite";

export const metadata: Metadata = {
  title: "ANCHOR | Governed AI workflows for veterinary clinics",
  description: "Governance, trust, learning, and accountability for safe day-to-day AI use in veterinary clinics.",
};

export default function HomePage() {
  return <PublicWebsite />;
}
