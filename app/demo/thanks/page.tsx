import type { Metadata } from "next";
import Link from "next/link";
import {
  MarketingShell,
  SectionHeading,
  marketingPrimaryButtonClass,
  marketingSecondaryButtonClass,
} from "@/components/marketing/MarketingShell";
import { Card } from "@/components/ui/Card";

export const metadata: Metadata = {
  title: "ANCHOR | Walkthrough request received",
  description: "Clear next steps after requesting an ANCHOR walkthrough.",
};

const nextSteps = [
  "We review your request",
  "We contact you to arrange a walkthrough",
  "We show the governed workflow, trust surfaces, and onboarding path",
] as const;

export default function DemoThanksPage() {
  return (
    <MarketingShell primaryCtaHref="/start" primaryCtaLabel="Start with ANCHOR">
      <section className="px-4 py-24 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-4xl">
          <SectionHeading
            title="Thanks — your request has been received"
            body={`We’ve received your walkthrough request and will review it shortly.
We’ll usually reply within one working day to arrange a walkthrough and understand your clinic’s use case.`}
            align="center"
          />

          <Card className="mt-10 rounded-[2rem] p-8">
            <h2 className="text-xl font-semibold text-slate-900">Next steps</h2>
            <div className="mt-6 space-y-3">
              {nextSteps.map((item, index) => (
                <div key={item} className="flex items-start gap-4 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4">
                  <span className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-900 text-sm font-semibold text-white">
                    {index + 1}
                  </span>
                  <p className="pt-1 text-sm font-medium text-slate-700">{item}</p>
                </div>
              ))}
            </div>

            <div className="mt-8 flex flex-col gap-4 sm:flex-row">
              <Link href="/start" className={marketingPrimaryButtonClass("px-6 py-3 text-sm")}>
                Start with ANCHOR
              </Link>
              <Link href="/" className={marketingSecondaryButtonClass("px-6 py-3 text-sm")}>
                Back to home
              </Link>
            </div>
          </Card>
        </div>
      </section>
    </MarketingShell>
  );
}
