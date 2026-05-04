import type { Metadata } from "next";
import Link from "next/link";
import { StartRequestForm } from "@/components/marketing/StartRequestForm";
import {
  MarketingShell,
  SectionHeading,
  marketingSecondaryButtonClass,
} from "@/components/marketing/MarketingShell";
import { Card } from "@/components/ui/Card";
import { onboardingOverviewSteps } from "@/lib/marketingContent";

export const metadata: Metadata = {
  title: "ANCHOR | Start",
  description: "Lightweight onboarding entry for clinics starting with ANCHOR.",
};

export default function StartPage() {
  return (
    <MarketingShell primaryCtaHref="/demo" primaryCtaLabel="Request a walkthrough">
      <section className="px-4 py-24 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-6xl">
          <SectionHeading
            title="Start with ANCHOR"
            body="Set up your clinic, create your first admin account, and begin governed AI workflow activation."
          />

          <div className="mt-10 grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
            <Card className="rounded-[2rem] p-8">
              <h2 className="text-2xl font-semibold text-slate-900">Onboarding sequence</h2>
              <div className="mt-6 space-y-3">
                {onboardingOverviewSteps.map((step, index) => (
                  <div key={step} className="flex items-start gap-4 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4">
                    <span className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-900 text-sm font-semibold text-white">
                      {index + 1}
                    </span>
                    <p className="pt-1 text-sm font-medium text-slate-700">{step}</p>
                  </div>
                ))}
              </div>
            </Card>

            <Card className="rounded-[2rem] p-8">
              <h2 className="text-2xl font-semibold text-slate-900">Assisted onboarding path</h2>
              <p className="mt-4 text-sm leading-6 text-slate-600">
                This is a production-minded onboarding entry point rather than an automated checkout. Clinic details, admin creation,
                plan selection, billing, confirmation, and first-use setup are framed here so the flow can later connect cleanly into
                billing and activation tooling.
              </p>
              <p className="mt-4 text-sm leading-6 text-slate-600">
                Use the form below to share the clinic setup context, preferred plan, and rollout timing so ANCHOR can respond with
                the right assisted onboarding path.
              </p>

              <div className="mt-8 flex flex-col gap-4">
                <Link href="/demo" className={marketingSecondaryButtonClass("px-6 py-3 text-sm")}>
                  Request a walkthrough
                </Link>
                <Link href="/plans" className={marketingSecondaryButtonClass("px-6 py-3 text-sm")}>
                  Compare plans
                </Link>
              </div>
            </Card>
          </div>

          <div className="mt-8">
            <StartRequestForm />
          </div>
        </div>
      </section>
    </MarketingShell>
  );
}
