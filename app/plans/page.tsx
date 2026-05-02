import type { Metadata } from "next";
import Link from "next/link";
import { MarketingShell, SectionHeading, marketingPrimaryButtonClass, marketingSecondaryButtonClass } from "@/components/marketing/MarketingShell";
import { Card } from "@/components/ui/Card";
import { onboardingOverviewSteps, planCards, planChoiceGuidance, plansFaqs, productDoctrineItems } from "@/lib/marketingContent";

export const metadata: Metadata = {
  title: "ANCHOR | Plans",
  description: "Choose the right starting point for governed AI use in veterinary clinics.",
};

export default function PlansPage() {
  return (
    <MarketingShell primaryCtaHref="/demo" primaryCtaLabel="Request a walkthrough">
      <section className="px-4 pb-16 pt-24 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <SectionHeading
            eyebrow="START WITH ANCHOR"
            title="Plans for governed AI use in veterinary clinics"
            body={`ANCHOR is designed to help clinics introduce safer AI use through governed workflows, visible accountability, and practical operational oversight.
Choose the right starting point for your clinic, then move into setup, onboarding, and first-use activation.`}
          />

          <div className="mt-8 flex flex-col gap-4 sm:flex-row">
            <Link href="/start" className={marketingPrimaryButtonClass("px-6 py-3 text-sm")}>
              Start with ANCHOR
            </Link>
            <Link href="/demo" className={marketingSecondaryButtonClass("px-6 py-3 text-sm")}>
              Request a walkthrough
            </Link>
          </div>
        </div>
      </section>

      <section className="border-y border-slate-200 bg-white px-4 py-20 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <h2 className="text-2xl font-semibold text-slate-900">How to choose a plan</h2>
          <div className="mt-6 grid gap-4 lg:grid-cols-3">
            {planChoiceGuidance.map((item) => (
              <Card key={item.title} className="rounded-[2rem] bg-slate-50 p-6">
                <p className="text-lg font-semibold text-slate-900">{item.title}</p>
                <p className="mt-3 text-sm leading-6 text-slate-600">{item.text}</p>
              </Card>
            ))}
          </div>
        </div>
      </section>

      <section className="px-4 py-20 sm:px-6 lg:px-8">
        <div className="mx-auto grid max-w-7xl gap-6 lg:grid-cols-3">
          {planCards.map((plan) => (
            <Card key={plan.name} className="rounded-[2rem] p-8">
              <p className="text-sm font-bold uppercase tracking-[0.2em] text-slate-500">{plan.name}</p>
              <h2 className="mt-3 text-2xl font-semibold text-slate-900">{plan.audience}</h2>
              <div className="mt-6 space-y-3">
                {plan.features.map((feature) => (
                  <div key={feature} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm font-medium text-slate-700">
                    {feature}
                  </div>
                ))}
              </div>
            </Card>
          ))}
        </div>
      </section>

      <section className="border-y border-slate-200 bg-white px-4 py-20 sm:px-6 lg:px-8">
        <div className="mx-auto grid max-w-7xl gap-6 xl:grid-cols-[1fr_1fr]">
          <Card className="rounded-[2rem] p-8">
            <h2 className="text-2xl font-semibold text-slate-900">Product doctrine</h2>
            <div className="mt-6 space-y-3">
              {productDoctrineItems.map((item) => (
                <div key={item} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4 text-sm font-medium text-slate-700">
                  {item}
                </div>
              ))}
            </div>
          </Card>

          <Card className="rounded-[2rem] p-8">
            <h2 className="text-2xl font-semibold text-slate-900">Onboarding overview</h2>
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
        </div>
      </section>

      <section className="px-4 py-20 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <h2 className="text-2xl font-semibold text-slate-900">FAQ</h2>
          <div className="mt-6 grid gap-4 xl:grid-cols-2">
            {plansFaqs.map((item) => (
              <Card key={item.question} className="rounded-[2rem] p-6">
                <h3 className="text-lg font-semibold text-slate-900">{item.question}</h3>
                <p className="mt-3 text-sm leading-6 text-slate-600">{item.answer}</p>
              </Card>
            ))}
          </div>
        </div>
      </section>

      <section className="border-t border-slate-200 bg-white px-4 py-24 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-4xl text-center">
          <h2 className="text-4xl font-extrabold tracking-tight text-slate-950">Choose a calm entry into governed AI use</h2>
          <p className="mt-4 text-xl text-slate-600">
            Start with the right ANCHOR path for your clinic, then move into setup, onboarding, and first-use activation.
          </p>
          <div className="mt-8 flex flex-col justify-center gap-4 sm:flex-row">
            <Link href="/start" className={marketingPrimaryButtonClass("px-10 py-4 text-base")}>
              Start with ANCHOR
            </Link>
            <Link href="/demo" className={marketingSecondaryButtonClass("px-10 py-4 text-base")}>
              Request a walkthrough
            </Link>
          </div>
        </div>
      </section>
    </MarketingShell>
  );
}
