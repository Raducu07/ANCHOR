import Link from "next/link";
import { BrowserFrame } from "@/components/marketing/BrowserFrame";
import { MarketingShell, marketingPrimaryButtonClass, marketingSecondaryButtonClass } from "@/components/marketing/MarketingShell";
import { Card } from "@/components/ui/Card";
import {
  homepageBoundaryCards,
  homepagePlatformCards,
  homepageWhyItems,
  homepageWorkflowSteps,
  trustStripItems,
} from "@/lib/marketingContent";

export function PublicWebsite() {
  return (
    <MarketingShell primaryCtaHref="/demo" primaryCtaLabel="Request a walkthrough">
      <section className="relative overflow-hidden px-4 pb-24 pt-32 sm:px-6 lg:px-8">
        <div className="absolute inset-0 bg-[radial-gradient(#e2e8f0_1px,transparent_1px)] [background-size:16px_16px] opacity-30" />
        <div className="relative z-10 mx-auto max-w-7xl">
          <div className="mx-auto mb-12 max-w-4xl text-center">
            <h1 className="mb-6 text-5xl font-extrabold tracking-tight text-slate-950 md:text-6xl">
              Governed AI workflows for veterinary clinics
            </h1>
            <p className="mx-auto max-w-3xl text-xl font-medium leading-relaxed text-slate-600 md:text-2xl">
              Governance, trust, learning, and accountability for safe day-to-day AI use in veterinary clinics.
            </p>

            <div className="mt-10 flex flex-col justify-center gap-4 sm:flex-row">
              <Link href="/demo" className={marketingPrimaryButtonClass("px-8 py-3.5 text-base")}>
                Request a walkthrough
              </Link>
              <Link href="/start" className={marketingSecondaryButtonClass("px-8 py-3.5 text-base")}>
                Start with ANCHOR
              </Link>
            </div>

            <div className="mt-6">
              <Link
                href="/plans"
                className="text-sm font-medium text-slate-600 underline underline-offset-4 transition-colors hover:text-slate-900"
              >
                Compare plans
              </Link>
            </div>
          </div>

          <BrowserFrame
            alt="ANCHOR Workspace interface showing governed review settings"
            imageClassName="object-top"
            imageSrc="/anchor-public/workspace-review-settings.png"
            priority
          />
        </div>
      </section>

      <section className="border-y border-slate-200 bg-white px-4 py-24 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="mx-auto mb-16 max-w-3xl text-center">
            <h2 className="mb-3 text-sm font-bold uppercase tracking-[0.2em] text-slate-500">
              Why clinics need governed AI workflows
            </h2>
            <h3 className="text-4xl font-bold tracking-tight text-slate-950 md:text-5xl">
              Operational governance for safe AI use in veterinary clinics
            </h3>
            <p className="mx-auto mt-6 max-w-4xl text-lg leading-8 text-slate-600">
              AI can help veterinary teams move faster, but unmanaged use creates avoidable risk. Privacy-sensitive details,
              inconsistent review, weak accountability, and limited leadership visibility make day-to-day adoption harder to trust
              and harder to scale.
            </p>
          </div>

          <div className="grid gap-8 md:grid-cols-2 xl:grid-cols-4">
            {homepageWhyItems.map((item) => (
              <div key={item.title}>
                <div className="mb-6 flex h-12 w-12 items-center justify-center rounded-xl bg-slate-100 text-slate-700">
                  <span className="h-2.5 w-2.5 rounded-full bg-slate-700" />
                </div>
                <h4 className="mb-3 text-xl font-bold text-slate-900">{item.title}</h4>
                <p className="text-base leading-7 text-slate-600">{item.text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="workflow" className="bg-slate-50 px-4 py-24 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="mb-20 text-center">
            <h2 className="text-4xl font-bold tracking-tight text-slate-950 md:text-5xl">The governed workflow</h2>
            <p className="mx-auto mt-4 max-w-2xl text-xl text-slate-600">
              A practical workflow for safer AI use in veterinary clinics.
            </p>
          </div>

          <div className="space-y-20">
            {homepageWorkflowSteps.map((step) => (
              <div
                key={step.step}
                className={`flex flex-col items-center gap-12 ${step.reverse ? "lg:flex-row-reverse" : "lg:flex-row"}`}
              >
                <div className="w-full lg:w-1/2">
                  <div className="mx-auto max-w-2xl">
                    <BrowserFrame imageClassName={step.crop} imageSrc={step.image} alt={step.alt} />
                  </div>
                </div>
                <div className={`w-full lg:w-1/2 ${step.reverse ? "lg:pr-12" : "lg:pl-12"}`}>
                  <div className="mb-2 text-xl font-bold text-slate-950">{step.step}</div>
                  <h3 className="mb-4 text-3xl font-bold text-slate-950">{step.title}</h3>
                  <p className="text-lg leading-8 text-slate-600">{step.text}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="platform" className="border-y border-slate-200 bg-white px-4 py-24 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="mb-16 text-center">
            <h2 className="text-4xl font-bold tracking-tight text-slate-950 md:text-5xl">
              A connected governance surface for safe AI use in veterinary clinics
            </h2>
            <p className="mx-auto mt-4 max-w-3xl text-xl text-slate-600">
              ANCHOR combines governed workflows, receipt-backed review, practical learning, trust surfaces, and operational
              intelligence in one clinic-scoped system.
            </p>
          </div>

          <div className="grid gap-8 md:grid-cols-2 xl:grid-cols-3">
            {homepagePlatformCards.map((card) => (
              <Card key={card.title} className="rounded-2xl bg-slate-50 p-6 transition-shadow hover:shadow-md">
                <h3 className="mb-3 text-2xl font-bold text-slate-950">{card.title}</h3>
                <p className="mb-6 text-base leading-7 text-slate-600">{card.text}</p>
                <BrowserFrame compact imageClassName="object-top" imageSrc={card.image} alt={card.alt} />
              </Card>
            ))}
          </div>
        </div>
      </section>

      <section id="trust" className="bg-slate-50 px-4 py-24 sm:px-6 lg:px-8">
        <div className="mx-auto flex max-w-7xl flex-col items-center gap-12 lg:flex-row">
          <div className="w-full lg:w-1/2">
            <h2 className="text-4xl font-bold tracking-tight text-slate-950 md:text-5xl">Trust made visible</h2>
            <p className="mb-6 mt-4 text-xl text-slate-600">
              ANCHOR helps clinics make AI use more reviewable, more accountable, and easier to govern operationally.
            </p>
            <p className="mb-8 text-lg leading-8 text-slate-600">
              The platform keeps policy traceability, metadata-only accountability, request-level receipts, and human review
              expectations visible across day-to-day workflows.
            </p>

            <ul className="mb-10 space-y-4">
              {trustStripItems.map((point) => (
                <li key={point} className="flex items-start">
                  <span className="mr-3 mt-1 h-3 w-3 flex-shrink-0 rounded-full bg-slate-950" />
                  <span className="font-medium text-slate-700">{point}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="w-full lg:w-1/2">
            <BrowserFrame imageClassName="object-top" imageSrc="/anchor-public/trust-center-overview.png" alt="ANCHOR Trust Center" />
          </div>
        </div>
      </section>

      <section className="border-y border-slate-200 bg-white px-4 py-24 sm:px-6 lg:px-8">
        <div className="mx-auto flex max-w-7xl flex-col items-center gap-12 lg:flex-row">
          <div className="order-2 w-full lg:order-1 lg:w-1/2">
            <div className="grid gap-6">
              <BrowserFrame
                compact
                imageClassName="object-top"
                imageSrc="/anchor-public/governance-events-overview.png"
                alt="Governance Events overview"
              />
              <BrowserFrame compact imageClassName="object-top" imageSrc="/anchor-public/learn-overview.png" alt="ANCHOR Learn overview" />
            </div>
          </div>

          <div className="order-1 w-full lg:order-2 lg:w-1/2 lg:pl-8">
            <h2 className="text-4xl font-bold tracking-tight text-slate-950 md:text-5xl">
              From governance signals to safer use
            </h2>
            <p className="mb-6 mt-4 text-xl text-slate-600">
              ANCHOR does not stop at oversight. It turns patterns, warnings, and friction into practical learning and operational
              next steps.
            </p>
            <p className="text-lg leading-8 text-slate-600">
              When privacy warnings or recurring patterns appear, staff can move into clear explainers, microlearning, and guided
              follow-up without losing the governance context.
            </p>
          </div>
        </div>
      </section>

      <section id="boundaries" className="bg-slate-900 px-4 py-24 text-white sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="mx-auto mb-16 max-w-3xl text-center">
            <h2 className="mb-6 text-3xl font-bold tracking-tight md:text-4xl">Clear product boundaries</h2>
            <p className="text-lg text-slate-300">
              ANCHOR is designed to support safer operational AI use without overstating what the product is.
            </p>
          </div>

          <div className="grid gap-8 md:grid-cols-3">
            {homepageBoundaryCards.map((card) => (
              <div key={card.title} className="rounded-xl border border-slate-700 bg-slate-800 p-6 text-center">
                <div className="mb-4 text-sm font-bold uppercase tracking-[0.18em] text-emerald-400">{card.title}</div>
                <p className="text-sm leading-7 text-slate-300">{card.text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
    </MarketingShell>
  );
}
