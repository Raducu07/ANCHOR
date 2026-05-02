import type { Metadata } from "next";
import Link from "next/link";
import { DemoRequestForm } from "@/components/marketing/DemoRequestForm";
import { MarketingShell, SectionHeading, marketingSecondaryButtonClass } from "@/components/marketing/MarketingShell";
import { Card } from "@/components/ui/Card";
import { demoAudience, demoReasons, demoWhatWeWillShow, trustStripItems } from "@/lib/marketingContent";

export const metadata: Metadata = {
  title: "ANCHOR | Request a walkthrough",
  description: "Book a short walkthrough of how veterinary clinics can use AI with stronger accountability, safer review, and visible trust surfaces.",
};

export default function DemoPage() {
  return (
    <MarketingShell primaryCtaHref="/#workflow" primaryCtaLabel="See the workflow">
      <section className="px-4 pb-16 pt-24 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <SectionHeading
            eyebrow="SEE ANCHOR IN A GOVERNED WORKFLOW"
            title="See ANCHOR in a governed workflow"
            body={`Book a short walkthrough of how veterinary clinics can use AI with stronger accountability, safer review, and visible trust surfaces.
ANCHOR helps clinics move from informal AI use into governed day-to-day workflows with metadata-only accountability by default, receipt-backed review, and human-review-visible operational use.`}
          />

          <div className="mt-8">
            <Link href="/start" className={marketingSecondaryButtonClass("px-6 py-3 text-sm")}>
              Start with ANCHOR
            </Link>
          </div>
        </div>
      </section>

      <section className="border-y border-slate-200 bg-white px-4 py-20 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <div className="grid gap-6 lg:grid-cols-4">
            {demoWhatWeWillShow.map((item) => (
              <Card key={item} className="rounded-[2rem] bg-slate-50 p-6">
                <p className="text-base font-semibold text-slate-900">{item}</p>
              </Card>
            ))}
          </div>
        </div>
      </section>

      <section className="px-4 py-20 sm:px-6 lg:px-8">
        <div className="mx-auto grid max-w-7xl gap-6 xl:grid-cols-[1fr_1fr]">
          <Card className="rounded-[2rem] p-8">
            <h2 className="text-2xl font-semibold text-slate-900">Who this walkthrough is for</h2>
            <div className="mt-6 grid gap-3 sm:grid-cols-2">
              {demoAudience.map((item) => (
                <div key={item} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4 text-sm font-medium text-slate-700">
                  {item}
                </div>
              ))}
            </div>
          </Card>

          <Card className="rounded-[2rem] p-8">
            <h2 className="text-2xl font-semibold text-slate-900">Why clinics usually come to us</h2>
            <div className="mt-6 space-y-3">
              {demoReasons.map((item) => (
                <div key={item} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4 text-sm font-medium text-slate-700">
                  {item}
                </div>
              ))}
            </div>
          </Card>
        </div>
      </section>

      <section className="border-y border-slate-200 bg-white px-4 py-14 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <p className="mb-6 text-sm font-bold uppercase tracking-[0.2em] text-slate-500">Trust strip</p>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
            {trustStripItems.map((item) => (
              <div key={item} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4 text-sm font-medium text-slate-700">
                {item}
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="px-4 py-20 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          <DemoRequestForm />
        </div>
      </section>
    </MarketingShell>
  );
}
