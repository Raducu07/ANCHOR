import Image from "next/image";
import Link from "next/link";

const layers = [
  {
    title: "ANCHOR Core",
    text: "Governance-first infrastructure for policy control, governance receipts, metadata-only accountability, privacy-aware controls, tenant isolation, and observability.",
  },
  {
    title: "ANCHOR Learn",
    text: "Practical staff enablement through microlearning, explainers, privacy-safe guidance, and reinforcement tied to governance patterns.",
  },
  {
    title: "ANCHOR Trust",
    text: "Leadership-facing trust profile, posture summary, and exportable trust materials built from governance evidence and privacy-aware controls.",
  },
  {
    title: "ANCHOR Intelligence",
    text: "Metadata-driven insight into governance hotspots, friction patterns, and training or policy improvement opportunities.",
  },
];

const proofPoints = [
  "Governance receipts",
  "Metadata-only accountability",
  "Clinic-scoped review",
  "Privacy-aware controls",
  "Safe AI-use learning",
  "Operational intelligence",
];

const workflow = [
  {
    step: "Step 1",
    title: "Dashboard",
    text: "Trust-oriented overview of governance activity, privacy signals, and operational concentration patterns.",
  },
  {
    step: "Step 2",
    title: "Governance Events",
    text: "Clinic-scoped review of metadata-only activity, current context, and recommended next actions.",
  },
  {
    step: "Step 3",
    title: "Receipt",
    text: "Request-level accountability showing decision, privacy handling, and policy traceability without exposing raw content.",
  },
  {
    step: "Step 4",
    title: "Learn / Intelligence",
    text: "Reinforcement and improvement loop built from governance patterns rather than generic AI hype.",
  },
  {
    step: "Step 5",
    title: "Trust",
    text: "Leadership-facing posture and external trust material grounded in real operational evidence.",
  },
];

const screenshotCards = [
  {
    title: "Dashboard",
    caption:
      "Trust-oriented clinic overview with governance activity, privacy-aware indicators, and operational concentration signals.",
    image: null,
    suggestedPath: "/marketing/dashboard.png",
  },
  {
    title: "Receipt Viewer",
    caption:
      "Request-level governance receipt showing decision, privacy handling, policy traceability, and metadata-only accountability.",
    image: null,
    suggestedPath: "/marketing/receipt.png",
  },
  {
    title: "Intelligence",
    caption:
      "Metadata-driven hotspot and recommendation view highlighting where reinforcement and operational attention are needed.",
    image: null,
    suggestedPath: "/marketing/intelligence.png",
  },
];

export default function MarketingPage() {
  return (
    <main className="min-h-screen bg-[var(--anchor-canvas)] text-[var(--anchor-ink)]">
      <header className="sticky top-0 z-50 border-b border-[var(--anchor-line)] bg-[rgba(246,244,238,0.92)] backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 md:px-10 lg:px-12">
          <div>
            <div className="text-sm font-semibold tracking-[0.18em] text-[var(--anchor-violet)]">
              ANCHOR
            </div>
            <div className="mt-1 text-sm text-[var(--anchor-slate)]">
              Governance-first AI infrastructure for veterinary clinics
            </div>
          </div>

          <nav className="hidden items-center gap-6 md:flex">
            <a href="#product" className="text-sm font-medium text-[var(--anchor-slate)] hover:text-[var(--anchor-ink)]">
              Product
            </a>
            <a href="#workflow" className="text-sm font-medium text-[var(--anchor-slate)] hover:text-[var(--anchor-ink)]">
              Workflow
            </a>
            <a href="#screenshots" className="text-sm font-medium text-[var(--anchor-slate)] hover:text-[var(--anchor-ink)]">
              Screens
            </a>
            <a href="#trust" className="text-sm font-medium text-[var(--anchor-slate)] hover:text-[var(--anchor-ink)]">
              Trust
            </a>
            <Link
              href="/login"
              className="rounded-xl border border-[var(--anchor-line)] bg-white px-4 py-2 text-sm font-medium hover:bg-[var(--anchor-paper)]"
            >
              Clinic login
            </Link>
          </nav>
        </div>
      </header>

      <section className="mx-auto max-w-7xl px-6 pb-12 pt-10 md:px-10 lg:px-12 md:pt-14">
        <div className="overflow-hidden rounded-[30px] border border-[var(--anchor-line)] bg-white shadow-[0_22px_70px_rgba(13,27,77,0.08)]">
          <div className="bg-[var(--anchor-ink)] px-8 py-10 text-white md:px-12 md:py-16">
            <div className="mb-4 inline-flex rounded-full border border-white/20 bg-white/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.16em] text-[var(--anchor-soft-violet)]">
              Governance, trust, learning, and intelligence
            </div>

            <h1 className="max-w-4xl text-4xl font-semibold leading-tight md:text-6xl md:leading-[1.04]">
              Governance infrastructure for safe AI use in veterinary clinics
            </h1>

            <p className="mt-6 max-w-3xl text-base leading-7 text-white/85 md:text-lg">
              ANCHOR gives veterinary clinics governance receipts, metadata-only
              accountability, privacy-aware controls, staff learning, trust
              reporting, and operational intelligence around AI-assisted
              workflows.
            </p>

            <div className="mt-8 flex flex-wrap gap-3">
              <a
                href="#workflow"
                className="inline-flex items-center rounded-xl bg-white px-5 py-3 text-sm font-semibold text-[var(--anchor-ink)] hover:bg-[var(--anchor-paper)]"
              >
                See the workflow →
              </a>

              <a
                href="#trust"
                className="inline-flex items-center rounded-xl border border-white/20 bg-white/10 px-5 py-3 text-sm font-semibold text-white hover:bg-white/15"
              >
                Explore trust surfaces
              </a>
            </div>
          </div>

          <div className="grid gap-0 border-t border-[var(--anchor-line)] md:grid-cols-3">
            <MetricCard
              glyph="▣"
              title="Request-level accountability"
              text="Receipts, policy traceability, privacy-aware indicators, and bounded exports create a clinic-scoped operating layer around AI use."
            />
            <MetricCard
              glyph="◌"
              title="Metadata-only doctrine"
              text="ANCHOR does not default into raw prompt or output storage. That keeps the product aligned with governance, trust, and privacy-aware oversight."
            />
            <MetricCard
              glyph="△"
              title="Adoption-ready value"
              text="Core, Learn, Trust, and Intelligence now form a product narrative that leadership, operators, and buyers can understand quickly."
            />
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 py-6 md:px-10 lg:px-12">
        <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
          {proofPoints.map((item) => (
            <div
              key={item}
              className="rounded-2xl border border-[var(--anchor-line)] bg-[var(--anchor-paper)] px-4 py-4 text-center text-sm font-medium text-[var(--anchor-ink)]"
            >
              {item}
            </div>
          ))}
        </div>
      </section>

      <section id="product" className="mx-auto max-w-7xl px-6 py-14 md:px-10 lg:px-12">
        <div className="grid gap-8 lg:grid-cols-[1.15fr_0.85fr]">
          <div>
            <SectionEyebrow>Why this matters now</SectionEyebrow>
            <h2 className="mt-2 max-w-3xl text-3xl font-semibold leading-tight md:text-4xl">
              AI adoption is moving faster than governance maturity in clinic workflows
            </h2>
            <p className="mt-5 max-w-3xl text-base leading-7 text-[var(--anchor-slate)]">
              Veterinary clinics are beginning to use AI across drafting,
              summarisation, communication, and administration. The strategic
              need is no longer just access to a model. It is institutional
              control around use.
            </p>

            <div className="mt-8 grid gap-4 md:grid-cols-2">
              <ContentCard title="What clinics need">
                <ul className="space-y-3 text-sm leading-6 text-[var(--anchor-slate)]">
                  <li>Leadership-facing accountability and trust surfaces</li>
                  <li>Reviewable governance events and request-level receipts</li>
                  <li>Staff reinforcement so adoption improves over time</li>
                  <li>Privacy-aware control without unnecessary content retention</li>
                </ul>
              </ContentCard>

              <ContentCard title="What ANCHOR already proves">
                <ul className="space-y-3 text-sm leading-6 text-[var(--anchor-slate)]">
                  <li>Core governance and receipt surfaces are live</li>
                  <li>Learn and Trust are materially present</li>
                  <li>Thin-slice Intelligence is operational</li>
                  <li>Workflow continuity exists across Dashboard, Events, Receipt, Learn, and Intelligence</li>
                </ul>
              </ContentCard>
            </div>
          </div>

          <div className="rounded-[24px] border border-[var(--anchor-line)] bg-[var(--anchor-card)] p-6">
            <SectionEyebrow>Commercial narrative</SectionEyebrow>
            <h3 className="mt-2 text-2xl font-semibold leading-tight">
              Most AI products help people generate outputs. ANCHOR helps veterinary clinics govern how AI is used.
            </h3>

            <div className="mt-6 space-y-4">
              <MiniPanel title="Buyer-facing message">
                ANCHOR helps veterinary clinics use AI with more control,
                clearer accountability, and stronger trust.
              </MiniPanel>

              <MiniPanel title="What makes ANCHOR distinctive">
                Governance-first positioning, metadata-only accountability,
                clinic-scoped review, and trust plus learning built into the
                same operating model.
              </MiniPanel>

              <MiniPanel title="Recommended adoption path">
                Prove workflow value, package for buyers, then sell
                institutional confidence.
              </MiniPanel>
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 py-14 md:px-10 lg:px-12">
        <SectionEyebrow>Product model</SectionEyebrow>
        <h2 className="mt-2 max-w-3xl text-3xl font-semibold leading-tight md:text-4xl">
          Four connected product layers
        </h2>

        <div className="mt-8 grid gap-5 md:grid-cols-2 xl:grid-cols-4">
          {layers.map((item, idx) => (
            <div
              key={item.title}
              className="rounded-[24px] border border-[var(--anchor-line)] bg-white p-6 shadow-[0_8px_24px_rgba(13,27,77,0.05)]"
            >
              <div className="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-2xl bg-[var(--anchor-soft-violet)] text-lg font-semibold text-[var(--anchor-ink)]">
                {idx + 1}
              </div>
              <h3 className="text-xl font-semibold">{item.title}</h3>
              <p className="mt-3 text-sm leading-6 text-[var(--anchor-slate)]">
                {item.text}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section id="workflow" className="border-y border-[var(--anchor-line)] bg-white">
        <div className="mx-auto max-w-7xl px-6 py-14 md:px-10 lg:px-12">
          <SectionEyebrow>Operational workflow</SectionEyebrow>
          <h2 className="mt-2 max-w-3xl text-3xl font-semibold leading-tight md:text-4xl">
            A usable governance workflow, not just static policy
          </h2>

          <div className="mt-8 grid gap-4 lg:grid-cols-5">
            {workflow.map((step) => (
              <div
                key={step.title}
                className="rounded-[22px] border border-[var(--anchor-line)] bg-[var(--anchor-paper)] p-5"
              >
                <div className="mb-3 text-xs font-semibold uppercase tracking-[0.16em] text-[var(--anchor-violet)]">
                  {step.step}
                </div>
                <h3 className="text-lg font-semibold">{step.title}</h3>
                <p className="mt-3 text-sm leading-6 text-[var(--anchor-slate)]">
                  {step.text}
                </p>
              </div>
            ))}
          </div>

          <div className="mt-8 rounded-[22px] border border-[var(--anchor-line)] bg-[var(--anchor-ink)] px-6 py-5 text-sm font-medium text-white">
            Dashboard → Governance Events → Receipt → Learn / Intelligence → Trust
          </div>
        </div>
      </section>

      <section id="screenshots" className="mx-auto max-w-7xl px-6 py-14 md:px-10 lg:px-12">
        <div className="flex items-end justify-between gap-6">
          <div>
            <SectionEyebrow>Product screens</SectionEyebrow>
            <h2 className="mt-2 max-w-3xl text-3xl font-semibold leading-tight md:text-4xl">
              Show the workflow, not just the claim
            </h2>
            <p className="mt-4 max-w-2xl text-base leading-7 text-[var(--anchor-slate)]">
              Add real screenshots here to make the public narrative feel grounded in the product you have already built.
            </p>
          </div>
        </div>

        <div className="mt-8 grid gap-6 lg:grid-cols-3">
          {screenshotCards.map((card) => (
            <ScreenshotCard
              key={card.title}
              title={card.title}
              caption={card.caption}
              image={card.image}
              suggestedPath={card.suggestedPath}
            />
          ))}
        </div>
      </section>

      <section id="trust" className="mx-auto max-w-7xl px-6 py-14 md:px-10 lg:px-12">
        <div className="grid gap-8 lg:grid-cols-[0.95fr_1.05fr]">
          <div>
            <SectionEyebrow>Why metadata-only</SectionEyebrow>
            <h2 className="mt-2 text-3xl font-semibold leading-tight md:text-4xl">
              Accountability without defaulting into raw-content accumulation
            </h2>
            <p className="mt-5 text-base leading-7 text-[var(--anchor-slate)]">
              ANCHOR’s current doctrine is metadata-only accountability.
              Receipts, events, exports, and intelligence surfaces are built
              around governance metadata, policy evidence, operational traces,
              and privacy-aware indicators rather than chat-history accumulation.
            </p>
          </div>

          <div className="rounded-[24px] border border-[var(--anchor-line)] bg-white p-6">
            <div className="grid gap-3 sm:grid-cols-2">
              {proofPoints.map((point) => (
                <div
                  key={point}
                  className="rounded-2xl border border-[var(--anchor-line)] bg-[var(--anchor-paper)] px-4 py-4 text-sm font-medium text-[var(--anchor-ink)]"
                >
                  {point}
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 pb-20 pt-6 md:px-10 lg:px-12">
        <div className="rounded-[28px] border border-[var(--anchor-line)] bg-white px-8 py-10 shadow-[0_18px_48px_rgba(13,27,77,0.06)] md:px-12 md:py-14">
          <SectionEyebrow>Final message</SectionEyebrow>
          <h2 className="mt-2 max-w-4xl text-3xl font-semibold leading-tight md:text-5xl">
            Use AI with more control, trust, and operational clarity
          </h2>
          <p className="mt-5 max-w-3xl text-base leading-7 text-[var(--anchor-slate)]">
            ANCHOR helps veterinary clinics adopt AI in a way that is safer,
            more explainable, more privacy-aware, and more institutionally
            credible.
          </p>

          <div className="mt-8 flex flex-wrap gap-3">
            <Link
              href="/dashboard"
              className="inline-flex items-center rounded-xl bg-[var(--anchor-ink)] px-5 py-3 text-sm font-semibold text-white hover:opacity-95"
            >
              Explore the product
            </Link>

            <Link
              href="/trust"
              className="inline-flex items-center rounded-xl border border-[var(--anchor-line)] bg-[var(--anchor-paper)] px-5 py-3 text-sm font-semibold text-[var(--anchor-ink)] hover:bg-white"
            >
              Review trust materials
            </Link>
          </div>
        </div>
      </section>
    </main>
  );
}

function SectionEyebrow({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-sm font-semibold uppercase tracking-[0.16em] text-[var(--anchor-violet)]">
      {children}
    </div>
  );
}

function MetricCard({
  glyph,
  title,
  text,
}: {
  glyph: string;
  title: string;
  text: string;
}) {
  return (
    <div className="border-b border-[var(--anchor-line)] px-6 py-6 md:border-b-0 md:border-r md:px-8 md:py-8 last:border-r-0">
      <div className="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-2xl bg-[var(--anchor-soft-violet)] text-lg font-semibold text-[var(--anchor-ink)]">
        {glyph}
      </div>
      <h3 className="text-xl font-semibold">{title}</h3>
      <p className="mt-3 text-sm leading-6 text-[var(--anchor-slate)]">{text}</p>
    </div>
  );
}

function ContentCard({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-[24px] border border-[var(--anchor-line)] bg-white p-6">
      <h3 className="text-xl font-semibold">{title}</h3>
      <div className="mt-4">{children}</div>
    </div>
  );
}

function MiniPanel({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-[20px] border border-[var(--anchor-line)] bg-white/80 p-4">
      <div className="text-sm font-semibold text-[var(--anchor-ink)]">{title}</div>
      <div className="mt-2 text-sm leading-6 text-[var(--anchor-slate)]">
        {children}
      </div>
    </div>
  );
}

function ScreenshotCard({
  title,
  caption,
  image,
  suggestedPath,
}: {
  title: string;
  caption: string;
  image: string | null;
  suggestedPath: string;
}) {
  return (
    <div className="overflow-hidden rounded-[24px] border border-[var(--anchor-line)] bg-white shadow-[0_8px_24px_rgba(13,27,77,0.05)]">
      <div className="border-b border-[var(--anchor-line)] bg-[var(--anchor-paper)] px-5 py-4">
        <div className="text-sm font-semibold tracking-[0.08em] text-[var(--anchor-violet)] uppercase">
          {title}
        </div>
      </div>

      <div className="p-5">
        <div className="relative overflow-hidden rounded-[18px] border border-[var(--anchor-line)] bg-[linear-gradient(180deg,#fff,#f7f3ea)]">
          {image ? (
            <div className="relative aspect-[16/10]">
              <Image
                src={image}
                alt={title}
                fill
                className="object-cover"
              />
            </div>
          ) : (
            <div className="aspect-[16/10] p-5">
              <div className="flex h-full flex-col rounded-[14px] border border-dashed border-[var(--anchor-line)] bg-white/70 p-4">
                <div className="flex items-center gap-2">
                  <span className="h-3 w-3 rounded-full bg-[#d8cfbf]" />
                  <span className="h-3 w-3 rounded-full bg-[#e8e0ff]" />
                  <span className="h-3 w-3 rounded-full bg-[#cfd6e6]" />
                </div>
                <div className="mt-4 flex-1 rounded-[12px] bg-[var(--anchor-paper)]" />
                <div className="mt-4 text-xs leading-5 text-[var(--anchor-slate)]">
                  Drop a real screenshot here later.
                  <br />
                  Suggested path: <span className="font-medium">{suggestedPath}</span>
                </div>
              </div>
            </div>
          )}
        </div>

        <p className="mt-4 text-sm leading-6 text-[var(--anchor-slate)]">
          {caption}
        </p>
      </div>
    </div>
  );
}