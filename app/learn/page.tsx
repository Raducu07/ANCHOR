"use client";

import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";

const featuredCards = [
  {
    title: "Metadata-only accountability",
    description:
      "Understand why ANCHOR surfaces governance metadata rather than storing raw prompt and output content.",
    href: "/learn/cards",
    tag: "core concept",
  },
  {
    title: "Handling PII safely",
    description:
      "Recognize privacy-sensitive details and understand why safe handling matters in clinic AI workflows.",
    href: "/learn/cards",
    tag: "privacy",
  },
  {
    title: "Review responsibility",
    description:
      "Clarify why AI-assisted material still requires human review, judgment, and accountability before use.",
    href: "/learn/cards",
    tag: "safe use",
  },
];

const explainerTopics = [
  "Why a request may be flagged for privacy concerns",
  "What replacement or modification outcomes mean operationally",
  "Why metadata-only governance matters",
  "How policy boundaries should be interpreted in day-to-day clinic use",
];

export default function LearnHomePage() {
  return (
    <AppShell>
      <div className="space-y-6">
        <div>
          <p className="text-sm font-medium text-slate-500">ANCHOR Learn</p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Safe AI-use learning</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            ANCHOR Learn helps clinic teams build practical AI literacy around governance, privacy, review
            responsibility, and safe operational use. This is professional enablement, not generic e-learning.
          </p>
        </div>

        <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
          <Card>
            <SectionTitle
              title="Why Learn exists"
              description="The role of Learn inside the ANCHOR product model."
            />
            <div className="mt-4 space-y-3 text-sm leading-6 text-slate-600">
              <p>
                ANCHOR Core provides governance surfaces, receipts, events, and bounded exports. ANCHOR Learn adds
                the next layer: helping clinic teams understand safe AI use rather than only seeing governance outcomes.
              </p>
              <p>
                The goal is to reduce avoidable friction, improve staff confidence, and make responsible AI adoption
                easier to sustain in real veterinary workflows.
              </p>
            </div>
          </Card>

          <Card>
            <SectionTitle
              title="Quick links"
              description="Move into the first Learn surfaces."
            />
            <div className="mt-4 space-y-3">
              <QuickLink
                href="/learn/cards"
                title="Microlearning cards"
                description="Short practical cards on safe AI use, governance, privacy, and review responsibility."
              />
              <QuickLink
                href="/learn/explainers"
                title="Why was this flagged?"
                description="Plain-language explainers that turn governance friction into staff understanding."
              />
            </div>
          </Card>
        </div>

        <div className="grid gap-4 xl:grid-cols-3">
          {featuredCards.map((item) => (
            <Card key={item.title}>
              <div className="flex items-start justify-between gap-3">
                <h2 className="text-base font-semibold text-slate-900">{item.title}</h2>
                <StatusBadge value={item.tag} />
              </div>
              <p className="mt-3 text-sm leading-6 text-slate-600">{item.description}</p>
              <div className="mt-4">
                <Link
                  href={item.href}
                  className="text-sm font-medium text-slate-900 underline underline-offset-4"
                >
                  Explore
                </Link>
              </div>
            </Card>
          ))}
        </div>

        <div className="grid gap-4 xl:grid-cols-[1fr_1fr]">
          <Card>
            <SectionTitle
              title="What Learn should help staff understand"
              description="Core learning outcomes for safer day-to-day AI use."
            />
            <ul className="mt-4 space-y-3 text-sm leading-6 text-slate-600">
              <li>&bull; Why governance surfaces exist and what they are for</li>
              <li>&bull; Why metadata-only accountability is a deliberate product doctrine</li>
              <li>&bull; How to handle privacy-sensitive details more safely</li>
              <li>&bull; Why AI-assisted outputs still require human review</li>
              <li>&bull; When safe drafting is appropriate and when escalation is better</li>
            </ul>
          </Card>

          <Card>
            <SectionTitle
              title="Explainer themes"
              description="The first common governance questions Learn should answer clearly."
            />
            <ul className="mt-4 space-y-3 text-sm leading-6 text-slate-600">
              {explainerTopics.map((topic) => (
                <li key={topic}>&bull; {topic}</li>
              ))}
            </ul>
          </Card>
        </div>

        <Card>
          <SectionTitle
            title="Why Learn is intentionally focused"
            description="Why this Learn surface is intentionally disciplined."
          />
          <div className="mt-4 space-y-3 text-sm leading-6 text-slate-600">
            <p>
              Learn is designed to extend ANCHOR Core without turning the product into a full learning
              management system. The emphasis is on high-signal, clinic-relevant education tied to governance-first AI adoption.
            </p>
            <p>
              That keeps Learn commercially coherent: practical, professional, and directly useful to veterinary clinics.
            </p>
          </div>
        </Card>
      </div>
    </AppShell>
  );
}

function SectionTitle({
  title,
  description,
}: {
  title: string;
  description?: string;
}) {
  return (
    <div>
      <h2 className="text-base font-semibold text-slate-900">{title}</h2>
      {description ? <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p> : null}
    </div>
  );
}

function QuickLink({
  href,
  title,
  description,
}: {
  href: string;
  title: string;
  description: string;
}) {
  return (
    <Link
      href={href}
      className="block rounded-2xl border border-slate-200 bg-slate-50 p-4 transition hover:border-slate-300 hover:bg-white"
    >
      <p className="text-sm font-semibold text-slate-900">{title}</p>
      <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p>
    </Link>
  );
}
