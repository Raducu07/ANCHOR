"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { listLearningModules } from "@/lib/learn";
import type { LearningModule } from "@/lib/types";

const CATEGORY_FILTERS: { value: string; label: string }[] = [
  { value: "", label: "All categories" },
  { value: "literacy", label: "Literacy" },
  { value: "bias_detection", label: "Bias detection" },
  { value: "ethical_use", label: "Ethical use" },
  { value: "confidentiality", label: "Confidentiality" },
  { value: "transparency", label: "Transparency" },
  { value: "preparation_for_practice", label: "Preparation for practice" },
];

const ROLE_FILTERS: { value: string; label: string }[] = [
  { value: "", label: "All audiences" },
  { value: "vet", label: "Vet" },
  { value: "nurse", label: "Nurse" },
  { value: "practice_manager", label: "Practice manager" },
  { value: "admin", label: "Admin" },
  { value: "reception", label: "Reception" },
  { value: "locum", label: "Locum" },
];

function formatTag(value: string) {
  return value.replace(/[_-]+/g, " ");
}

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

        <ModuleCatalogue />

        <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
          <Card variant="native">
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

          <Card variant="native">
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
            <Card variant="native" key={item.title}>
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
          <Card variant="native">
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

          <Card variant="native">
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

        <Card variant="native">
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

function ModuleCatalogue() {
  const [modules, setModules] = useState<LearningModule[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [category, setCategory] = useState("");
  const [role, setRole] = useState("");

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const result = await listLearningModules({
          category: category || undefined,
          role: role || undefined,
        });
        if (!active) return;
        setModules(result);
      } catch (err: unknown) {
        if (!active) return;
        const message =
          err instanceof Error ? err.message : "Unable to load AI literacy modules.";
        setError(message);
        setModules(null);
      } finally {
        if (active) setLoading(false);
      }
    }

    void load();

    return () => {
      active = false;
    };
  }, [category, role]);

  return (
    <Card variant="native">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <SectionTitle
          title="CPD-recordable AI literacy modules"
          description="Supports CPD-recordable AI literacy activity. Aligned with RCVS AI literacy expectations and EU AI Act Article 4 readiness."
        />
      </div>

      <p className="mt-2 max-w-3xl text-xs leading-5 text-slate-500">
        Metadata-only evidence of module availability and future completion activity. Human review of
        AI-assisted work remains required.
      </p>

      <div className="mt-4 flex flex-wrap gap-3">
        <label className="flex flex-col text-xs font-medium text-slate-500">
          Category
          <select
            value={category}
            onChange={(event) => setCategory(event.target.value)}
            className="mt-1 rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-normal text-slate-900"
          >
            {CATEGORY_FILTERS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col text-xs font-medium text-slate-500">
          Audience
          <select
            value={role}
            onChange={(event) => setRole(event.target.value)}
            className="mt-1 rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-normal text-slate-900"
          >
            {ROLE_FILTERS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="mt-5">
        {loading ? (
          <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading AI literacy modules...
          </div>
        ) : error ? (
          <div className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {error}
          </div>
        ) : modules && modules.length > 0 ? (
          <div className="grid gap-4 xl:grid-cols-2">
            {modules.map((module) => (
              <ModuleCard key={module.module_id} module={module} />
            ))}
          </div>
        ) : (
          <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No AI literacy modules match the current filters.
          </div>
        )}
      </div>
    </Card>
  );
}

function ModuleCard({ module }: { module: LearningModule }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-[0_8px_24px_rgba(42,52,57,0.05)]">
      <div className="flex items-start justify-between gap-3">
        <h3 className="text-base font-semibold text-slate-900">{module.title}</h3>
        <StatusBadge value={module.category} />
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-2">
        {module.category === "bias_detection" ? (
          <span className="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-2 py-0.5 text-xs font-medium text-amber-700">
            Bias detection
          </span>
        ) : null}
        <span className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs font-medium text-slate-600">
          {module.cpd_minutes} CPD minutes
        </span>
        <span className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs font-medium text-slate-500">
          v{module.version}
        </span>
      </div>

      <p className="mt-3 text-sm leading-6 text-slate-600">{module.summary}</p>

      {module.role_applicability.length > 0 ? (
        <PillGroup label="Audience" items={module.role_applicability.map(formatTag)} />
      ) : null}
      {module.rcvs_principle_mappings.length > 0 ? (
        <PillGroup
          label="RCVS principle mapping"
          items={module.rcvs_principle_mappings.map(formatTag)}
        />
      ) : null}
      {module.eu_ai_act_article_mappings.length > 0 ? (
        <PillGroup
          label="EU AI Act article mapping"
          items={module.eu_ai_act_article_mappings.map(formatTag)}
        />
      ) : null}
    </div>
  );
}

function PillGroup({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="mt-4">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <div className="mt-2 flex flex-wrap gap-2">
        {items.map((item) => (
          <span
            key={item}
            className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-medium capitalize text-slate-700"
          >
            {item}
          </span>
        ))}
      </div>
    </div>
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
