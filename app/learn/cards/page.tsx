"use client";

import { AppShell } from "@/components/shell/AppShell";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";

const cards = [
  {
    title: "Metadata-only accountability",
    category: "core concept",
    summary:
      "ANCHOR is designed to provide governance evidence without storing raw prompt or output content in the current product doctrine.",
    keyPoints: [
      "Receipts and events record governance metadata rather than chat history.",
      "This reduces unnecessary content retention risk.",
      "The product is designed for oversight, not raw-content archiving.",
    ],
  },
  {
    title: "Handling PII safely",
    category: "privacy",
    summary:
      "Privacy-sensitive details require greater care in AI-assisted workflows, especially when staff are drafting or summarizing material.",
    keyPoints: [
      "Not all details should be moved casually into AI-assisted workflows.",
      "Identifiable information should be handled carefully and intentionally.",
      "Governance and privacy surfaces exist to reduce avoidable risk, not to replace staff judgment.",
    ],
  },
  {
    title: "Human review responsibility",
    category: "safe use",
    summary:
      "AI-assisted outputs still require professional review before being used in clinic operations.",
    keyPoints: [
      "AI assistance does not remove accountability from the human user.",
      "Staff remain responsible for checking accuracy, tone, and appropriateness.",
      "Review is especially important when communication or operational consequences matter.",
    ],
  },
  {
    title: "When AI assistance is appropriate",
    category: "workflow",
    summary:
      "AI can support drafting, summarization, and communication assistance when used within policy boundaries and with review.",
    keyPoints: [
      "Use AI as support, not as an unchecked authority.",
      "Low-risk drafting tasks are often more suitable than sensitive or ambiguous tasks.",
      "When uncertainty is high, escalation and human judgment should take priority.",
    ],
  },
  {
    title: "Understanding governance receipts",
    category: "receipts",
    summary:
      "Receipts provide traceable governance evidence for a request without exposing raw content.",
    keyPoints: [
      "They summarize decision, risk, privacy handling, and policy traceability.",
      "They support clinic-scoped auditability and operational review.",
      "They are one of ANCHOR’s clearest accountability surfaces.",
    ],
  },
  {
    title: "When escalation is better",
    category: "judgment",
    summary:
      "Some situations are not well suited to routine AI assistance and should be escalated or handled more carefully.",
    keyPoints: [
      "Escalate when privacy sensitivity, ambiguity, or operational risk is high.",
      "Do not rely on AI assistance to resolve unclear or high-stakes judgment calls.",
      "Safe adoption depends on knowing when not to use AI casually.",
    ],
  },
];

export default function LearnCardsPage() {
  return (
    <AppShell>
      <div className="space-y-6">
        <div>
          <p className="text-sm font-medium text-slate-500">ANCHOR Learn</p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Microlearning cards</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            Short practical learning units designed to strengthen safe AI use, privacy awareness, and governance literacy
            in veterinary clinic settings.
          </p>
        </div>

        <div className="grid gap-4 xl:grid-cols-2">
          {cards.map((card) => (
            <Card variant="native" key={card.title}>
              <div className="flex items-start justify-between gap-3">
                <h2 className="text-base font-semibold text-slate-900">{card.title}</h2>
                <StatusBadge value={card.category} />
              </div>

              <p className="mt-3 text-sm leading-6 text-slate-600">{card.summary}</p>

              <div className="mt-4">
                <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
                  Key points
                </p>
                <ul className="mt-3 space-y-2 text-sm leading-6 text-slate-600">
                  {card.keyPoints.map((point) => (
                    <li key={point}>&bull; {point}</li>
                  ))}
                </ul>
              </div>
            </Card>
          ))}
        </div>
      </div>
    </AppShell>
  );
}
