"use client";

import { AppShell } from "@/components/shell/AppShell";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";

const explainers = [
  {
    title: "Why a request may be flagged for privacy concerns",
    label: "privacy",
    explanation:
      "A request may attract additional governance attention when it appears to contain identifiable or privacy-sensitive details that should be handled more cautiously.",
    whatToLearn: [
      "Privacy concerns are about reducing avoidable risk, not blocking useful work unnecessarily.",
      "Users should think carefully about what information is being included in AI-assisted workflows.",
      "Governance surfaces help make these risks more visible without storing raw content in routine operational views.",
    ],
  },
  {
    title: "What replacement or modification outcomes mean",
    label: "governance",
    explanation:
      "Replacement or modification signals indicate that the governance layer intervened rather than leaving the request untouched.",
    whatToLearn: [
      "This usually means the system detected something that required safer handling.",
      "Interventions should be interpreted as operational signals, not as punishment.",
      "Repeated intervention patterns can indicate training or policy clarification needs.",
    ],
  },
  {
    title: "Why metadata-only governance matters",
    label: "core concept",
    explanation:
      "ANCHOR’s current doctrine centers on metadata-only accountability rather than building a raw-content archive.",
    whatToLearn: [
      "This supports auditability without normalizing broad content retention.",
      "The product is built for oversight and trust, not for storing everything users say to AI.",
      "This is part of ANCHOR’s commercial and ethical differentiation.",
    ],
  },
  {
    title: "How policy boundaries should be read",
    label: "policy",
    explanation:
      "Policy boundaries define what kinds of AI use fit the clinic’s operating model and where extra care or escalation is appropriate.",
    whatToLearn: [
      "Policy is there to create safe, repeatable use patterns.",
      "It should be read as a practical operating boundary, not abstract bureaucracy.",
      "Good policy understanding reduces friction and improves staff confidence.",
    ],
  },
];

export default function LearnExplainersPage() {
  return (
    <AppShell>
      <div className="space-y-6">
        <div>
          <p className="text-sm font-medium text-slate-500">ANCHOR Learn</p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Why was this flagged?</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            Plain-language explainers that help staff understand common governance signals, privacy concerns,
            and policy-boundary outcomes in day-to-day clinic AI use.
          </p>
        </div>

        <div className="grid gap-4 xl:grid-cols-2">
          {explainers.map((item) => (
            <Card key={item.title}>
              <div className="flex items-start justify-between gap-3">
                <h2 className="text-base font-semibold text-slate-900">{item.title}</h2>
                <StatusBadge value={item.label} />
              </div>

              <p className="mt-3 text-sm leading-6 text-slate-600">{item.explanation}</p>

              <div className="mt-4">
                <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
                  What staff should take from this
                </p>
                <ul className="mt-3 space-y-2 text-sm leading-6 text-slate-600">
                  {item.whatToLearn.map((point) => (
                    <li key={point}>• {point}</li>
                  ))}
                </ul>
              </div>
            </Card>
          ))}
        </div>

        <Card>
          <div>
            <h2 className="text-base font-semibold text-slate-900">Why this matters</h2>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
              One of ANCHOR Learn’s strongest roles is turning governance friction into practical understanding.
              Good explainers reduce uncertainty, improve safe AI use, and make the platform feel enabling rather than merely restrictive.
            </p>
          </div>
        </Card>
      </div>
    </AppShell>
  );
}