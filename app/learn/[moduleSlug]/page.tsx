"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { AppShell } from "@/components/shell/AppShell";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { Button } from "@/components/ui/Button";
import { ApiError } from "@/lib/api";
import { findLearningModuleBySlug, recordLearningCompletion } from "@/lib/learn";
import type { LearningModule } from "@/lib/types";

function formatTag(value: string) {
  return value.replace(/[_-]+/g, " ");
}

type CompletionState =
  | { kind: "idle" }
  | { kind: "submitting" }
  | { kind: "recorded" }
  | { kind: "already_completed" }
  | { kind: "error"; message: string };

export default function LearnModuleDetailPage() {
  const params = useParams<{ moduleSlug: string | string[] }>();
  const moduleSlug =
    typeof params.moduleSlug === "string" ? params.moduleSlug : "";

  const [module, setModule] = useState<LearningModule | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [acknowledged, setAcknowledged] = useState(false);
  const [completion, setCompletion] = useState<CompletionState>({ kind: "idle" });

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);
      setError(null);
      setNotFound(false);
      try {
        const result = await findLearningModuleBySlug(moduleSlug);
        if (!active) return;
        if (!result) {
          setNotFound(true);
          setModule(null);
        } else {
          setModule(result);
        }
      } catch (err: unknown) {
        if (!active) return;
        const message =
          err instanceof Error ? err.message : "Unable to load this AI literacy module.";
        setError(message);
        setModule(null);
      } finally {
        if (active) setLoading(false);
      }
    }

    void load();

    return () => {
      active = false;
    };
  }, [moduleSlug]);

  async function handleMarkComplete() {
    if (!module) return;
    setCompletion({ kind: "submitting" });
    try {
      await recordLearningCompletion({
        module_id: module.module_id,
        acknowledgement_provided: acknowledged,
      });
      setCompletion({ kind: "recorded" });
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 409) {
        setCompletion({ kind: "already_completed" });
        return;
      }
      const message =
        err instanceof Error ? err.message : "Unable to record completion.";
      setCompletion({ kind: "error", message });
    }
  }

  return (
    <AppShell>
      <div className="mx-auto max-w-4xl space-y-6">
        <div>
          <Link
            href="/learn"
            className="text-sm font-medium text-slate-500 underline underline-offset-4 hover:text-slate-700"
          >
            Back to Learn
          </Link>
        </div>

        {loading ? (
          <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading AI literacy module...
          </div>
        ) : error ? (
          <div className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {error}
          </div>
        ) : notFound || !module ? (
          <Card variant="native">
            <h1 className="text-xl font-semibold text-slate-900">Module not found</h1>
            <p className="mt-2 text-sm leading-6 text-slate-600">
              This AI literacy module is not available in the current catalogue.
            </p>
            <div className="mt-4">
              <Link
                href="/learn"
                className="text-sm font-medium text-slate-900 underline underline-offset-4"
              >
                Return to the module catalogue
              </Link>
            </div>
          </Card>
        ) : (
          <>
            <div>
              <p className="text-sm font-medium text-slate-500">ANCHOR Learn</p>
              <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
                {module.title}
              </h1>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <StatusBadge value={module.category} />
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
              <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-600">{module.summary}</p>
            </div>

            {module.learning_objectives.length > 0 ? (
              <Card variant="native">
                <h2 className="text-base font-semibold text-slate-900">Learning objectives</h2>
                <ul className="mt-4 space-y-2 text-sm leading-6 text-slate-600">
                  {module.learning_objectives.map((objective) => (
                    <li key={objective}>&bull; {objective}</li>
                  ))}
                </ul>
              </Card>
            ) : null}

            <Card variant="native">
              <h2 className="text-base font-semibold text-slate-900">Module mapping</h2>
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
            </Card>

            <Card variant="native">
              <h2 className="text-base font-semibold text-slate-900">Record completion</h2>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
                Marking this module complete records metadata-only evidence of AI literacy activity.
                Human review of AI-assisted work remains required.
              </p>

              {completion.kind === "recorded" ? (
                <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
                  Completion recorded as metadata-only evidence of CPD-recordable AI literacy activity.
                </div>
              ) : completion.kind === "already_completed" ? (
                <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700">
                  This module version is already recorded as complete for your account.
                </div>
              ) : (
                <>
                  <label className="mt-4 flex items-start gap-3 text-sm leading-6 text-slate-700">
                    <input
                      type="checkbox"
                      checked={acknowledged}
                      onChange={(event) => setAcknowledged(event.target.checked)}
                      className="mt-1 h-4 w-4 rounded border-slate-300"
                    />
                    <span>I confirm I have reviewed this AI literacy module.</span>
                  </label>

                  {completion.kind === "error" ? (
                    <div className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
                      {completion.message}
                    </div>
                  ) : null}

                  <div className="mt-4">
                    <Button
                      onClick={handleMarkComplete}
                      loading={completion.kind === "submitting"}
                    >
                      Mark complete
                    </Button>
                  </div>
                </>
              )}
            </Card>
          </>
        )}
      </div>
    </AppShell>
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
