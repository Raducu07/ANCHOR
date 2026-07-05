"use client";

// Fable roadmap-completion experiment - Slice F3 (M4.6 Learn Maturity,
// internal preview).
//
// Self-check reinforcement panel for a Learn module detail page.
// Renders nothing when the internal-preview flag is off, so the shipped
// module page is unchanged in every deployed environment.
//
// Non-certifying doctrine: this is learning reinforcement, not a
// competence assessment. No pass/fail language anywhere; the backend
// self_check_note is displayed verbatim with every result.

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { InternalPreviewBadge } from "@/components/experiment/InternalPreviewGate";
import { ApiError } from "@/lib/api";
import { INTERNAL_PREVIEW_ENABLED } from "@/lib/internalPreview";
import {
  listModuleSelfChecks,
  submitSelfCheckAttempt,
} from "@/lib/learnMaturity";
import type {
  SelfCheckAttemptResponse,
  SelfCheckListResponse,
} from "@/lib/learnMaturity";

type SubmitState =
  | { kind: "idle" }
  | { kind: "submitting" }
  | { kind: "error"; message: string };

export function ModuleSelfCheck({ moduleId }: { moduleId: string }) {
  if (!INTERNAL_PREVIEW_ENABLED) return null;
  return <ModuleSelfCheckContent moduleId={moduleId} />;
}

function ModuleSelfCheckContent({ moduleId }: { moduleId: string }) {
  const [checks, setChecks] = useState<SelfCheckListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [selected, setSelected] = useState<Record<string, number>>({});
  const [submitState, setSubmitState] = useState<SubmitState>({ kind: "idle" });
  const [result, setResult] = useState<SelfCheckAttemptResponse | null>(null);

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);
      setLoadError(null);
      try {
        const response = await listModuleSelfChecks(moduleId);
        if (!active) return;
        setChecks(response);
      } catch (err: unknown) {
        if (!active) return;
        setChecks(null);
        // A module without self-checks (or a backend without this
        // surface) is a normal state for this preview, not an error.
        if (err instanceof ApiError && err.status === 404) {
          setLoadError(null);
        } else {
          setLoadError(
            err instanceof Error ? err.message : "Unable to load self-check questions.",
          );
        }
      } finally {
        if (active) setLoading(false);
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, [moduleId]);

  if (loading) return null;
  if (loadError === null && (!checks || checks.questions.length === 0)) return null;

  const questions = checks?.questions ?? [];
  const allAnswered =
    questions.length > 0 && questions.every((q) => selected[q.check_id] !== undefined);

  async function handleSubmit() {
    if (!allAnswered) return;
    setSubmitState({ kind: "submitting" });
    try {
      const response = await submitSelfCheckAttempt(
        moduleId,
        questions.map((q) => ({
          check_id: q.check_id,
          selected_option_index: selected[q.check_id],
        })),
      );
      setResult(response);
      setSubmitState({ kind: "idle" });
    } catch (err: unknown) {
      setSubmitState({
        kind: "error",
        message:
          err instanceof Error ? err.message : "Unable to record this self-check attempt.",
      });
    }
  }

  function handleRetry() {
    setResult(null);
    setSelected({});
    setSubmitState({ kind: "idle" });
  }

  const feedbackByCheckId = new Map(
    (result?.feedback ?? []).map((item) => [item.check_id, item]),
  );

  return (
    <Card variant="native">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <h2 className="text-base font-semibold text-slate-900">Self-check reinforcement</h2>
        <InternalPreviewBadge />
      </div>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
        A short learning-reinforcement self-check for this module. Answers are marked for
        immediate feedback; only aggregate counts are recorded as completion evidence.
      </p>

      {loadError ? (
        <div className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {loadError}
        </div>
      ) : (
        <>
          <div className="mt-4 space-y-5">
            {questions.map((question, questionIndex) => {
              const feedback = feedbackByCheckId.get(question.check_id);
              return (
                <div
                  key={question.check_id}
                  className="border-b border-slate-100 pb-5 last:border-b-0 last:pb-0"
                >
                  <p className="text-sm font-semibold text-slate-900">
                    {questionIndex + 1}. {question.prompt}
                  </p>
                  {question.kind === "scenario" ? (
                    <span className="mt-1 inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs font-medium text-slate-600">
                      Scenario question
                    </span>
                  ) : null}
                  <div className="mt-3 space-y-2">
                    {question.options.map((option, optionIndex) => {
                      const chosen = selected[question.check_id] === optionIndex;
                      const showAsHelpful =
                        feedback !== undefined && feedback.correct_option_index === optionIndex;
                      const showAsRevisit =
                        feedback !== undefined && chosen && !feedback.correct;
                      return (
                        <label
                          key={optionIndex}
                          className={[
                            "flex items-start gap-3 rounded-xl border px-3 py-2.5 text-sm leading-6",
                            showAsHelpful
                              ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                              : showAsRevisit
                                ? "border-amber-200 bg-amber-50 text-amber-800"
                                : chosen
                                  ? "border-slate-400 bg-slate-50 text-slate-900"
                                  : "border-slate-200 bg-white text-slate-700",
                            result ? "cursor-default" : "cursor-pointer hover:border-slate-300",
                          ].join(" ")}
                        >
                          <input
                            type="radio"
                            name={question.check_id}
                            checked={chosen}
                            disabled={result !== null || submitState.kind === "submitting"}
                            onChange={() =>
                              setSelected((prev) => ({
                                ...prev,
                                [question.check_id]: optionIndex,
                              }))
                            }
                            className="mt-1.5 h-4 w-4 border-slate-300"
                          />
                          <span>{option}</span>
                        </label>
                      );
                    })}
                  </div>
                  {feedback ? (
                    <p className="mt-3 text-sm leading-6 text-slate-600">
                      <span className="font-semibold text-slate-900">
                        {feedback.correct ? "Reinforced: " : "Worth revisiting: "}
                      </span>
                      {feedback.explanation}
                    </p>
                  ) : null}
                </div>
              );
            })}
          </div>

          {result ? (
            <div className="mt-5 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
              <p className="font-semibold text-slate-900">
                Self-check recorded: {result.questions_correct} of {result.questions_total}{" "}
                answers matched the reinforcement guidance.
              </p>
              <p className="mt-1 leading-6">
                Aggregate counts were recorded as learning-reinforcement completion evidence
                for module version {result.module_version}.
              </p>
            </div>
          ) : null}

          {submitState.kind === "error" ? (
            <div className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
              {submitState.message}
            </div>
          ) : null}

          <div className="mt-5 flex flex-wrap items-center gap-3">
            {result ? (
              <Button variant="secondary" onClick={handleRetry}>
                Try the self-check again
              </Button>
            ) : (
              <Button
                onClick={handleSubmit}
                disabled={!allAnswered}
                loading={submitState.kind === "submitting"}
              >
                Check my answers
              </Button>
            )}
            {!result && !allAnswered ? (
              <p className="text-xs text-slate-500">
                Answer every question to check your answers.
              </p>
            ) : null}
          </div>

          <p className="mt-4 max-w-3xl text-xs leading-5 text-slate-500">
            {checks?.self_check_note}
          </p>
        </>
      )}
    </Card>
  );
}
