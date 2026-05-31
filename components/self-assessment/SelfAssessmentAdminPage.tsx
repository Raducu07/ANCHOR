"use client";

// Phase 2A-3.5 - RCVS-aligned AI Governance Self-Assessment admin page.
//
// Metadata-only doctrine:
//   * No raw free-text answers. Answers are bounded enums only.
//   * No scoring, pass/fail, or competence grading.
//   * No staff identifiers surfaced in summary copy.
//   * Frontend admin gate is UX hardening only; the backend remains the
//     real authorization control.

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { ApiError } from "@/lib/api";
import {
  SESSION_SERVER_SNAPSHOT,
  getSessionUserSnapshot,
  subscribeSessionStorage,
} from "@/lib/auth";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import {
  archiveSelfAssessment,
  createSelfAssessmentDraft,
  getLatestSelfAssessments,
  getSelfAssessmentTemplate,
  listSelfAssessments,
  submitSelfAssessment,
  upsertSelfAssessmentAnswer,
} from "@/lib/selfAssessment";
import type {
  ClinicSelfAssessment,
  LatestSelfAssessmentEntry,
  SelfAssessmentAnswerValue,
  SelfAssessmentEvidenceLink,
  SelfAssessmentQuestion,
  SelfAssessmentTemplate,
} from "@/lib/types";

const ADMIN_ROLES = new Set(["admin", "owner", "practice_manager"]);

const TEMPLATE_SLUG = "rcvs_ai_governance_self_assessment";

const ANSWER_CHOICES: { value: SelfAssessmentAnswerValue; label: string }[] = [
  { value: "yes", label: "Yes" },
  { value: "partial", label: "Partial" },
  { value: "planned", label: "Planned" },
  { value: "no", label: "No" },
  { value: "not_applicable", label: "Not applicable" },
];

const EVIDENCE_CHOICES: { value: SelfAssessmentEvidenceLink; label: string }[] = [
  { value: "policy_library", label: "Policy library" },
  { value: "staff_attestation", label: "Staff attestation" },
  { value: "learn_cpd", label: "Learn / CPD activity" },
  { value: "assistant_receipts", label: "Assistant receipts" },
  { value: "trust_posture", label: "Trust posture" },
  { value: "manual_review", label: "Manual review" },
];

function formatDateTime(value?: string | null): string {
  if (!value) return "Not set";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function formatTag(value: string): string {
  return value.replace(/[_-]+/g, " ");
}

function errorMessageFromUnknown(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return fallback;
}

type ActionFeedback = { kind: "success" | "error"; message: string } | null;

type DraftAnswerState = {
  answerValue: SelfAssessmentAnswerValue | null;
  evidenceLinks: SelfAssessmentEvidenceLink[];
  saving: boolean;
};

function emptyAnswerState(): DraftAnswerState {
  return { answerValue: null, evidenceLinks: [], saving: false };
}

function buildAnswerMapFromDraft(
  draft: ClinicSelfAssessment | null,
  questions: SelfAssessmentQuestion[],
): Record<string, DraftAnswerState> {
  const map: Record<string, DraftAnswerState> = {};
  for (const q of questions) {
    map[q.question_slug] = emptyAnswerState();
  }
  if (!draft?.answers) return map;
  for (const a of draft.answers) {
    map[a.question_slug] = {
      answerValue: a.answer_value,
      evidenceLinks: [...a.evidence_links],
      saving: false,
    };
  }
  return map;
}

export function SelfAssessmentAdminPage() {
  const sessionUser = useSyncExternalStore(
    subscribeSessionStorage,
    getSessionUserSnapshot,
    SESSION_SERVER_SNAPSHOT,
  );
  const isAdmin = Boolean(sessionUser?.role && ADMIN_ROLES.has(sessionUser.role));

  const [template, setTemplate] = useState<SelfAssessmentTemplate | null>(null);
  const [questions, setQuestions] = useState<SelfAssessmentQuestion[] | null>(null);
  const [templateLoading, setTemplateLoading] = useState(false);
  const [templateError, setTemplateError] = useState<string | null>(null);

  const [latest, setLatest] = useState<LatestSelfAssessmentEntry[] | null>(null);
  const [latestLoading, setLatestLoading] = useState(false);
  const [latestError, setLatestError] = useState<string | null>(null);

  const [draft, setDraft] = useState<ClinicSelfAssessment | null>(null);
  const [draftLoading, setDraftLoading] = useState(false);
  const [draftError, setDraftError] = useState<string | null>(null);
  const [draftCreating, setDraftCreating] = useState(false);

  const [answerStates, setAnswerStates] = useState<Record<string, DraftAnswerState>>({});
  const [submitting, setSubmitting] = useState(false);
  const [archiving, setArchiving] = useState(false);
  const [feedback, setFeedback] = useState<ActionFeedback>(null);

  const loadTemplate = useCallback(async () => {
    setTemplateLoading(true);
    setTemplateError(null);
    try {
      const result = await getSelfAssessmentTemplate(TEMPLATE_SLUG);
      setTemplate(result.template);
      const ordered = [...result.questions].sort(
        (a, b) => a.question_order - b.question_order,
      );
      setQuestions(ordered);
    } catch (err) {
      setTemplate(null);
      setQuestions(null);
      setTemplateError(
        errorMessageFromUnknown(
          err,
          "The self-assessment template could not be loaded.",
        ),
      );
    } finally {
      setTemplateLoading(false);
    }
  }, []);

  const loadLatest = useCallback(async () => {
    setLatestLoading(true);
    setLatestError(null);
    try {
      const result = await getLatestSelfAssessments();
      setLatest(result.latest ?? []);
    } catch (err) {
      setLatest(null);
      setLatestError(
        errorMessageFromUnknown(
          err,
          "The latest self-assessment record could not be loaded.",
        ),
      );
    } finally {
      setLatestLoading(false);
    }
  }, []);

  const loadExistingDraft = useCallback(async () => {
    setDraftLoading(true);
    setDraftError(null);
    try {
      const result = await listSelfAssessments({ status: "draft", limit: 1 });
      const existing = result.assessments?.[0] ?? null;
      setDraft(existing);
    } catch (err) {
      // 403 is expected for non-admins; keep silent in that case.
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        setDraft(null);
      } else {
        setDraftError(
          errorMessageFromUnknown(
            err,
            "An existing draft could not be checked.",
          ),
        );
      }
    } finally {
      setDraftLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!isAdmin) return;
    void loadTemplate();
    void loadLatest();
    void loadExistingDraft();
  }, [isAdmin, loadTemplate, loadLatest, loadExistingDraft]);

  useEffect(() => {
    if (!questions) return;
    setAnswerStates(buildAnswerMapFromDraft(draft, questions));
  }, [draft, questions]);

  const handleStartDraft = useCallback(async () => {
    setDraftCreating(true);
    setFeedback(null);
    try {
      const result = await createSelfAssessmentDraft({
        templateSlug: TEMPLATE_SLUG,
      });
      setDraft(result.assessment);
      setFeedback({
        kind: "success",
        message: "Draft self-assessment ready. Answers below are saved per question.",
      });
    } catch (err) {
      setFeedback({
        kind: "error",
        message: errorMessageFromUnknown(
          err,
          "Unable to start a self-assessment draft.",
        ),
      });
    } finally {
      setDraftCreating(false);
    }
  }, []);

  const handleSelectAnswer = useCallback(
    (questionSlug: string, value: SelfAssessmentAnswerValue) => {
      setAnswerStates((prev) => ({
        ...prev,
        [questionSlug]: {
          ...(prev[questionSlug] ?? emptyAnswerState()),
          answerValue: value,
        },
      }));
    },
    [],
  );

  const handleToggleEvidence = useCallback(
    (questionSlug: string, link: SelfAssessmentEvidenceLink) => {
      setAnswerStates((prev) => {
        const current = prev[questionSlug] ?? emptyAnswerState();
        const present = current.evidenceLinks.includes(link);
        const next = present
          ? current.evidenceLinks.filter((l) => l !== link)
          : [...current.evidenceLinks, link];
        return {
          ...prev,
          [questionSlug]: { ...current, evidenceLinks: next },
        };
      });
    },
    [],
  );

  const handleSaveAnswer = useCallback(
    async (question: SelfAssessmentQuestion) => {
      if (!draft) return;
      const state = answerStates[question.question_slug];
      if (!state?.answerValue) return;
      setAnswerStates((prev) => ({
        ...prev,
        [question.question_slug]: { ...state, saving: true },
      }));
      setFeedback(null);
      try {
        const result = await upsertSelfAssessmentAnswer({
          assessmentId: draft.assessment_id,
          questionSlug: question.question_slug,
          answerValue: state.answerValue,
          evidenceLinks: state.evidenceLinks,
        });
        setDraft(result.assessment);
        setFeedback({
          kind: "success",
          message: "Answer saved.",
        });
      } catch (err) {
        setAnswerStates((prev) => ({
          ...prev,
          [question.question_slug]: {
            ...(prev[question.question_slug] ?? emptyAnswerState()),
            saving: false,
          },
        }));
        setFeedback({
          kind: "error",
          message: errorMessageFromUnknown(err, "Unable to save this answer."),
        });
      }
    },
    [answerStates, draft],
  );

  const handleSubmit = useCallback(async () => {
    if (!draft) return;
    setSubmitting(true);
    setFeedback(null);
    try {
      const result = await submitSelfAssessment(draft.assessment_id);
      setDraft(null);
      await loadLatest();
      setFeedback({
        kind: "success",
        message:
          "Self-assessment submitted as a dated metadata-only governance record.",
      });
      // intentionally keep result.assessment available for future use; not needed in UI yet
      void result;
    } catch (err) {
      setFeedback({
        kind: "error",
        message: errorMessageFromUnknown(
          err,
          "Unable to submit the self-assessment.",
        ),
      });
    } finally {
      setSubmitting(false);
    }
  }, [draft, loadLatest]);

  const handleArchive = useCallback(async () => {
    if (!draft) return;
    setArchiving(true);
    setFeedback(null);
    try {
      await archiveSelfAssessment(draft.assessment_id);
      setDraft(null);
      setFeedback({
        kind: "success",
        message: "Draft archived. You can start a new draft when ready.",
      });
    } catch (err) {
      setFeedback({
        kind: "error",
        message: errorMessageFromUnknown(
          err,
          "Unable to archive this draft.",
        ),
      });
    } finally {
      setArchiving(false);
    }
  }, [draft]);

  const allAnswered = useMemo(() => {
    if (!draft || !questions || questions.length === 0) return false;
    return questions.every(
      (q) => answerStates[q.question_slug]?.answerValue != null,
    );
  }, [answerStates, draft, questions]);

  if (!isAdmin) {
    return (
      <div className="space-y-6">
        <div>
          <p className="text-sm font-medium text-slate-500">Clinic administration</p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
            RCVS-aligned AI Governance Self-Assessment
          </h1>
        </div>
        <Card variant="native">
          <p className="text-sm leading-6 text-slate-700">
            The self-assessment workflow is available to clinic administrators
            only. Contact your clinic administrator if you need access. Human
            review remains required.
          </p>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <p className="text-sm font-medium text-slate-500">Clinic administration</p>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          RCVS-aligned AI Governance Self-Assessment
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          Complete a metadata-only governance self-assessment for clinic review
          and readiness evidence. Human review remains required.
        </p>
      </div>

      <Card variant="native">
        <SectionTitle title="About this self-assessment" />
        <ul className="mt-3 list-disc space-y-1 pl-5 text-sm leading-6 text-slate-700">
          <li>Metadata-only. Answers are bounded choices; no free-text notes are captured.</li>
          <li>Supports governance review and produces readiness evidence for the clinic.</li>
          <li>Does not replace professional judgement or legal advice.</li>
          <li>Human review remains required for every clinical decision.</li>
        </ul>
      </Card>

      {feedback ? (
        <div
          className={[
            "rounded-xl border px-4 py-3 text-sm",
            feedback.kind === "success"
              ? "border-emerald-200 bg-emerald-50 text-emerald-700"
              : "border-rose-200 bg-rose-50 text-rose-700",
          ].join(" ")}
          role="status"
        >
          {feedback.message}
        </div>
      ) : null}

      <Card variant="native">
        <SectionTitle
          title="Latest submitted self-assessment"
          description="The most recent dated metadata-only governance record for this clinic."
        />
        {latestLoading && latest === null ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading latest self-assessment...
          </p>
        ) : latestError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {latestError}
          </p>
        ) : (() => {
            const entry = latest?.find((l) => l.template_slug === TEMPLATE_SLUG);
            const submitted = entry?.assessment ?? null;
            if (!submitted) {
              return (
                <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
                  No submitted self-assessment yet.
                </p>
              );
            }
            return (
              <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-4">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <p className="text-sm font-semibold text-slate-900">
                      {submitted.title_snapshot}
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      Template v{submitted.template_version_snapshot} - clinic version v
                      {submitted.clinic_assessment_version}
                    </p>
                  </div>
                  <StatusBadge value={submitted.status} />
                </div>
                <div className="mt-3 space-y-1">
                  <DetailLine
                    label="Submitted"
                    value={formatDateTime(submitted.submitted_at)}
                  />
                  <DetailLine
                    label="Answered"
                    value={`${submitted.answered_questions} of ${submitted.total_questions}`}
                  />
                  <DetailLine
                    label="Gap count"
                    value={String(submitted.gap_count)}
                  />
                </div>
              </div>
            );
          })()}
      </Card>

      <Card variant="native">
        <SectionTitle
          title="Template"
          description="ANCHOR-curated RCVS-aligned self-assessment template."
        />
        {templateLoading && template === null ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading template...
          </p>
        ) : templateError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {templateError}
          </p>
        ) : !template ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No self-assessment template is available.
          </p>
        ) : (
          <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-4">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <h3 className="text-sm font-semibold text-slate-900">
                {template.title}
              </h3>
              <StatusBadge value={template.is_active ? "active" : "inactive"} />
            </div>
            <p className="mt-2 text-sm leading-6 text-slate-600">
              {template.summary}
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              <Pill label={`v${template.template_version}`} />
              <Pill label={`${template.total_questions} questions`} />
            </div>
            {template.source_basis.length > 0 ? (
              <PillGroup
                label="Source basis"
                items={template.source_basis.map(formatTag)}
              />
            ) : null}
            {template.jurisdiction_tags.length > 0 ? (
              <PillGroup
                label="Jurisdiction"
                items={template.jurisdiction_tags.map(formatTag)}
              />
            ) : null}
          </div>
        )}
      </Card>

      <Card variant="native">
        <SectionTitle
          title="Draft self-assessment"
          description="Save each answer as you go. Submit when all questions are answered."
        />
        {draftError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {draftError}
          </p>
        ) : null}
        {!draft ? (
          <div className="mt-4 flex flex-wrap items-center gap-3">
            <Button
              onClick={() => void handleStartDraft()}
              loading={draftCreating}
              disabled={draftCreating || draftLoading || !template}
            >
              Start self-assessment draft
            </Button>
            {draftLoading ? (
              <span className="text-xs text-slate-500">
                Checking for existing draft...
              </span>
            ) : null}
          </div>
        ) : (
          <div className="mt-4 space-y-3">
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <p className="text-sm font-semibold text-slate-900">
                    Active draft
                  </p>
                  <p className="mt-1 text-xs text-slate-500">
                    Clinic version v{draft.clinic_assessment_version} - template v
                    {draft.template_version_snapshot}
                  </p>
                </div>
                <StatusBadge value={draft.status} />
              </div>
              <div className="mt-3 space-y-1">
                <DetailLine
                  label="Answered"
                  value={`${draft.answered_questions} of ${draft.total_questions}`}
                />
                <DetailLine
                  label="Created"
                  value={formatDateTime(draft.created_at)}
                />
                <DetailLine
                  label="Updated"
                  value={formatDateTime(draft.updated_at)}
                />
              </div>
              <div className="mt-4 flex flex-wrap gap-2">
                <Button
                  onClick={() => void handleSubmit()}
                  loading={submitting}
                  disabled={!allAnswered || submitting || archiving}
                >
                  Submit self-assessment
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => void handleArchive()}
                  loading={archiving}
                  disabled={submitting || archiving}
                >
                  Archive draft
                </Button>
              </div>
              {!allAnswered ? (
                <p className="mt-2 text-xs text-slate-500">
                  Submission becomes available once every question has a saved
                  answer.
                </p>
              ) : null}
            </div>
          </div>
        )}
      </Card>

      <Card variant="native">
        <SectionTitle
          title="Questions"
          description="Bounded answer choices and metadata-only evidence links."
        />
        {!questions || questions.length === 0 ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No questions are available yet.
          </p>
        ) : (
          <ol className="mt-4 space-y-4">
            {questions.map((q) => {
              const state = answerStates[q.question_slug] ?? emptyAnswerState();
              const disabled = !draft || state.saving || submitting || archiving;
              return (
                <li
                  key={q.question_id}
                  className="rounded-xl border border-slate-200 bg-slate-50 p-4"
                >
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <p className="text-sm font-semibold text-slate-900">
                      {q.question_order}. {q.question_text}
                    </p>
                    {q.rcvs_theme ? (
                      <Pill label={`Theme: ${formatTag(q.rcvs_theme)}`} />
                    ) : null}
                  </div>
                  {q.guidance ? (
                    <p className="mt-2 text-sm leading-6 text-slate-600">
                      {q.guidance}
                    </p>
                  ) : null}
                  {q.source_basis.length > 0 ? (
                    <PillGroup
                      label="Source basis"
                      items={q.source_basis.map(formatTag)}
                    />
                  ) : null}
                  {q.suggested_evidence_links.length > 0 ? (
                    <PillGroup
                      label="Suggested evidence"
                      items={q.suggested_evidence_links.map(formatTag)}
                    />
                  ) : null}

                  <fieldset className="mt-3">
                    <legend className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
                      Answer
                    </legend>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {ANSWER_CHOICES.map((choice) => {
                        const checked = state.answerValue === choice.value;
                        return (
                          <label
                            key={choice.value}
                            className={[
                              "inline-flex cursor-pointer items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium transition",
                              checked
                                ? "border-slate-900 bg-slate-900 text-white"
                                : "border-slate-200 bg-white text-slate-700 hover:border-slate-300",
                              disabled ? "cursor-not-allowed opacity-60" : "",
                            ].join(" ")}
                          >
                            <input
                              type="radio"
                              className="sr-only"
                              name={`answer-${q.question_slug}`}
                              value={choice.value}
                              checked={checked}
                              disabled={disabled}
                              onChange={() =>
                                handleSelectAnswer(q.question_slug, choice.value)
                              }
                            />
                            {choice.label}
                          </label>
                        );
                      })}
                    </div>
                  </fieldset>

                  <fieldset className="mt-3">
                    <legend className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
                      Evidence links
                    </legend>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {EVIDENCE_CHOICES.map((choice) => {
                        const checked = state.evidenceLinks.includes(
                          choice.value,
                        );
                        return (
                          <label
                            key={choice.value}
                            className={[
                              "inline-flex cursor-pointer items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium transition",
                              checked
                                ? "border-slate-900 bg-white text-slate-900"
                                : "border-slate-200 bg-white text-slate-600 hover:border-slate-300",
                              disabled ? "cursor-not-allowed opacity-60" : "",
                            ].join(" ")}
                          >
                            <input
                              type="checkbox"
                              className="h-3.5 w-3.5"
                              checked={checked}
                              disabled={disabled}
                              onChange={() =>
                                handleToggleEvidence(q.question_slug, choice.value)
                              }
                            />
                            {choice.label}
                          </label>
                        );
                      })}
                    </div>
                  </fieldset>

                  <div className="mt-4">
                    <Button
                      onClick={() => void handleSaveAnswer(q)}
                      loading={state.saving}
                      disabled={disabled || state.answerValue == null}
                    >
                      Save answer
                    </Button>
                    {!draft ? (
                      <span className="ml-3 text-xs text-slate-500">
                        Start a draft above to save answers.
                      </span>
                    ) : null}
                  </div>
                </li>
              );
            })}
          </ol>
        )}
      </Card>
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
      {description ? (
        <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p>
      ) : null}
    </div>
  );
}

function Pill({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center rounded-full border border-slate-200 bg-white px-2 py-0.5 text-xs font-medium capitalize text-slate-600">
      {label}
    </span>
  );
}

function PillGroup({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="mt-3">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
        {label}
      </p>
      <div className="mt-2 flex flex-wrap gap-2">
        {items.map((item) => (
          <span
            key={item}
            className="inline-flex items-center rounded-full border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium capitalize text-slate-700"
          >
            {item}
          </span>
        ))}
      </div>
    </div>
  );
}

function DetailLine({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="flex flex-wrap items-baseline gap-x-2 text-xs text-slate-600">
      <span className="font-medium text-slate-500">{label}:</span>
      <span className="text-slate-700">{value}</span>
    </div>
  );
}
