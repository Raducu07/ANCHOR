"use client";

// Phase 2A-5.6 - Incident / Near-Miss create + list page.
//
// Metadata-only doctrine:
//   * No free-text narrative, no summary/note/description/comment, no
//     clinical content, no client/patient/staff identifiers, no raw
//     prompts/outputs/transcripts.
//   * All record fields are bounded enums sourced from the backend
//     vocabulary endpoint; optional links are ID-only references.
//   * No review / close / void controls in this slice; those are
//     deferred to Phase 2A-5.7.
//   * Frontend admin gate is UX hardening only; backend remains the
//     real authorization control.

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  useSyncExternalStore,
} from "react";
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
  createIncidentNearMissRecord,
  getIncidentNearMissSummary,
  getIncidentNearMissVocabulary,
  listIncidentNearMissRecords,
  listMyIncidentNearMissRecords,
} from "@/lib/incidentNearMiss";
import type {
  IncidentNearMissActionTakenCategory,
  IncidentNearMissCategory,
  IncidentNearMissCreateRequest,
  IncidentNearMissOutcome,
  IncidentNearMissRecord,
  IncidentNearMissSeverity,
  IncidentNearMissSource,
  IncidentNearMissStatus,
  IncidentNearMissSummary,
  IncidentNearMissVocabularyResponse,
} from "@/lib/types";

const ADMIN_ROLES = new Set(["admin", "owner", "practice_manager"]);

function titleCase(value?: string | null): string {
  if (!value) return "-";
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

function formatDateTime(value?: string | null): string {
  if (!value) return "Not set";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function trimOrNull(value: string): string | null {
  const v = value.trim();
  return v.length > 0 ? v : null;
}

function errorMessageFromUnknown(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    const msg = err.message ?? "";
    if (err.status === 401 || err.status === 403) {
      return "You do not have permission to perform this action.";
    }
    if (err.status === 404 && /linked|not_found/i.test(msg)) {
      return "Linked metadata record was not found for this clinic.";
    }
    if (err.status === 400 || err.status === 422) {
      return "Unable to create record. Check the selected structured fields and try again.";
    }
    if (err.message) return err.message;
  }
  if (err instanceof Error) return err.message;
  return fallback;
}

type ActionFeedback = { kind: "success" | "error"; message: string } | null;

type CreateFormState = {
  category: IncidentNearMissCategory | "";
  severity: IncidentNearMissSeverity | "";
  source: IncidentNearMissSource | "";
  outcome: IncidentNearMissOutcome | "";
  actionTakenCategory: IncidentNearMissActionTakenCategory | "";
  occurredAt: string;
  detectedAt: string;
  learningRecommended: boolean;
  policyReviewRecommended: boolean;
  clientCommunicationReviewRecommended: boolean;
  linkedReceiptId: string;
  linkedGovernanceEventId: string;
  linkedAssistantRunId: string;
  linkedClinicPolicyVersionId: string;
};

type ListFilterState = {
  status: IncidentNearMissStatus | "";
  severity: IncidentNearMissSeverity | "";
};

function emptyCreateForm(
  vocab: IncidentNearMissVocabularyResponse | null,
): CreateFormState {
  return {
    category: vocab?.categories?.[0] ?? "misleading_output",
    severity: vocab?.severities?.[0] ?? "low",
    source: vocab?.sources?.[0] ?? "assistant_workspace",
    outcome: vocab?.outcomes?.[0] ?? "caught_before_use",
    actionTakenCategory: "",
    occurredAt: "",
    detectedAt: "",
    learningRecommended: false,
    policyReviewRecommended: false,
    clientCommunicationReviewRecommended: false,
    linkedReceiptId: "",
    linkedGovernanceEventId: "",
    linkedAssistantRunId: "",
    linkedClinicPolicyVersionId: "",
  };
}

function emptyFilter(): ListFilterState {
  return { status: "", severity: "" };
}

export function IncidentNearMissPage() {
  const sessionUser = useSyncExternalStore(
    subscribeSessionStorage,
    getSessionUserSnapshot,
    SESSION_SERVER_SNAPSHOT,
  );
  const isAdmin = Boolean(sessionUser?.role && ADMIN_ROLES.has(sessionUser.role));

  const [vocab, setVocab] =
    useState<IncidentNearMissVocabularyResponse | null>(null);
  const [vocabLoading, setVocabLoading] = useState(false);
  const [vocabError, setVocabError] = useState<string | null>(null);

  const [summary, setSummary] = useState<IncidentNearMissSummary | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [summaryError, setSummaryError] = useState<string | null>(null);

  const [myRecords, setMyRecords] = useState<IncidentNearMissRecord[] | null>(null);
  const [myLoading, setMyLoading] = useState(false);
  const [myError, setMyError] = useState<string | null>(null);
  const [myFilter, setMyFilter] = useState<ListFilterState>(emptyFilter);

  const [allRecords, setAllRecords] = useState<IncidentNearMissRecord[] | null>(null);
  const [allLoading, setAllLoading] = useState(false);
  const [allError, setAllError] = useState<string | null>(null);
  const [allFilter, setAllFilter] = useState<ListFilterState>(emptyFilter);

  const [createForm, setCreateForm] = useState<CreateFormState>(() =>
    emptyCreateForm(null),
  );
  const [creating, setCreating] = useState(false);
  const [feedback, setFeedback] = useState<ActionFeedback>(null);

  // ----- Loaders -----

  const loadVocab = useCallback(async () => {
    setVocabLoading(true);
    setVocabError(null);
    try {
      const result = await getIncidentNearMissVocabulary();
      setVocab(result);
      setCreateForm((prev) => {
        // Initialise enum defaults from the loaded vocab only if the user
        // has not yet changed them away from the placeholder.
        const isUntouched =
          prev.category === "misleading_output" &&
          prev.severity === "low" &&
          prev.source === "assistant_workspace" &&
          prev.outcome === "caught_before_use" &&
          prev.actionTakenCategory === "" &&
          !prev.learningRecommended &&
          !prev.policyReviewRecommended &&
          !prev.clientCommunicationReviewRecommended &&
          prev.occurredAt === "" &&
          prev.detectedAt === "" &&
          prev.linkedReceiptId === "" &&
          prev.linkedGovernanceEventId === "" &&
          prev.linkedAssistantRunId === "" &&
          prev.linkedClinicPolicyVersionId === "";
        return isUntouched ? emptyCreateForm(result) : prev;
      });
    } catch (err) {
      setVocab(null);
      setVocabError(
        errorMessageFromUnknown(
          err,
          "Incident vocabulary could not be loaded.",
        ),
      );
    } finally {
      setVocabLoading(false);
    }
  }, []);

  const loadSummary = useCallback(async () => {
    setSummaryLoading(true);
    setSummaryError(null);
    try {
      const result = await getIncidentNearMissSummary();
      setSummary(result.summary ?? null);
    } catch (err) {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        setSummary(null);
      } else {
        setSummaryError(
          errorMessageFromUnknown(
            err,
            "Incident summary could not be loaded.",
          ),
        );
      }
    } finally {
      setSummaryLoading(false);
    }
  }, []);

  const loadMyRecords = useCallback(
    async (filter: ListFilterState) => {
      setMyLoading(true);
      setMyError(null);
      try {
        const result = await listMyIncidentNearMissRecords({
          status: filter.status || undefined,
          severity: filter.severity || undefined,
          limit: 25,
        });
        setMyRecords(result.records ?? []);
      } catch (err) {
        if (
          err instanceof ApiError &&
          (err.status === 401 || err.status === 403)
        ) {
          setMyRecords([]);
        } else {
          setMyRecords(null);
          setMyError(
            errorMessageFromUnknown(
              err,
              "Your incident / near-miss records could not be loaded.",
            ),
          );
        }
      } finally {
        setMyLoading(false);
      }
    },
    [],
  );

  const loadAllRecords = useCallback(
    async (filter: ListFilterState) => {
      if (!isAdmin) return;
      setAllLoading(true);
      setAllError(null);
      try {
        const result = await listIncidentNearMissRecords({
          status: filter.status || undefined,
          severity: filter.severity || undefined,
          limit: 25,
        });
        setAllRecords(result.records ?? []);
      } catch (err) {
        if (
          err instanceof ApiError &&
          (err.status === 401 || err.status === 403)
        ) {
          setAllRecords([]);
        } else {
          setAllRecords(null);
          setAllError(
            errorMessageFromUnknown(
              err,
              "Clinic incident / near-miss records could not be loaded.",
            ),
          );
        }
      } finally {
        setAllLoading(false);
      }
    },
    [isAdmin],
  );

  const reloadAll = useCallback(async () => {
    await Promise.all([
      loadSummary(),
      loadMyRecords(myFilter),
      isAdmin ? loadAllRecords(allFilter) : Promise.resolve(),
    ]);
  }, [loadSummary, loadMyRecords, loadAllRecords, isAdmin, myFilter, allFilter]);

  useEffect(() => {
    void loadVocab();
    void loadSummary();
    void loadMyRecords(myFilter);
    if (isAdmin) void loadAllRecords(allFilter);
    // Run once on mount; subsequent reloads are explicit.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  // ----- Create -----

  function isFormReady(form: CreateFormState): form is CreateFormState & {
    category: IncidentNearMissCategory;
    severity: IncidentNearMissSeverity;
    source: IncidentNearMissSource;
    outcome: IncidentNearMissOutcome;
  } {
    return Boolean(form.category && form.severity && form.source && form.outcome);
  }

  async function handleCreate() {
    if (!isFormReady(createForm)) {
      setFeedback({
        kind: "error",
        message: "Select a category, severity, source, and outcome before submitting.",
      });
      return;
    }
    setFeedback(null);
    setCreating(true);
    try {
      const body: IncidentNearMissCreateRequest = {
        category: createForm.category,
        severity: createForm.severity,
        source: createForm.source,
        outcome: createForm.outcome,
        action_taken_category: createForm.actionTakenCategory
          ? createForm.actionTakenCategory
          : null,
        occurred_at: trimOrNull(createForm.occurredAt),
        detected_at: trimOrNull(createForm.detectedAt),
        learning_recommended: createForm.learningRecommended,
        policy_review_recommended: createForm.policyReviewRecommended,
        client_communication_review_recommended:
          createForm.clientCommunicationReviewRecommended,
        linked_receipt_id: trimOrNull(createForm.linkedReceiptId),
        linked_governance_event_id: trimOrNull(createForm.linkedGovernanceEventId),
        linked_assistant_run_id: trimOrNull(createForm.linkedAssistantRunId),
        linked_clinic_policy_version_id: trimOrNull(
          createForm.linkedClinicPolicyVersionId,
        ),
      };
      await createIncidentNearMissRecord(body);
      setFeedback({
        kind: "success",
        message: "Incident / near-miss record created.",
      });
      setCreateForm(emptyCreateForm(vocab));
      await reloadAll();
    } catch (err) {
      setFeedback({
        kind: "error",
        message: errorMessageFromUnknown(
          err,
          "Unable to create incident / near-miss record.",
        ),
      });
    } finally {
      setCreating(false);
    }
  }

  // ----- Derived -----

  const sortedMy = useMemo(() => sortByReportedDesc(myRecords ?? []), [myRecords]);
  const sortedAll = useMemo(() => sortByReportedDesc(allRecords ?? []), [allRecords]);

  // ----- Render -----

  return (
    <div className="space-y-6">
      <div>
        <p className="text-sm font-medium text-slate-500">Clinic governance</p>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          Incident &amp; near-miss logging
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          Record structured, metadata-only AI-use review signals for clinic
          governance and learning. Human professional review remains required.
        </p>
      </div>

      <Card variant="native">
        <SectionTitle title="About this surface" />
        <ul className="mt-3 list-disc space-y-1 pl-5 text-sm leading-6 text-slate-700">
          <li>
            This surface records structured governance metadata only. Do not
            enter client identifiers, patient identifiers, case notes, clinical
            findings, raw prompts, outputs, transcripts, or free-text narrative.
          </li>
          <li>
            This is not a clinical record, legal report, or regulator report.
            It does not replace professional incident reporting duties.
          </li>
          <li>Bounded enum fields only. No free-text request or response fields.</li>
          <li>Human professional review remains required.</li>
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

      {/* ---------- Summary ---------- */}
      <Card variant="native">
        <SectionTitle
          title="Summary"
          description="Aggregate metadata about clinic incident and near-miss records."
        />
        {summaryLoading && !summary ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading summary...
          </p>
        ) : summaryError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {summaryError}
          </p>
        ) : !summary ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No incident or near-miss records have been logged yet.
          </p>
        ) : (
          <SummaryBlock summary={summary} />
        )}
      </Card>

      {/* ---------- Create ---------- */}
      <Card variant="native">
        <SectionTitle
          title="Create structured record"
          description="Bounded fields only. No free-text narrative is captured."
        />
        {vocabLoading && !vocab ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading vocabulary...
          </p>
        ) : vocabError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {vocabError}
          </p>
        ) : !vocab ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Incident vocabulary is not available.
          </p>
        ) : (
          <CreateFormFields
            form={createForm}
            vocab={vocab}
            onChange={setCreateForm}
            disabled={creating}
            submitting={creating}
            onSubmit={() => void handleCreate()}
          />
        )}
      </Card>

      {/* ---------- My records ---------- */}
      <Card variant="native">
        <SectionTitle
          title="My records"
          description="Records you have created."
        />
        <FilterRow
          filter={myFilter}
          vocab={vocab}
          idPrefix="my"
          onApply={(next) => {
            setMyFilter(next);
            void loadMyRecords(next);
          }}
        />
        {myLoading && !myRecords ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading my records...
          </p>
        ) : myError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {myError}
          </p>
        ) : sortedMy.length === 0 ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            You have not logged any incident or near-miss records yet.
          </p>
        ) : (
          <RecordList records={sortedMy} />
        )}
      </Card>

      {/* ---------- All clinic records ---------- */}
      <Card variant="native">
        <SectionTitle
          title="All clinic records"
          description="Clinic-wide incident and near-miss records (admin view)."
        />
        {!isAdmin ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
            Admin access is required to view all clinic incident and near-miss
            records.
          </p>
        ) : (
          <>
            <FilterRow
              filter={allFilter}
              vocab={vocab}
              idPrefix="all"
              onApply={(next) => {
                setAllFilter(next);
                void loadAllRecords(next);
              }}
            />
            {allLoading && !allRecords ? (
              <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
                Loading clinic records...
              </p>
            ) : allError ? (
              <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
                {allError}
              </p>
            ) : sortedAll.length === 0 ? (
              <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
                No clinic-wide incident or near-miss records yet.
              </p>
            ) : (
              <RecordList records={sortedAll} />
            )}
          </>
        )}
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------

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

function DetailLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-wrap items-baseline gap-x-2 text-xs text-slate-600">
      <span className="font-medium text-slate-500">{label}:</span>
      <span className="text-slate-700">{value}</span>
    </div>
  );
}

function Chip({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center rounded-full border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-700">
      {label}
    </span>
  );
}

function SummaryBlock({ summary }: { summary: IncidentNearMissSummary }) {
  const tiles: { label: string; value: string | number }[] = [
    { label: "Total records", value: summary.records_total ?? 0 },
    {
      label: `Records in ${summary.window_days ?? 30}d window`,
      value: summary.records_in_window ?? summary.records_last_30d ?? 0,
    },
    { label: "Open", value: summary.open_records ?? 0 },
    { label: "In review", value: summary.in_review_records ?? 0 },
    { label: "Actioned", value: summary.actioned_records ?? 0 },
    { label: "Closed", value: summary.closed_records ?? 0 },
    { label: "Voided", value: summary.voided_records ?? 0 },
    { label: "High or critical", value: summary.high_or_critical_records ?? 0 },
    { label: "Privacy-related", value: summary.privacy_related_records ?? 0 },
    { label: "Linked receipts", value: summary.linked_receipt_records ?? 0 },
    {
      label: "Learning recommendations",
      value: summary.learning_recommended_count ?? 0,
    },
    {
      label: "Policy review recommendations",
      value: summary.policy_review_recommended_count ?? 0,
    },
    {
      label: "Client communication review recommendations",
      value: summary.client_communication_review_recommended_count ?? 0,
    },
    {
      label: "Last reported",
      value: summary.last_reported_at
        ? formatDateTime(summary.last_reported_at)
        : "Not reported yet",
    },
  ];

  return (
    <div className="mt-4 space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {tiles.map((t) => (
          <div
            key={t.label}
            className="rounded-xl border border-slate-200 bg-slate-50 p-4"
          >
            <div className="text-xs uppercase tracking-wide text-slate-500">
              {t.label}
            </div>
            <div className="mt-2 text-sm font-semibold text-slate-900">
              {t.value}
            </div>
          </div>
        ))}
      </div>
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Honest disclosure
        </p>
        <div className="mt-2 flex flex-wrap gap-2 text-xs text-slate-700">
          <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1">
            Raw content included: No
          </span>
          <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1">
            Clinical content included: No
          </span>
          <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1">
            Staff identifiers included: No
          </span>
          <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1">
            Client identifiers included: No
          </span>
          <span className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1">
            Patient identifiers included: No
          </span>
        </div>
      </div>
    </div>
  );
}

type EnumOption<T extends string> = { value: T; label: string };

function makeOptions<T extends string>(values: T[] | undefined): EnumOption<T>[] {
  return (values ?? []).map((v) => ({ value: v, label: titleCase(v) }));
}

function EnumSelect<T extends string>({
  id,
  label,
  value,
  options,
  required,
  allowEmpty,
  emptyLabel,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  value: T | "";
  options: EnumOption<T>[];
  required?: boolean;
  allowEmpty?: boolean;
  emptyLabel?: string;
  disabled?: boolean;
  onChange: (next: T | "") => void;
}) {
  return (
    <div>
      <label
        htmlFor={id}
        className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500"
      >
        {label}
        {required ? " *" : ""}
      </label>
      <select
        id={id}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange((e.target.value as T) || "")}
        className="mt-1 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm focus:border-slate-400 focus:outline-none"
      >
        {allowEmpty ? (
          <option value="">{emptyLabel ?? "None"}</option>
        ) : null}
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  );
}

function CreateFormFields({
  form,
  vocab,
  onChange,
  disabled,
  submitting,
  onSubmit,
}: {
  form: CreateFormState;
  vocab: IncidentNearMissVocabularyResponse;
  onChange: (next: CreateFormState) => void;
  disabled: boolean;
  submitting: boolean;
  onSubmit: () => void;
}) {
  const categoryOptions = makeOptions(vocab.categories);
  const severityOptions = makeOptions(vocab.severities);
  const sourceOptions = makeOptions(vocab.sources);
  const outcomeOptions = makeOptions(vocab.outcomes);
  const actionOptions = makeOptions(vocab.action_taken_categories);

  return (
    <div className="mt-4 space-y-4">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <EnumSelect<IncidentNearMissCategory>
          id="incident-category"
          label="Category"
          required
          value={form.category}
          options={categoryOptions}
          disabled={disabled}
          onChange={(v) => onChange({ ...form, category: v })}
        />
        <EnumSelect<IncidentNearMissSeverity>
          id="incident-severity"
          label="Severity"
          required
          value={form.severity}
          options={severityOptions}
          disabled={disabled}
          onChange={(v) => onChange({ ...form, severity: v })}
        />
        <EnumSelect<IncidentNearMissSource>
          id="incident-source"
          label="Source"
          required
          value={form.source}
          options={sourceOptions}
          disabled={disabled}
          onChange={(v) => onChange({ ...form, source: v })}
        />
        <EnumSelect<IncidentNearMissOutcome>
          id="incident-outcome"
          label="Outcome"
          required
          value={form.outcome}
          options={outcomeOptions}
          disabled={disabled}
          onChange={(v) => onChange({ ...form, outcome: v })}
        />
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <EnumSelect<IncidentNearMissActionTakenCategory>
          id="incident-action"
          label="Action taken category"
          allowEmpty
          emptyLabel="None / not yet decided"
          value={form.actionTakenCategory}
          options={actionOptions}
          disabled={disabled}
          onChange={(v) => onChange({ ...form, actionTakenCategory: v })}
        />
        <div>
          <label
            htmlFor="incident-occurred"
            className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500"
          >
            Occurred at (optional)
          </label>
          <input
            id="incident-occurred"
            type="datetime-local"
            value={form.occurredAt}
            disabled={disabled}
            onChange={(e) => onChange({ ...form, occurredAt: e.target.value })}
            className="mt-1 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm focus:border-slate-400 focus:outline-none"
          />
        </div>
        <div>
          <label
            htmlFor="incident-detected"
            className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500"
          >
            Detected at (optional)
          </label>
          <input
            id="incident-detected"
            type="datetime-local"
            value={form.detectedAt}
            disabled={disabled}
            onChange={(e) => onChange({ ...form, detectedAt: e.target.value })}
            className="mt-1 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm focus:border-slate-400 focus:outline-none"
          />
        </div>
      </div>

      <fieldset>
        <legend className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Recommendations
        </legend>
        <div className="mt-2 flex flex-wrap gap-3">
          <ToggleRow
            id="rec-learning"
            label="Learning recommended"
            checked={form.learningRecommended}
            disabled={disabled}
            onChange={(v) => onChange({ ...form, learningRecommended: v })}
          />
          <ToggleRow
            id="rec-policy"
            label="Policy review recommended"
            checked={form.policyReviewRecommended}
            disabled={disabled}
            onChange={(v) => onChange({ ...form, policyReviewRecommended: v })}
          />
          <ToggleRow
            id="rec-client"
            label="Client communication review recommended"
            checked={form.clientCommunicationReviewRecommended}
            disabled={disabled}
            onChange={(v) =>
              onChange({
                ...form,
                clientCommunicationReviewRecommended: v,
              })
            }
          />
        </div>
      </fieldset>

      <fieldset>
        <legend className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Optional metadata links
        </legend>
        <p className="mt-1 text-xs text-slate-500">
          Optional ID-only links to existing ANCHOR metadata records. Do not
          enter clinical content or identifiers.
        </p>
        <div className="mt-2 grid gap-3 md:grid-cols-2">
          <IdInput
            id="link-receipt"
            label="Linked receipt ID"
            value={form.linkedReceiptId}
            disabled={disabled}
            onChange={(v) => onChange({ ...form, linkedReceiptId: v })}
          />
          <IdInput
            id="link-event"
            label="Linked governance event ID"
            value={form.linkedGovernanceEventId}
            disabled={disabled}
            onChange={(v) =>
              onChange({ ...form, linkedGovernanceEventId: v })
            }
          />
          <IdInput
            id="link-assistant"
            label="Linked assistant run ID"
            value={form.linkedAssistantRunId}
            disabled={disabled}
            onChange={(v) =>
              onChange({ ...form, linkedAssistantRunId: v })
            }
          />
          <IdInput
            id="link-policy"
            label="Linked clinic policy version ID"
            value={form.linkedClinicPolicyVersionId}
            disabled={disabled}
            onChange={(v) =>
              onChange({ ...form, linkedClinicPolicyVersionId: v })
            }
          />
        </div>
      </fieldset>

      <div className="flex flex-wrap items-center gap-3">
        <Button onClick={onSubmit} loading={submitting} disabled={submitting}>
          Create record
        </Button>
        <span className="text-xs text-slate-500">
          Structured fields only. No free-text narrative is captured.
        </span>
      </div>
    </div>
  );
}

function ToggleRow({
  id,
  label,
  checked,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (next: boolean) => void;
}) {
  return (
    <label
      htmlFor={id}
      className={[
        "inline-flex cursor-pointer items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium transition",
        checked
          ? "border-slate-900 bg-slate-900 text-white"
          : "border-slate-200 bg-white text-slate-700 hover:border-slate-300",
        disabled ? "cursor-not-allowed opacity-60" : "",
      ].join(" ")}
    >
      <input
        id={id}
        type="checkbox"
        className="sr-only"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      {label}
    </label>
  );
}

function IdInput({
  id,
  label,
  value,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  disabled?: boolean;
  onChange: (next: string) => void;
}) {
  return (
    <div>
      <label
        htmlFor={id}
        className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500"
      >
        {label}
      </label>
      <input
        id={id}
        type="text"
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        placeholder="(optional)"
        className="mt-1 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-mono text-slate-900 shadow-sm focus:border-slate-400 focus:outline-none"
      />
    </div>
  );
}

function FilterRow({
  filter,
  vocab,
  idPrefix,
  onApply,
}: {
  filter: ListFilterState;
  vocab: IncidentNearMissVocabularyResponse | null;
  idPrefix: string;
  onApply: (next: ListFilterState) => void;
}) {
  const statusOptions = makeOptions(vocab?.statuses);
  const severityOptions = makeOptions(vocab?.severities);
  return (
    <div className="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <EnumSelect<IncidentNearMissStatus>
        id={`${idPrefix}-filter-status`}
        label="Status filter"
        allowEmpty
        emptyLabel="Any"
        value={filter.status}
        options={statusOptions}
        onChange={(v) => onApply({ ...filter, status: v })}
      />
      <EnumSelect<IncidentNearMissSeverity>
        id={`${idPrefix}-filter-severity`}
        label="Severity filter"
        allowEmpty
        emptyLabel="Any"
        value={filter.severity}
        options={severityOptions}
        onChange={(v) => onApply({ ...filter, severity: v })}
      />
    </div>
  );
}

function RecordList({ records }: { records: IncidentNearMissRecord[] }) {
  return (
    <ul className="mt-4 space-y-3">
      {records.map((r) => (
        <RecordRow key={r.incident_id} record={r} />
      ))}
    </ul>
  );
}

function RecordRow({ record }: { record: IncidentNearMissRecord }) {
  return (
    <li className="rounded-xl border border-slate-200 bg-slate-50 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-semibold text-slate-900">
            {titleCase(record.category)}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {titleCase(record.source)} - {titleCase(record.outcome)}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <StatusBadge value={record.status} />
          <Chip label={`Severity: ${titleCase(record.severity)}`} />
        </div>
      </div>
      <div className="mt-3 grid gap-1 sm:grid-cols-2">
        <DetailLine label="Reported" value={formatDateTime(record.reported_at)} />
        <DetailLine label="Occurred" value={formatDateTime(record.occurred_at)} />
        <DetailLine label="Detected" value={formatDateTime(record.detected_at)} />
        {record.action_taken_category ? (
          <DetailLine
            label="Action taken"
            value={titleCase(record.action_taken_category)}
          />
        ) : null}
      </div>
      <div className="mt-3">
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Recommendations
        </p>
        <div className="mt-2 flex flex-wrap gap-2 text-xs text-slate-700">
          <Chip
            label={`Learning: ${record.learning_recommended ? "Yes" : "No"}`}
          />
          <Chip
            label={`Policy review: ${record.policy_review_recommended ? "Yes" : "No"}`}
          />
          <Chip
            label={`Client communication review: ${
              record.client_communication_review_recommended ? "Yes" : "No"
            }`}
          />
        </div>
      </div>
      <div className="mt-3">
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Linked metadata
        </p>
        <div className="mt-2 flex flex-wrap gap-2 text-xs text-slate-700">
          <Chip
            label={`Receipt linked: ${record.linked_receipt_id ? "Yes" : "No"}`}
          />
          <Chip
            label={`Governance event linked: ${
              record.linked_governance_event_id ? "Yes" : "No"
            }`}
          />
          <Chip
            label={`Assistant run linked: ${
              record.linked_assistant_run_id ? "Yes" : "No"
            }`}
          />
          <Chip
            label={`Policy version linked: ${
              record.linked_clinic_policy_version_id ? "Yes" : "No"
            }`}
          />
        </div>
      </div>
      <div className="mt-3">
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Honest disclosure
        </p>
        <div className="mt-2 flex flex-wrap gap-2 text-xs text-slate-700">
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Raw content included: No
          </span>
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Clinical content included: No
          </span>
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Staff identifiers included: No
          </span>
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Client identifiers included: No
          </span>
          <span className="rounded-full border border-slate-200 bg-white px-2.5 py-1">
            Patient identifiers included: No
          </span>
        </div>
      </div>
    </li>
  );
}

function sortByReportedDesc(records: IncidentNearMissRecord[]) {
  return [...records].sort((a, b) => {
    const aT = new Date(a.reported_at).getTime();
    const bT = new Date(b.reported_at).getTime();
    return bT - aT;
  });
}
