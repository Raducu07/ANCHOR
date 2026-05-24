"use client";

import Link from "next/link";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  ASSISTANT_MODE_CLIENT_COMMUNICATION,
  getAssistantContract,
  getAssistantRun,
  listAssistantRuns,
  submitAssistantRun,
  updateAssistantRunReview,
} from "@/lib/assistant";
import { ApiError } from "@/lib/api";
import type {
  AssistantContractResponse,
  AssistantReviewStatusInput,
  AssistantRunDetailResponse,
  AssistantRunRecord,
  AssistantRunTraceItem,
} from "@/lib/types";

// PR 2B: client_communication is the only active assistant mode. Safe
// requests may return a transient draft for review; unsafe clinical
// requests are refused before any model call.
const SAFE_USE_CASES = [
  {
    value: ASSISTANT_MODE_CLIENT_COMMUNICATION,
    label: "Help rewrite client communication (human review required)",
    active: true,
  },
  { value: "explain_governance_receipt", label: "Explain a governance receipt", active: false },
  { value: "explain_why_flagged", label: "Explain why something was flagged", active: false },
  { value: "help_prepare_internal_summary", label: "Help prepare an internal summary", active: false },
  { value: "explain_clinic_ai_policy", label: "Explain clinic AI policy", active: false },
  { value: "suggest_learn_guidance", label: "Suggest relevant Learn guidance", active: false },
] as const;

const PROHIBITED_USE_CASES = [
  "Diagnose a patient",
  "Recommend treatment or prescribing",
  "Prescribe medication",
  "Replace veterinary judgement",
  "Autonomous clinical decision-making",
] as const;

type RunState =
  | { kind: "idle" }
  | { kind: "submitting" }
  | { kind: "record"; data: AssistantRunRecord }
  | { kind: "unavailable"; reason: string }
  | { kind: "error"; message: string };

export function AssistantSurface() {
  const [contract, setContract] = useState<AssistantContractResponse | null>(null);
  const [contractLoading, setContractLoading] = useState(true);
  const [contractError, setContractError] = useState<string | null>(null);
  const [contractUnavailable, setContractUnavailable] = useState(false);

  const [communicationGoal, setCommunicationGoal] = useState("");
  const [clinicianFacts, setClinicianFacts] = useState("");
  const [runState, setRunState] = useState<RunState>({ kind: "idle" });

  // M6.3 — evidence/traceability surface state.
  const [evidenceRuns, setEvidenceRuns] = useState<AssistantRunTraceItem[] | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<AssistantRunDetailResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const canSubmit = communicationGoal.trim().length > 0 && clinicianFacts.trim().length > 0;

  async function loadEvidence() {
    setEvidenceLoading(true);
    setEvidenceError(null);
    try {
      const result = await listAssistantRuns({ limit: 25 });
      setEvidenceRuns(result.runs ?? []);
    } catch (err) {
      setEvidenceRuns(null);
      const message = err instanceof ApiError ? err.message : "Unable to load recent assistant runs.";
      setEvidenceError(message);
    } finally {
      setEvidenceLoading(false);
    }
  }

  // M6.4 — review action state. `reviewSubmitting` is the runId being
  // PATCHed (or null when idle); `reviewError` is the last error message.
  const [reviewSubmitting, setReviewSubmitting] = useState<string | null>(null);
  const [reviewError, setReviewError] = useState<string | null>(null);

  async function updateReview(runId: string, reviewStatus: AssistantReviewStatusInput) {
    setReviewSubmitting(runId);
    setReviewError(null);
    try {
      const updated = await updateAssistantRunReview(runId, reviewStatus);
      // Update the loaded detail in-place and refresh the recent-runs list
      // so the new review state is visible without a manual reload.
      setSelectedDetail(updated);
      void loadEvidence();
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : "Unable to record review outcome.";
      setReviewError(message);
    } finally {
      setReviewSubmitting(null);
    }
  }

  async function selectRun(runId: string) {
    setSelectedRunId(runId);
    setSelectedDetail(null);
    setDetailError(null);
    setReviewError(null);
    setDetailLoading(true);
    // Scroll the evidence section into view so the detail is visible.
    if (typeof document !== "undefined") {
      const el = document.getElementById("assistant-evidence");
      if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    try {
      const detail = await getAssistantRun(runId);
      setSelectedDetail(detail);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Unable to load assistant run detail.";
      setDetailError(message);
    } finally {
      setDetailLoading(false);
    }
  }

  async function loadContract(isRefresh = false) {
    try {
      if (!isRefresh) setContractLoading(true);
      setContractError(null);
      setContractUnavailable(false);
      const result = await getAssistantContract();
      setContract(result);
    } catch (err) {
      setContract(null);
      if (err instanceof ApiError && (err.status === 404 || err.status === 501)) {
        setContractUnavailable(true);
        setContractError(
          "The assistant contract endpoint is not yet available. Backend provisioning for /v1/assistant/contracts is expected as part of M6.1 backend delivery."
        );
      } else {
        const message = err instanceof ApiError ? err.message : "Unable to load assistant contract.";
        setContractError(message);
      }
    } finally {
      setContractLoading(false);
    }
  }

  useEffect(() => {
    void loadContract(false);
  }, []);

  async function handleRunSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const goal = communicationGoal.trim();
    const facts = clinicianFacts.trim();
    if (!goal || !facts) return;

    setRunState({ kind: "submitting" });
    try {
      const record = await submitAssistantRun({
        mode: ASSISTANT_MODE_CLIENT_COMMUNICATION,
        input: {
          communication_goal: goal,
          clinician_confirmed_facts: facts,
        },
      });
      setRunState({ kind: "record", data: record });
    } catch (err) {
      if (
        err instanceof ApiError &&
        (err.status === 404 || err.status === 501 || err.status === 405 || err.status === 0)
      ) {
        setRunState({
          kind: "unavailable",
          reason:
            "The assistant run endpoint (POST /v1/assistant/runs) is not yet available. Run record creation is expected as part of M6.1 backend delivery. Contract governance boundaries above remain active.",
        });
      } else {
        const message = err instanceof ApiError ? err.message : "Unable to submit assistant run.";
        setRunState({ kind: "error", message });
      }
    }
  }

  function handleClear() {
    setRunState({ kind: "idle" });
    setCommunicationGoal("");
    setClinicianFacts("");
  }

  const contractVersion = contract?.contract_version ?? contract?.version ?? "-";
  const storagePolicy = contract?.storage_policy ?? "Metadata-only by default";
  const metadataOnly = contract?.metadata_only ?? contract?.no_raw_content ?? true;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <p className="text-sm font-medium text-slate-500">Assistant</p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Governed Assistant</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            Client communication is the only active assistant mode in this release. Safe
            requests may return a transient draft. Raw input and draft output are not stored.
            ANCHOR stores hashes, field keys, safety flags, and governance metadata only.
            Human review is required before operational use.
          </p>
        </div>
        <button
          onClick={() => void loadContract(true)}
          disabled={contractLoading}
          className="inline-flex shrink-0 items-center rounded-2xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-medium text-slate-900 shadow-sm transition hover:border-slate-300 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {contractLoading ? "Loading..." : "Refresh contract"}
        </button>
      </div>

      <div className="rounded-xl border border-amber-200 bg-amber-50 px-5 py-4">
        <div className="flex items-start gap-3">
          <span className="material-symbols-outlined mt-0.5 text-[18px] text-amber-600">policy</span>
          <div>
            <p className="text-sm font-semibold text-amber-900">Storage policy - metadata-only by default</p>
            <p className="mt-1 text-sm leading-6 text-amber-800">
              No raw prompts, inputs, drafts, transcripts, or clinical content are stored by this
              assistant. A draft may be returned transiently for review; only hashes, field keys,
              PII flags, safety flags, and run status are retained. Human review is required
              before any result is used operationally. ANCHOR is not a clinical decision-making
              system.
            </p>
          </div>
        </div>
      </div>

      <NativeCard>
        <SectionTitle
          title="Active assistant contract"
          description="The contract governs permitted use cases, storage boundaries, and safety rules for this assistant session."
        />

        {contractLoading ? (
          <EmptyState title="Loading contract..." description="Fetching the active assistant contract." />
        ) : contractError ? (
          <div className="mt-4 space-y-3">
            <UnavailableState
              title={contractUnavailable ? "Contract endpoint unavailable" : "Contract could not be loaded"}
              description={contractError}
            />
            {contractUnavailable ? (
              <p className="text-sm leading-6 text-slate-600">
                Governance boundaries, storage policy, and use case rules on this page remain
                active regardless of contract endpoint availability.
              </p>
            ) : null}
          </div>
        ) : contract ? (
          <div className="mt-4 space-y-4">
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <MetricCell label="Contract version" value={contractVersion} />
              <MetricCell label="Storage policy" value={storagePolicy} />
              <MetricCell
                label="Metadata only"
                value={metadataOnly ? "Yes" : "Not confirmed"}
                tone={metadataOnly ? "success" : "default"}
              />
              <MetricCell
                label="Status"
                value={contract.status ?? "active"}
                tone={!contract.status || contract.status === "active" ? "success" : "default"}
              />
            </div>
            <div className="space-y-2">
              {contract.policy_version ? (
                <DetailRow label="Policy version" value={`v${String(contract.policy_version)}`} />
              ) : null}
              {contract.issued_at ?? contract.created_at ? (
                <DetailRow
                  label="Issued at"
                  value={formatDateTime(contract.issued_at ?? contract.created_at)}
                />
              ) : null}
              {contract.contract_id ? (
                <DetailRow label="Contract ID" value={String(contract.contract_id)} mono />
              ) : null}
            </div>
          </div>
        ) : (
          <UnavailableState
            title="No contract returned"
            description="The contract endpoint responded but returned no contract data."
          />
        )}
      </NativeCard>

      <div className="grid gap-4 xl:grid-cols-2">
        <NativeCard>
          <SectionTitle title="Permitted use cases" />
          <p className="mt-1 text-sm leading-5 text-slate-500">
            Only client communication is callable in this release. Other use cases are
            contract-defined and not yet active.
          </p>
          <ul className="mt-4 space-y-2">
            {SAFE_USE_CASES.map((item) => (
              <li key={item.value} className="flex items-start gap-3">
                <span
                  className={[
                    "material-symbols-outlined mt-0.5 shrink-0 text-[18px]",
                    item.active ? "text-emerald-500" : "text-slate-300",
                  ].join(" ")}
                >
                  {item.active ? "check_circle" : "schedule"}
                </span>
                <span className="text-sm leading-6 text-slate-700">
                  {item.label}
                  {item.active ? (
                    <span className="ml-2 rounded-full bg-emerald-50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.1em] text-emerald-700">
                      Active
                    </span>
                  ) : (
                    <span className="ml-2 rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.1em] text-slate-500">
                      Not yet active
                    </span>
                  )}
                </span>
              </li>
            ))}
          </ul>
        </NativeCard>

        <NativeCard>
          <SectionTitle title="Prohibited use cases - hard refusals" />
          <p className="mt-1 text-sm leading-5 text-slate-500">
            Outside ANCHOR doctrine. These will never be supported.
          </p>
          <ul className="mt-4 space-y-2">
            {PROHIBITED_USE_CASES.map((item) => (
              <li key={item} className="flex items-start gap-3">
                <span className="material-symbols-outlined mt-0.5 shrink-0 text-[18px] text-rose-500">
                  cancel
                </span>
                <span className="text-sm leading-6 text-slate-700">{item}</span>
              </li>
            ))}
          </ul>
        </NativeCard>
      </div>

      <NativeCard>
        <SectionTitle
          title="Submit a governed assistant run"
          description="Client communication is the only active assistant mode in this release. Safe requests may return a transient draft. Raw input and draft output are not stored. ANCHOR stores hashes, field keys, safety flags, and governance metadata only. Human review is required before operational use."
        />

        <form onSubmit={(e) => void handleRunSubmit(e)} className="mt-6 space-y-4">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
              Mode
            </label>
            <div
              aria-readonly="true"
              className="mt-2 flex items-center justify-between rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-900"
            >
              <span className="font-medium">Client communication</span>
              <span className="rounded-full bg-emerald-50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.1em] text-emerald-700">
                Active
              </span>
            </div>
            <p className="mt-1.5 text-xs text-slate-500">
              Other assistant modes are contract-defined but not yet callable.
            </p>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
              Communication goal
            </label>
            <textarea
              value={communicationGoal}
              onChange={(e) => setCommunicationGoal(e.target.value)}
              disabled={runState.kind === "submitting"}
              placeholder="e.g. Reassure an owner about post-op recovery and next steps."
              rows={2}
              className="mt-2 w-full resize-none rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm placeholder:text-slate-400 focus:border-slate-400 focus:outline-none disabled:opacity-60"
            />
            <p className="mt-1.5 text-xs text-slate-500">
              What you want the communication to achieve. Required.
            </p>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
              Clinician-confirmed facts
            </label>
            <textarea
              value={clinicianFacts}
              onChange={(e) => setClinicianFacts(e.target.value)}
              disabled={runState.kind === "submitting"}
              placeholder="The facts you have personally confirmed and are willing to stand behind."
              rows={4}
              className="mt-2 w-full resize-none rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm placeholder:text-slate-400 focus:border-slate-400 focus:outline-none disabled:opacity-60"
            />
            <p className="mt-1.5 text-xs text-slate-500">
              Required. Do not include patient names, identifiers, or anything you have not
              personally confirmed. Field values are used transiently to generate the draft and
              are not stored. ANCHOR retains metadata only: hashes, field keys, PII flags,
              safety flags, and run status.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-4">
            <button
              type="submit"
              disabled={runState.kind === "submitting" || !canSubmit}
              className="inline-flex items-center rounded-xl bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {runState.kind === "submitting" ? "Submitting..." : "Submit assistant run"}
            </button>
            {runState.kind !== "idle" ? (
              <button
                type="button"
                onClick={handleClear}
                className="text-sm font-medium text-slate-500 hover:text-slate-900"
              >
                Clear
              </button>
            ) : null}
          </div>

          <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
            <p className="text-xs leading-5 text-slate-600">
              <strong>Human review required.</strong> Any draft returned by ANCHOR must be
              checked against the clinical record before use. ANCHOR does not make clinical
              decisions.
            </p>
          </div>
        </form>
      </NativeCard>

      {runState.kind === "record" ? (
        <RunRecordCard
          record={runState.data}
          onViewMetadata={(runId) => {
            void loadEvidence();
            void selectRun(runId);
          }}
        />
      ) : runState.kind === "unavailable" ? (
        <NativeCard>
          <UnavailableState title="Run endpoint unavailable" description={runState.reason} />
          <p className="mt-4 text-sm leading-6 text-slate-600">
            Governance contract boundaries, storage policy, and use case rules remain active.
            Once the run endpoint is deployed, run records and governance receipts will be
            available here.
          </p>
          <div className="mt-4">
            <Link
              href="/receipts"
              className="text-sm font-medium text-slate-900 underline underline-offset-4"
            >
              View existing governance receipts
            </Link>
          </div>
        </NativeCard>
      ) : runState.kind === "error" ? (
        <NativeCard className="border-rose-200 bg-rose-50">
          <p className="text-sm font-semibold text-rose-700">Run submission failed</p>
          <p className="mt-2 text-sm leading-6 text-rose-600">{runState.message}</p>
        </NativeCard>
      ) : null}

      <EvidenceSection
        id="assistant-evidence"
        runs={evidenceRuns}
        loading={evidenceLoading}
        error={evidenceError}
        onRefresh={() => void loadEvidence()}
        selectedRunId={selectedRunId}
        selectedDetail={selectedDetail}
        detailLoading={detailLoading}
        detailError={detailError}
        onSelectRun={(runId) => void selectRun(runId)}
        onUpdateReview={(runId, status) => void updateReview(runId, status)}
        reviewSubmitting={reviewSubmitting}
        reviewError={reviewError}
      />

      <div className="grid gap-4 xl:grid-cols-3">
        <NavCard
          href="/receipts"
          icon="receipt_long"
          title="Governance receipts"
          description="Receipts from governed workspace runs and assistant run records."
        />
        <NavCard
          href="/learn"
          icon="school"
          title="Learn"
          description="Guidance on safe AI use, governance receipts, and privacy-aware practice."
        />
        <NavCard
          href="/trust/profile"
          icon="shield_with_heart"
          title="Trust Center"
          description="Current trust posture, evidence basis, and exportable trust artifacts."
        />
      </div>
    </div>
  );
}

// PR 2B run_status labels. Backward compatible: if run_status is missing
// (PR 2A-style response), fall back to "Created".
function runStatusLabel(runStatus: string | undefined): string {
  switch (runStatus) {
    case "generation_succeeded":
      return "Draft generated";
    case "generation_refused":
      return "Refused before model call";
    case "generation_failed":
      return "Generation failed";
    case "created":
    case undefined:
    case "":
      return "Created";
    default:
      return runStatus;
  }
}

function runStatusTone(runStatus: string | undefined): "default" | "success" {
  return runStatus === "generation_succeeded" ? "success" : "default";
}

function truncateHash(hash: string | null | undefined): string {
  if (!hash) return "None";
  if (hash.length <= 16) return hash;
  return `${hash.slice(0, 10)}…${hash.slice(-6)}`;
}

function reviewStatusLabel(status: string | undefined | null): string {
  switch (status) {
    case "reviewed_approved":
      return "Approved";
    case "reviewed_rejected":
      return "Rejected";
    case "reviewed_needs_edit":
      return "Needs edit";
    case "not_reviewed":
    case undefined:
    case null:
    case "":
      return "Not reviewed";
    default:
      return String(status);
  }
}

function reviewDecisionLabel(decision: string | undefined | null): string {
  switch (decision) {
    case "approved_for_use":
      return "Approved for use";
    case "rejected_not_safe":
      return "Rejected — not safe";
    case "needs_edit_before_use":
      return "Needs edit before use";
    default:
      return decision ? String(decision) : "None";
  }
}

function RunRecordCard({
  record,
  onViewMetadata,
}: {
  record: AssistantRunRecord;
  onViewMetadata?: (runId: string) => void;
}) {
  const runId = record.run_id ?? record.request_id;
  const noRawContent = record.no_raw_content_stored ?? record.no_content_stored ?? true;
  const piiDetected = record.pii_detected === true;
  const piiTypes = record.pii_types ?? [];
  const fieldKeys = record.input_field_keys ?? [];
  const reviewStatus = record.review_status ?? record.status ?? "not_reviewed";
  const generationEnabled = record.generation_enabled === true;
  const runStatus = typeof record.run_status === "string" ? record.run_status : undefined;
  const refused = record.refused === true || runStatus === "generation_refused";
  const refusalCodes = record.refusal_reason_codes ?? [];
  const safetyFlags = record.safety_flags ?? [];
  const draft = typeof record.draft === "string" ? record.draft : null;
  const showDraftPanel = runStatus === "generation_succeeded" && !!draft && !refused;
  const showRefusalPanel = refused;
  const showFailurePanel = runStatus === "generation_failed";

  return (
    <NativeCard>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4">
        <SectionTitle
          title="Assistant run"
          description="ANCHOR retains governance metadata only. Any returned draft is transient and is not stored. Human review is required before operational use."
        />
        {noRawContent ? (
          <span className="shrink-0 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.1em] text-emerald-700">
            No raw content stored
          </span>
        ) : null}
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCell label="Run ID" value={runId ? `${String(runId).slice(0, 12)}…` : "-"} />
        <MetricCell label="Review status" value={reviewStatus} tone="success" />
        <MetricCell
          label="PII detected"
          value={piiDetected ? "Yes" : "No"}
          tone={piiDetected ? "default" : "success"}
        />
        <MetricCell
          label="Generation"
          value={runStatusLabel(runStatus)}
          tone={runStatusTone(runStatus)}
        />
      </div>

      {showDraftPanel ? <TransientDraftPanel draft={draft as string} /> : null}
      {showRefusalPanel ? (
        <RefusalPanel reasonCodes={refusalCodes} safetyFlags={safetyFlags} />
      ) : null}
      {showFailurePanel ? <FailurePanel /> : null}

      <div className="mt-4 space-y-2">
        {record.contract_version ?? record.contract_id ? (
          <DetailRow
            label="Contract"
            value={String(record.contract_version ?? record.contract_id)}
          />
        ) : null}
        {record.mode ? <DetailRow label="Mode" value={record.mode} /> : null}
        <DetailRow label="Run status" value={runStatusLabel(runStatus)} />
        <DetailRow label="Refused" value={refused ? "Yes" : "No"} />
        {fieldKeys.length ? (
          <DetailRow label="Input fields" value={fieldKeys.join(", ")} />
        ) : null}
        {piiTypes.length ? (
          <DetailRow label="PII types" value={piiTypes.join(", ")} />
        ) : null}
        {refusalCodes.length ? (
          <DetailRow label="Refusal codes" value={refusalCodes.join(", ")} />
        ) : null}
        {safetyFlags.length ? (
          <DetailRow label="Safety flags" value={safetyFlags.join(", ")} />
        ) : null}
        <DetailRow
          label="Output hash"
          value={record.output_sha256 ? truncateHash(record.output_sha256) : "None"}
          mono={!!record.output_sha256}
        />
        <DetailRow
          label="Model"
          value={
            record.model_provider || record.model_name
              ? `${record.model_provider ?? "-"} / ${record.model_name ?? "-"}`
              : "Not invoked"
          }
        />
        <DetailRow label="Generation enabled" value={generationEnabled ? "Yes" : "No"} />
        {record.created_at_utc ?? record.created_at ? (
          <DetailRow
            label="Created at"
            value={formatDateTime(record.created_at_utc ?? record.created_at)}
          />
        ) : null}
      </div>

      {record.governance_note ? (
        <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
          <p className="text-xs leading-5 text-slate-700">{record.governance_note}</p>
        </div>
      ) : null}

      <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3">
        <p className="text-xs leading-5 text-amber-800">
          <strong>Human review required.</strong> Any draft returned by ANCHOR must be checked
          against the clinical record before use. ANCHOR does not make clinical decisions.
        </p>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-4">
        {onViewMetadata && runId ? (
          <button
            type="button"
            onClick={() => onViewMetadata(String(runId))}
            className="text-sm font-medium text-slate-900 underline underline-offset-4"
          >
            View metadata record
          </button>
        ) : null}
        <Link
          href="/receipts"
          className="text-sm font-medium text-slate-900 underline underline-offset-4"
        >
          View governance receipts
        </Link>
      </div>
    </NativeCard>
  );
}

function TransientDraftPanel({ draft }: { draft: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard) {
        await navigator.clipboard.writeText(draft);
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1800);
      }
    } catch {
      // Best-effort: failure to copy is non-fatal. The draft is still
      // visible on screen for manual copy.
    }
  }

  return (
    <div className="mt-5 rounded-xl border border-emerald-200 bg-emerald-50/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-emerald-900">Transient draft</p>
          <p className="mt-1 text-xs leading-5 text-emerald-800">
            This draft is returned for review only. It is not stored by ANCHOR.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void handleCopy()}
          className="inline-flex shrink-0 items-center rounded-lg border border-emerald-200 bg-white px-3 py-1.5 text-xs font-medium text-emerald-900 shadow-sm transition hover:border-emerald-300"
        >
          {copied ? "Copied" : "Copy draft"}
        </button>
      </div>
      <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap rounded-lg border border-emerald-100 bg-white p-4 text-sm leading-6 text-slate-900">
        {draft}
      </pre>
    </div>
  );
}

function RefusalPanel({
  reasonCodes,
  safetyFlags,
}: {
  reasonCodes: string[];
  safetyFlags: string[];
}) {
  return (
    <div className="mt-5 rounded-xl border border-rose-200 bg-rose-50 p-4">
      <p className="text-sm font-semibold text-rose-800">Refused before model call</p>
      <p className="mt-1 text-xs leading-5 text-rose-700">
        ANCHOR does not provide clinical judgements. The model was not invoked. No output hash
        is recorded.
      </p>
      {reasonCodes.length ? (
        <div className="mt-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-rose-700">
            Refusal reason codes
          </p>
          <ul className="mt-1 flex flex-wrap gap-1.5">
            {reasonCodes.map((code) => (
              <li
                key={code}
                className="rounded-full border border-rose-200 bg-white px-2 py-0.5 text-[11px] font-medium text-rose-700"
              >
                {code}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {safetyFlags.length ? (
        <div className="mt-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-rose-700">
            Safety flags
          </p>
          <ul className="mt-1 flex flex-wrap gap-1.5">
            {safetyFlags.map((flag) => (
              <li
                key={flag}
                className="rounded-full border border-rose-200 bg-white px-2 py-0.5 text-[11px] font-medium text-rose-700"
              >
                {flag}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function FailurePanel() {
  return (
    <div className="mt-5 rounded-xl border border-slate-300 bg-slate-100 p-4">
      <p className="text-sm font-semibold text-slate-800">Generation unavailable</p>
      <p className="mt-1 text-xs leading-5 text-slate-700">
        The assistant is temporarily unavailable. No draft was produced and no output hash is
        recorded. Governance metadata for this run has been captured.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------
// M6.3 — Evidence/traceability section
// ---------------------------------------------------------------------
//
// Metadata-only governance evidence. This is NOT a chat history. It shows
// the most recent assistant_runs metadata for the clinic and lets a user
// open a single run's metadata detail. No draft text, no raw input, no
// prompt is ever loaded from the backend on this surface.

function EvidenceSection({
  id,
  runs,
  loading,
  error,
  onRefresh,
  selectedRunId,
  selectedDetail,
  detailLoading,
  detailError,
  onSelectRun,
  onUpdateReview,
  reviewSubmitting,
  reviewError,
}: {
  id: string;
  runs: AssistantRunTraceItem[] | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
  selectedRunId: string | null;
  selectedDetail: AssistantRunDetailResponse | null;
  detailLoading: boolean;
  detailError: string | null;
  onSelectRun: (runId: string) => void;
  onUpdateReview: (runId: string, reviewStatus: AssistantReviewStatusInput) => void;
  reviewSubmitting: string | null;
  reviewError: string | null;
}) {
  return (
    <NativeCard>
      <div id={id} className="flex flex-wrap items-start justify-between gap-4">
        <SectionTitle
          title="Recent Assistant runs"
          description="Metadata-only Assistant evidence. No raw input, prompt, or draft output is stored. This is not a chat history."
        />
        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex shrink-0 items-center rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-900 shadow-sm transition hover:border-slate-300 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading ? "Loading…" : runs === null ? "View recent runs" : "Refresh runs"}
        </button>
      </div>

      {runs === null && !loading && !error ? (
        <p className="mt-3 text-sm leading-6 text-slate-600">
          Click <span className="font-medium">View recent runs</span> to load metadata-only
          Assistant evidence for this clinic.
        </p>
      ) : null}

      {error ? (
        <div className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3">
          <p className="text-sm font-semibold text-rose-700">Could not load Assistant runs</p>
          <p className="mt-1 text-sm leading-6 text-rose-600">{error}</p>
        </div>
      ) : null}

      {runs && runs.length === 0 && !loading ? (
        <p className="mt-3 text-sm leading-6 text-slate-600">
          No Assistant runs recorded yet for this clinic.
        </p>
      ) : null}

      {runs && runs.length > 0 ? (
        <div className="mt-4 overflow-hidden rounded-xl border border-slate-200">
          <table className="w-full table-fixed text-left text-sm">
            <thead className="bg-slate-50">
              <tr className="border-b border-slate-200 text-[11px] uppercase tracking-[0.1em] text-slate-500">
                <th className="w-[12%] px-3 py-2 font-semibold">Run ID</th>
                <th className="w-[14%] px-3 py-2 font-semibold">Created</th>
                <th className="w-[12%] px-3 py-2 font-semibold">Status</th>
                <th className="w-[12%] px-3 py-2 font-semibold">Review</th>
                <th className="w-[8%] px-3 py-2 font-semibold">PII</th>
                <th className="w-[8%] px-3 py-2 font-semibold">Refused</th>
                <th className="w-[14%] px-3 py-2 font-semibold">Output hash</th>
                <th className="w-[14%] px-3 py-2 font-semibold">Model</th>
                <th className="w-[6%] px-3 py-2 font-semibold" />
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => {
                const isSelected = selectedRunId === r.run_id;
                return (
                  <tr
                    key={r.run_id}
                    className={[
                      "border-b border-slate-100 last:border-b-0",
                      isSelected ? "bg-slate-50" : "hover:bg-slate-50/50",
                    ].join(" ")}
                  >
                    <td className="px-3 py-2 font-mono text-[12px] text-slate-700">
                      {`${r.run_id.slice(0, 8)}…`}
                    </td>
                    <td className="px-3 py-2 text-slate-700">{formatDateTime(r.created_at)}</td>
                    <td className="px-3 py-2 text-slate-700">{runStatusLabel(r.run_status)}</td>
                    <td className="px-3 py-2 text-slate-700">{reviewStatusLabel(r.review_status)}</td>
                    <td className="px-3 py-2 text-slate-700">{r.pii_detected ? "Yes" : "No"}</td>
                    <td className="px-3 py-2 text-slate-700">
                      {r.refusal_reason_codes.length > 0 ? "Yes" : "No"}
                    </td>
                    <td className="px-3 py-2 font-mono text-[12px] text-slate-700">
                      {truncateHash(r.output_sha256)}
                    </td>
                    <td className="px-3 py-2 text-slate-700">
                      {r.model_provider || r.model_name
                        ? `${r.model_provider ?? "-"} / ${r.model_name ?? "-"}`
                        : "Not invoked"}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <button
                        type="button"
                        onClick={() => onSelectRun(r.run_id)}
                        className="text-xs font-medium text-slate-900 underline underline-offset-4"
                      >
                        Open
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}

      {selectedRunId ? (
        <RunDetailPanel
          runId={selectedRunId}
          detail={selectedDetail}
          loading={detailLoading}
          error={detailError}
          onUpdateReview={onUpdateReview}
          reviewSubmitting={reviewSubmitting}
          reviewError={reviewError}
        />
      ) : null}

      <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
        <p className="text-xs leading-5 text-slate-600">
          Output hash confirms a draft was produced without retaining the draft. Refused runs
          show safety flags and refusal reason codes. ANCHOR stores hashes, field keys, PII
          flags, safety flags, and run status only.
        </p>
      </div>
    </NativeCard>
  );
}

function RunDetailPanel({
  runId,
  detail,
  loading,
  error,
  onUpdateReview,
  reviewSubmitting,
  reviewError,
}: {
  runId: string;
  detail: AssistantRunDetailResponse | null;
  loading: boolean;
  error: string | null;
  onUpdateReview: (runId: string, reviewStatus: AssistantReviewStatusInput) => void;
  reviewSubmitting: string | null;
  reviewError: string | null;
}) {
  return (
    <section className="mt-5 rounded-xl border border-slate-200 bg-white p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-slate-900">Run metadata</p>
          <p className="mt-1 text-xs leading-5 text-slate-500 font-mono">{runId}</p>
        </div>
        {detail ? (
          <span className="shrink-0 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.1em] text-emerald-700">
            Metadata only
          </span>
        ) : null}
      </div>

      {loading ? (
        <p className="mt-4 text-sm text-slate-500">Loading metadata…</p>
      ) : null}

      {error ? (
        <div className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3">
          <p className="text-sm font-semibold text-rose-700">Could not load run metadata</p>
          <p className="mt-1 text-sm leading-6 text-rose-600">{error}</p>
        </div>
      ) : null}

      {detail ? (
        <RunDetailBody
          detail={detail}
          onUpdateReview={onUpdateReview}
          reviewSubmitting={reviewSubmitting}
          reviewError={reviewError}
        />
      ) : null}
    </section>
  );
}

function RunDetailBody({
  detail,
  onUpdateReview,
  reviewSubmitting,
  reviewError,
}: {
  detail: AssistantRunDetailResponse;
  onUpdateReview: (runId: string, reviewStatus: AssistantReviewStatusInput) => void;
  reviewSubmitting: string | null;
  reviewError: string | null;
}) {
  const r = detail.run;
  const isReviewed = r.review_status && r.review_status !== "not_reviewed";

  return (
    <>
      <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCell
          label="Storage policy"
          value={detail.storage_policy ?? "metadata_only_by_default"}
          tone="success"
        />
        <MetricCell label="Raw input stored" value={detail.raw_content_stored ? "Yes" : "No"} tone="success" />
        <MetricCell label="Prompt stored" value={detail.prompt_stored ? "Yes" : "No"} tone="success" />
        <MetricCell label="Draft stored" value={detail.draft_stored ? "Yes" : "No"} tone="success" />
      </div>

      {isReviewed ? (
        <ReviewEvidenceCard
          reviewStatus={r.review_status}
          reviewDecision={r.review_decision ?? null}
          reviewedAt={r.reviewed_at ?? null}
          reviewedByUserId={r.reviewed_by_user_id ?? null}
        />
      ) : (
        <ReviewActionArea
          runId={r.run_id}
          onUpdateReview={onUpdateReview}
          submitting={reviewSubmitting === r.run_id}
          error={reviewError}
        />
      )}

      <div className="mt-4 space-y-2">
        <DetailRow label="Run status" value={runStatusLabel(r.run_status)} />
        <DetailRow label="Review status" value={reviewStatusLabel(r.review_status)} />
        {r.review_decision ? (
          <DetailRow label="Review decision" value={reviewDecisionLabel(r.review_decision)} />
        ) : null}
        {r.reviewed_at ? (
          <DetailRow label="Reviewed at" value={formatDateTime(r.reviewed_at)} />
        ) : null}
        {r.reviewed_by_user_id ? (
          <DetailRow label="Reviewed by" value={r.reviewed_by_user_id} mono />
        ) : null}
        <DetailRow label="Mode" value={r.mode} />
        <DetailRow label="Contract" value={r.contract_version} />
        <DetailRow label="Workflow origin" value={r.workflow_origin} />
        <DetailRow
          label="Input fields"
          value={r.input_field_keys.length ? r.input_field_keys.join(", ") : "None"}
        />
        <DetailRow
          label="PII detected"
          value={r.pii_detected ? "Yes" : "No"}
        />
        <DetailRow
          label="PII types"
          value={r.pii_types.length ? r.pii_types.join(", ") : "None"}
        />
        <DetailRow
          label="Safety flags"
          value={r.safety_flags.length ? r.safety_flags.join(", ") : "None"}
        />
        <DetailRow
          label="Refusal codes"
          value={r.refusal_reason_codes.length ? r.refusal_reason_codes.join(", ") : "None"}
        />
        <DetailRow label="Input hash" value={r.input_sha256} mono />
        <DetailRow
          label="Output hash"
          value={r.output_sha256 ? r.output_sha256 : "None"}
          mono={!!r.output_sha256}
        />
        <DetailRow
          label="Model"
          value={
            r.model_provider || r.model_name
              ? `${r.model_provider ?? "-"} / ${r.model_name ?? "-"}`
              : "Not invoked"
          }
        />
        <DetailRow
          label="Receipt"
          value={r.receipt_id ? r.receipt_id : "Not linked yet"}
          mono={!!r.receipt_id}
        />
        <DetailRow
          label="Governance event"
          value={r.governance_event_id ? r.governance_event_id : "Not linked yet"}
          mono={!!r.governance_event_id}
        />
        <DetailRow label="Created at" value={formatDateTime(r.created_at)} />
        <DetailRow label="Updated at" value={formatDateTime(r.updated_at)} />
      </div>

      <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
        <p className="text-xs leading-5 text-slate-700">{detail.governance_note}</p>
      </div>
    </>
  );
}

function ReviewActionArea({
  runId,
  onUpdateReview,
  submitting,
  error,
}: {
  runId: string;
  onUpdateReview: (runId: string, reviewStatus: AssistantReviewStatusInput) => void;
  submitting: boolean;
  error: string | null;
}) {
  return (
    <div className="mt-5 rounded-xl border border-amber-200 bg-amber-50/60 p-4">
      <p className="text-sm font-semibold text-amber-900">Record human review</p>
      <p className="mt-1 text-xs leading-5 text-amber-800">
        Record a metadata-only review outcome. Do not enter clinical notes here. ANCHOR does
        not store draft text or clinical content. Human review is required before operational
        use. This does not replace professional judgement.
      </p>

      <div className="mt-3 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => onUpdateReview(runId, "reviewed_approved")}
          disabled={submitting}
          className="inline-flex items-center rounded-lg border border-emerald-300 bg-white px-3 py-1.5 text-xs font-medium text-emerald-900 shadow-sm transition hover:border-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {submitting ? "Recording…" : "Mark approved"}
        </button>
        <button
          type="button"
          onClick={() => onUpdateReview(runId, "reviewed_needs_edit")}
          disabled={submitting}
          className="inline-flex items-center rounded-lg border border-amber-300 bg-white px-3 py-1.5 text-xs font-medium text-amber-900 shadow-sm transition hover:border-amber-400 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {submitting ? "Recording…" : "Mark needs edit"}
        </button>
        <button
          type="button"
          onClick={() => onUpdateReview(runId, "reviewed_rejected")}
          disabled={submitting}
          className="inline-flex items-center rounded-lg border border-rose-300 bg-white px-3 py-1.5 text-xs font-medium text-rose-900 shadow-sm transition hover:border-rose-400 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {submitting ? "Recording…" : "Mark rejected"}
        </button>
      </div>

      {error ? (
        <p className="mt-3 text-xs leading-5 text-rose-700">
          Could not record review: {error}
        </p>
      ) : null}
    </div>
  );
}

function ReviewEvidenceCard({
  reviewStatus,
  reviewDecision,
  reviewedAt,
  reviewedByUserId,
}: {
  reviewStatus: string;
  reviewDecision: string | null;
  reviewedAt: string | null;
  reviewedByUserId: string | null;
}) {
  return (
    <div className="mt-5 rounded-xl border border-emerald-200 bg-emerald-50/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-emerald-900">Review evidence</p>
          <p className="mt-1 text-xs leading-5 text-emerald-800">
            Metadata-only review evidence. Draft text is not stored. This does not replace
            professional judgement.
          </p>
        </div>
        <span className="shrink-0 rounded-full border border-emerald-200 bg-white px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.1em] text-emerald-700">
          {reviewStatusLabel(reviewStatus)}
        </span>
      </div>
      <div className="mt-3 grid gap-2 sm:grid-cols-2">
        <div className="rounded-lg border border-emerald-100 bg-white px-3 py-2">
          <p className="text-[11px] uppercase tracking-wide text-emerald-700">Decision</p>
          <p className="mt-1 text-sm font-medium text-slate-900">
            {reviewDecisionLabel(reviewDecision)}
          </p>
        </div>
        <div className="rounded-lg border border-emerald-100 bg-white px-3 py-2">
          <p className="text-[11px] uppercase tracking-wide text-emerald-700">Reviewed at</p>
          <p className="mt-1 text-sm font-medium text-slate-900">
            {reviewedAt ? formatDateTime(reviewedAt) : "—"}
          </p>
        </div>
        <div className="rounded-lg border border-emerald-100 bg-white px-3 py-2 sm:col-span-2">
          <p className="text-[11px] uppercase tracking-wide text-emerald-700">Reviewed by</p>
          <p className="mt-1 font-mono text-xs text-slate-900">
            {reviewedByUserId ?? "—"}
          </p>
        </div>
      </div>
    </div>
  );
}

function NativeCard({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <section
      className={[
        "rounded-xl border border-slate-200/80 bg-white p-8 shadow-[0_18px_40px_rgba(42,52,57,0.07)]",
        className,
      ].join(" ")}
    >
      {children}
    </section>
  );
}

function SectionTitle({ title, description }: { title: string; description?: string }) {
  return (
    <div>
      <h2 className="text-base font-semibold text-slate-900">{title}</h2>
      {description ? (
        <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p>
      ) : null}
    </div>
  );
}

function MetricCell({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: string;
  tone?: "default" | "success";
}) {
  return (
    <div className="rounded-lg border border-slate-200/70 bg-slate-50 p-4">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p
        className={[
          "mt-2 text-sm font-semibold leading-tight",
          tone === "success" ? "text-emerald-700" : "text-slate-900",
        ].join(" ")}
      >
        {value}
      </p>
    </div>
  );
}

function DetailRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="grid grid-cols-[160px_1fr] gap-4 border-b border-slate-100 py-2 text-sm last:border-b-0">
      <dt className="text-slate-500">{label}</dt>
      <dd className={["font-medium text-slate-900", mono ? "font-mono text-xs" : ""].join(" ")}>
        {value}
      </dd>
    </div>
  );
}

function EmptyState({ title, description }: { title: string; description: string }) {
  return (
    <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-4">
      <p className="text-sm font-semibold text-slate-900">{title}</p>
      <p className="mt-2 text-sm leading-6 text-slate-600">{description}</p>
    </div>
  );
}

function UnavailableState({ title, description }: { title: string; description: string }) {
  return (
    <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-4">
      <div className="flex items-start gap-3">
        <span className="material-symbols-outlined mt-0.5 shrink-0 text-[18px] text-slate-400">
          info
        </span>
        <div>
          <p className="text-sm font-semibold text-slate-700">{title}</p>
          <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p>
        </div>
      </div>
    </div>
  );
}

function NavCard({
  href,
  icon,
  title,
  description,
}: {
  href: string;
  icon: string;
  title: string;
  description: string;
}) {
  return (
    <Link
      href={href}
      className="group flex items-start gap-4 rounded-xl border border-slate-200/80 bg-white p-5 shadow-sm transition hover:border-slate-300 hover:bg-slate-50/60"
    >
      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-600 transition group-hover:bg-slate-200">
        <span className="material-symbols-outlined text-[20px]">{icon}</span>
      </div>
      <div className="min-w-0">
        <p className="text-sm font-semibold text-slate-900">{title}</p>
        <p className="mt-0.5 text-sm leading-5 text-slate-600">{description}</p>
      </div>
      <span className="material-symbols-outlined ml-auto mt-0.5 shrink-0 text-[18px] text-slate-400 transition group-hover:translate-x-0.5">
        chevron_right
      </span>
    </Link>
  );
}

function formatDateTime(value?: string | null) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

