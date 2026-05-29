"use client";

import Link from "next/link";
import {
  useEffect,
  useState,
  useSyncExternalStore,
  type FormEvent,
  type ReactNode,
} from "react";
import {
  ASSISTANT_MODE_CLIENT_COMMUNICATION,
  createAssistantRunReceipt,
  getAssistantContract,
  getAssistantPolicy,
  getAssistantRun,
  getAssistantRunReceipt,
  listAssistantRuns,
  submitAssistantRun,
  updateAssistantPolicy,
  updateAssistantRunReview,
} from "@/lib/assistant";
import { ApiError } from "@/lib/api";
import {
  SESSION_SERVER_SNAPSHOT,
  getSessionUserSnapshot,
  subscribeSessionStorage,
} from "@/lib/auth";
import type {
  AssistantContractResponse,
  AssistantPolicySettings,
  AssistantReviewStatusInput,
  AssistantRunDetailResponse,
  AssistantRunReceipt,
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

// Clinic-admin roles permitted to edit Assistant policy metadata
// (policy_label, policy_notes only). Mirrors the same admin set used for
// the Learn CPD export gate. Hard clinical safety rules and the
// human-review requirement are NOT editable from the UI at any role.
const POLICY_ADMIN_ROLES = new Set(["admin", "owner", "practice_manager"]);

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

  // M6.5 — receipt action state.
  const [selectedReceipt, setSelectedReceipt] = useState<AssistantRunReceipt | null>(null);
  const [receiptLoading, setReceiptLoading] = useState(false);
  const [receiptError, setReceiptError] = useState<string | null>(null);
  const [receiptSubmitting, setReceiptSubmitting] = useState<string | null>(null);

  async function loadReceiptFor(runId: string) {
    setReceiptError(null);
    setReceiptLoading(true);
    try {
      const result = await getAssistantRunReceipt(runId);
      setSelectedReceipt(result.receipt);
      // The GET response also carries the latest run snapshot — refresh
      // the selected detail in-place so the receipt linkage state stays
      // consistent without a second request.
      setSelectedDetail({
        run: result.run,
        storage_policy: "metadata_only_by_default",
        raw_content_stored: false,
        draft_stored: false,
        prompt_stored: false,
        governance_note: result.governance_note,
      });
    } catch (err) {
      // 404 just means no receipt has been created yet — that's a normal
      // state, not an error. Surface other errors only.
      if (err instanceof ApiError && err.status === 404) {
        setSelectedReceipt(null);
      } else {
        const message =
          err instanceof ApiError ? err.message : "Unable to load receipt.";
        setReceiptError(message);
        setSelectedReceipt(null);
      }
    } finally {
      setReceiptLoading(false);
    }
  }

  async function createReceipt(runId: string) {
    setReceiptSubmitting(runId);
    setReceiptError(null);
    try {
      const result = await createAssistantRunReceipt(runId);
      setSelectedReceipt(result.receipt);
      setSelectedDetail({
        run: result.run,
        storage_policy: "metadata_only_by_default",
        raw_content_stored: false,
        draft_stored: false,
        prompt_stored: false,
        governance_note: result.governance_note,
      });
      // Refresh recent-runs list so receipt linkage appears in the table.
      void loadEvidence();
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : "Unable to create receipt.";
      setReceiptError(message);
    } finally {
      setReceiptSubmitting(null);
    }
  }

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
    setSelectedReceipt(null);
    setReceiptError(null);
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
      // If a receipt is already linked, lazily load it now so the
      // receipt evidence card renders without a second click.
      if (detail.run?.has_receipt) {
        void loadReceiptFor(runId);
      }
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

  // M6.7 — Assistant policy state. Read-only in this PR (no admin-role
  // detection in the frontend yet). Failure to load policy must not
  // block the rest of the Assistant flow.
  const [policy, setPolicy] = useState<AssistantPolicySettings | null>(null);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [policyLoading, setPolicyLoading] = useState(false);

  async function loadPolicy(isRefresh = false) {
    try {
      if (!isRefresh) setPolicyLoading(true);
      setPolicyError(null);
      const result = await getAssistantPolicy();
      setPolicy(result.policy);
    } catch (err) {
      setPolicy(null);
      const message =
        err instanceof ApiError
          ? err.message
          : "Unable to load Assistant policy.";
      setPolicyError(message);
    } finally {
      setPolicyLoading(false);
    }
  }

  useEffect(() => {
    void loadContract(false);
    void loadPolicy(false);
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
    <div className="space-y-5">
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

      <div className="rounded-xl border border-slate-200 bg-slate-50 px-5 py-4">
        <div className="flex items-start gap-3">
          <span className="material-symbols-outlined mt-0.5 text-[18px] text-slate-500">policy</span>
          <div>
            <p className="text-sm font-semibold text-slate-900">
              Storage policy — metadata-only by default
            </p>
            <p className="mt-1 text-sm leading-6 text-slate-700">
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

      <AssistantPolicyCard
        policy={policy}
        loading={policyLoading}
        error={policyError}
        onRefresh={() => void loadPolicy(true)}
        onPolicyUpdated={(next) => setPolicy(next)}
      />

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
        selectedReceipt={selectedReceipt}
        receiptLoading={receiptLoading}
        receiptError={receiptError}
        receiptSubmitting={receiptSubmitting}
        onCreateReceipt={(runId) => void createReceipt(runId)}
        onRefreshReceipt={(runId) => void loadReceiptFor(runId)}
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
    case "output_blocked":
      return "Output blocked";
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

// M6.7.1 — policy-version display helper.
//   `null` / `undefined` / `0` → "Default policy"
//   number N  → "v{N}"
// Stays a string so it can flow through the existing DetailRow.
function policyVersionLabel(version: number | null | undefined): string {
  if (version === null || version === undefined || version === 0) {
    return "Default policy";
  }
  return `v${version}`;
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
  const blocked = record.blocked === true || runStatus === "output_blocked";
  // `refused` historically encoded both "input refused" and (since M6.6)
  // "output blocked" — keep the input-side specifically so the UI can
  // pick the right panel.
  const refusedBeforeModel = runStatus === "generation_refused" || (
    record.refused === true && !blocked
  );
  const refusalCodes = record.refusal_reason_codes ?? [];
  const safetyFlags = record.safety_flags ?? [];
  const draft = typeof record.draft === "string" ? record.draft : null;
  const blockedMessage = typeof record.blocked_message === "string" ? record.blocked_message : null;
  const showDraftPanel = runStatus === "generation_succeeded" && !!draft && !refusedBeforeModel && !blocked;
  const showRefusalPanel = refusedBeforeModel;
  const showBlockedPanel = blocked;
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
        <MetricCell label="Run ID" value={formatShortId(runId ? String(runId) : null)} />
        <MetricCell label="Review status" value={reviewStatusLabel(reviewStatus)} tone="success" />
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
      {showBlockedPanel ? (
        <OutputBlockedPanel
          reasonCodes={refusalCodes}
          safetyFlags={safetyFlags}
          blockedMessage={blockedMessage}
          outputSha256={typeof record.output_sha256 === "string" ? record.output_sha256 : null}
          modelProvider={typeof record.model_provider === "string" ? record.model_provider : null}
          modelName={typeof record.model_name === "string" ? record.model_name : null}
        />
      ) : null}
      {showFailurePanel ? <FailurePanel /> : null}

      <div className="mt-4 space-y-2">
        {runId ? (
          <DetailRow
            label="Run ID"
            value={String(runId)}
            displayValue={formatShortId(String(runId))}
            mono
            copyValue={String(runId)}
          />
        ) : null}
        {record.contract_version ?? record.contract_id ? (
          <DetailRow
            label="Contract"
            value={String(record.contract_version ?? record.contract_id)}
          />
        ) : null}
        {record.mode ? <DetailRow label="Mode" value={record.mode} /> : null}
        <DetailRow label="Run status" value={runStatusLabel(runStatus)} />
        <DetailRow
          label="Refused"
          value={blocked ? "Blocked" : refusedBeforeModel ? "Yes" : "No"}
        />
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
          value={record.output_sha256 ?? "None"}
          displayValue={record.output_sha256 ? formatShortId(record.output_sha256) : "None"}
          mono={!!record.output_sha256}
          copyValue={record.output_sha256 ?? null}
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
        <DetailRow
          label="Policy version"
          value={policyVersionLabel(
            typeof record.assistant_policy_version === "number"
              ? record.assistant_policy_version
              : null,
          )}
        />
        <DetailRow
          label="Validation profile"
          value={
            typeof record.assistant_validation_profile === "string" &&
            record.assistant_validation_profile
              ? record.assistant_validation_profile
              : "standard"
          }
        />
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

      <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
        <p className="text-xs leading-5 text-slate-700">
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

function OutputBlockedPanel({
  reasonCodes,
  safetyFlags,
  blockedMessage,
  outputSha256,
  modelProvider,
  modelName,
}: {
  reasonCodes: string[];
  safetyFlags: string[];
  blockedMessage: string | null;
  outputSha256: string | null;
  modelProvider: string | null;
  modelName: string | null;
}) {
  return (
    <div className="mt-5 rounded-xl border border-rose-300 bg-rose-50 p-4">
      <p className="text-sm font-semibold text-rose-900">Output blocked</p>
      <p className="mt-1 text-xs leading-5 text-rose-800">
        ANCHOR blocked this generated draft because it may contain unsafe clinical content.
        No draft text is stored or shown. Output hash records that a generated output existed
        without retaining it. This is governance evidence, not a clinical correctness check.
      </p>
      {blockedMessage ? (
        <p className="mt-2 text-xs leading-5 text-rose-800">{blockedMessage}</p>
      ) : null}

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

      <div className="mt-3 grid gap-2 sm:grid-cols-2">
        <div className="rounded-lg border border-rose-100 bg-white px-3 py-2">
          <p className="text-[11px] uppercase tracking-wide text-rose-700">Output hash</p>
          <p className="mt-1 font-mono text-xs text-slate-900 break-all">
            {outputSha256 ?? "None"}
          </p>
        </div>
        <div className="rounded-lg border border-rose-100 bg-white px-3 py-2">
          <p className="text-[11px] uppercase tracking-wide text-rose-700">Model</p>
          <p className="mt-1 text-xs font-medium text-slate-900">
            {modelProvider || modelName
              ? `${modelProvider ?? "-"} / ${modelName ?? "-"}`
              : "Not invoked"}
          </p>
        </div>
      </div>
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
  selectedReceipt,
  receiptLoading,
  receiptError,
  receiptSubmitting,
  onCreateReceipt,
  onRefreshReceipt,
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
  selectedReceipt: AssistantRunReceipt | null;
  receiptLoading: boolean;
  receiptError: string | null;
  receiptSubmitting: string | null;
  onCreateReceipt: (runId: string) => void;
  onRefreshReceipt: (runId: string) => void;
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
                <th className="w-[12%] px-3 py-2 font-semibold">Output hash</th>
                <th className="w-[12%] px-3 py-2 font-semibold">Model</th>
                <th className="w-[8%] px-3 py-2 font-semibold">Receipt</th>
                <th className="w-[6%] px-3 py-2 font-semibold" />
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => {
                const isSelected = selectedRunId === r.run_id;
                const receiptLinked = Boolean(r.has_receipt || r.receipt_id);
                return (
                  <tr
                    key={r.run_id}
                    className={[
                      "border-b border-slate-100 last:border-b-0",
                      isSelected ? "bg-slate-50" : "hover:bg-slate-50/50",
                    ].join(" ")}
                  >
                    <td className="px-3 py-2 font-mono text-[12px] text-slate-700">
                      {formatShortId(r.run_id)}
                    </td>
                    <td className="px-3 py-2 text-slate-700">{formatDateTime(r.created_at)}</td>
                    <td className="px-3 py-2">
                      <StatusPill
                        label={runStatusLabel(r.run_status)}
                        tone={runStatusTonePill(r.run_status)}
                      />
                    </td>
                    <td className="px-3 py-2">
                      <StatusPill
                        label={reviewStatusLabel(r.review_status)}
                        tone={reviewStatusTonePill(r.review_status)}
                      />
                    </td>
                    <td className="px-3 py-2 text-slate-700">{r.pii_detected ? "Yes" : "No"}</td>
                    <td className="px-3 py-2 text-slate-700">
                      {r.run_status === "output_blocked"
                        ? "Blocked"
                        : r.refusal_reason_codes.length > 0
                          ? "Yes"
                          : "No"}
                    </td>
                    <td className="px-3 py-2 font-mono text-[12px] text-slate-700">
                      {r.output_sha256 ? formatShortId(r.output_sha256) : "—"}
                    </td>
                    <td className="px-3 py-2 text-slate-700">
                      {r.model_provider || r.model_name
                        ? `${r.model_provider ?? "-"} / ${r.model_name ?? "-"}`
                        : "Not invoked"}
                    </td>
                    <td className="px-3 py-2">
                      <StatusPill
                        label={receiptLinked ? "Linked" : "Not linked"}
                        tone={receiptLinked ? "info" : "neutral"}
                      />
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
          receipt={selectedReceipt}
          receiptLoading={receiptLoading}
          receiptError={receiptError}
          receiptSubmitting={receiptSubmitting}
          onCreateReceipt={onCreateReceipt}
          onRefreshReceipt={onRefreshReceipt}
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
  receipt,
  receiptLoading,
  receiptError,
  receiptSubmitting,
  onCreateReceipt,
  onRefreshReceipt,
}: {
  runId: string;
  detail: AssistantRunDetailResponse | null;
  loading: boolean;
  error: string | null;
  onUpdateReview: (runId: string, reviewStatus: AssistantReviewStatusInput) => void;
  reviewSubmitting: string | null;
  reviewError: string | null;
  receipt: AssistantRunReceipt | null;
  receiptLoading: boolean;
  receiptError: string | null;
  receiptSubmitting: string | null;
  onCreateReceipt: (runId: string) => void;
  onRefreshReceipt: (runId: string) => void;
}) {
  return (
    <section className="mt-5 rounded-xl border border-slate-200 bg-white p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-sm font-semibold text-slate-900">Run metadata</p>
          <div className="mt-1 flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-slate-500 break-all">
              {formatShortId(runId)}
            </span>
            <CopyButton value={runId} ariaLabel="Copy run ID" />
          </div>
        </div>
        {detail ? (
          <span className="shrink-0 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.1em] text-emerald-700">
            Metadata only
          </span>
        ) : null}
      </div>

      <p className="mt-3 text-xs leading-5 text-slate-500">
        This is an Assistant governance record, not a chat history. ANCHOR stores metadata,
        hashes, policy context, review state, and receipt evidence only.
      </p>

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
          receipt={receipt}
          receiptLoading={receiptLoading}
          receiptError={receiptError}
          receiptSubmitting={receiptSubmitting}
          onCreateReceipt={onCreateReceipt}
          onRefreshReceipt={onRefreshReceipt}
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
  receipt,
  receiptLoading,
  receiptError,
  receiptSubmitting,
  onCreateReceipt,
  onRefreshReceipt,
}: {
  detail: AssistantRunDetailResponse;
  onUpdateReview: (runId: string, reviewStatus: AssistantReviewStatusInput) => void;
  reviewSubmitting: string | null;
  reviewError: string | null;
  receipt: AssistantRunReceipt | null;
  receiptLoading: boolean;
  receiptError: string | null;
  receiptSubmitting: string | null;
  onCreateReceipt: (runId: string) => void;
  onRefreshReceipt: (runId: string) => void;
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

      <ReceiptSection
        runId={r.run_id}
        reviewStatus={r.review_status}
        hasReceipt={Boolean(r.has_receipt) || r.receipt_id != null || receipt != null}
        receipt={receipt}
        loading={receiptLoading}
        error={receiptError}
        submitting={receiptSubmitting === r.run_id}
        onCreateReceipt={onCreateReceipt}
        onRefreshReceipt={onRefreshReceipt}
      />

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
          <DetailRow
            label="Reviewed by"
            value={r.reviewed_by_user_id}
            displayValue={reviewerFriendlyLabel(r.reviewed_by_user_id)}
            copyValue={r.reviewed_by_user_id}
          />
        ) : null}
        <DetailRow
          label="Policy version"
          value={policyVersionLabel(r.assistant_policy_version ?? null)}
        />
        <DetailRow
          label="Validation profile"
          value={r.assistant_validation_profile ?? "standard"}
        />
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
        <DetailRow
          label="Input hash"
          value={r.input_sha256}
          displayValue={formatShortId(r.input_sha256)}
          mono
          copyValue={r.input_sha256}
        />
        <DetailRow
          label="Output hash"
          value={r.output_sha256 ?? "None"}
          displayValue={r.output_sha256 ? formatShortId(r.output_sha256) : "None"}
          mono={!!r.output_sha256}
          copyValue={r.output_sha256 ?? null}
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
          value={r.receipt_id ?? "Not linked yet"}
          displayValue={r.receipt_id ? formatShortId(r.receipt_id) : "Not linked yet"}
          mono={!!r.receipt_id}
          copyValue={r.receipt_id ?? null}
        />
        {r.receipt_created_at ? (
          <DetailRow
            label="Receipt created at"
            value={formatDateTime(r.receipt_created_at)}
          />
        ) : null}
        <DetailRow
          label="Governance event"
          value={r.governance_event_id ?? "Not linked yet"}
          displayValue={
            r.governance_event_id ? formatShortId(r.governance_event_id) : "Not linked yet"
          }
          mono={!!r.governance_event_id}
          copyValue={r.governance_event_id ?? null}
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

function ReceiptSection({
  runId,
  reviewStatus,
  hasReceipt,
  receipt,
  loading,
  error,
  submitting,
  onCreateReceipt,
  onRefreshReceipt,
}: {
  runId: string;
  reviewStatus: string;
  hasReceipt: boolean;
  receipt: AssistantRunReceipt | null;
  loading: boolean;
  error: string | null;
  submitting: boolean;
  onCreateReceipt: (runId: string) => void;
  onRefreshReceipt: (runId: string) => void;
}) {
  const reviewed = reviewStatus && reviewStatus !== "not_reviewed";

  // 1) Not reviewed — receipt creation is blocked at the backend (400).
  if (!reviewed) {
    return (
      <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
        <p className="text-sm font-semibold text-slate-900">Receipt</p>
        <p className="mt-1 text-xs leading-5 text-slate-600">
          Record human review before creating a receipt. Human review must be recorded before
          receipt creation. This receipt is not a clinical record.
        </p>
      </div>
    );
  }

  // 2) Reviewed but no receipt yet — show create action.
  if (!hasReceipt && !receipt) {
    return (
      <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
        <p className="text-sm font-semibold text-slate-900">Create metadata receipt</p>
        <p className="mt-1 text-xs leading-5 text-slate-600">
          Creates a metadata-only governance receipt. Raw input, prompts, and draft output are
          not stored. Receipt confirms governance metadata, not clinical correctness.
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => onCreateReceipt(runId)}
            disabled={submitting}
            className="inline-flex items-center rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-900 shadow-sm transition hover:border-slate-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? "Creating…" : "Create metadata receipt"}
          </button>
          {error ? (
            <p className="text-xs leading-5 text-rose-700">
              Could not create receipt: {error}
            </p>
          ) : null}
        </div>
      </div>
    );
  }

  // 3) Reviewed and receipt exists — show evidence card.
  if (receipt) {
    return <ReceiptEvidenceCard receipt={receipt} onRefresh={() => onRefreshReceipt(runId)} />;
  }

  // 4) Linked but not yet fetched — surface a load state / link.
  return (
    <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-slate-900">Receipt linked</p>
          <p className="mt-1 text-xs leading-5 text-slate-600">
            A metadata-only receipt is linked to this run. Open it to inspect receipt metadata.
          </p>
        </div>
        <button
          type="button"
          onClick={() => onRefreshReceipt(runId)}
          disabled={loading}
          className="inline-flex shrink-0 items-center rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-900 shadow-sm transition hover:border-slate-400 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading ? "Loading…" : "Open receipt metadata"}
        </button>
      </div>
      {error ? (
        <p className="mt-2 text-xs leading-5 text-rose-700">
          Could not load receipt: {error}
        </p>
      ) : null}
    </div>
  );
}

function ReceiptEvidenceCard({
  receipt,
  onRefresh,
}: {
  receipt: AssistantRunReceipt;
  onRefresh: () => void;
}) {
  return (
    <div className="mt-5 rounded-xl border border-sky-200 bg-sky-50/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-sky-900">Metadata-only governance receipt</p>
          <p className="mt-1 text-xs leading-5 text-sky-800">
            Raw input, prompts, and draft output are not stored. Receipt confirms governance
            metadata, not clinical correctness. This receipt is not a clinical record.
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          <Link
            href={`/receipts?assistantRunId=${encodeURIComponent(receipt.assistant_run_id)}`}
            className="inline-flex items-center rounded-lg border border-sky-200 bg-white px-3 py-1.5 text-xs font-medium text-sky-900 shadow-sm transition hover:border-sky-300"
          >
            Open in Receipts
          </Link>
          <button
            type="button"
            onClick={onRefresh}
            className="inline-flex items-center rounded-lg border border-sky-200 bg-white px-3 py-1.5 text-xs font-medium text-sky-900 shadow-sm transition hover:border-sky-300"
          >
            Refresh receipt
          </button>
        </div>
      </div>

      <ReceiptGroup title="Storage posture">
        <ReceiptCell label="Storage policy" value={receipt.storage_policy} />
        <ReceiptCell
          label="Raw input stored"
          value={receipt.raw_content_stored ? "Yes" : "No"}
        />
        <ReceiptCell label="Prompt stored" value={receipt.prompt_stored ? "Yes" : "No"} />
        <ReceiptCell label="Draft stored" value={receipt.draft_stored ? "Yes" : "No"} />
      </ReceiptGroup>

      <ReceiptGroup title="Receipt identity">
        <ReceiptCell
          label="Receipt ID"
          value={formatShortId(receipt.receipt_id)}
          copyValue={receipt.receipt_id}
          mono
        />
        <ReceiptCell label="Receipt kind" value={receipt.receipt_kind} />
        <ReceiptCell label="Receipt version" value={receipt.receipt_version} />
        <ReceiptCell label="Created at" value={formatDateTime(receipt.receipt_created_at)} />
      </ReceiptGroup>

      <ReceiptGroup title="Review outcome">
        <ReceiptCell label="Run status" value={runStatusLabel(receipt.run_status)} />
        <ReceiptCell label="Review status" value={reviewStatusLabel(receipt.review_status)} />
        <ReceiptCell
          label="Review decision"
          value={reviewDecisionLabel(receipt.review_decision)}
        />
      </ReceiptGroup>

      <ReceiptGroup title="Policy context">
        <ReceiptCell
          label="Policy version"
          value={policyVersionLabel(
            typeof receipt.assistant_policy_version === "number"
              ? receipt.assistant_policy_version
              : null,
          )}
        />
        <ReceiptCell
          label="Validation profile"
          value={
            typeof receipt.assistant_validation_profile === "string" &&
            receipt.assistant_validation_profile
              ? receipt.assistant_validation_profile
              : "standard"
          }
        />
      </ReceiptGroup>

      <ReceiptGroup title="Hash evidence">
        <ReceiptCell
          label="Input hash"
          value={formatShortId(receipt.input_sha256)}
          copyValue={receipt.input_sha256}
          mono
        />
        <ReceiptCell
          label="Output hash"
          value={receipt.output_sha256 ? formatShortId(receipt.output_sha256) : "None"}
          copyValue={receipt.output_sha256 ?? null}
          mono={!!receipt.output_sha256}
        />
      </ReceiptGroup>

      <p className="mt-3 text-[11px] leading-5 text-emerald-700">
        Policy context is metadata only. Hard clinical safety rules cannot be disabled.
      </p>
      <p className="mt-1 text-[11px] leading-5 text-sky-700">
        This is an Assistant governance record, not a chat history. ANCHOR stores metadata,
        hashes, policy context, review state, and receipt evidence only.
      </p>
    </div>
  );
}

function ReceiptGroup({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="mt-3">
      <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-sky-700">
        {title}
      </p>
      <div className="mt-1.5 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">{children}</div>
    </div>
  );
}

function ReceiptCell({
  label,
  value,
  mono = false,
  copyValue,
}: {
  label: string;
  value: string;
  mono?: boolean;
  copyValue?: string | null;
}) {
  return (
    <div className="rounded-lg border border-sky-100 bg-white px-3 py-2">
      <p className="text-[11px] uppercase tracking-wide text-sky-700">{label}</p>
      <div className="mt-1 flex flex-wrap items-center gap-2">
        <span
          className={[
            "text-sm text-slate-900",
            mono ? "font-mono text-xs break-all" : "font-medium",
          ].join(" ")}
        >
          {value}
        </span>
        {copyValue ? <CopyButton value={copyValue} ariaLabel={`Copy ${label}`} /> : null}
      </div>
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
          <p className="mt-1 text-sm font-medium text-slate-900">
            {reviewedByUserId ? "Clinic user" : "—"}
          </p>
          {reviewedByUserId ? (
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-slate-500 break-all">
                Reviewer ID: {formatShortId(reviewedByUserId)}
              </span>
              <CopyButton value={reviewedByUserId} ariaLabel="Copy reviewer ID" />
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------
// M6.7 — Assistant policy card
// M6.10.1 — Adds an admin-only edit affordance for policy METADATA only
// (policy_label, policy_notes). Hard clinical safety rules, the
// human-review requirement, validation profile, generation/communication
// toggles, and run limits remain read-only display. The backend PATCH
// endpoint is admin-only; this frontend gate is UX hardening so
// non-admin users do not see edit controls.
// ---------------------------------------------------------------------

function AssistantPolicyCard({
  policy,
  loading,
  error,
  onRefresh,
  onPolicyUpdated,
}: {
  policy: AssistantPolicySettings | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
  onPolicyUpdated: (next: AssistantPolicySettings) => void;
}) {
  // Session is read here (not at the parent) so the policy card stays
  // self-contained. Pattern mirrors AppShell's session subscription.
  const sessionUser = useSyncExternalStore(
    subscribeSessionStorage,
    getSessionUserSnapshot,
    SESSION_SERVER_SNAPSHOT,
  );
  const isPolicyAdmin = Boolean(
    sessionUser?.role && POLICY_ADMIN_ROLES.has(sessionUser.role),
  );

  const [isEditing, setIsEditing] = useState(false);
  const [editLabel, setEditLabel] = useState("");
  const [editNotes, setEditNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  function openEdit() {
    setEditLabel(policy?.policy_label ?? "");
    setEditNotes(policy?.policy_notes ?? "");
    setSaveError(null);
    setIsEditing(true);
  }

  function cancelEdit() {
    setIsEditing(false);
    setSaveError(null);
  }

  async function handleSave() {
    setSaving(true);
    setSaveError(null);
    try {
      const result = await updateAssistantPolicy({
        policy_label: editLabel,
        policy_notes: editNotes,
      });
      onPolicyUpdated(result.policy);
      setIsEditing(false);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Unable to save policy metadata.";
      setSaveError(message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <NativeCard>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <SectionTitle
          title="Assistant policy"
          description="Metadata-only governance configuration. Hard clinical safety rules cannot be disabled."
        />
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {isPolicyAdmin && !isEditing ? (
            <button
              type="button"
              onClick={openEdit}
              disabled={loading || !policy}
              className="inline-flex shrink-0 items-center rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-900 shadow-sm transition hover:border-slate-300 disabled:cursor-not-allowed disabled:opacity-60"
            >
              Edit policy metadata
            </button>
          ) : null}
        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex shrink-0 items-center rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-900 shadow-sm transition hover:border-slate-300 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading ? "Loading…" : "Refresh policy"}
        </button>
        </div>
      </div>

      {error ? (
        <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3">
          <p className="text-sm font-semibold text-amber-900">
            Policy could not be loaded
          </p>
          <p className="mt-1 text-sm leading-6 text-amber-800">{error}</p>
          <p className="mt-2 text-xs leading-5 text-amber-700">
            The Assistant continues to operate with safe defaults until the
            policy can be loaded.
          </p>
        </div>
      ) : null}

      {policy ? (
        <>
          <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <MetricCell
              label="Active version"
              value={
                policy.is_default
                  ? "Default (no override)"
                  : `v${policy.policy_version}${policy.is_active ? " (active)" : ""}`
              }
              tone="success"
            />
            <MetricCell
              label="Validation profile"
              value={policy.validation_profile}
              tone="success"
            />
            <MetricCell
              label="Generation enabled"
              value={policy.generation_enabled ? "Yes" : "No"}
              tone={policy.generation_enabled ? "success" : "default"}
            />
            <MetricCell
              label="Client communication"
              value={policy.client_communication_enabled ? "Enabled" : "Disabled"}
              tone={policy.client_communication_enabled ? "success" : "default"}
            />
          </div>

          <div className="mt-4 space-y-2">
            <DetailRow label="Policy label" value={policy.policy_label} />
            <DetailRow
              label="Daily run limit (per clinic)"
              value={String(policy.daily_run_limit_per_clinic)}
            />
            <DetailRow
              label="Monthly run limit (per clinic)"
              value={String(policy.monthly_run_limit_per_clinic)}
            />
            <DetailRow
              label="Human review required"
              value={policy.require_human_review ? "Yes" : "No"}
            />
            <DetailRow
              label="Receipts after review"
              value={policy.allow_receipts_after_review ? "Yes" : "No"}
            />
            {policy.policy_notes ? (
              <DetailRow label="Notes" value={policy.policy_notes} />
            ) : null}
            {policy.activated_at ? (
              <DetailRow
                label="Activated at"
                value={formatDateTime(policy.activated_at)}
              />
            ) : null}
          </div>

          {isPolicyAdmin && isEditing ? (
            <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-4">
              <p className="text-xs leading-5 text-slate-600">
                Update the policy label and notes shown on this clinic&apos;s
                policy snapshot. Hard clinical safety rules and human-review
                requirements are not configurable here.
              </p>

              <label className="mt-3 block text-xs font-medium text-slate-500">
                Policy label
                <input
                  type="text"
                  value={editLabel}
                  onChange={(event) => setEditLabel(event.target.value)}
                  disabled={saving}
                  className="mt-1 block w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-normal text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
                />
              </label>

              <label className="mt-3 block text-xs font-medium text-slate-500">
                Policy notes
                <textarea
                  value={editNotes}
                  onChange={(event) => setEditNotes(event.target.value)}
                  rows={3}
                  disabled={saving}
                  className="mt-1 block w-full rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-normal text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
                />
              </label>

              {saveError ? (
                <div className="mt-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3">
                  <p className="text-sm font-semibold text-amber-900">
                    Policy metadata could not be saved
                  </p>
                  <p className="mt-1 text-sm leading-6 text-amber-800">
                    {saveError}
                  </p>
                </div>
              ) : null}

              <div className="mt-4 flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => void handleSave()}
                  disabled={saving}
                  className="inline-flex shrink-0 items-center rounded-xl border border-slate-900 bg-slate-900 px-3 py-1.5 text-sm font-medium text-white shadow-sm transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {saving ? "Saving…" : "Save metadata"}
                </button>
                <button
                  type="button"
                  onClick={cancelEdit}
                  disabled={saving}
                  className="inline-flex shrink-0 items-center rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-900 shadow-sm transition hover:border-slate-300 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  Cancel
                </button>
              </div>
            </div>
          ) : null}

          <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
            <p className="text-xs leading-5 text-slate-700">
              <strong>Hard clinical safety rules cannot be disabled.</strong>{" "}
              Human review is required before operational use. Diagnosis,
              prescribing, dosing, and autonomous triage decisions are not
              configurable and are always blocked. Policy edits are admin-only
              and audited.
            </p>
          </div>
        </>
      ) : !loading && !error ? (
        <EmptyState
          title="No policy loaded"
          description="Click Refresh policy to load the current Assistant policy."
        />
      ) : null}
    </NativeCard>
  );
}

function NativeCard({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <section
      className={[
        "rounded-xl border border-slate-200/80 bg-white p-6 shadow-[0_18px_40px_rgba(42,52,57,0.07)]",
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
  copyValue,
  displayValue,
}: {
  label: string;
  value: string;
  mono?: boolean;
  copyValue?: string | null;
  displayValue?: string;
}) {
  return (
    <div className="grid grid-cols-[160px_1fr] gap-4 border-b border-slate-100 py-2 text-sm last:border-b-0">
      <dt className="text-slate-500">{label}</dt>
      <dd className="flex min-w-0 flex-wrap items-center gap-2">
        <span
          className={[
            "font-medium text-slate-900",
            mono ? "font-mono text-xs break-all" : "",
          ].join(" ")}
        >
          {displayValue ?? value}
        </span>
        {copyValue ? <CopyButton value={copyValue} ariaLabel={`Copy ${label}`} /> : null}
      </dd>
    </div>
  );
}

// M6.9 — local UX helpers. Long hashes/IDs are visually noisy and break
// table layout. We shorten the display but keep the full value behind a
// copy button so governance evidence stays inspectable.
function formatShortId(value: string | null | undefined): string {
  if (!value) return "—";
  if (value.length <= 18) return value;
  return `${value.slice(0, 8)}…${value.slice(-6)}`;
}

// Reviewer identity is currently a UUID from the authenticated clinic
// user context. We show a safe friendly label plus a shortened ID, and
// keep the full UUID copyable below — no name is invented.
function reviewerFriendlyLabel(reviewedByUserId: string | null | undefined): string {
  if (!reviewedByUserId) return "—";
  return `Clinic user · ${formatShortId(reviewedByUserId)}`;
}

async function copyToClipboard(value: string): Promise<boolean> {
  if (!value) return false;
  try {
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch {
    // Best-effort: clipboard access can fail in restricted contexts.
    // The on-screen value remains selectable for manual copy.
  }
  return false;
}

function CopyButton({
  value,
  ariaLabel,
}: {
  value: string;
  ariaLabel: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label={ariaLabel}
      onClick={async () => {
        const ok = await copyToClipboard(value);
        if (ok) {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1500);
        }
      }}
      className="inline-flex shrink-0 items-center rounded-md border border-slate-200 bg-white px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-[0.08em] text-slate-600 shadow-sm transition hover:border-slate-300 hover:text-slate-900"
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function StatusPill({
  label,
  tone = "neutral",
}: {
  label: string;
  tone?: "neutral" | "success" | "warn" | "danger" | "info";
}) {
  const toneClass =
    tone === "success"
      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
      : tone === "warn"
        ? "border-amber-200 bg-amber-50 text-amber-800"
        : tone === "danger"
          ? "border-rose-200 bg-rose-50 text-rose-800"
          : tone === "info"
            ? "border-sky-200 bg-sky-50 text-sky-800"
            : "border-slate-200 bg-slate-50 text-slate-700";
  return (
    <span
      className={[
        "inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium",
        toneClass,
      ].join(" ")}
    >
      {label}
    </span>
  );
}

function runStatusTonePill(runStatus: string | undefined | null): "neutral" | "success" | "warn" | "danger" {
  switch (runStatus) {
    case "generation_succeeded":
      return "success";
    case "generation_refused":
    case "output_blocked":
      return "danger";
    case "generation_failed":
      return "warn";
    default:
      return "neutral";
  }
}

function reviewStatusTonePill(status: string | undefined | null): "neutral" | "success" | "warn" | "danger" {
  switch (status) {
    case "reviewed_approved":
      return "success";
    case "reviewed_rejected":
      return "danger";
    case "reviewed_needs_edit":
      return "warn";
    default:
      return "neutral";
  }
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

