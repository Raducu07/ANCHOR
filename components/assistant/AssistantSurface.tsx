"use client";

import Link from "next/link";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { getAssistantContract, submitAssistantRun } from "@/lib/assistant";
import { ApiError } from "@/lib/api";
import type { AssistantContractResponse, AssistantRunRecord } from "@/lib/types";

const SAFE_USE_CASES = [
  { value: "explain_governance_receipt", label: "Explain a governance receipt" },
  { value: "explain_why_flagged", label: "Explain why something was flagged" },
  {
    value: "help_rewrite_client_communication",
    label: "Help rewrite client communication (human review required)",
  },
  { value: "help_prepare_internal_summary", label: "Help prepare an internal summary" },
  { value: "explain_clinic_ai_policy", label: "Explain clinic AI policy" },
  { value: "suggest_learn_guidance", label: "Suggest relevant Learn guidance" },
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

  const [useCase, setUseCase] = useState<string>(SAFE_USE_CASES[0].value);
  const [intentSummary, setIntentSummary] = useState("");
  const [runState, setRunState] = useState<RunState>({ kind: "idle" });

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
    if (!intentSummary.trim()) return;

    setRunState({ kind: "submitting" });
    try {
      const record = await submitAssistantRun({
        use_case: useCase,
        intent_summary: intentSummary.trim(),
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
    setIntentSummary("");
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
            A contract-bound, metadata-only assistant layer operating under explicit governance
            rules, storage policy, and safety boundaries. Not a clinical decision-making system.
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
              No raw prompts, outputs, transcripts, or clinical content are stored by this assistant.
              Governance receipts and run records capture accountability metadata only. Human review
              is required before any result is used operationally. ANCHOR is not a clinical
              decision-making system.
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
          <ul className="mt-4 space-y-2">
            {SAFE_USE_CASES.map((item) => (
              <li key={item.value} className="flex items-start gap-3">
                <span className="material-symbols-outlined mt-0.5 shrink-0 text-[18px] text-emerald-500">
                  check_circle
                </span>
                <span className="text-sm leading-6 text-slate-700">{item.label}</span>
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
          title="Submit a governed run record"
          description="Select a permitted use case and describe your intent. A metadata-only governance run record will be created if the endpoint is available. No LLM call is made at this stage. Human review is required before operational use."
        />

        <form onSubmit={(e) => void handleRunSubmit(e)} className="mt-6 space-y-4">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
              Use case
            </label>
            <select
              value={useCase}
              onChange={(e) => setUseCase(e.target.value)}
              disabled={runState.kind === "submitting"}
              className="mt-2 w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm focus:border-slate-400 focus:outline-none disabled:opacity-60"
            >
              {SAFE_USE_CASES.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
              Intent summary
            </label>
            <textarea
              value={intentSummary}
              onChange={(e) => setIntentSummary(e.target.value)}
              disabled={runState.kind === "submitting"}
              placeholder="Briefly describe what you need, without including clinical case details or patient information."
              rows={4}
              className="mt-2 w-full resize-none rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm placeholder:text-slate-400 focus:border-slate-400 focus:outline-none disabled:opacity-60"
            />
            <p className="mt-1.5 text-xs text-slate-500">
              Do not include patient names, clinical case specifics, or identifiable information.
              Intent text is not stored - only governance metadata from the run record is retained.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-4">
            <button
              type="submit"
              disabled={runState.kind === "submitting" || !intentSummary.trim()}
              className="inline-flex items-center rounded-xl bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {runState.kind === "submitting" ? "Submitting..." : "Submit run record"}
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
              <strong>Human review required.</strong> Run records are metadata-only governance
              records. Any output associated with a run must be reviewed by a qualified
              veterinary professional before operational use. ANCHOR does not make clinical
              decisions.
            </p>
          </div>
        </form>
      </NativeCard>

      {runState.kind === "record" ? (
        <RunRecordCard record={runState.data} />
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

function RunRecordCard({ record }: { record: AssistantRunRecord }) {
  const runId = record.run_id ?? record.request_id;
  const noRawContent = record.no_raw_content_stored ?? record.no_content_stored ?? true;

  return (
    <NativeCard>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4">
        <SectionTitle
          title="Governed run record"
          description="This is a governance metadata record only. No output content is stored. Human review is required before operational use."
        />
        {noRawContent ? (
          <span className="shrink-0 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.1em] text-emerald-700">
            No raw content stored
          </span>
        ) : null}
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCell label="Run ID" value={runId ? `${String(runId).slice(0, 12)}â€¦` : "-"} />
        <MetricCell label="Status" value={record.status ?? "recorded"} tone="success" />
        <MetricCell label="Storage decision" value={record.storage_decision ?? "metadata-only"} />
        <MetricCell
          label="Policy version"
          value={record.policy_version ? `v${String(record.policy_version)}` : "-"}
        />
      </div>

      <div className="mt-4 space-y-2">
        {record.contract_version ?? record.contract_id ? (
          <DetailRow
            label="Contract"
            value={String(record.contract_version ?? record.contract_id)}
          />
        ) : null}
        {record.risk_grade ? <DetailRow label="Risk grade" value={record.risk_grade} /> : null}
        {record.reason_code ? (
          <DetailRow label="Reason code" value={record.reason_code} />
        ) : null}
        {record.policy_decision ? (
          <DetailRow label="Policy decision" value={record.policy_decision} />
        ) : null}
        {record.mode ? <DetailRow label="Mode" value={record.mode} /> : null}
        {record.created_at_utc ?? record.created_at ? (
          <DetailRow
            label="Created at"
            value={formatDateTime(record.created_at_utc ?? record.created_at)}
          />
        ) : null}
      </div>

      <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3">
        <p className="text-xs leading-5 text-amber-800">
          <strong>Human review required.</strong> This run record confirms governance metadata was
          captured. Any output associated with this run must be reviewed by a qualified veterinary
          professional before use. ANCHOR does not make clinical decisions.
        </p>
      </div>

      <div className="mt-4">
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

