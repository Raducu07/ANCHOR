"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { fetchReceipt, fetchRecentSubmissions } from "@/lib/receipts/api";
import type { RecentSubmission } from "@/lib/receipts/api";
import { exportReceiptAsJson } from "@/lib/receipts/export";
import {
  getAssistantReceiptByIdentifier,
  listAssistantRuns,
} from "@/lib/assistant";
import { ApiError } from "@/lib/api";
import type {
  AssistantRunReceipt,
  AssistantRunTraceItem,
} from "@/lib/types";
import {
  buildInterpretation,
  decisionLabel,
  extractHumanReview,
  extractInputKind,
  extractPiiSignal,
  extractWorkflowOrigin,
  formatPiiDetected,
  formatScore,
  formatTimestamp,
  getCreatedAt,
  getNoContentStored,
  getPolicyHash,
  humanizeToken,
  prettyMode,
  safeText,
  summarizeRules,
} from "@/lib/receipts/formatters";
import type { ReceiptPayload } from "@/lib/types";

type LoadState = "idle" | "loading" | "loaded" | "error";
type CopyState = "idle" | "copied" | "error";
type ModeFilter = "all" | "internal_summary" | "client_comm" | "clinical_note";

const MODE_FILTER_OPTIONS: Array<{ value: ModeFilter; label: string }> = [
  { value: "all", label: "All modes" },
  { value: "internal_summary", label: "Internal summary" },
  { value: "client_comm", label: "Client communication" },
  { value: "clinical_note", label: "Clinical note drafting" },
];

export function ReceiptsPage({
  initialRequestId = "",
  initialAssistantRunId = "",
  initialAssistantReceiptId = "",
}: {
  initialRequestId?: string;
  initialAssistantRunId?: string;
  initialAssistantReceiptId?: string;
}) {
  const router = useRouter();
  const hasAssistantDeepLink = Boolean(
    initialAssistantRunId || initialAssistantReceiptId,
  );

  const [inputValue, setInputValue] = useState(initialRequestId);
  const [trackedRequestId, setTrackedRequestId] = useState(initialRequestId);
  const [receipt, setReceipt] = useState<ReceiptPayload | null>(null);
  const [loadState, setLoadState] = useState<LoadState>("idle");
  const [errorMessage, setErrorMessage] = useState("");
  const [attemptedId, setAttemptedId] = useState("");
  const [copyState, setCopyState] = useState<CopyState>("idle");

  const [recentSubmissions, setRecentSubmissions] = useState<RecentSubmission[]>([]);
  const [recentLoadState, setRecentLoadState] = useState<LoadState>("idle");
  const [recentError, setRecentError] = useState("");
  const [modeFilter, setModeFilter] = useState<ModeFilter>("all");
  const [refreshing, setRefreshing] = useState(false);

  if (trackedRequestId !== initialRequestId) {
    setTrackedRequestId(initialRequestId);
    setInputValue(initialRequestId);
    if (!initialRequestId) {
      setReceipt(null);
      setLoadState("idle");
      setErrorMessage("");
      setAttemptedId("");
    }
  }

  const loadReceipt = useCallback(
    async (rawId: string, updateUrl: boolean) => {
      const id = rawId.trim();
      if (!id) {
        setReceipt(null);
        setLoadState("idle");
        setErrorMessage("");
        setAttemptedId("");
        return;
      }

      setAttemptedId(id);
      setLoadState("loading");
      setErrorMessage("");

      try {
        const result = await fetchReceipt(id);
        setReceipt(result);
        setLoadState("loaded");
        if (updateUrl) {
          router.replace(`/receipts?request_id=${encodeURIComponent(id)}`);
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unable to load receipt.";
        setReceipt(null);
        setErrorMessage(message);
        setLoadState("error");
      }
    },
    [router]
  );

  const loadDashboard = useCallback(async () => {
    setRecentLoadState("loading");
    setRecentError("");
    try {
      const items = await fetchRecentSubmissions();
      setRecentSubmissions(items);
      setRecentLoadState("loaded");
      const firstId = items[0]?.request_id;
      if (firstId) {
        setInputValue((current) => (current ? current : firstId));
      }
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unable to load recent receipts.";
      setRecentSubmissions([]);
      setRecentError(message);
      setRecentLoadState("error");
    }
  }, []);

  useEffect(() => {
    if (!initialRequestId) return;
    if (attemptedId === initialRequestId) return;
    void loadReceipt(initialRequestId, false);
  }, [initialRequestId, attemptedId, loadReceipt]);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  const handleSubmit = () => {
    void loadReceipt(inputValue, true);
  };

  const handleCopyHash = async () => {
    const hash = getPolicyHash(receipt);
    if (!hash) return;
    try {
      await navigator.clipboard.writeText(hash);
      setCopyState("copied");
    } catch {
      setCopyState("error");
    }
    setTimeout(() => setCopyState("idle"), 1500);
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await loadDashboard();
      if (initialRequestId) {
        await loadReceipt(initialRequestId, false);
      }
    } finally {
      setRefreshing(false);
    }
  };

  const handleExport = () => {
    if (!receipt) return;
    exportReceiptAsJson(receipt);
  };

  const handleOpenRecent = (id: string) => {
    if (!id) return;
    setInputValue(id);
    void loadReceipt(id, true);
  };

  const filteredRecent =
    modeFilter === "all"
      ? recentSubmissions
      : recentSubmissions.filter(
          (item) => String(item.mode ?? "").toLowerCase() === modeFilter
        );
  const visibleRows = filteredRecent.slice(0, 8);

  const status =
    loadState === "loading" ? "Loading" : receipt?.request_id ? "Active" : "Ready";
  const noContentChip = getNoContentStored(receipt);
  const selectedMode = receipt ? prettyMode(receipt.mode) : "—";
  const policyHash = getPolicyHash(receipt);
  const requestStatus = receipt?.request_id ? "Active" : "Pending";
  const copyLabel =
    copyState === "copied" ? "Copied" : copyState === "error" ? "Copy failed" : "Copy";
  const interpretation = buildInterpretation(receipt);
  const reminder = receipt
    ? "Receipt review should confirm whether the governance outcome, PII handling, and downstream operational use remain appropriate for this request."
    : "Receipts support review, traceability, and governance visibility without storing raw prompt or raw output content by default.";

  const learningHref =
    receipt?.pii_detected === true
      ? "/learn/cards/privacy-safe-ai-use"
      : "/learn/cards/governance-basics";

  const postureLabel = receipt
    ? `Posture · ${decisionLabel(receipt.decision)}`
    : "Posture · Ready";
  const postureBody = receipt
    ? `Selected receipt remains reviewable through governance metadata, decision trace, and policy reference.`
    : "Governance receipts provide request-level traceability, policy visibility, and reviewable metadata for safe operational use.";
  const postureBullets = receipt
    ? [
        `Mode: ${prettyMode(receipt.mode)}`,
        `Policy version: ${safeText(receipt.policy_version, "—")}`,
        `No content stored: ${getNoContentStored(receipt)}`,
      ]
    : [
        "Metadata-only accountability is the default doctrine.",
        "Human review remains expected before operational use.",
        "Policy trace stays visible at request level.",
      ];

  return (
    <div className="mx-auto max-w-[1480px] space-y-8">
      <section className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Receipts</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            Request-level accountability, traceability, and metadata-backed governance review.
            ANCHOR receipts persist governance metadata only — no raw prompt or output content.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <MetaChip label={`Receipt status (${status})`} dot />
          <MetaChip label={`No content stored (${noContentChip})`} tone="success" />
          <MetaChip label={`Selected mode (${selectedMode})`} />
        </div>

        <div className="flex flex-wrap gap-3">
          <Button
            variant="ghost"
            onClick={() => void handleRefresh()}
            loading={refreshing}
            disabled={refreshing}
            className="rounded-md px-5 py-2.5"
          >
            Refresh receipts
          </Button>
          <Button
            variant="secondary"
            onClick={handleExport}
            disabled={!receipt}
            className="rounded-md px-5 py-2.5"
          >
            Export metadata
          </Button>
        </div>
      </section>

      {loadState === "error" && errorMessage ? (
        <NativeCard className="border-rose-200 bg-rose-50 text-rose-700">
          <p className="text-sm font-medium">Receipt unavailable</p>
          <p className="mt-2 text-sm leading-6">{errorMessage}</p>
        </NativeCard>
      ) : null}

      {hasAssistantDeepLink ? (
        <AssistantReceiptsSection
          initialAssistantRunId={initialAssistantRunId}
          initialAssistantReceiptId={initialAssistantReceiptId}
          priority
        />
      ) : null}

      <NativeCard>
        <SectionEyebrow>Receipt lookup</SectionEyebrow>
        <h2 className="mt-2 text-base font-semibold text-slate-900">Open a governance receipt</h2>
        <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-600">
          Paste a request ID to open the corresponding governance receipt, or pick one from the
          recent ledger below.
        </p>

        <div className="mt-6 flex flex-col gap-3 lg:flex-row lg:items-end">
          <div className="flex-1">
            <label
              htmlFor="receipt-request-id"
              className="block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500"
            >
              Request ID
            </label>
            <input
              id="receipt-request-id"
              type="text"
              value={inputValue}
              onChange={(event) => setInputValue(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  handleSubmit();
                }
              }}
              placeholder="Paste a request ID to load its receipt"
              className="mt-2 w-full rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 font-mono text-sm font-medium text-slate-900 outline-none transition placeholder:font-sans placeholder:font-normal placeholder:text-slate-400 focus:border-slate-400 focus:bg-white focus:ring-1 focus:ring-slate-300"
              spellCheck={false}
              autoComplete="off"
            />
          </div>
          <Button
            onClick={handleSubmit}
            loading={loadState === "loading"}
            disabled={loadState === "loading"}
            className="rounded-md px-6 py-3"
          >
            Load receipt
          </Button>
        </div>
      </NativeCard>

      <div className="grid gap-8 xl:grid-cols-[minmax(0,1.3fr)_minmax(320px,0.7fr)] xl:items-start">
        <div className="space-y-8">
          <NativeCard>
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <SectionEyebrow>Governance receipt</SectionEyebrow>
                <h2 className="mt-2 text-base font-semibold text-slate-900">
                  {safeText(receipt?.request_id, "No receipt selected")}
                </h2>
                <p className="mt-1 font-mono text-xs text-slate-500">
                  Created at {formatTimestamp(getCreatedAt(receipt))}
                </p>
              </div>
              <DecisionBadge decision={receipt?.decision} />
            </div>

            {receipt ? (
              <div className="mt-8 grid grid-cols-2 gap-4 md:grid-cols-4">
                <FieldTile label="Mode" value={prettyMode(receipt.mode)} compact />
                <FieldTile label="Risk grade" value={humanizeToken(receipt.risk_grade)} />
                <FieldTile
                  label="Governance score"
                  value={formatScore(receipt.governance_score)}
                />
                <FieldTile
                  label="Reason code"
                  value={safeText(receipt.reason_code, "—")}
                  compact
                />
                <FieldTile
                  label="Policy version"
                  value={safeText(receipt.policy_version, "—")}
                />
                <FieldTile
                  label="Neutrality version"
                  value={safeText(receipt.neutrality_version, "—")}
                  mono
                  compact
                />
                <FieldTile
                  label="PII detected"
                  value={formatPiiDetected(receipt.pii_detected)}
                  tone={receipt.pii_detected ? "danger" : "default"}
                />
                <FieldTile
                  label="PII action"
                  value={humanizeToken(receipt.pii_action)}
                  compact
                />
              </div>
            ) : loadState === "loading" ? (
              <EmptyState text="Loading receipt..." />
            ) : (
              <EmptyState text="Paste a request ID above or open one from the recent ledger to view governance metadata." />
            )}
          </NativeCard>

          <NativeCard>
            <SectionEyebrow>Traceability</SectionEyebrow>
            <h2 className="mt-2 text-base font-semibold text-slate-900">
              Policy trace and review state
            </h2>

            <div className="mt-6 rounded-lg border border-slate-200/70 bg-slate-50 p-4">
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs uppercase tracking-wide text-slate-500">Policy hash</p>
                <button
                  type="button"
                  onClick={handleCopyHash}
                  disabled={!policyHash}
                  className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium text-slate-600 transition hover:bg-white hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-50"
                  aria-label="Copy policy hash"
                >
                  <span className="material-symbols-outlined text-[16px]" aria-hidden="true">
                    content_copy
                  </span>
                  {copyLabel}
                </button>
              </div>
              <p className="mt-2 break-all font-mono text-xs font-medium text-slate-900">
                {policyHash || "—"}
              </p>
            </div>

            <div className="mt-6 grid gap-10 md:grid-cols-2">
              <DataList
                title="Governance detail"
                rows={[
                  ["Rules fired", summarizeRules(receipt?.rules_fired)],
                  ["Signal detail", extractPiiSignal(receipt)],
                  ["Workflow origin", extractWorkflowOrigin(receipt)],
                  ["Input kind", extractInputKind(receipt)],
                ]}
              />
              <DataList
                title="Review state"
                rows={[
                  ["Human review", extractHumanReview(receipt)],
                  ["Metadata model", "Metadata-only accountability"],
                  ["No content stored", noContentChip],
                  ["Receipt status", requestStatus],
                ]}
              />
            </div>

            <p className="mt-6 border-l-2 border-slate-200 pl-4 text-sm leading-6 text-slate-500">
              {reminder}
            </p>
          </NativeCard>

          <NativeCard>
            <SectionEyebrow>Interpretation</SectionEyebrow>
            <h2 className="mt-2 text-base font-semibold text-slate-900">Governance reading</h2>
            <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-700">{interpretation}</p>
          </NativeCard>

          <NativeCard>
            <div className="mb-6 flex flex-col gap-4 border-b border-slate-100 pb-4 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <SectionEyebrow>Activity</SectionEyebrow>
                <h2 className="mt-2 text-base font-semibold text-slate-900">
                  Recent receipt ledger
                </h2>
                <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-600">
                  Metadata-only ledger. Use request IDs to move directly into governance receipts
                  without exposing raw prompt or output content.
                </p>
              </div>
              <div>
                <label
                  htmlFor="receipt-mode-filter"
                  className="block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500"
                >
                  Filter mode
                </label>
                <select
                  id="receipt-mode-filter"
                  value={modeFilter}
                  onChange={(event) => setModeFilter(event.target.value as ModeFilter)}
                  className="mt-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm font-medium text-slate-900 outline-none transition focus:border-slate-400 focus:bg-white focus:ring-1 focus:ring-slate-300"
                >
                  {MODE_FILTER_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {recentLoadState === "loading" ? (
              <EmptyState text="Loading recent receipts..." />
            ) : recentLoadState === "error" ? (
              <p className="py-8 text-sm text-rose-700">
                {recentError || "Unable to load recent receipts."}
              </p>
            ) : visibleRows.length === 0 ? (
              <EmptyState
                text={
                  recentSubmissions.length > 0
                    ? "No recent receipts available for the current filter."
                    : "No recent receipts available."
                }
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[860px] text-left">
                  <colgroup>
                    <col className="w-[32%]" />
                    <col className="w-[18%]" />
                    <col className="w-[14%]" />
                    <col className="w-[12%]" />
                    <col className="w-[14%]" />
                    <col className="w-[10%]" />
                  </colgroup>
                  <thead>
                    <tr className="border-b border-slate-100 text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">
                      <th scope="col" className="pb-4 pr-6">Request ID</th>
                      <th scope="col" className="pb-4 pr-6">Mode</th>
                      <th scope="col" className="pb-4 pr-6">Decision</th>
                      <th scope="col" className="pb-4 pr-6">PII</th>
                      <th scope="col" className="pb-4 pr-6 whitespace-nowrap">Time</th>
                      <th scope="col" className="pb-4 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleRows.map((item, index) => {
                      const requestId = item.request_id ?? "";
                      const piiDetected = Boolean(item.pii_detected);
                      const displayId = shortenRequestId(requestId);
                      return (
                        <tr
                          key={`${requestId || "row"}-${index}`}
                          className="border-b border-slate-100/80 align-top text-sm text-slate-700 last:border-b-0"
                        >
                          <td className="py-5 pr-6 font-mono text-xs font-bold text-slate-900 whitespace-nowrap">
                            {requestId ? (
                              <span title={requestId} aria-label={`Request ID ${requestId}`}>
                                {displayId}
                              </span>
                            ) : (
                              "—"
                            )}
                          </td>
                          <td className="py-5 pr-6 text-xs font-medium text-slate-900">
                            {prettyMode(item.mode)}
                          </td>
                          <td className="py-5 pr-6">
                            <DecisionBadge decision={item.decision} />
                          </td>
                          <td className="py-5 pr-6 text-[11px] italic text-slate-500">
                            {piiDetected ? (
                              <span className="not-italic font-semibold uppercase text-rose-600">
                                Detected
                              </span>
                            ) : (
                              "Not detected"
                            )}
                          </td>
                          <td className="py-5 pr-6 whitespace-nowrap text-[11px] text-slate-500">
                            {formatTimestamp(item.created_at_utc ?? item.created_at)}
                          </td>
                          <td className="py-5 text-right">
                            <button
                              type="button"
                              onClick={() => handleOpenRecent(requestId)}
                              disabled={!requestId}
                              className="inline-flex items-center gap-1 whitespace-nowrap text-xs font-bold text-slate-600 transition hover:text-slate-900 hover:underline disabled:cursor-not-allowed disabled:opacity-40"
                            >
                              Open receipt
                              <span
                                className="material-symbols-outlined text-[14px]"
                                aria-hidden="true"
                              >
                                open_in_new
                              </span>
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </NativeCard>

          {hasAssistantDeepLink ? null : (
            <AssistantReceiptsSection
              initialAssistantRunId={initialAssistantRunId}
              initialAssistantReceiptId={initialAssistantReceiptId}
            />
          )}
        </div>

        <aside className="space-y-6">
          <NativeCard className="bg-slate-50/70">
            <div className="flex items-start justify-between gap-3">
              <SectionEyebrow>Trust posture</SectionEyebrow>
              <span className="rounded-full border border-slate-200 bg-white px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-[0.12em] text-slate-600">
                {postureLabel}
              </span>
            </div>
            <h2 className="mt-2 text-base font-semibold text-slate-900">
              Receipt trust posture
            </h2>
            <p className="mt-2 text-sm leading-6 text-slate-600">{postureBody}</p>
            <ul className="mt-4 space-y-2 text-sm leading-6 text-slate-700">
              {postureBullets.map((line) => (
                <li key={line} className="flex items-start gap-2">
                  <span
                    className="mt-2 inline-block h-1 w-1 shrink-0 rounded-full bg-slate-400"
                    aria-hidden="true"
                  />
                  <span>{line}</span>
                </li>
              ))}
            </ul>
          </NativeCard>

          <NativeCard>
            <SectionEyebrow>Recommended actions</SectionEyebrow>
            <div className="mt-4 space-y-2">
              <ActionLink
                href={learningHref}
                icon="school"
                label="Open related learning"
              />
              <ActionLink href="/intelligence" icon="psychology" label="Open Intelligence" />
              <ActionButton
                icon="download"
                label="Export metadata bundle"
                onClick={handleExport}
                disabled={!receipt}
              />
              <ActionLink
                href="/trust/profile"
                icon="shield"
                label="Open trust profile"
              />
            </div>
          </NativeCard>

          <NativeCard>
            <SectionEyebrow>Platform quick actions</SectionEyebrow>
            <div className="mt-4 grid grid-cols-2 gap-3">
              <QuickTile href="/dashboard" icon="dashboard" label="Dashboard" />
              <QuickTile href="/workspace" icon="clinical_notes" label="Workspace" />
              <QuickTile href="/intelligence" icon="psychology" label="Intelligence" />
              <QuickTile href="/trust/profile" icon="shield" label="Trust" />
            </div>
          </NativeCard>

          <NativeCard>
            <SectionEyebrow>Doctrine</SectionEyebrow>
            <div className="mt-4 space-y-4 text-sm leading-6 text-slate-600">
              <Pillar
                title="Metadata-only accountability"
                body="Receipts persist governance metadata rather than raw working content by default."
              />
              <Pillar
                title="Human review before use"
                body="Receipts support review and traceability; staff still confirm operational use."
              />
              <Pillar
                title="Traceable governance decisions"
                body="Each receipt ties request metadata to policy, decision, and reviewable governance context."
              />
            </div>
          </NativeCard>
        </aside>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Local primitives — mirror DashboardSurface / WorkspaceSurface conventions  */
/* -------------------------------------------------------------------------- */

function NativeCard({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
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

function SectionEyebrow({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={[
        "block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500",
        className,
      ].join(" ")}
    >
      {children}
    </span>
  );
}

function MetaChip({
  label,
  dot = false,
  tone = "default",
}: {
  label: string;
  dot?: boolean;
  tone?: "default" | "success";
}) {
  return (
    <span
      className={[
        "inline-flex items-center rounded-full border px-3 py-1 text-[11px] font-medium uppercase tracking-[0.12em]",
        tone === "success"
          ? "border-emerald-200 bg-emerald-50 text-emerald-700"
          : "border-slate-200 bg-slate-100 text-slate-500",
      ].join(" ")}
    >
      {dot ? <span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-slate-500" /> : null}
      {label}
    </span>
  );
}

function FieldTile({
  label,
  value,
  tone = "default",
  compact = false,
  mono = false,
}: {
  label: string;
  value: string;
  tone?: "default" | "danger";
  compact?: boolean;
  mono?: boolean;
}) {
  return (
    <div className="rounded-lg border border-slate-200/70 bg-slate-50 p-4">
      <p className="mb-1 text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p
        className={[
          compact ? "text-base leading-tight" : "text-2xl leading-tight",
          "font-semibold tracking-tight",
          mono ? "font-mono break-all" : "",
          tone === "danger" ? "text-rose-600" : "text-slate-900",
        ].join(" ")}
      >
        {value}
      </p>
    </div>
  );
}

function DataList({
  title,
  rows,
}: {
  title: string;
  rows: Array<[string, string]>;
}) {
  return (
    <div className="space-y-4">
      <h3 className="text-xs uppercase tracking-wide text-slate-500">{title}</h3>
      <div className="space-y-3">
        {rows.map(([label, value]) => (
          <div
            key={label}
            className="flex items-start justify-between gap-4 border-b border-slate-100 py-1 text-sm"
          >
            <span className="text-slate-500">{label}</span>
            <span className="text-right font-medium text-slate-900">{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DecisionBadge({ decision }: { decision?: string }) {
  const normalized = (decision ?? "").toLowerCase();
  const tone =
    normalized === "allowed" || normalized === "verified" || normalized === "pass"
      ? "bg-emerald-50 text-emerald-700"
      : normalized === "modified" || normalized === "warning" || normalized === "warn"
        ? "bg-amber-100 text-amber-800"
        : normalized === "blocked" || normalized === "replaced" || normalized === "flagged"
          ? "bg-rose-50 text-rose-700"
          : "bg-slate-100 text-slate-600";

  return (
    <span
      className={[
        "inline-flex rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em]",
        tone,
      ].join(" ")}
    >
      {humanizeToken(decision ?? "unknown")}
    </span>
  );
}

function EmptyState({ text }: { text: string }) {
  return <p className="py-8 text-sm text-slate-500">{text}</p>;
}

function ActionLink({
  href,
  icon,
  label,
}: {
  href: string;
  icon: string;
  label: string;
}) {
  return (
    <Link
      href={href}
      className="group flex items-center justify-between rounded-xl border border-slate-200/80 bg-slate-50 px-4 py-3 transition hover:border-slate-300 hover:bg-white"
    >
      <span className="flex items-center gap-3">
        <span
          className="material-symbols-outlined text-[18px] text-slate-600"
          aria-hidden="true"
        >
          {icon}
        </span>
        <span className="text-sm font-medium text-slate-900">{label}</span>
      </span>
      <span
        className="material-symbols-outlined text-[18px] text-slate-400 transition group-hover:translate-x-0.5 group-hover:text-slate-700"
        aria-hidden="true"
      >
        chevron_right
      </span>
    </Link>
  );
}

function ActionButton({
  icon,
  label,
  onClick,
  disabled,
}: {
  icon: string;
  label: string;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="group flex w-full items-center justify-between rounded-xl border border-slate-200/80 bg-slate-50 px-4 py-3 text-left transition hover:border-slate-300 hover:bg-white disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:bg-slate-50"
    >
      <span className="flex items-center gap-3">
        <span
          className="material-symbols-outlined text-[18px] text-slate-600"
          aria-hidden="true"
        >
          {icon}
        </span>
        <span className="text-sm font-medium text-slate-900">{label}</span>
      </span>
      <span
        className="material-symbols-outlined text-[18px] text-slate-400 transition group-hover:translate-x-0.5 group-hover:text-slate-700"
        aria-hidden="true"
      >
        chevron_right
      </span>
    </button>
  );
}

function QuickTile({ href, icon, label }: { href: string; icon: string; label: string }) {
  return (
    <Link
      href={href}
      className="flex flex-col items-start gap-2 rounded-xl border border-slate-200/80 bg-slate-50 p-4 transition hover:border-slate-300 hover:bg-white"
    >
      <span className="material-symbols-outlined text-[20px] text-slate-600" aria-hidden="true">
        {icon}
      </span>
      <span className="text-sm font-semibold text-slate-900">{label}</span>
    </Link>
  );
}

function shortenRequestId(value: string): string {
  if (!value) return "";
  // Display-only shortener for the ledger. Keeps enough leading + trailing
  // characters to remain visually distinct while never wrapping awkwardly.
  // Full request_id is always preserved for handlers, URL updates, and the
  // accessible label / hover title on the cell.
  if (value.length <= 16) return value;
  return `${value.slice(0, 8)}…${value.slice(-6)}`;
}

function Pillar({ title, body }: { title: string; body: string }) {
  return (
    <div>
      <p className="text-sm font-semibold text-slate-900">{title}</p>
      <p className="mt-1 text-sm leading-6 text-slate-600">{body}</p>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* M6.9.1 — Assistant receipts on the central Receipts surface                */
/* -------------------------------------------------------------------------- */
//
// The Assistant page already creates and inspects metadata-only Assistant
// receipts via /v1/assistant/runs/{run_id}/receipt. This section surfaces
// the same evidence from /receipts without any new backend endpoint:
//
//   * Recent list is derived from /v1/assistant/runs and filtered to runs
//     that have a linked receipt.
//   * Detail lookup takes a run ID and calls the existing per-run receipt
//     endpoint. Receipt-ID-only lookup requires a backend endpoint and is
//     deferred — the recent list and Assistant "Open in Receipts" deep link
//     cover the primary discovery paths.
//   * No raw input, prompt, or draft is ever fetched or rendered.

type AssistantReceiptLoadState = "idle" | "loading" | "loaded" | "error" | "not_found";

function AssistantReceiptsSection({
  initialAssistantRunId,
  initialAssistantReceiptId,
  priority = false,
}: {
  initialAssistantRunId: string;
  initialAssistantReceiptId: string;
  priority?: boolean;
}) {
  const router = useRouter();

  const [runs, setRuns] = useState<AssistantRunTraceItem[] | null>(null);
  const [runsLoading, setRunsLoading] = useState(false);
  const [runsError, setRunsError] = useState<string | null>(null);

  // M6.11.1 — light client-side filters over the latest 25 fetched runs
  // only. These do NOT page or query the backend; they narrow what is
  // already on screen. The footer helper text makes that scope explicit
  // so admins do not mistake "no filtered results" for "no matching
  // receipts in clinic history".
  const [filterReview, setFilterReview] = useState<
    "any" | "reviewed" | "unreviewed"
  >("any");
  const [filterStatus, setFilterStatus] = useState<
    "any" | "succeeded" | "refused" | "blocked" | "failed"
  >("any");
  const [filterPii, setFilterPii] = useState<"any" | "detected">("any");

  // Pre-populate the lookup with whichever identifier was provided via
  // deep link. Either resolves through the same /receipts/{identifier}
  // backend route.
  const initialLookup = initialAssistantReceiptId || initialAssistantRunId;
  const [lookupInput, setLookupInput] = useState(initialLookup);
  const [activeIdentifier, setActiveIdentifier] = useState<string>("");
  const [activeRunId, setActiveRunId] = useState<string>("");
  const [matchedBy, setMatchedBy] = useState<"receipt_id" | "run_id" | null>(null);
  const [receipt, setReceipt] = useState<AssistantRunReceipt | null>(null);
  const [receiptState, setReceiptState] = useState<AssistantReceiptLoadState>("idle");
  const [receiptError, setReceiptError] = useState<string | null>(null);
  const [autoTriedIdentifier, setAutoTriedIdentifier] = useState<string>("");

  const loadRecent = useCallback(async () => {
    setRunsLoading(true);
    setRunsError(null);
    try {
      const result = await listAssistantRuns({ limit: 25 });
      const items = result.runs ?? [];
      // Keep only runs that actually have a linked Assistant receipt —
      // this section is about receipts as governance evidence, not raw runs.
      setRuns(items.filter((r) => Boolean(r.has_receipt || r.receipt_id)));
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : "Unable to load recent Assistant receipts.";
      setRuns(null);
      setRunsError(message);
    } finally {
      setRunsLoading(false);
    }
  }, []);

  const loadReceiptByIdentifier = useCallback(
    async (
      rawIdentifier: string,
      updateUrl: boolean,
      urlKey: "assistantRunId" | "assistantReceiptId" = "assistantRunId",
    ) => {
      const identifier = rawIdentifier.trim();
      if (!identifier) {
        setReceipt(null);
        setActiveIdentifier("");
        setActiveRunId("");
        setMatchedBy(null);
        setReceiptState("idle");
        setReceiptError(null);
        return;
      }
      setActiveIdentifier(identifier);
      setReceiptState("loading");
      setReceiptError(null);
      try {
        const result = await getAssistantReceiptByIdentifier(identifier);
        setReceipt(result.receipt);
        setActiveRunId(result.receipt.assistant_run_id);
        setMatchedBy(result.matched_by ?? null);
        setReceiptState("loaded");
        if (updateUrl) {
          // Reflect the actual lookup mode in the URL so the link is
          // shareable and refresh-safe.
          const key =
            result.matched_by === "receipt_id"
              ? "assistantReceiptId"
              : result.matched_by === "run_id"
                ? "assistantRunId"
                : urlKey;
          router.replace(`/receipts?${key}=${encodeURIComponent(identifier)}`);
        }
      } catch (err) {
        setReceipt(null);
        setActiveRunId("");
        setMatchedBy(null);
        if (err instanceof ApiError && err.status === 404) {
          setReceiptState("not_found");
        } else {
          const message =
            err instanceof ApiError ? err.message : "Unable to load Assistant receipt.";
          setReceiptError(message);
          setReceiptState("error");
        }
      }
    },
    [router],
  );

  useEffect(() => {
    void loadRecent();
  }, [loadRecent]);

  // Auto-load from whichever deep-link identifier is present. We prefer
  // assistantReceiptId, then fall back to assistantRunId; both go through
  // the same backend lookup so either resolves correctly.
  useEffect(() => {
    const incoming = initialAssistantReceiptId || initialAssistantRunId;
    if (!incoming) return;
    if (autoTriedIdentifier === incoming) return;
    setAutoTriedIdentifier(incoming);
    setLookupInput(incoming);
    void loadReceiptByIdentifier(incoming, false);
  }, [
    initialAssistantReceiptId,
    initialAssistantRunId,
    autoTriedIdentifier,
    loadReceiptByIdentifier,
  ]);

  const headingTitle = priority ? "Assistant receipt" : "Assistant receipts";
  const headingBody = priority
    ? "Metadata-only Assistant evidence. This is not a chat transcript or clinical record."
    : "Metadata-only governance receipts for governed Assistant runs. Not chat transcripts; not clinical records.";

  return (
    <NativeCard>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <SectionEyebrow>Assistant evidence</SectionEyebrow>
          <h2 className="mt-2 text-base font-semibold text-slate-900">{headingTitle}</h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-600">{headingBody}</p>
        </div>
        <Button
          variant="ghost"
          onClick={() => void loadRecent()}
          disabled={runsLoading}
          loading={runsLoading}
          className="rounded-md px-4 py-2"
        >
          Refresh receipts
        </Button>
      </div>

      {/* When arriving via deep link, surface the Assistant receipt result
          immediately at the top so the user does not have to scan past the
          generic governance receipt lookup. */}
      {priority && receiptState === "loading" ? (
        <p className="mt-4 text-sm text-slate-600">Loading Assistant receipt…</p>
      ) : null}
      {priority && receiptState === "not_found" ? (
        <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3">
          <p className="text-sm font-semibold text-amber-900">
            No Assistant receipt linked yet
          </p>
          <p className="mt-1 text-xs leading-5 text-amber-800">
            No Assistant receipt is linked to{" "}
            <span className="font-mono break-all">{activeIdentifier}</span> yet. Receipts
            are created from the Assistant page after a run has been human-reviewed.
          </p>
        </div>
      ) : null}
      {priority && receiptState === "error" && receiptError ? (
        <div className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3">
          <p className="text-sm font-semibold text-rose-700">
            Could not load Assistant receipt
          </p>
          <p className="mt-1 text-xs leading-5 text-rose-600">{receiptError}</p>
        </div>
      ) : null}

      {receipt && priority ? (
        <AssistantReceiptDetail
          receipt={receipt}
          runId={activeRunId}
          matchedBy={matchedBy}
        />
      ) : null}

      {/* Lookup panel — separate from the older governance receipt lookup
          so existing flows remain unchanged. */}
      <div className="mt-6 rounded-xl border border-slate-200 bg-slate-50 p-4">
        <p className="text-sm font-semibold text-slate-900">Open an Assistant receipt</p>
        <p className="mt-1 text-xs leading-5 text-slate-600">
          Paste an Assistant receipt ID or run ID. Receipts are metadata-only and are not
          chat transcripts.
        </p>
        <div className="mt-3 flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="flex-1">
            <label
              htmlFor="assistant-receipt-identifier"
              className="block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500"
            >
              Assistant receipt ID or run ID
            </label>
            <input
              id="assistant-receipt-identifier"
              type="text"
              value={lookupInput}
              onChange={(e) => setLookupInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  void loadReceiptByIdentifier(lookupInput, true);
                }
              }}
              placeholder="Paste an Assistant receipt ID or run ID"
              spellCheck={false}
              autoComplete="off"
              className="mt-2 w-full rounded-lg border border-slate-200 bg-white px-4 py-2.5 font-mono text-sm text-slate-900 outline-none transition placeholder:font-sans placeholder:font-normal placeholder:text-slate-400 focus:border-slate-400 focus:ring-1 focus:ring-slate-300"
            />
          </div>
          <Button
            onClick={() => void loadReceiptByIdentifier(lookupInput, true)}
            loading={receiptState === "loading"}
            disabled={receiptState === "loading" || !lookupInput.trim()}
            className="rounded-md px-5 py-2.5"
          >
            Open receipt
          </Button>
        </div>
        {!priority && receiptState === "not_found" && activeIdentifier ? (
          <p className="mt-3 text-xs leading-5 text-amber-700">
            No Assistant receipt is linked to that ID yet. A receipt is created from the
            Assistant page after the run has been human-reviewed.
          </p>
        ) : null}
        {!priority && receiptState === "error" && receiptError ? (
          <p className="mt-3 text-xs leading-5 text-rose-700">{receiptError}</p>
        ) : null}
      </div>

      {receipt && !priority ? (
        <AssistantReceiptDetail
          receipt={receipt}
          runId={activeRunId}
          matchedBy={matchedBy}
        />
      ) : null}

      <div className="mt-6">
        <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
          Recent Assistant receipts
        </p>

        <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50 p-3">
          <div className="flex flex-wrap gap-3">
            <label className="flex flex-col text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
              Review
              <select
                value={filterReview}
                onChange={(e) =>
                  setFilterReview(
                    e.target.value as "any" | "reviewed" | "unreviewed",
                  )
                }
                className="mt-1 rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-xs font-normal normal-case tracking-normal text-slate-900"
              >
                <option value="any">Any</option>
                <option value="reviewed">Reviewed</option>
                <option value="unreviewed">Unreviewed</option>
              </select>
            </label>

            <label className="flex flex-col text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
              Run status
              <select
                value={filterStatus}
                onChange={(e) =>
                  setFilterStatus(
                    e.target.value as
                      | "any"
                      | "succeeded"
                      | "refused"
                      | "blocked"
                      | "failed",
                  )
                }
                className="mt-1 rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-xs font-normal normal-case tracking-normal text-slate-900"
              >
                <option value="any">Any</option>
                <option value="succeeded">Succeeded</option>
                <option value="refused">Refused</option>
                <option value="blocked">Blocked</option>
                <option value="failed">Failed</option>
              </select>
            </label>

            <label className="flex flex-col text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
              PII
              <select
                value={filterPii}
                onChange={(e) =>
                  setFilterPii(e.target.value as "any" | "detected")
                }
                className="mt-1 rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-xs font-normal normal-case tracking-normal text-slate-900"
              >
                <option value="any">Any</option>
                <option value="detected">PII detected</option>
              </select>
            </label>
          </div>
          <p className="mt-2 text-[11px] leading-5 text-slate-500">
            Filters apply to the latest 25 shown here.
          </p>
        </div>

        {(() => {
          if (runsError) {
            return <p className="mt-3 text-sm text-rose-700">{runsError}</p>;
          }
          if (runsLoading && runs === null) {
            return <EmptyState text="Loading recent Assistant receipts..." />;
          }
          if (!runs || runs.length === 0) {
            return (
              <EmptyState text="No Assistant receipts in the latest 25 runs. Create one from a governed Assistant run, or look one up by ID below." />
            );
          }
          const filteredRuns = runs.filter((r) => {
            const isReviewed =
              typeof r.review_status === "string" &&
              r.review_status.startsWith("reviewed_");
            if (filterReview === "reviewed" && !isReviewed) return false;
            if (filterReview === "unreviewed" && isReviewed) return false;
            if (filterStatus !== "any") {
              const want =
                filterStatus === "succeeded"
                  ? "generation_succeeded"
                  : filterStatus === "refused"
                    ? "generation_refused"
                    : filterStatus === "blocked"
                      ? "output_blocked"
                      : "generation_failed";
              if (r.run_status !== want) return false;
            }
            if (filterPii === "detected" && !r.pii_detected) return false;
            return true;
          });
          if (filteredRuns.length === 0) {
            return (
              <EmptyState text="No Assistant receipts in the latest 25 match these filters." />
            );
          }
          return (
            <>
              <ul className="mt-3 divide-y divide-slate-100 rounded-xl border border-slate-200 bg-white">
                {filteredRuns.map((r) => {
                  const receiptShort = r.receipt_id
                    ? shortenAssistantId(r.receipt_id)
                    : "—";
                  const runShort = shortenAssistantId(r.run_id);
                  const isActive = activeRunId === r.run_id;
                  return (
                    <li
                      key={r.run_id}
                      className={[
                        "flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between",
                        isActive ? "bg-slate-50" : "",
                      ].join(" ")}
                    >
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2 text-xs">
                          <span className="font-mono font-semibold text-slate-900">
                            Receipt {receiptShort}
                          </span>
                          <ReceiptPill
                            label={humanizeAssistantStatus(r.run_status)}
                            tone={assistantRunTone(r.run_status)}
                          />
                          <ReceiptPill
                            label={humanizeAssistantReview(r.review_status)}
                            tone={assistantReviewTone(r.review_status)}
                          />
                        </div>
                        <p className="mt-1 font-mono text-[11px] text-slate-500">
                          Run {runShort} · {formatTimestamp(r.created_at)}
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setLookupInput(r.run_id);
                          void loadReceiptByIdentifier(r.run_id, true);
                        }}
                        className="self-start whitespace-nowrap text-xs font-semibold text-slate-900 underline underline-offset-4 hover:text-slate-700 sm:self-auto"
                      >
                        Open receipt
                      </button>
                    </li>
                  );
                })}
              </ul>
              <p className="mt-3 text-[11px] leading-5 text-slate-500">
                Showing latest 25 Assistant receipts. More may exist — look up a
                specific receipt or run ID below.
              </p>
            </>
          );
        })()}
      </div>

      <div className="mt-6 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
        <p className="text-xs leading-5 text-slate-700">
          Assistant receipts are governance metadata for review. Human review of
          AI-assisted work remains required.
        </p>
      </div>
    </NativeCard>
  );
}

function AssistantReceiptDetail({
  receipt,
  runId,
  matchedBy,
}: {
  receipt: AssistantRunReceipt;
  runId: string;
  matchedBy?: "receipt_id" | "run_id" | null;
}) {
  return (
    <div className="mt-6 rounded-xl border border-sky-200 bg-sky-50/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-sky-900">
            Assistant metadata receipt
          </p>
          <p className="mt-1 text-xs leading-5 text-sky-800">
            Metadata-only governance evidence. Raw prompt, input, draft output, and
            clinical content are not stored. This receipt is not a chat transcript and
            not a clinical record.
          </p>
          {matchedBy ? (
            <p className="mt-1 text-[11px] text-sky-700">
              Matched by {matchedBy === "receipt_id" ? "receipt ID" : "run ID"}.
            </p>
          ) : null}
        </div>
        <Link
          href={`/assistant?runId=${encodeURIComponent(runId || receipt.assistant_run_id)}`}
          className="inline-flex shrink-0 items-center rounded-lg border border-sky-200 bg-white px-3 py-1.5 text-xs font-medium text-sky-900 shadow-sm transition hover:border-sky-300"
        >
          Open in Assistant
        </Link>
      </div>

      <ReceiptGroup title="Storage posture">
        <AssistantReceiptCell label="Storage policy" value={receipt.storage_policy} />
        <AssistantReceiptCell
          label="Raw input stored"
          value={receipt.raw_content_stored ? "Yes" : "No"}
        />
        <AssistantReceiptCell
          label="Prompt stored"
          value={receipt.prompt_stored ? "Yes" : "No"}
        />
        <AssistantReceiptCell
          label="Draft stored"
          value={receipt.draft_stored ? "Yes" : "No"}
        />
      </ReceiptGroup>

      <ReceiptGroup title="Receipt identity">
        <AssistantReceiptCell
          label="Receipt ID"
          value={shortenAssistantId(receipt.receipt_id)}
          copyValue={receipt.receipt_id}
          mono
        />
        <AssistantReceiptCell label="Receipt kind" value={receipt.receipt_kind} />
        <AssistantReceiptCell label="Receipt version" value={receipt.receipt_version} />
        <AssistantReceiptCell
          label="Run ID"
          value={shortenAssistantId(receipt.assistant_run_id)}
          copyValue={receipt.assistant_run_id}
          mono
        />
        <AssistantReceiptCell
          label="Created at"
          value={formatTimestamp(receipt.receipt_created_at)}
        />
      </ReceiptGroup>

      <ReceiptGroup title="Review outcome">
        <AssistantReceiptCell
          label="Run status"
          value={humanizeAssistantStatus(receipt.run_status)}
        />
        <AssistantReceiptCell
          label="Review status"
          value={humanizeAssistantReview(receipt.review_status)}
        />
        <AssistantReceiptCell
          label="Review decision"
          value={humanizeAssistantDecision(receipt.review_decision)}
        />
      </ReceiptGroup>

      <ReceiptGroup title="Policy context">
        <AssistantReceiptCell
          label="Policy version"
          value={
            typeof receipt.assistant_policy_version === "number" &&
            receipt.assistant_policy_version > 0
              ? `v${receipt.assistant_policy_version}`
              : "Default policy"
          }
        />
        <AssistantReceiptCell
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
        <AssistantReceiptCell
          label="Input hash"
          value={shortenAssistantId(receipt.input_sha256)}
          copyValue={receipt.input_sha256}
          mono
        />
        <AssistantReceiptCell
          label="Output hash"
          value={
            receipt.output_sha256 ? shortenAssistantId(receipt.output_sha256) : "None"
          }
          copyValue={receipt.output_sha256 ?? null}
          mono={!!receipt.output_sha256}
        />
      </ReceiptGroup>

      <ReceiptGroup title="Safety metadata">
        <AssistantReceiptCell
          label="PII detected"
          value={receipt.pii_detected ? "Yes" : "No"}
        />
        <AssistantReceiptCell
          label="Safety flags"
          value={receipt.safety_flags.length ? receipt.safety_flags.join(", ") : "None"}
        />
        <AssistantReceiptCell
          label="Refusal codes"
          value={
            receipt.refusal_reason_codes.length
              ? receipt.refusal_reason_codes.join(", ")
              : "None"
          }
        />
      </ReceiptGroup>

      <p className="mt-3 text-[11px] leading-5 text-emerald-700">
        Policy context is metadata only. Hard clinical safety rules cannot be disabled.
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

function AssistantReceiptCell({
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
        {copyValue ? <CopyChip value={copyValue} ariaLabel={`Copy ${label}`} /> : null}
      </div>
    </div>
  );
}

function CopyChip({ value, ariaLabel }: { value: string; ariaLabel: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label={ariaLabel}
      onClick={async () => {
        try {
          if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
          }
        } catch {
          // Best-effort: failure is non-fatal; value remains on-screen.
        }
      }}
      className="inline-flex shrink-0 items-center rounded-md border border-slate-200 bg-white px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-[0.08em] text-slate-600 shadow-sm transition hover:border-slate-300 hover:text-slate-900"
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function ReceiptPill({
  label,
  tone,
}: {
  label: string;
  tone: "neutral" | "success" | "warn" | "danger" | "info";
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

function shortenAssistantId(value: string | null | undefined): string {
  if (!value) return "—";
  if (value.length <= 18) return value;
  return `${value.slice(0, 8)}…${value.slice(-6)}`;
}

function humanizeAssistantStatus(status: string | null | undefined): string {
  switch (status) {
    case "generation_succeeded":
      return "Draft generated";
    case "generation_refused":
      return "Refused before model call";
    case "generation_failed":
      return "Generation failed";
    case "output_blocked":
      return "Output blocked";
    case "created":
    case "":
    case null:
    case undefined:
      return "Created";
    default:
      return status;
  }
}

function humanizeAssistantReview(status: string | null | undefined): string {
  switch (status) {
    case "reviewed_approved":
      return "Approved";
    case "reviewed_rejected":
      return "Rejected";
    case "reviewed_needs_edit":
      return "Needs edit";
    case "not_reviewed":
    case "":
    case null:
    case undefined:
      return "Not reviewed";
    default:
      return String(status);
  }
}

function humanizeAssistantDecision(decision: string | null | undefined): string {
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

function assistantRunTone(
  status: string | null | undefined,
): "neutral" | "success" | "warn" | "danger" | "info" {
  switch (status) {
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

function assistantReviewTone(
  status: string | null | undefined,
): "neutral" | "success" | "warn" | "danger" | "info" {
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
