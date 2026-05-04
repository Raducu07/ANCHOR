"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { fetchReceipt, fetchRecentSubmissions } from "@/lib/receipts/api";
import type { RecentSubmission } from "@/lib/receipts/api";
import { exportReceiptAsJson } from "@/lib/receipts/export";
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

export function ReceiptsPage({ initialRequestId = "" }: { initialRequestId?: string }) {
  const router = useRouter();

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
