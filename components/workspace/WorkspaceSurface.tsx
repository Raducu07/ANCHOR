"use client";

import { useEffect, useMemo, useRef, useState, type ChangeEventHandler, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { apiFetch, ApiError } from "@/lib/api";
import type { ReceiptEnvelope, ReceiptPayload } from "@/lib/types";
import {
  WORKSPACE_INSTRUCTION_PRESETS,
  WORKSPACE_MODE_OPTIONS,
  WORKSPACE_ORIGIN_OPTIONS,
  WORKSPACE_REVIEW_BOUNDARIES,
  WORKSPACE_REVIEW_STEPS,
  WORKSPACE_ROLE_OPTIONS,
  buildAssistSourceText,
  buildWorkspaceRunInstruction,
  computeWorkspaceSourceInsights,
  createPastedTextSource,
  createWorkspaceSourceFromFile,
  formatExtractionStatusLabel,
  formatOriginLabel,
  formatSourceKindLabel,
  mapWorkflowOriginToApi,
  mapWorkspaceModeToApi,
  normalizeWorkspaceOutput,
  type WorkspaceMode,
  type WorkspaceReviewState,
  type WorkspaceSourceItem,
  type WorkspaceWorkflowOrigin,
} from "@/lib/workspace";

type AssistResponse = Partial<ReceiptPayload> & {
  final_text?: string;
  output?: string;
  governed_output?: string;
  result?: string;
  rewritten_text?: string;
  assistant_output?: string;
  text?: string;
  request_id?: string;
  receipt?: ReceiptPayload;
  rules_fired?: unknown;
  created_at?: string;
  created_at_utc?: string;
};

const SOURCE_ACCEPT = "text/*,.txt,.md,.csv,.json,.xml,.html,.htm,.log,application/pdf,image/*,.doc,.docx,.rtf,.odt";
const PDF_ACCEPT = "application/pdf,.pdf";
const IMAGE_ACCEPT = "image/*";
const DEFAULT_WORKFLOW_ORIGIN: WorkspaceWorkflowOrigin = "direct";
const DEFAULT_ROLE = WORKSPACE_ROLE_OPTIONS[0];
const DEFAULT_MODE: WorkspaceMode = "Internal governance review";
const DEFAULT_INSTRUCTION = WORKSPACE_INSTRUCTION_PRESETS[DEFAULT_MODE];
const WORKSPACE_SECONDARY_ACTION_CLASS =
  "border-slate-400 bg-white text-slate-800 shadow-[inset_0_1px_0_rgba(255,255,255,0.72)] hover:border-slate-500 hover:bg-slate-50";
const WORKSPACE_ACTIVE_STEP_CLASS =
  "border-slate-400 bg-slate-100 text-slate-900";
const DEFAULT_ACTION_MESSAGE =
  "Complete setup, then run through ANCHOR to create the governed result, receipt linkage, and human-review path.";
const RERUN_REQUIRED_ACTION_MESSAGE =
  "Source material or workflow controls changed. Run through ANCHOR again to generate a current governed result and receipt.";
const WORKFLOW_ORIGIN_HELP_TEXT =
  "Workflow origin stays at the workflow level. Uploaded files, PDFs, and images are source-entry pathways inside the current direct workspace flow.";

export function WorkspaceSurface() {
  const router = useRouter();
  const genericInputRef = useRef<HTMLInputElement | null>(null);
  const pdfInputRef = useRef<HTMLInputElement | null>(null);
  const imageInputRef = useRef<HTMLInputElement | null>(null);
  const reviewConfirmationRef = useRef<HTMLDivElement | null>(null);
  const sourcesRef = useRef<WorkspaceSourceItem[]>([]);

  const [workflowOrigin, setWorkflowOrigin] = useState<WorkspaceWorkflowOrigin>(DEFAULT_WORKFLOW_ORIGIN);
  const [role, setRole] = useState<(typeof WORKSPACE_ROLE_OPTIONS)[number]>(DEFAULT_ROLE);
  const [mode, setMode] = useState<WorkspaceMode>(DEFAULT_MODE);
  const [instruction, setInstruction] = useState(DEFAULT_INSTRUCTION);
  const [draftText, setDraftText] = useState("");
  const [editingTextSourceId, setEditingTextSourceId] = useState<string | null>(null);
  const [replaceSourceId, setReplaceSourceId] = useState<string | null>(null);
  const [sourceItems, setSourceItems] = useState<WorkspaceSourceItem[]>([]);
  const [dragActive, setDragActive] = useState(false);
  const [running, setRunning] = useState(false);
  const [resultText, setResultText] = useState("");
  const [assistPayload, setAssistPayload] = useState<AssistResponse | null>(null);
  const [receipt, setReceipt] = useState<ReceiptPayload | null>(null);
  const [requestId, setRequestId] = useState<string | null>(null);
  const [reviewConfirmed, setReviewConfirmed] = useState(false);
  const [workflowStage, setWorkflowStage] = useState<WorkspaceReviewState>("drafted");
  const [runError, setRunError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState(DEFAULT_ACTION_MESSAGE);

  useEffect(() => {
    sourcesRef.current = sourceItems;
  }, [sourceItems]);

  useEffect(() => {
    return () => {
      sourcesRef.current.forEach((item) => {
        if (item.objectUrl) {
          URL.revokeObjectURL(item.objectUrl);
        }
      });
    };
  }, []);

  const sourceInsights = useMemo(() => computeWorkspaceSourceInsights(sourceItems), [sourceItems]);
  const activeRequestId = requestId ?? receipt?.request_id ?? null;
  const actionState = useMemo(
    () =>
      buildWorkspaceActionState({
        hasSourceItems: sourceItems.length > 0,
        hasPendingDraft: draftText.trim().length > 0,
        hasGovernedRun: !!resultText,
        receiptAvailable: !!activeRequestId,
        reviewConfirmed,
        role,
        mode,
        instruction,
        workflowOrigin,
        runErrorPresent: !!runError,
        running,
      }),
    [activeRequestId, draftText, instruction, mode, resultText, reviewConfirmed, role, runError, running, sourceItems.length, workflowOrigin]
  );
  const liveOutcome = receipt ?? assistPayload;
  const isOperationallyReady = actionState.canCopyOrExport;
  const canCopyOrExport = actionState.canCopyOrExport;
  const reviewState = workflowStage;
  const currentReviewStepIndex = WORKSPACE_REVIEW_STEPS.findIndex((step) => step.key === reviewState);

  function normalizeWorkspaceText(value: string) {
    return value.replace(/\r\n/g, "\n").trim();
  }

  function invalidateGovernedState(message = RERUN_REQUIRED_ACTION_MESSAGE) {
    const hasGovernedState =
      !!resultText ||
      !!assistPayload ||
      !!receipt ||
      !!requestId ||
      !!reviewConfirmed ||
      !!runError ||
      workflowStage !== "drafted";

    setResultText("");
    setAssistPayload(null);
    setReceipt(null);
    setRequestId(null);
    setReviewConfirmed(false);
    setWorkflowStage("drafted");
    setRunError(null);
    setActionMessage(hasGovernedState ? message : DEFAULT_ACTION_MESSAGE);
  }

  function continueToReviewConfirmation() {
    if (!resultText) return;
    if (!activeRequestId) {
      setActionMessage("Receipt linkage is still pending. Human review begins once a linked receipt is available for this governed run.");
      return;
    }
    setWorkflowStage("awaiting_review");
    setActionMessage(
      "Human review confirmation is the next required step before operational use."
    );
    reviewConfirmationRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function handleReviewConfirmationChange(checked: boolean) {
    if (!resultText) return;
    if (!activeRequestId) {
      setActionMessage("Human review confirmation activates once the linked receipt is available for this governed run.");
      return;
    }

    setReviewConfirmed(checked);

    if (!checked) {
      setWorkflowStage("awaiting_review");
      setActionMessage("Human review confirmation was removed. Operational actions are blocked until review is confirmed again.");
      return;
    }

    setWorkflowStage("review_confirmed");
    setActionMessage("Human review confirmed. Governed output is now ready for controlled operational use.");
  }

  const readinessItems = useMemo(
    () => [
      {
        label: "Source present",
        ready: sourceItems.length > 0 || draftText.trim().length > 0,
        detail:
          sourceItems.length > 0
            ? `${sourceItems.length} item${sourceItems.length === 1 ? "" : "s"} in the source bundle`
            : draftText.trim().length > 0
              ? "Pasted source text is ready to add to the bundle"
              : "Add pasted text or upload files",
      },
      {
        label: "Governance run complete",
        ready: actionState.hasGovernedRun,
        detail: actionState.hasGovernedRun
          ? "Governed result is available"
          : "Complete setup, then run through ANCHOR to create the first governed result",
      },
      {
        label: "Receipt available",
        ready: actionState.hasReviewableReceipt,
        detail: actionState.hasReviewableReceipt
          ? `Receipt ${activeRequestId?.slice(0, 8)} is reviewable`
          : actionState.hasGovernedRun
            ? "Receipt linkage is still pending for the latest governed run"
            : "Receipt preview activates after the first governed run",
      },
      {
        label: "Review confirmed",
        ready: actionState.canConfirmReview && reviewConfirmed,
        detail: reviewConfirmed
          ? "Human review has been confirmed"
          : actionState.canConfirmReview
            ? "Human review confirmation is still required"
            : actionState.hasGovernedRun
              ? "Human review confirmation unlocks once receipt linkage is available"
              : "Human review confirmation is inactive until the first governed run",
      },
      {
        label: "Operationally ready",
        ready: isOperationallyReady,
        detail: isOperationallyReady
          ? "Governed result is ready for controlled operational use"
          : !actionState.hasGovernedRun
            ? "Complete setup and run through ANCHOR before operational use"
            : !actionState.hasReviewableReceipt
              ? "Operational use remains blocked until receipt linkage is available"
              : "Operational use remains blocked until review is confirmed",
      },
    ],
    [actionState, activeRequestId, draftText, isOperationallyReady, reviewConfirmed, sourceItems.length]
  );

  const sourceBundleText = useMemo(() => buildAssistSourceText(sourceItems), [sourceItems]);
  const comparableSourceText = useMemo(
    () =>
      sourceItems
        .filter((item) => item.extractionStatus === "ready" && normalizeWorkspaceText(item.extractedText).length > 0)
        .map((item) => normalizeWorkspaceText(item.extractedText))
        .join("\n\n"),
    [sourceItems]
  );

  const governanceSummary = useMemo(() => {
    const live = liveOutcome;
    return {
      decision: humanizeToken(live?.decision),
      riskGrade: humanizeToken(live?.risk_grade),
      piiDetected:
        live?.pii_detected === undefined ? "Pending" : live.pii_detected ? "Detected" : "Not detected",
      piiAction: humanizeToken(live?.pii_action),
      governanceScore:
        typeof live?.governance_score === "number" ? live.governance_score.toFixed(2) : "Pending",
      policyVersion: live?.policy_version != null ? `v${live.policy_version}` : "Pending",
      neutralityVersion: live?.neutrality_version ?? "Pending",
      noContentStored: live?.no_content_stored === false ? "No" : "Yes",
      rulesFired: formatRulesFired(live?.rules_fired),
      policyHash: (live?.policy_hash as string | undefined) ?? (live?.policy_sha256 as string | undefined) ?? "Pending",
      createdAt: formatDateTime(live?.created_at_utc ?? (live?.created_at as string | undefined)),
    };
  }, [liveOutcome]);

  const resultStatus = useMemo(() => {
    if (running) return { label: "Running", tone: "running" as const, detail: "Running through ANCHOR..." };
    if (runError) return { label: "Attention", tone: "danger" as const, detail: "Run failed" };
    if (reviewState === "ready_for_use") {
      return { label: "Ready", tone: "success" as const, detail: "Governed result cleared for controlled use" };
    }
    if (reviewState === "review_confirmed") {
      return { label: "Reviewed", tone: "success" as const, detail: "Human review has been confirmed" };
    }
    if (reviewState === "awaiting_review") {
      return { label: "Awaiting review", tone: "running" as const, detail: "Move into review confirmation before use" };
    }
    if (resultText) return { label: "Governed", tone: "success" as const, detail: "Governed result ready" };
    return { label: "Awaiting run", tone: "default" as const, detail: "No governed output yet" };
  }, [resultText, reviewState, runError, running]);

  const rulesFiredCount = useMemo(() => countRulesFired(liveOutcome?.rules_fired), [liveOutcome]);
  const runSummary = useMemo(
    () =>
      buildRunSummary({
        reviewState,
        mode,
        role,
        sourceCount: sourceInsights.itemCount,
        textReadyCount: sourceInsights.readyCount,
        receiptAvailable: !!activeRequestId,
        reviewConfirmed,
        createdAt: governanceSummary.createdAt,
      }),
    [
      activeRequestId,
      governanceSummary.createdAt,
      mode,
      reviewConfirmed,
      reviewState,
      role,
      sourceInsights.itemCount,
      sourceInsights.readyCount,
    ]
  );
  const governanceOutcomeItems = useMemo(
    () =>
      buildGovernanceOutcomeItems({
        governanceSummary,
        receiptAvailable: !!activeRequestId,
        reviewConfirmed,
      }),
    [activeRequestId, governanceSummary, reviewConfirmed]
  );
  const interventionItems = useMemo(
    () =>
      buildInterventionItems({
        decision: liveOutcome?.decision,
        resultAvailable: !!resultText,
        receiptAvailable: !!activeRequestId,
        reviewConfirmed,
        piiDetected: liveOutcome?.pii_detected,
        piiAction: liveOutcome?.pii_action,
        rulesFiredCount,
        noContentStored: liveOutcome?.no_content_stored !== false,
      }),
    [activeRequestId, liveOutcome, resultText, reviewConfirmed, rulesFiredCount]
  );
  const reviewGuidanceItems = useMemo(
    () =>
      buildReviewGuidanceItems({
        piiDetected: liveOutcome?.pii_detected,
        receiptAvailable: !!activeRequestId,
        reviewConfirmed,
        pendingSourceCount: sourceInsights.pendingCount + sourceInsights.manualCount,
        sensitiveHintPresent: !!sourceInsights.sensitiveHint,
      }),
    [activeRequestId, liveOutcome, reviewConfirmed, sourceInsights.manualCount, sourceInsights.pendingCount, sourceInsights.sensitiveHint]
  );
  const changeOverviewItems = useMemo(
    () =>
      buildChangeOverviewItems({
        sourceCount: sourceInsights.itemCount,
        textReadyCount: sourceInsights.readyCount,
        sourceLength: comparableSourceText.length,
        outputLength: resultText.length,
        outputChanged: compareComparableText(comparableSourceText, resultText),
        warningsPresent: liveOutcome?.pii_detected === true || (rulesFiredCount ?? 0) > 0,
      }),
    [comparableSourceText, liveOutcome, resultText, rulesFiredCount, sourceInsights.itemCount, sourceInsights.readyCount]
  );
  const showRelatedLearning = useMemo(
    () =>
      !!resultText &&
      (liveOutcome?.pii_detected === true ||
        (rulesFiredCount ?? 0) > 0 ||
        !reviewConfirmed ||
        !!sourceInsights.sensitiveHint),
    [liveOutcome, resultText, reviewConfirmed, rulesFiredCount, sourceInsights.sensitiveHint]
  );

  function resetWorkspace() {
    sourcesRef.current.forEach((item) => {
      if (item.objectUrl) {
        URL.revokeObjectURL(item.objectUrl);
      }
    });
    setSourceItems([]);
    setDraftText("");
    setEditingTextSourceId(null);
    setReplaceSourceId(null);
    setInstruction(DEFAULT_INSTRUCTION);
    setMode(DEFAULT_MODE);
    setRole(DEFAULT_ROLE);
    setWorkflowOrigin(DEFAULT_WORKFLOW_ORIGIN);
    setResultText("");
    setAssistPayload(null);
    setReceipt(null);
    setRequestId(null);
    setReviewConfirmed(false);
    setWorkflowStage("drafted");
    setRunError(null);
    setActionMessage(DEFAULT_ACTION_MESSAGE);
  }

  function applySourceItems(
    updater: (items: WorkspaceSourceItem[]) => WorkspaceSourceItem[],
    removedItems: WorkspaceSourceItem[] = []
  ) {
    removedItems.forEach((item) => {
      if (item.objectUrl) {
        URL.revokeObjectURL(item.objectUrl);
      }
    });
    setSourceItems((current) => updater(current));
  }

  function stagePastedSource({
    skipInvalidation = false,
  }: {
    skipInvalidation?: boolean;
  } = {}) {
    const clean = draftText.trim();
    if (!clean) return sourceItems;

    const normalizedDraft = normalizeWorkspaceText(clean);
    const existingSource = editingTextSourceId
      ? sourceItems.find((item) => item.sourceId === editingTextSourceId)
      : null;
    const hasMaterialChange =
      !existingSource ||
      normalizeWorkspaceText(existingSource.extractedText) !== normalizedDraft ||
      existingSource.origin !== workflowOrigin;

    const existingTextCount = sourceItems.filter((item) => item.sourceKind === "pasted_text").length;
    const source = createPastedTextSource(
      clean,
      workflowOrigin,
      editingTextSourceId ? existingTextCount : existingTextCount + 1,
      editingTextSourceId ?? undefined
    );

    const nextItems = editingTextSourceId
      ? sourceItems.map((item) => (item.sourceId === editingTextSourceId ? source : item))
      : [source, ...sourceItems];

    setSourceItems(nextItems);
    setDraftText("");
    setEditingTextSourceId(null);
    setRunError(null);
    if (!skipInvalidation && hasMaterialChange) {
      invalidateGovernedState();
    }

    return nextItems;
  }

  function addOrReplacePastedSource() {
    stagePastedSource();
  }

  function ensurePendingDraftIsStaged() {
    if (!draftText.trim()) {
      return sourceItems;
    }
    return stagePastedSource({ skipInvalidation: true });
  }

  async function handleFiles(files: FileList | File[] | null) {
    const incoming = files ? Array.from(files) : [];
    if (!incoming.length) {
      setReplaceSourceId(null);
      return;
    }

    const targetFiles = replaceSourceId ? incoming.slice(0, 1) : incoming;
    const built = await Promise.all(
      targetFiles.map((file) => createWorkspaceSourceFromFile(file, workflowOrigin, replaceSourceId ?? undefined))
    );

    if (replaceSourceId) {
      const toReplace = sourceItems.find((item) => item.sourceId === replaceSourceId);
      applySourceItems(
        (current) => current.map((item) => (item.sourceId === replaceSourceId ? built[0] : item)),
        toReplace ? [toReplace] : []
      );
      setReplaceSourceId(null);
    } else {
      setSourceItems((current) => [...built, ...current]);
    }

    invalidateGovernedState();
    setRunError(null);
  }

  function openPicker(kind: "generic" | "pdf" | "image", targetId?: string) {
    if (targetId) {
      setReplaceSourceId(targetId);
    } else {
      setReplaceSourceId(null);
    }

    const input =
      kind === "pdf" ? pdfInputRef.current : kind === "image" ? imageInputRef.current : genericInputRef.current;
    input?.click();
  }

  function handleRemoveSource(sourceId: string) {
    const target = sourceItems.find((item) => item.sourceId === sourceId);
    applySourceItems((current) => current.filter((item) => item.sourceId !== sourceId), target ? [target] : []);
    if (target) {
      invalidateGovernedState();
    }

    if (editingTextSourceId === sourceId) {
      setEditingTextSourceId(null);
      setDraftText("");
    }
  }

  function handleReplaceSource(sourceId: string) {
    const item = sourceItems.find((entry) => entry.sourceId === sourceId);
    if (!item) return;

    if (item.sourceKind === "pasted_text") {
      setDraftText(item.extractedText);
      setEditingTextSourceId(item.sourceId);
      setRunError(null);
      return;
    }

    if (item.sourceKind === "pdf") {
      openPicker("pdf", item.sourceId);
      return;
    }

    if (item.sourceKind === "image") {
      openPicker("image", item.sourceId);
      return;
    }

    openPicker("generic", item.sourceId);
  }

  async function fetchReceipt(requestIdValue: string): Promise<ReceiptPayload> {
    const payload = await apiFetch<ReceiptEnvelope | ReceiptPayload>(
      `/v1/portal/receipt/${encodeURIComponent(requestIdValue)}`
    );
    return ("receipt" in payload ? payload.receipt : payload) as ReceiptPayload;
  }

  async function handleRun() {
    setRunError(null);
    setReviewConfirmed(false);
    setWorkflowStage("drafted");
    const nextSources = ensurePendingDraftIsStaged();
    const sourceText = buildAssistSourceText(nextSources);
    const runInstruction = buildWorkspaceRunInstruction(mode, instruction);

    if (!sourceText) {
      setRunError(
        "Add pasted text or a text-readable source before running ANCHOR. PDF and image items are supported in the bundle, but extracted text is not yet available in Workspace v1."
      );
      return;
    }

    setRunning(true);
    setResultText("");
    setAssistPayload(null);
    setReceipt(null);
    setRequestId(null);
    setActionMessage("Governance run in progress. Receipt actions will activate after a completed run.");
    const combinedPrompt = `${runInstruction}\n\nSource material:\n${sourceText}`;

    const payload = {
      mode: mapWorkspaceModeToApi(mode),
      role,
      instruction: runInstruction,
      text: sourceText,
      input: sourceText,
      input_text: sourceText,
      source_material: sourceText,
      source_text: sourceText,
      prompt: combinedPrompt,
      content: combinedPrompt,
      workflow_origin: mapWorkflowOriginToApi(workflowOrigin),
      input_kind: "source_bundle",
    };

    try {
      const data = await apiFetch<AssistResponse>("/v1/portal/assist", {
        method: "POST",
        body: JSON.stringify(payload),
      });

      const governedText =
        normalizeWorkspaceOutput(
          mode,
          data.final_text ??
            data.output ??
            data.governed_output ??
            data.result ??
            data.rewritten_text ??
            data.assistant_output ??
            data.text ??
            ""
        );

      setAssistPayload(data);
      setResultText(governedText);
      setWorkflowStage("governed");

      const nextRequestId = data.request_id ?? data.receipt?.request_id ?? null;
      setRequestId(nextRequestId ?? null);

      const provisionalReceipt: ReceiptPayload = {
        request_id: nextRequestId ?? undefined,
        decision: data.decision,
        risk_grade: data.risk_grade,
        pii_detected: data.pii_detected,
        pii_action: data.pii_action,
        pii_types: data.pii_types,
        governance_score: data.governance_score,
        policy_version: data.policy_version,
        neutrality_version: data.neutrality_version,
        policy_hash: data.policy_hash ?? data.policy_sha256,
        policy_sha256: data.policy_sha256,
        rules_fired: data.rules_fired,
        no_content_stored: data.no_content_stored ?? true,
        created_at_utc: data.created_at_utc ?? data.created_at,
      };

      setReceipt(provisionalReceipt);

      if (nextRequestId) {
        try {
          const liveReceipt = await fetchReceipt(nextRequestId);
          setReceipt(liveReceipt);
        } catch (receiptError) {
          console.warn("Unable to fetch live receipt", receiptError);
        }
      }

      setActionMessage(
        nextRequestId
          ? "Governed output is ready. Continue into human review confirmation before operational use."
          : "Governed output is ready. Receipt preview is still pending before review can continue."
      );
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "ANCHOR could not complete this run right now.";
      setRunError(message);
      setResultText("");
      setAssistPayload(null);
      setReceipt(null);
      setRequestId(null);
      setWorkflowStage("drafted");
      setActionMessage("Receipt actions remain unavailable because the latest run did not complete.");
    } finally {
      setRunning(false);
    }
  }

  async function handleExportMetadata() {
    if (!activeRequestId) {
      setActionMessage("Export metadata becomes available after a governed run creates a receipt.");
      return;
    }

    if (!reviewConfirmed) {
      setActionMessage("Confirm human review before exporting receipt metadata.");
      return;
    }

    try {
      const liveReceipt = receipt ?? (await fetchReceipt(activeRequestId));
      setReceipt(liveReceipt);
      const blob = new Blob([JSON.stringify({ receipt: liveReceipt }, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `anchor-receipt-${activeRequestId}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      setWorkflowStage("ready_for_use");
      setActionMessage("Receipt metadata exported for this governed run.");
    } catch {
      setActionMessage("Metadata export could not be completed right now.");
    }
  }

  async function handleCopyResult() {
    if (!resultText) {
      setActionMessage("Copy governed result becomes available after ANCHOR produces governed output.");
      return;
    }

    if (!reviewConfirmed) {
      setActionMessage("Confirm human review before copying governed output.");
      return;
    }

    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(resultText);
      } else {
        const copyField = document.createElement("textarea");
        copyField.value = resultText;
        copyField.setAttribute("readonly", "true");
        copyField.style.position = "fixed";
        copyField.style.opacity = "0";
        document.body.appendChild(copyField);
        copyField.select();
        document.execCommand("copy");
        document.body.removeChild(copyField);
      }
      setWorkflowStage("ready_for_use");
      setActionMessage("Governed result copied to clipboard.");
    } catch {
      setActionMessage("Copy governed result could not access the clipboard in this browser context.");
    }
  }

  function openReceipt() {
    if (!activeRequestId) {
      setActionMessage(actionState.receiptSupportText);
      return;
    }
    router.push(`/receipts?request_id=${encodeURIComponent(activeRequestId)}`);
  }

  return (
    <div className="mx-auto max-w-[1480px] space-y-8">
      <section>
        <NativeCard className="overflow-hidden p-0">
          <div className="grid gap-6 px-7 py-6 xl:grid-cols-[minmax(0,1.2fr)_minmax(320px,0.78fr)] xl:items-end">
            <div>
              <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Workspace</h1>
              <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-600">
                Canonical governed work surface for direct drafting, uploaded source bundles, and future multi-origin
                AI workflows under ANCHOR.
              </p>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <TopCommandStat
                label="Current stage"
                value={humanizeToken(reviewState)}
                detail={resultStatus.detail}
              />
              <TopCommandStat
                label="Source bundle"
                value={`${sourceItems.length} item${sourceItems.length === 1 ? "" : "s"}`}
                detail={
                  sourceItems.length > 0
                    ? `${sourceInsights.readyCount} text-ready, ${sourceInsights.pendingCount + sourceInsights.manualCount} pending or manual`
                    : draftText.trim().length > 0
                      ? "Pasted source text is ready to add to the bundle"
                      : "Add pasted text or uploaded sources to begin"
                }
              />
            </div>
          </div>

          <div className="border-t border-slate-100 bg-slate-50/85 px-7 py-4">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
              <div className="flex flex-wrap gap-2">
                <MetaChip label={`Workflow origin (${formatOriginLabel(workflowOrigin)})`} dot />
                <MetaChip label="Metadata-only accountability" />
                <MetaChip label="Human review visible" />
                <MetaChip label={`Source bundle (${sourceItems.length})`} />
              </div>

              <div className="flex flex-wrap gap-3">
                <Button
                  variant="secondary"
                  onClick={resetWorkspace}
                  disabled={!actionState.canResetSession}
                  className={["rounded-md px-3.5 py-2 text-sm font-medium", WORKSPACE_SECONDARY_ACTION_CLASS].join(" ")}
                >
                  New governed session
                </Button>
              </div>
            </div>
          </div>
        </NativeCard>
      </section>

      <div className="grid grid-cols-1 gap-8 xl:grid-cols-[minmax(0,1.55fr)_minmax(320px,0.82fr)] xl:items-start">
        <div>
          <NativeCard className="overflow-hidden p-0">
            <div className="px-7 py-7">
            <div className="mb-7">
              <SectionEyebrow>Workflow controls</SectionEyebrow>
              <h2 className="mt-2 text-base font-semibold text-slate-900">Instruction, mode, and review model</h2>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
                Define how this governed run should behave before source material is bundled. Workflow origin stays at
                the workflow level, while files, PDFs, and images remain source-entry pathways inside the current
                direct workspace flow.
              </p>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
              <SelectField
                label="Workflow origin"
                value={workflowOrigin}
                onChange={(event) => {
                  const nextOrigin = event.target.value as WorkspaceWorkflowOrigin;
                  if (nextOrigin === workflowOrigin) {
                    return;
                  }
                  setWorkflowOrigin(nextOrigin);
                  setSourceItems((current) =>
                    current.map((item) => (item.origin === nextOrigin ? item : { ...item, origin: nextOrigin }))
                  );
                  invalidateGovernedState();
                }}
              >
                {WORKSPACE_ORIGIN_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value} disabled={!option.available}>
                    {option.label}
                    {!option.available ? " (Future)" : ""}
                  </option>
                ))}
              </SelectField>

              <SelectField
                label="Staff role"
                value={role}
                onChange={(event) => {
                  const nextRole = event.target.value as (typeof WORKSPACE_ROLE_OPTIONS)[number];
                  if (nextRole === role) {
                    return;
                  }
                  setRole(nextRole);
                  invalidateGovernedState();
                }}
              >
                {WORKSPACE_ROLE_OPTIONS.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </SelectField>

              <SelectField
                label="Workflow mode"
                value={mode}
                onChange={(event) => {
                  const nextMode = event.target.value as WorkspaceMode;
                  if (nextMode === mode) {
                    return;
                  }
                  setMode(nextMode);
                  setInstruction((current) => {
                    const presets = Object.values(WORKSPACE_INSTRUCTION_PRESETS);
                    if (!current.trim() || presets.includes(current.trim())) {
                      return WORKSPACE_INSTRUCTION_PRESETS[nextMode];
                    }
                    return current;
                  });
                  invalidateGovernedState();
                }}
              >
                {WORKSPACE_MODE_OPTIONS.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </SelectField>
            </div>

            <p className="mt-4 text-sm leading-6 text-slate-600">{WORKFLOW_ORIGIN_HELP_TEXT}</p>

            <div className="mt-5 rounded-xl border border-slate-200/80 bg-slate-50/70 p-4">
              <label className="mb-2 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
                Instruction
              </label>
              <textarea
                value={instruction}
                onChange={(event) => {
                  const nextInstruction = event.target.value;
                  if (nextInstruction === instruction) {
                    return;
                  }
                  setInstruction(nextInstruction);
                  invalidateGovernedState();
                }}
                rows={3}
                className="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm leading-6 text-slate-700 outline-none transition placeholder:text-slate-400 focus:border-slate-400 focus:ring-1 focus:ring-slate-300"
              />
            </div>
            </div>

            <div className="border-t border-slate-100 px-7 py-7">
            <div className="mb-6 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div>
                <SectionEyebrow>Source material</SectionEyebrow>
                <h2 className="mt-2 text-base font-semibold text-slate-900">Multi-origin source bundle</h2>
                <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
                  Add pasted text, text-readable files, PDFs, and images into one governed source manifest. Workspace v1
                  uses text-ready items today and preserves future hooks for richer extraction flows. Files, PDFs, and
                  images enter as source-entry pathways inside the active workflow origin.
                </p>
              </div>

              <div className="flex flex-wrap gap-2">
                <Button variant="secondary" onClick={() => openPicker("generic")}>
                  Upload files
                </Button>
                <Button variant="secondary" onClick={() => openPicker("pdf")}>
                  Upload PDFs
                </Button>
                <Button variant="secondary" onClick={() => openPicker("image")}>
                  Upload images
                </Button>
              </div>
            </div>

            <div
              onDragEnter={(event) => {
                event.preventDefault();
                setDragActive(true);
              }}
              onDragOver={(event) => {
                event.preventDefault();
                setDragActive(true);
              }}
              onDragLeave={(event) => {
                event.preventDefault();
                if (event.currentTarget === event.target) {
                  setDragActive(false);
                }
              }}
              onDrop={(event) => {
                event.preventDefault();
                setDragActive(false);
                void handleFiles(event.dataTransfer.files);
              }}
              className={[
                "rounded-xl border border-dashed bg-slate-50/80 px-5 py-5 transition",
                dragActive ? "border-slate-500 bg-slate-100/90" : "border-slate-200/90",
              ].join(" ")}
            >
              <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div className="flex items-start gap-3">
                  <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-white text-slate-600 shadow-sm">
                    <span className="material-symbols-outlined text-[20px]">upload_file</span>
                  </div>
                  <div>
                <p className="text-sm font-semibold text-slate-900">Drop files directly into the bundle</p>
                <p className="mt-1 text-sm leading-6 text-slate-600">
                  PDFs and images are stored as source items now, with extracted text added later as Workspace
                  capabilities expand.
                </p>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  {sourceInsights.typeLabels.length > 0 ? (
                    sourceInsights.typeLabels.map((label) => <MetaChip key={label} label={label} />)
                  ) : (
                    <MetaChip label="No sources yet" />
                  )}
                </div>
              </div>
            </div>

            <div className="mt-5 rounded-xl border border-slate-200/80 bg-slate-50/70 p-4">
              <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div>
                  <p className="text-sm font-semibold text-slate-900">
                    {editingTextSourceId ? "Replace pasted source" : "Paste source material"}
                  </p>
                  <p className="mt-1 text-sm leading-6 text-slate-600">
                    Paste notes, transcripts, draft content, or vendor output that should be governed before use.
                  </p>
                </div>

                <Button onClick={addOrReplacePastedSource} disabled={!draftText.trim()}>
                  {editingTextSourceId ? "Replace source text" : "Add pasted source"}
                </Button>
              </div>

              <textarea
                value={draftText}
                onChange={(event) => setDraftText(event.target.value)}
                placeholder="Paste operational source material for governed review."
                rows={6}
                className="mt-4 w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm leading-6 text-slate-700 outline-none transition placeholder:text-slate-400 focus:border-slate-400 focus:ring-1 focus:ring-slate-300"
              />

              <p className="mt-3 text-[11px] italic text-slate-500">
                Privacy-aware handling is applied during governed review. Metadata-only accountability remains the default
                doctrine. Always confirm the output before operational use.
              </p>
            </div>

            <div className="mt-5">
              <div className="mb-3 flex items-center justify-between">
                <p className="text-sm font-semibold text-slate-900">Source manifest</p>
                <p className="text-xs text-slate-500">
                  {sourceItems.length} item{sourceItems.length === 1 ? "" : "s"}
                </p>
              </div>

              {sourceItems.length === 0 ? (
                <EmptyState text="No source items are in the bundle yet. Add pasted text or upload files to begin." />
              ) : (
                <div className="space-y-3">
                  {sourceItems.map((item) => (
                    <div
                      key={item.sourceId}
                      className="rounded-xl border border-slate-200/80 bg-white px-4 py-4 shadow-[0_8px_20px_rgba(42,52,57,0.04)]"
                    >
                      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <p className="text-sm font-semibold text-slate-900">{item.filename}</p>
                            <StatusPill
                              tone={item.extractionStatus === "ready" ? "success" : item.extractionStatus === "error" ? "danger" : "default"}
                              label={formatExtractionStatusLabel(item.extractionStatus)}
                            />
                            <MetaChip label={formatSourceKindLabel(item.sourceKind)} />
                            <MetaChip label={formatOriginLabel(item.origin)} />
                          </div>

                          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
                            <span>{item.mimeType}</span>
                            <span>{formatFileSize(item.sizeBytes)}</span>
                            <span>Added {formatDateTime(item.addedAt)}</span>
                          </div>

                          <p className="mt-3 text-sm leading-6 text-slate-600">{item.previewText}</p>
                        </div>

                        <div className="flex shrink-0 flex-wrap gap-2">
                          <button
                            type="button"
                            onClick={() => handleReplaceSource(item.sourceId)}
                            className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-semibold text-slate-700 transition hover:bg-white"
                          >
                            {item.sourceKind === "pasted_text" ? "Replace text" : "Replace"}
                          </button>
                          <button
                            type="button"
                            onClick={() => handleRemoveSource(item.sourceId)}
                            className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-semibold text-slate-700 transition hover:bg-white"
                          >
                            Remove
                          </button>
                        </div>
                      </div>

                      {item.sourceKind === "image" && item.objectUrl ? (
                        <div className="mt-4 overflow-hidden rounded-xl border border-slate-200/80 bg-slate-50 p-2">
                          {/* eslint-disable-next-line @next/next/no-img-element */}
                          <img
                            alt={item.filename}
                            src={item.objectUrl}
                            className="max-h-48 w-auto rounded-lg object-contain"
                          />
                        </div>
                      ) : null}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <input
              ref={genericInputRef}
              type="file"
              accept={SOURCE_ACCEPT}
              multiple={!replaceSourceId}
              className="hidden"
              onChange={(event) => {
                void handleFiles(event.target.files);
                event.currentTarget.value = "";
              }}
            />
            <input
              ref={pdfInputRef}
              type="file"
              accept={PDF_ACCEPT}
              multiple={!replaceSourceId}
              className="hidden"
              onChange={(event) => {
                void handleFiles(event.target.files);
                event.currentTarget.value = "";
              }}
            />
            <input
              ref={imageInputRef}
              type="file"
              accept={IMAGE_ACCEPT}
              multiple={!replaceSourceId}
              className="hidden"
              onChange={(event) => {
                void handleFiles(event.target.files);
                event.currentTarget.value = "";
              }}
            />
            </div>

            <div className="border-t border-slate-100 bg-slate-50/45 px-7 py-7">
              <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div>
                  <SectionEyebrow>Review boundaries</SectionEyebrow>
                  <h2 className="mt-2 text-base font-semibold text-slate-900">Review expectations before release</h2>
                  <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
                    Confirm the governance boundaries that frame the run, then move through the visible handoff state
                    before any controlled operational use.
                  </p>
                </div>
                <MetaChip label={humanizeToken(reviewState)} dot />
              </div>

              <div className="mt-5 flex flex-wrap gap-2">
                {WORKSPACE_REVIEW_BOUNDARIES.map((boundary, index) => (
                  <span
                    key={boundary}
                    className={[
                      "inline-flex items-center rounded-full border px-3 py-1 text-[11px] font-bold uppercase tracking-wide",
                      index === 1
                        ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                        : index === 0
                          ? "border-slate-200 bg-slate-100 text-slate-600"
                          : "border-slate-200 bg-white text-slate-500",
                    ].join(" ")}
                  >
                    {boundary}
                  </span>
                ))}
              </div>

              <div className="mt-6">
                <label className="mb-3 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
                  Review / handoff state
                </label>
                <div className="grid gap-2 md:grid-cols-5">
                  {WORKSPACE_REVIEW_STEPS.map((step, index) => {
                    const isCurrent = reviewState === step.key;
                    const isComplete = currentReviewStepIndex > index;

                    return (
                      <div
                        key={step.key}
                        className={[
                          "rounded-xl border px-3 py-3 text-sm",
                          isCurrent
                            ? WORKSPACE_ACTIVE_STEP_CLASS
                            : isComplete
                              ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                              : "border-slate-200 bg-white text-slate-500",
                        ].join(" ")}
                      >
                        <div className="flex flex-col gap-1.5">
                          <span
                            className={[
                              "flex h-6 w-6 items-center justify-center rounded-full text-[11px] font-semibold",
                              isCurrent
                                ? "bg-white text-slate-900"
                                : isComplete
                                  ? "bg-emerald-100 text-emerald-700"
                                  : "bg-slate-50 text-slate-500",
                            ].join(" ")}
                          >
                            {String(index + 1).padStart(2, "0")}
                          </span>
                          <span className="font-medium leading-snug">{step.label}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            <div className="border-t border-slate-100 bg-slate-50/70 px-7 py-6">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                <div>
                  <SectionEyebrow>Run through ANCHOR</SectionEyebrow>
                  <h2 className="mt-2 text-base font-semibold text-slate-900">Generate the governed result and receipt path</h2>
                  <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
                    Finalize the setup flow above, then run the current source bundle through ANCHOR to create the
                    governed output, receipt linkage, and review-ready operational path.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  <MetaChip label={`${sourceItems.length} source item${sourceItems.length === 1 ? "" : "s"}`} />
                  <Button
                    variant="primary"
                    onClick={() => void handleRun()}
                    loading={running}
                    disabled={running || (!sourceBundleText && !draftText.trim())}
                    className="disabled:opacity-80"
                  >
                    Run through ANCHOR
                  </Button>
                </div>
              </div>
              <p className="mt-3 text-sm leading-6 text-slate-500">{actionState.setupRunHint}</p>
            </div>

            <div className="border-t border-slate-100 px-7 py-7">
              <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div>
                  <SectionEyebrow>Governed result</SectionEyebrow>
                  <h2 className="mt-2 text-base font-semibold text-slate-900">Governed output surface</h2>
                  <p className="mt-2 text-sm leading-6 text-slate-600">
                    Governed output appears here after a completed run. Workspace v1 keeps the result truthful and
                    reviewable while the source bundle model expands.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <StatusPill
                    tone={resultStatus.tone}
                    label={resultStatus.label}
                    icon={resultStatus.tone === "success" ? "verified" : resultStatus.tone === "danger" ? "warning" : "pending"}
                  />
                  {actionState.canContinueToReview ? (
                    <Button
                      variant="secondary"
                      onClick={continueToReviewConfirmation}
                      className="rounded-md border-slate-200 px-4 py-2 text-sm font-medium text-slate-700"
                    >
                      Continue to review
                    </Button>
                  ) : actionState.reviewActionLabel ? (
                    <MetaChip label={actionState.reviewActionLabel} />
                  ) : null}
                </div>
              </div>

              <div className="mt-5">
                {runError ? (
                  <div className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-4 text-sm leading-6 text-rose-700">
                    {runError}
                  </div>
                ) : resultText ? (
                  <div className="space-y-4">
                    <div className="rounded-xl border border-slate-200/80 bg-slate-50/80 p-5">
                      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                        <div>
                          <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
                            Live run summary
                          </p>
                          <h3 className="mt-2 text-sm font-semibold text-slate-900">{runSummary.headline}</h3>
                          <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">{runSummary.detail}</p>
                        </div>
                        <div className="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-medium text-slate-700">
                          {runSummary.nextAction}
                        </div>
                      </div>

                      <div className="mt-4 grid gap-3 sm:grid-cols-3">
                        {runSummary.metrics.map((metric) => (
                          <PostRunMetric key={metric.label} label={metric.label} value={metric.value} detail={metric.detail} />
                        ))}
                      </div>
                    </div>

                    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.18fr)_minmax(300px,0.82fr)]">
                      <div className="rounded-xl border border-slate-200/80 bg-slate-50/70 p-5">
                        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                          <div>
                            <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
                              Governed output
                            </p>
                            <p className="mt-1 text-sm leading-6 text-slate-600">
                              Review the governed output before releasing it operationally.
                            </p>
                          </div>
                          <MetaChip label={`${formatCharacterCount(resultText.length)} output chars`} />
                        </div>
                        <div className="mt-4 whitespace-pre-wrap rounded-xl border border-slate-200 bg-white px-4 py-4 text-sm leading-7 text-slate-700">
                          {resultText}
                        </div>
                      </div>

                      <div className="space-y-4">
                        <PostRunPanel
                          title="Governance outcome"
                          description="Current live outcome fields from the assist and receipt flow."
                        >
                          <div className="grid gap-3 sm:grid-cols-2">
                            {governanceOutcomeItems.map((item) => (
                              <PostRunMetric
                                key={item.label}
                                label={item.label}
                                value={item.value}
                                detail={item.detail}
                                mono={item.mono}
                              />
                            ))}
                          </div>
                        </PostRunPanel>

                        <PostRunPanel
                          title="What ANCHOR noticed"
                          description="Only live governance observations that are available from the current run are shown."
                        >
                          <PostRunItemList items={interventionItems} />
                        </PostRunPanel>
                      </div>
                    </div>

                    <div className="grid gap-4 lg:grid-cols-[minmax(0,1.02fr)_minmax(0,0.98fr)]">
                      <PostRunPanel
                        title="Change overview"
                        description="Workspace v1 shows only the limited change state that can be derived from current source and receipt data."
                      >
                        <div className="grid gap-3 sm:grid-cols-2">
                          {changeOverviewItems.map((item) => (
                            <PostRunMetric key={item.label} label={item.label} value={item.value} detail={item.detail} />
                          ))}
                        </div>
                      </PostRunPanel>

                      <PostRunPanel
                        title="Human review guidance"
                        description="Use these review checks before copying forward or using the governed output operationally."
                      >
                        <PostRunItemList items={reviewGuidanceItems} />
                      </PostRunPanel>
                    </div>

                    <div className="rounded-xl border border-slate-200/80 bg-white p-5 shadow-[0_8px_20px_rgba(42,52,57,0.04)]">
                      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                        <div>
                          <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
                            Release actions
                          </p>
                          <h3 className="mt-2 text-sm font-semibold text-slate-900">{runSummary.nextAction}</h3>
                          <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">{actionMessage}</p>
                        </div>

                        <div className="flex flex-wrap gap-2 lg:max-w-[440px] lg:justify-end">
                          <WorkspaceActionButton onClick={() => void handleCopyResult()} disabled={!canCopyOrExport}>
                            Copy governed result
                          </WorkspaceActionButton>
                          {actionState.hasReviewableReceipt ? (
                            <WorkspaceActionButton onClick={openReceipt}>
                              Open this receipt
                            </WorkspaceActionButton>
                          ) : null}
                          <WorkspaceActionButton onClick={() => void handleExportMetadata()} disabled={!canCopyOrExport}>
                            Export metadata
                          </WorkspaceActionButton>
                          {showRelatedLearning ? (
                            <WorkspaceActionButton onClick={() => router.push("/learn/cards")}>
                              Open related learning
                            </WorkspaceActionButton>
                          ) : null}
                          <WorkspaceActionButton
                            onClick={resetWorkspace}
                            className={WORKSPACE_SECONDARY_ACTION_CLASS}
                          >
                            Start a new governed session
                          </WorkspaceActionButton>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="rounded-xl border border-slate-200/80 bg-slate-50/70 p-5">
                    <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">
                      Awaiting first governed run
                    </p>
                    <h3 className="mt-2 text-sm font-semibold text-slate-900">
                      This surface becomes the primary review and release area after a completed run.
                    </h3>
                    <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
                      Add source material, confirm the workflow controls, and run through ANCHOR to review the governed
                      output, live governance outcome, intervention notices, and release steps in one place.
                    </p>
                    <div className="mt-4 grid gap-3 sm:grid-cols-3">
                      <PostRunMetric label="1" value="Add source material" detail="Paste text or upload supported files into the source bundle." />
                      <PostRunMetric label="2" value="Set workflow controls" detail="Choose the mode, role, and instruction that should govern the run." />
                      <PostRunMetric label="3" value="Run through ANCHOR" detail="Generate the governed output, receipt linkage, and human-review path." />
                    </div>
                  </div>
                )}
              </div>
            </div>
          </NativeCard>
        </div>

        <div className="space-y-4">
          <NativeCard className="p-5">
            <SectionEyebrow>Readiness status</SectionEyebrow>
            <div className="mt-4 space-y-3">
              {readinessItems.map((item) => (
                <StatusRow key={item.label} label={item.label} ready={item.ready} detail={item.detail} />
              ))}
            </div>
          </NativeCard>

          <NativeCard className="p-5">
            <SectionEyebrow>Source bundle insight</SectionEyebrow>
            <div className="mt-4 grid grid-cols-2 gap-3">
              <MetricTile label="Source items" value={String(sourceInsights.itemCount)} compact />
              <MetricTile
                label="Text ready"
                value={`${sourceInsights.readyCount}/${sourceInsights.itemCount || 0}`}
                compact
              />
            </div>

            <div className="mt-4 flex flex-wrap gap-2">
              {sourceInsights.typeLabels.length > 0 ? (
                sourceInsights.typeLabels.map((label) => <MetaChip key={label} label={label} />)
              ) : (
                <MetaChip label="Awaiting source material" />
              )}
            </div>

            <div className="mt-4 space-y-3 text-sm leading-6 text-slate-600">
              <p>{sourceInsights.completenessHint}</p>
              <p>
                Extraction status: {sourceInsights.readyCount} ready, {sourceInsights.pendingCount} pending,{" "}
                {sourceInsights.manualCount} manual review, {sourceInsights.errorCount} error.
              </p>
              <p>Total bundle size: {formatFileSize(sourceInsights.totalBytes)}</p>
              {sourceInsights.sensitiveHint ? (
                <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-amber-800">
                  {sourceInsights.sensitiveHint}
                </div>
              ) : null}
            </div>
          </NativeCard>

          <NativeCard className="p-5">
            <SectionEyebrow>Governance summary</SectionEyebrow>
            <WorkspaceSupportCardRows>
              <InlineDataRow label="Decision" value={governanceSummary.decision} />
              <InlineDataRow label="Risk grade" value={governanceSummary.riskGrade} />
              <InlineDataRow label="PII detected" value={governanceSummary.piiDetected} />
              <InlineDataRow label="PII action" value={governanceSummary.piiAction} />
              <InlineDataRow label="Governance score" value={governanceSummary.governanceScore} />
              <InlineDataRow label="Policy version" value={governanceSummary.policyVersion} />
              <InlineDataRow label="Neutrality version" value={governanceSummary.neutralityVersion} />
              <InlineDataRow label="No content stored" value={governanceSummary.noContentStored} />
            </WorkspaceSupportCardRows>
          </NativeCard>

          <NativeCard className="p-5">
            <SectionEyebrow>Traceability</SectionEyebrow>
            <WorkspaceSupportCardRows>
              <InlineDataRow label="Workflow origin" value={formatOriginLabel(workflowOrigin)} />
              <InlineDataRow label="Request ID" value={activeRequestId ?? "Pending"} mono />
              <InlineDataRow label="Policy hash" value={governanceSummary.policyHash} mono />
              <InlineDataRow label="Rules fired" value={governanceSummary.rulesFired} />
              <InlineDataRow label="Receipt available" value={activeRequestId ? "Active" : "Pending"} />
              <InlineDataRow label="Sources in scope" value={String(sourceItems.length)} />
              <InlineDataRow label="Created at" value={governanceSummary.createdAt} />
            </WorkspaceSupportCardRows>
          </NativeCard>

          <NativeCard className="p-5">
            <SectionEyebrow>Receipt preview</SectionEyebrow>
            <WorkspaceSupportCardRows>
              <InlineDataRow
                label="Receipt"
                value={actionState.hasReviewableReceipt ? `RECEIPT_${activeRequestId?.slice(0, 8)}` : actionState.receiptHeading}
              />
              <InlineDataRow
                label="Request ID"
                value={actionState.hasReviewableReceipt ? activeRequestId ?? "Pending" : actionState.receiptRequestIdValue}
                mono={actionState.hasReviewableReceipt}
              />
              <InlineDataRow label="Policy version" value={governanceSummary.policyVersion} />
              <InlineDataRow label="Neutrality version" value={governanceSummary.neutralityVersion} />
              <InlineDataRow label="No content stored" value={governanceSummary.noContentStored} />
              <InlineDataRow label="Human review confirmed" value={reviewConfirmed ? "Yes" : "No"} />
            </WorkspaceSupportCardRows>

            {actionState.canOpenReceipt ? (
              <div className="mt-4">
                <Button variant="secondary" onClick={openReceipt} className="rounded-md px-3 py-2 text-[11px] font-bold">
                  <span className="material-symbols-outlined mr-1 text-sm">open_in_new</span>
                  Open receipt
                </Button>
              </div>
            ) : (
              <p className="mt-4 text-sm leading-6 text-slate-600">{actionState.receiptSupportText}</p>
            )}

            <p className="mt-4 text-sm leading-6 text-slate-600">
              {actionState.hasGovernedRun
                ? `Request-level release actions are handled from the governed result surface. ${actionMessage}`
                : actionMessage}
            </p>
          </NativeCard>

          <NativeCard className="p-5">
            <SectionEyebrow>Human review confirmation</SectionEyebrow>
            <div ref={reviewConfirmationRef} className="mt-4 rounded-xl border border-slate-200/80 bg-slate-50 p-4">
              <label className="flex items-start gap-3">
                <input
                  checked={reviewConfirmed}
                  onChange={(event) => handleReviewConfirmationChange(event.target.checked)}
                  type="checkbox"
                  disabled={!actionState.canConfirmReview}
                  className="mt-1 h-4 w-4 rounded border-slate-300 text-slate-900 focus:ring-slate-400"
                />
                <div>
                  <p className="text-sm font-semibold text-slate-900">Confirm human review before operational use</p>
                  <p className="mt-1 text-sm leading-6 text-slate-600">
                    {actionState.reviewPrompt}
                  </p>
                </div>
              </label>
            </div>

            <div className="mt-4 flex flex-wrap gap-2">
              <MetaChip label={`State (${humanizeToken(reviewState)})`} />
              <MetaChip label={actionState.reviewStatusLabel} />
            </div>

            <p className="mt-4 text-sm leading-6 text-slate-600">
              {actionState.reviewFooter}
            </p>
          </NativeCard>
        </div>
      </div>
    </div>
  );
}

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
    <span className={["block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500", className].join(" ")}>
      {children}
    </span>
  );
}

function MetaChip({ label, dot = false }: { label: string; dot?: boolean }) {
  return (
    <span className="inline-flex items-center rounded-full border border-slate-200 bg-slate-100 px-3 py-1 text-[11px] font-medium uppercase tracking-[0.12em] text-slate-500">
      {dot ? <span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-slate-500" /> : null}
      {label}
    </span>
  );
}

function TopCommandStat({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-xl border border-slate-200/80 bg-slate-50/80 px-4 py-4">
      <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">{label}</p>
      <p className="mt-2 text-lg font-semibold tracking-tight text-slate-900">{value}</p>
      <p className="mt-1 text-sm leading-6 text-slate-600">{detail}</p>
    </div>
  );
}

type PostRunMetricItem = {
  label: string;
  value: string;
  detail?: string;
  mono?: boolean;
};

type PostRunListItem = {
  title: string;
  detail: string;
};

type RunSummary = {
  headline: string;
  detail: string;
  nextAction: string;
  metrics: PostRunMetricItem[];
};

type WorkspaceActionState = {
  canResetSession: boolean;
  canOpenReceipt: boolean;
  canContinueToReview: boolean;
  canConfirmReview: boolean;
  canCopyOrExport: boolean;
  hasGovernedRun: boolean;
  hasReviewableReceipt: boolean;
  receiptHeading: string;
  receiptRequestIdValue: string;
  receiptSupportText: string;
  reviewStatusLabel: string;
  reviewPrompt: string;
  reviewFooter: string;
  reviewActionLabel: string | null;
  setupRunHint: string;
};

function PostRunPanel({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <div className="rounded-xl border border-slate-200/80 bg-white p-5 shadow-[0_8px_20px_rgba(42,52,57,0.04)]">
      <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">{title}</p>
      <p className="mt-2 text-sm leading-6 text-slate-600">{description}</p>
      <div className="mt-4">{children}</div>
    </div>
  );
}

function PostRunMetric({
  label,
  value,
  detail,
  mono = false,
}: PostRunMetricItem) {
  return (
    <div className="rounded-xl border border-slate-200/80 bg-slate-50/80 px-4 py-4">
      <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">{label}</p>
      <p
        className={[
          "mt-2 font-semibold tracking-tight text-slate-900",
          mono ? "break-all font-mono text-[13px] leading-5" : "text-sm leading-6",
        ].join(" ")}
      >
        {value}
      </p>
      {detail ? <p className="mt-1 text-sm leading-6 text-slate-600">{detail}</p> : null}
    </div>
  );
}

function PostRunItemList({ items }: { items: PostRunListItem[] }) {
  return (
    <div className="space-y-3">
      {items.map((item) => (
        <div key={item.title} className="rounded-xl border border-slate-200/80 bg-slate-50/80 px-4 py-4">
          <p className="text-sm font-semibold text-slate-900">{item.title}</p>
          <p className="mt-1 text-sm leading-6 text-slate-600">{item.detail}</p>
        </div>
      ))}
    </div>
  );
}

function WorkspaceActionButton({
  children,
  onClick,
  disabled = false,
  className = "",
}: {
  children: ReactNode;
  onClick: () => void;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={[
        "inline-flex items-center rounded-md border border-slate-200 bg-white px-4 py-2.5 text-sm font-medium text-slate-700 shadow-[inset_0_1px_0_rgba(255,255,255,0.55)] transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50",
        className,
      ].join(" ")}
    >
      {children}
    </button>
  );
}

function StatusPill({
  label,
  tone,
  icon,
}: {
  label: string;
  tone: "default" | "running" | "success" | "danger";
  icon?: string;
}) {
  const toneClass =
    tone === "success"
      ? "border-emerald-200 bg-emerald-50 text-emerald-700"
      : tone === "danger"
        ? "border-rose-200 bg-rose-50 text-rose-700"
        : tone === "running"
          ? "border-slate-300 bg-slate-100 text-slate-700"
          : "border-slate-200 bg-slate-100 text-slate-500";

  return (
    <span
      className={[
        "inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.12em]",
        toneClass,
      ].join(" ")}
    >
      {icon ? <span className="material-symbols-outlined text-[14px]">{icon}</span> : null}
      {label}
    </span>
  );
}

function SelectField({
  label,
  value,
  onChange,
  children,
}: {
  label: string;
  value: string;
  onChange: ChangeEventHandler<HTMLSelectElement>;
  children: ReactNode;
}) {
  return (
    <label>
      <span className="mb-2 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">{label}</span>
      <select
        value={value}
        onChange={onChange}
        className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700 outline-none transition focus:border-slate-400 focus:ring-1 focus:ring-slate-300"
      >
        {children}
      </select>
    </label>
  );
}

function MetricTile({
  label,
  value,
  compact = false,
}: {
  label: string;
  value: string;
  compact?: boolean;
}) {
  return (
    <div className="rounded-lg border border-slate-200/70 bg-slate-50 p-4">
      <p className="mb-1 text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className={[compact ? "text-lg leading-tight" : "text-2xl", "font-semibold tracking-tight text-slate-900"].join(" ")}>
        {value}
      </p>
    </div>
  );
}

function StatusRow({
  label,
  ready,
  detail,
}: {
  label: string;
  ready: boolean;
  detail: string;
}) {
  return (
    <div className="rounded-xl border border-slate-200/80 bg-slate-50 px-4 py-3">
      <div className="flex items-start gap-3">
        <span
          className={[
            "material-symbols-outlined mt-0.5 text-[18px]",
            ready ? "text-emerald-600" : "text-slate-400",
          ].join(" ")}
        >
          {ready ? "check_circle" : "radio_button_unchecked"}
        </span>
        <div>
          <p className="text-sm font-semibold text-slate-900">{label}</p>
          <p className="mt-1 text-sm leading-6 text-slate-600">{detail}</p>
        </div>
      </div>
    </div>
  );
}

function WorkspaceSupportCardRows({ children }: { children: ReactNode }) {
  return <div className="mt-4 rounded-xl border border-slate-200/80 bg-slate-50 p-3">{children}</div>;
}

function InlineDataRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="grid grid-cols-[116px_minmax(0,1fr)] gap-x-3 gap-y-1 border-b border-slate-200/80 py-2.5 text-sm last:border-b-0 last:pb-0">
      <span className="pt-0.5 text-slate-500">{label}</span>
      <span
        className={[
          "min-w-0 font-medium text-slate-900",
          mono ? "break-all font-mono text-[12px] leading-5" : "break-words leading-5",
        ].join(" ")}
      >
        {value}
      </span>
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <div className="rounded-xl border border-slate-200/80 bg-slate-50 px-4 py-5 text-sm leading-6 text-slate-500">
      {text}
    </div>
  );
}

function humanizeToken(value?: string | null) {
  if (!value) return "Pending";
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatDateTime(value?: string | null) {
  if (!value) return "Pending";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function formatFileSize(bytes: number) {
  if (!bytes) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatRulesFired(value: unknown) {
  const count = countRulesFired(value);
  if (typeof count === "number") {
    return String(count);
  }
  if (!value) return "Pending";
  return String(value);
}

function countRulesFired(value: unknown) {
  if (!value) return null;
  if (Array.isArray(value)) return value.length;
  if (typeof value === "object") {
    try {
      const ruleMap = value as { output?: { triggered_rule_ids?: unknown[] } };
      const outputRules = Array.isArray(ruleMap.output?.triggered_rule_ids)
        ? ruleMap.output?.triggered_rule_ids.length
        : null;
      if (typeof outputRules === "number") {
        return outputRules;
      }
      return Object.keys(value).length;
    } catch {
      return null;
    }
  }

  const numericValue = Number(value);
  return Number.isFinite(numericValue) ? numericValue : null;
}

function buildWorkspaceActionState({
  hasSourceItems,
  hasPendingDraft,
  hasGovernedRun,
  receiptAvailable,
  reviewConfirmed,
  role,
  mode,
  instruction,
  workflowOrigin,
  runErrorPresent,
  running,
}: {
  hasSourceItems: boolean;
  hasPendingDraft: boolean;
  hasGovernedRun: boolean;
  receiptAvailable: boolean;
  reviewConfirmed: boolean;
  role: string;
  mode: WorkspaceMode;
  instruction: string;
  workflowOrigin: WorkspaceWorkflowOrigin;
  runErrorPresent: boolean;
  running: boolean;
}): WorkspaceActionState {
  const hasReviewableReceipt = hasGovernedRun && receiptAvailable;
  const canConfirmReview = hasReviewableReceipt;
  const canContinueToReview = canConfirmReview && !reviewConfirmed;
  const canCopyOrExport = canConfirmReview && reviewConfirmed;
  const hasSessionState =
    hasSourceItems ||
    hasPendingDraft ||
    hasGovernedRun ||
    receiptAvailable ||
    reviewConfirmed ||
    runErrorPresent ||
    role !== DEFAULT_ROLE ||
    mode !== DEFAULT_MODE ||
    workflowOrigin !== DEFAULT_WORKFLOW_ORIGIN ||
    normalizeComparisonValue(instruction) !== normalizeComparisonValue(DEFAULT_INSTRUCTION);

  const setupRunHint =
    !hasSourceItems && !hasPendingDraft
      ? "Add source material to enable the first governed run."
      : !hasGovernedRun
        ? "Run through ANCHOR when the source bundle and workflow controls above look correct."
        : hasReviewableReceipt
          ? "Update the bundle or workflow controls and rerun any time the governed output needs to stay current."
          : "The latest governed run is complete. Receipt linkage is still pending.";

  if (!hasGovernedRun) {
    return {
      canResetSession: hasSessionState && !running,
      canOpenReceipt: false,
      canContinueToReview: false,
      canConfirmReview: false,
      canCopyOrExport,
      hasGovernedRun,
      hasReviewableReceipt,
      receiptHeading: "Awaiting receipt",
      receiptRequestIdValue: "Not available yet",
      receiptSupportText: "A real receipt appears after the first governed run completes.",
      reviewStatusLabel: "Awaiting governed run",
      reviewPrompt: "This confirmation stays inactive until a governed run creates a reviewable receipt.",
      reviewFooter: "Add source material, confirm workflow controls, and run through ANCHOR first.",
      reviewActionLabel: null,
      setupRunHint,
    };
  }

  if (!hasReviewableReceipt) {
    return {
      canResetSession: hasSessionState && !running,
      canOpenReceipt: false,
      canContinueToReview: false,
      canConfirmReview: false,
      canCopyOrExport,
      hasGovernedRun,
      hasReviewableReceipt,
      receiptHeading: "Receipt pending",
      receiptRequestIdValue: "Pending",
      receiptSupportText: "The governed run completed, but the linked receipt is still pending.",
      reviewStatusLabel: "Awaiting receipt",
      reviewPrompt: "Governed output is present. Human review confirmation activates once the linked receipt is available.",
      reviewFooter: "Operational actions stay blocked until receipt linkage is available for this run.",
      reviewActionLabel: "Receipt pending before review",
      setupRunHint,
    };
  }

  return {
    canResetSession: hasSessionState && !running,
    canOpenReceipt: true,
    canContinueToReview,
    canConfirmReview,
    canCopyOrExport,
    hasGovernedRun,
    hasReviewableReceipt,
    receiptHeading: "Receipt ready",
    receiptRequestIdValue: "Pending",
    receiptSupportText: "The linked receipt is available for this governed run.",
    reviewStatusLabel: reviewConfirmed ? "Review confirmed" : "Review pending",
    reviewPrompt: reviewConfirmed
      ? "Human review has been confirmed for this governed run."
      : "Check the governed output, then confirm human review before operational use.",
    reviewFooter: reviewConfirmed
      ? "Human review is complete. Use the governed result surface for controlled release actions or start a new governed session."
      : "Human review remains visible before copying forward, exporting, or operational use.",
    reviewActionLabel: reviewConfirmed ? "Review confirmed" : null,
    setupRunHint,
  };
}

function normalizeComparisonValue(value: string) {
  return value.replace(/\r\n/g, "\n").trim();
}

function formatCharacterCount(length: number) {
  return new Intl.NumberFormat("en-GB").format(length);
}

function compareComparableText(sourceText: string, outputText: string) {
  const normalizedSource = sourceText.replace(/\s+/g, " ").trim();
  const normalizedOutput = outputText.replace(/\s+/g, " ").trim();

  if (!normalizedSource || !normalizedOutput) {
    return null;
  }

  return normalizedSource !== normalizedOutput;
}

function buildRunSummary({
  reviewState,
  mode,
  role,
  sourceCount,
  textReadyCount,
  receiptAvailable,
  reviewConfirmed,
  createdAt,
}: {
  reviewState: WorkspaceReviewState;
  mode: string;
  role: string;
  sourceCount: number;
  textReadyCount: number;
  receiptAvailable: boolean;
  reviewConfirmed: boolean;
  createdAt: string;
}): RunSummary {
  const headline =
    reviewState === "ready_for_use"
      ? "Governed run is ready for controlled use"
      : reviewState === "review_confirmed"
        ? "Governed run is reviewed and awaiting release"
        : reviewState === "awaiting_review"
          ? "Governed run is complete and awaiting human review"
          : "Governed run completed";

  const detail = [
    `Built in ${mode} mode for ${role}.`,
    `${sourceCount} source item${sourceCount === 1 ? "" : "s"} were in scope, with ${textReadyCount} text-ready for the current run.`,
    createdAt !== "Pending" ? `Latest receipt timestamp: ${createdAt}.` : "Receipt timing is still limited in Workspace v1.",
  ].join(" ");

  const nextAction =
    reviewState === "ready_for_use"
      ? "Release the governed output or start a new governed session."
      : reviewState === "review_confirmed"
        ? "Choose a release action for this reviewed output."
        : receiptAvailable
          ? "Confirm human review before operational use."
          : "Await receipt linkage, then continue into human review.";

  return {
    headline,
    detail,
    nextAction,
    metrics: [
      {
        label: "Workflow mode",
        value: mode,
        detail: role,
      },
      {
        label: "Source bundle",
        value: `${sourceCount} item${sourceCount === 1 ? "" : "s"}`,
        detail: `${textReadyCount} text-ready for the current run`,
      },
      {
        label: "Receipt status",
        value: receiptAvailable ? "Linked" : "Pending",
        detail: reviewConfirmed ? "Human review confirmed" : "Human review still required",
      },
    ],
  };
}

function buildGovernanceOutcomeItems({
  governanceSummary,
  receiptAvailable,
  reviewConfirmed,
}: {
  governanceSummary: {
    decision: string;
    riskGrade: string;
    piiDetected: string;
    piiAction: string;
    governanceScore: string;
    policyVersion: string;
    neutralityVersion: string;
    noContentStored: string;
    rulesFired: string;
    policyHash: string;
  };
  receiptAvailable: boolean;
  reviewConfirmed: boolean;
}): PostRunMetricItem[] {
  return [
    { label: "Decision", value: governanceSummary.decision },
    { label: "Risk grade", value: governanceSummary.riskGrade },
    { label: "PII detected", value: governanceSummary.piiDetected },
    { label: "PII action", value: governanceSummary.piiAction },
    { label: "Governance score", value: governanceSummary.governanceScore },
    { label: "Policy version", value: governanceSummary.policyVersion },
    { label: "Neutrality version", value: governanceSummary.neutralityVersion },
    { label: "Receipt", value: receiptAvailable ? "Available" : "Pending" },
    { label: "Review state", value: reviewConfirmed ? "Confirmed" : "Pending" },
  ];
}

function buildInterventionItems({
  decision,
  resultAvailable,
  receiptAvailable,
  reviewConfirmed,
  piiDetected,
  piiAction,
  rulesFiredCount,
  noContentStored,
}: {
  decision?: string;
  resultAvailable: boolean;
  receiptAvailable: boolean;
  reviewConfirmed: boolean;
  piiDetected?: boolean;
  piiAction?: string;
  rulesFiredCount: number | null;
  noContentStored: boolean;
}): PostRunListItem[] {
  const items: PostRunListItem[] = [];
  const hasRecordedPiiAction = !!piiAction && piiAction.toLowerCase() !== "pending";
  const hasRecordedDecision = !!decision && decision.toLowerCase() !== "pending";

  if (resultAvailable) {
    items.push({
      title: "Governed output available",
      detail: "A governed output is present and ready for review inside this workspace session.",
    });
  }

  if (piiDetected === true) {
    items.push({
      title: "PII warning present",
      detail: "The current run recorded a privacy-sensitive warning in the live governance outcome.",
    });
  }

  if (hasRecordedPiiAction) {
    items.push({
      title: "Governance action recorded",
      detail: `The current run recorded a PII action of ${humanizeToken(piiAction)}.`,
    });
  } else if (hasRecordedDecision) {
    items.push({
      title: "Decision recorded",
      detail: `The current run recorded a decision of ${humanizeToken(decision)}.`,
    });
  }

  if (receiptAvailable) {
    items.push({
      title: "Receipt linked",
      detail: "Request-level receipt review is available for this governed run.",
    });
  }

  if ((rulesFiredCount ?? 0) > 0) {
    items.push({
      title: "Governance rules fired",
      detail: `${rulesFiredCount} governance rule${rulesFiredCount === 1 ? "" : "s"} were recorded for this run.`,
    });
  }

  if (!reviewConfirmed) {
    items.push({
      title: "Manual review still required",
      detail: "Human review remains required before the governed result should be copied forward or used operationally.",
    });
  }

  if (noContentStored) {
    items.push({
      title: "Metadata-only accountability retained",
      detail: "The current outcome still reflects ANCHOR's no-content-stored posture unless the live receipt says otherwise.",
    });
  }

  return items.slice(0, 5);
}

function buildReviewGuidanceItems({
  piiDetected,
  receiptAvailable,
  reviewConfirmed,
  pendingSourceCount,
  sensitiveHintPresent,
}: {
  piiDetected?: boolean;
  receiptAvailable: boolean;
  reviewConfirmed: boolean;
  pendingSourceCount: number;
  sensitiveHintPresent: boolean;
}): PostRunListItem[] {
  const items: PostRunListItem[] = [
    {
      title: "Verify factual details before use",
      detail: "Confirm that names, dates, identifiers, and operational facts still match the intended source material.",
    },
    {
      title: "Confirm audience appropriateness",
      detail: "Check that the output tone, structure, and level of detail fit the intended operational audience.",
    },
    {
      title: "Confirm operational intent",
      detail: "Make sure the governed result still matches the action you intended before copying it forward.",
    },
  ];

  if (piiDetected || sensitiveHintPresent) {
    items.push({
      title: "Check sensitive-content handling",
      detail: "Confirm that privacy-sensitive details are handled appropriately before any operational use.",
    });
  }

  if (pendingSourceCount > 0) {
    items.push({
      title: "Review bundle completeness",
      detail: "Some sources remain pending or manual-review only, so confirm the output is sufficient for the intended task.",
    });
  }

  if (!receiptAvailable) {
    items.push({
      title: "Wait for receipt linkage",
      detail: "A reviewable receipt is still pending, so hold operational release until request-level accountability is available.",
    });
  } else if (!reviewConfirmed) {
    items.push({
      title: "Confirm human review",
      detail: "Use the review confirmation gate once the governed output has been checked and is safe to release forward.",
    });
  }

  return items.slice(0, 4);
}

function buildChangeOverviewItems({
  sourceCount,
  textReadyCount,
  sourceLength,
  outputLength,
  outputChanged,
  warningsPresent,
}: {
  sourceCount: number;
  textReadyCount: number;
  sourceLength: number;
  outputLength: number;
  outputChanged: boolean | null;
  warningsPresent: boolean;
}): PostRunMetricItem[] {
  return [
    {
      label: "Source items",
      value: `${sourceCount}`,
      detail: `${textReadyCount} text-ready for comparison`,
    },
    {
      label: "Source text",
      value: `${formatCharacterCount(sourceLength)} chars`,
      detail: sourceLength > 0 ? "Comparable text length from the current source bundle" : "No comparable source text available",
    },
    {
      label: "Governed output",
      value: `${formatCharacterCount(outputLength)} chars`,
      detail: "Length of the current governed result",
    },
    {
      label: "Output changed",
      value:
        outputChanged === null
          ? "Limited"
          : outputChanged
            ? "Modified"
            : "No material text change",
      detail:
        outputChanged === null
          ? "Workspace v1 only has a limited text-level comparison today."
          : "Compared only against text-ready source content in the current bundle.",
    },
    {
      label: "Warnings present",
      value: warningsPresent ? "Yes" : "No live warning recorded",
      detail: warningsPresent ? "PII or governance warning fields were recorded for this run." : "No live warning field is currently recorded.",
    },
  ];
}
