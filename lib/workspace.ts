export type WorkspaceWorkflowOrigin = "direct" | "ambient" | "external_ai" | "connected_vendor";

export type WorkspaceSourceKind =
  | "pasted_text"
  | "text_file"
  | "pdf"
  | "image"
  | "document"
  | "unknown";

export type WorkspaceExtractionStatus = "ready" | "pending" | "manual_review" | "error";

export type WorkspaceReviewState =
  | "drafted"
  | "governed"
  | "awaiting_review"
  | "review_confirmed"
  | "ready_for_use";

export type WorkspaceSourceItem = {
  sourceId: string;
  sourceKind: WorkspaceSourceKind;
  filename: string;
  mimeType: string;
  sizeBytes: number;
  origin: WorkspaceWorkflowOrigin;
  previewText: string;
  extractedText: string;
  extractionStatus: WorkspaceExtractionStatus;
  addedAt: string;
  objectUrl?: string;
};

export const WORKSPACE_ROLE_OPTIONS = [
  "Practice Manager",
  "Clinician",
  "Receptionist / Front desk",
  "Practice / Admin staff",
] as const;

export const WORKSPACE_MODE_OPTIONS = [
  "Internal governance review",
  "Internal summary",
  "Client communication",
  "Clinical note drafting",
] as const;

export type WorkspaceMode = (typeof WORKSPACE_MODE_OPTIONS)[number];

export const WORKSPACE_ORIGIN_OPTIONS: Array<{
  value: WorkspaceWorkflowOrigin;
  label: string;
  available: boolean;
}> = [
  { value: "direct", label: "Direct", available: true },
  { value: "ambient", label: "Ambient", available: false },
  { value: "external_ai", label: "External AI", available: false },
  { value: "connected_vendor", label: "Connected vendor", available: false },
] as const;

export const WORKSPACE_REVIEW_STEPS: Array<{
  key: WorkspaceReviewState;
  label: string;
}> = [
  { key: "drafted", label: "Drafted" },
  { key: "governed", label: "Governed" },
  { key: "awaiting_review", label: "Awaiting review" },
  { key: "review_confirmed", label: "Review confirmed" },
  { key: "ready_for_use", label: "Ready for use" },
] as const;

export const WORKSPACE_REVIEW_BOUNDARIES = [
  "Standard privacy",
  "Receipt-backed traceability",
  "Metadata-only accountability",
] as const;

export const WORKSPACE_INSTRUCTION_PRESETS: Record<WorkspaceMode, string> = {
  "Internal governance review":
    "Refine for internal staff handover, preserve meaning, and keep the summary concise, clear, and reviewable.",
  "Internal summary":
    "Summarise clearly for internal staff handover, preserve meaning, and keep the output concise and reviewable.",
  "Client communication":
    "Improve clarity and structure, preserve meaning, keep a professional tone, and make the message suitable for client communication.",
  "Clinical note drafting":
    "Refine for clinical note drafting, preserve meaning, and keep the output concise, factual, documentation-ready, and reviewable.",
};

const MODE_TO_API: Record<WorkspaceMode, string> = {
  "Client communication": "client_comm",
  "Clinical note drafting": "clinical_note",
  "Internal governance review": "internal_summary",
  "Internal summary": "internal_summary",
};

const TEXT_EXTENSIONS = new Set(["txt", "md", "csv", "json", "xml", "html", "htm", "log"]);

function createSourceId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  return `source-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function normalizeText(input: string) {
  return input.replace(/\r\n/g, "\n").trim();
}

function previewText(input: string, maxLength = 220) {
  const normalized = normalizeText(input).replace(/\s+/g, " ");
  if (normalized.length <= maxLength) return normalized;
  return `${normalized.slice(0, maxLength).trimEnd()}…`;
}

function fileExtension(filename: string) {
  const parts = filename.toLowerCase().split(".");
  return parts.length > 1 ? parts.pop() ?? "" : "";
}

function classifySourceKind(file: File): WorkspaceSourceKind {
  const extension = fileExtension(file.name);

  if (file.type.startsWith("image/")) return "image";
  if (file.type === "application/pdf" || extension === "pdf") return "pdf";
  if (file.type.startsWith("text/") || TEXT_EXTENSIONS.has(extension)) return "text_file";
  if (
    extension === "doc" ||
    extension === "docx" ||
    extension === "rtf" ||
    extension === "odt" ||
    extension === "ppt" ||
    extension === "pptx"
  ) {
    return "document";
  }
  return "unknown";
}

function canReadText(file: File, kind: WorkspaceSourceKind) {
  if (kind !== "text_file") return false;
  return typeof file.text === "function";
}

export function mapWorkspaceModeToApi(modeLabel: WorkspaceMode) {
  return MODE_TO_API[modeLabel] ?? "internal_summary";
}

export function mapWorkflowOriginToApi(origin: WorkspaceWorkflowOrigin) {
  if (origin === "direct") return "direct_anchor_workspace";
  return origin;
}

export function formatSourceKindLabel(kind: WorkspaceSourceKind) {
  if (kind === "pasted_text") return "Pasted text";
  if (kind === "text_file") return "Text file";
  if (kind === "pdf") return "PDF";
  if (kind === "image") return "Image";
  if (kind === "document") return "Document";
  return "Unknown";
}

export function formatOriginLabel(origin: WorkspaceWorkflowOrigin) {
  if (origin === "direct") return "Direct";
  if (origin === "external_ai") return "External AI";
  if (origin === "connected_vendor") return "Connected vendor";
  return "Ambient";
}

export function formatExtractionStatusLabel(status: WorkspaceExtractionStatus) {
  if (status === "ready") return "Text ready";
  if (status === "pending") return "Extraction pending";
  if (status === "manual_review") return "Manual review needed";
  return "Extraction error";
}

export function createPastedTextSource(
  text: string,
  origin: WorkspaceWorkflowOrigin,
  index: number,
  sourceId = createSourceId()
): WorkspaceSourceItem {
  const normalized = normalizeText(text);
  const sizeBytes = new Blob([normalized]).size;

  return {
    sourceId,
    sourceKind: "pasted_text",
    filename: `Pasted source ${index}`,
    mimeType: "text/plain",
    sizeBytes,
    origin,
    previewText: previewText(normalized),
    extractedText: normalized,
    extractionStatus: "ready",
    addedAt: new Date().toISOString(),
  };
}

export async function createWorkspaceSourceFromFile(
  file: File,
  origin: WorkspaceWorkflowOrigin,
  sourceId = createSourceId()
): Promise<WorkspaceSourceItem> {
  const sourceKind = classifySourceKind(file);

  try {
    if (canReadText(file, sourceKind)) {
      const extracted = normalizeText(await file.text());
      return {
        sourceId,
        sourceKind,
        filename: file.name,
        mimeType: file.type || "text/plain",
        sizeBytes: file.size,
        origin,
        previewText: previewText(extracted || file.name),
        extractedText: extracted,
        extractionStatus: "ready",
        addedAt: new Date().toISOString(),
      };
    }

    if (sourceKind === "image") {
      return {
        sourceId,
        sourceKind,
        filename: file.name,
        mimeType: file.type || "image/*",
        sizeBytes: file.size,
        origin,
        previewText: "Image attached. OCR and extracted text are not wired into Workspace v1 yet.",
        extractedText: "",
        extractionStatus: "pending",
        addedAt: new Date().toISOString(),
        objectUrl: URL.createObjectURL(file),
      };
    }

    if (sourceKind === "pdf") {
      return {
        sourceId,
        sourceKind,
        filename: file.name,
        mimeType: file.type || "application/pdf",
        sizeBytes: file.size,
        origin,
        previewText: "PDF attached. Extracted text is not yet available in Workspace v1.",
        extractedText: "",
        extractionStatus: "pending",
        addedAt: new Date().toISOString(),
      };
    }

    return {
      sourceId,
      sourceKind,
      filename: file.name,
      mimeType: file.type || "application/octet-stream",
      sizeBytes: file.size,
      origin,
      previewText: "This file is attached, but extracted text is not available yet. Add pasted text or a text-readable file to include it in the current governed run.",
      extractedText: "",
      extractionStatus: "manual_review",
      addedAt: new Date().toISOString(),
    };
  } catch {
    return {
      sourceId,
      sourceKind,
      filename: file.name,
      mimeType: file.type || "application/octet-stream",
      sizeBytes: file.size,
      origin,
      previewText: "Source extraction could not be completed in this browser session.",
      extractedText: "",
      extractionStatus: "error",
      addedAt: new Date().toISOString(),
    };
  }
}

export function buildAssistSourceText(items: WorkspaceSourceItem[]) {
  const readyItems = items.filter(
    (item) => item.extractionStatus === "ready" && normalizeText(item.extractedText).length > 0
  );

  if (!readyItems.length) return "";

  return readyItems.map((item) => normalizeText(item.extractedText)).join("\n\n");
}

const COMMON_OUTPUT_CONTRACT = [
  "Use only facts present in the supplied source material.",
  "Do not mention source manifest labels, source numbers, file names, or phrases like SOURCE 1, Pasted source, or Pasted text.",
  "Do not invent facts, recommendations, diagnoses, treatments, or follow-up steps that are not supported by the source.",
  "Return only the final governed output text.",
  "Omit empty sections and avoid structurally empty templates.",
].join(" ");

const MODE_OUTPUT_CONTRACT: Record<WorkspaceMode, string> = {
  "Internal governance review":
    "Produce a concise governed internal review summary that preserves meaning, stays structured and reviewable, and avoids source scaffolding or empty shells.",
  "Internal summary":
    "Produce a short internal handover summary that is operationally clear, concise, and free from scaffolding labels or empty structure.",
  "Client communication":
    "Produce a polished client-facing draft with a professional tone, clear wording, and no internal manifest artifacts.",
  "Clinical note drafting":
    "Produce a concise clinical note using only provided facts. Prefer short declarative documentation phrasing over request-style wording or rigid templates. For sparse source material, return one to three factual sentences instead of an empty shell. Do not begin with instruction phrasing such as please write or clinical note regarding. Do not output empty SOAP-style sections, and do not imply assessment or plan content unless the source explicitly supports it.",
};

const SCAFFOLDING_LINE_PATTERNS = [
  /^\s*[-*#>]*\s*\**\s*source\s*\d+\s*:.*$/i,
  /^\s*[-*#>]*\s*\**\s*pasted source\s*\d+\s*(?:\(.+\))?\s*\**\s*$/i,
  /^\s*[-*#>]*\s*\**\s*\(?(?:pasted text|text file|pdf|image|document)\)?\s*\**\s*$/i,
];

const EMPTY_SECTION_VALUE_PATTERNS = [
  /^\s*[-–—]\s*$/,
  /^\s*(?:n\/a|na|none|none provided|not provided|not stated|not available|pending)\s*$/i,
];

const CLINICAL_SECTION_PATTERNS = [
  /^\s*(?:subjective|objective|assessment|plan|history|findings|review note)\s*:?\s*$/i,
  /^\s*[SOAP]\s*:?\s*$/i,
];

const GENERIC_SECTION_PATTERNS = [/^\s*[A-Z][A-Za-z /-]{1,40}:\s*$/];

const CLINICAL_NOTE_PREFIX_PATTERNS = [
  /^(?:please\s+)?(?:write|draft|create|prepare|generate|provide)\s+(?:a\s+)?(?:brief\s+|concise\s+|short\s+)?(?:(?:clinical|medical|progress|procedure|surgical|post[- ]?op(?:erative)?)\s+)?note\b[:\s-]*/i,
  /^(?:please\s+)?(?:(?:clinical|medical|progress|procedure|surgical|post[- ]?op(?:erative)?)\s+)?note\b[:\s-]*/i,
];

const CLINICAL_NOTE_CONTEXT_PREFIX_PATTERNS = [/^(?:regarding|for|about|on)\b[:\s-]*/i];

export function buildWorkspaceRunInstruction(mode: WorkspaceMode, instruction: string) {
  const userInstruction = normalizeText(instruction);
  return [userInstruction, COMMON_OUTPUT_CONTRACT, MODE_OUTPUT_CONTRACT[mode]].filter(Boolean).join("\n\n");
}

export function normalizeWorkspaceOutput(mode: WorkspaceMode, output: string) {
  const cleaned = stripSourceScaffolding(output);
  const withoutEmptySections = stripEmptySections(cleaned, mode === "Clinical note drafting");
  const modeNormalized =
    mode === "Clinical note drafting" ? normalizeClinicalNoteOutput(withoutEmptySections) : withoutEmptySections;
  return collapseWhitespace(modeNormalized);
}

function detectSensitiveHint(items: WorkspaceSourceItem[]) {
  const visibleText = items
    .map((item) => item.extractedText)
    .filter(Boolean)
    .join("\n");

  if (!visibleText) return null;

  const hasEmail = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(visibleText);
  const hasPhone = /(?:\+?\d[\d\s().-]{7,}\d)/.test(visibleText);
  const hasDenseIdentifier = /\b\d{6,}\b/.test(visibleText);

  if (hasEmail || hasPhone || hasDenseIdentifier) {
    return "Potential sensitive details detected in visible text sources. Confirm privacy-aware handling before operational use.";
  }

  return null;
}

export function computeWorkspaceSourceInsights(items: WorkspaceSourceItem[]) {
  const readyCount = items.filter((item) => item.extractionStatus === "ready").length;
  const pendingCount = items.filter((item) => item.extractionStatus === "pending").length;
  const manualCount = items.filter((item) => item.extractionStatus === "manual_review").length;
  const errorCount = items.filter((item) => item.extractionStatus === "error").length;
  const totalBytes = items.reduce((sum, item) => sum + item.sizeBytes, 0);
  const typeLabels = Array.from(new Set(items.map((item) => formatSourceKindLabel(item.sourceKind))));
  const hasReadyText = readyCount > 0;

  let completenessHint = "Add pasted text or upload files to assemble a governed source bundle.";
  if (items.length > 0 && !hasReadyText) {
    completenessHint =
      "Files are present, but extracted text is not yet available for the current run. Add pasted text or a text-readable file to use Workspace v1 today.";
  } else if (pendingCount > 0 || manualCount > 0) {
    completenessHint =
      "Some sources still need extraction or manual review. The current governed run will use only text-ready source items.";
  } else if (items.length === 1) {
    completenessHint =
      "Single-source bundle. Add another source item if the workflow needs corroboration or broader context.";
  } else if (items.length > 1) {
    completenessHint = "Bundle is structurally ready for governed review with multiple source items in scope.";
  }

  return {
    itemCount: items.length,
    readyCount,
    pendingCount,
    manualCount,
    errorCount,
    totalBytes,
    typeLabels,
    hasReadyText,
    completenessHint,
    sensitiveHint: detectSensitiveHint(items),
  };
}

function stripSourceScaffolding(output: string) {
  return output
    .split(/\r?\n/)
    .filter((line) => !SCAFFOLDING_LINE_PATTERNS.some((pattern) => pattern.test(line)))
    .join("\n");
}

function stripEmptySections(output: string, clinicalMode: boolean) {
  const lines = output.split(/\r?\n/);
  const nextLines: string[] = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index] ?? "";
    const isClinicalSection = clinicalMode && CLINICAL_SECTION_PATTERNS.some((pattern) => pattern.test(line));
    const isGenericSection = GENERIC_SECTION_PATTERNS.some((pattern) => pattern.test(line));

    if (!isClinicalSection && !isGenericSection) {
      nextLines.push(line);
      index += 1;
      continue;
    }

    const block: string[] = [];
    let cursor = index + 1;

    while (
      cursor < lines.length &&
      !CLINICAL_SECTION_PATTERNS.some((pattern) => pattern.test(lines[cursor] ?? "")) &&
      !GENERIC_SECTION_PATTERNS.some((pattern) => pattern.test(lines[cursor] ?? ""))
    ) {
      block.push(lines[cursor] ?? "");
      cursor += 1;
    }

    const meaningfulLines = block.filter((entry) => {
      const trimmed = entry.trim();
      if (!trimmed) return false;
      return !EMPTY_SECTION_VALUE_PATTERNS.some((pattern) => pattern.test(trimmed));
    });

    if (meaningfulLines.length > 0) {
      nextLines.push(line);
      nextLines.push(...block);
    }

    index = cursor;
  }

  return nextLines.join("\n");
}

function normalizeClinicalNoteOutput(output: string) {
  const lines = output.split(/\r?\n/);
  const firstContentIndex = lines.findIndex((line) => line.trim().length > 0);

  if (firstContentIndex === -1) {
    return output;
  }

  const nextLines = [...lines];
  const cleanedLeadLine = stripClinicalNoteLead(nextLines[firstContentIndex] ?? "");

  if (cleanedLeadLine) {
    nextLines[firstContentIndex] = cleanedLeadLine;
  }

  return finalizeSparseClinicalNote(nextLines.join("\n"));
}

function stripClinicalNoteLead(line: string) {
  let next = line.trim().replace(/^[`"'([{]+/, "").replace(/[`"')\]}]+$/, "");
  let previous = "";

  while (next && next !== previous) {
    previous = next;

    CLINICAL_NOTE_PREFIX_PATTERNS.forEach((pattern) => {
      next = next.replace(pattern, "");
    });

    CLINICAL_NOTE_CONTEXT_PREFIX_PATTERNS.forEach((pattern) => {
      next = next.replace(pattern, "");
    });

    next = next.replace(/^[\s:;,-]+/, "").trim();
  }

  if (!next) {
    return "";
  }

  if (/^[a-z]/.test(next)) {
    next = `${next.slice(0, 1).toUpperCase()}${next.slice(1)}`;
  }

  return next;
}

function finalizeSparseClinicalNote(output: string) {
  const normalized = collapseWhitespace(output);

  if (!normalized) {
    return normalized;
  }

  if (/\n/.test(normalized)) {
    return normalized;
  }

  if (/[.!?]$/.test(normalized)) {
    return normalized;
  }

  if (!/[A-Za-z0-9)]$/.test(normalized)) {
    return normalized;
  }

  return `${normalized}.`;
}

function collapseWhitespace(output: string) {
  return output
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}
