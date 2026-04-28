import type { ReceiptPayload } from "@/lib/types";

export function safeText(value: unknown, fallback = "—"): string {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

export function humanizeToken(value: unknown): string {
  const text = safeText(value, "—");
  return text.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

const MODE_LABELS: Record<string, string> = {
  client_comm: "Client communication",
  client_communication: "Client communication",
  clinical_note: "Clinical note drafting",
  clinical_note_baseline: "Clinical note drafting",
  internal_summary: "Internal summary",
};

export function prettyMode(value: unknown): string {
  const raw = safeText(value, "—");
  const normalized = raw.toLowerCase().trim();
  return MODE_LABELS[normalized] ?? humanizeToken(raw);
}

export function formatDecision(value: unknown): string {
  return humanizeToken(value);
}

export function formatPiiDetected(value: unknown): string {
  if (value === true) return "Yes";
  if (value === false) return "No";
  return "—";
}

export function formatScore(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  return value.toFixed(1);
}

export function formatTimestamp(value: unknown): string {
  if (!value) return "—";
  const d = new Date(String(value));
  if (Number.isNaN(d.getTime())) return String(value);
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(d);
}

export function summarizeRules(rules: unknown): string {
  if (!rules) return "No rule detail recorded";
  if (Array.isArray(rules)) {
    return `${rules.length} ${rules.length === 1 ? "rule" : "rules"}`;
  }
  if (typeof rules === "object") {
    let total = 0;
    for (const value of Object.values(rules as Record<string, unknown>)) {
      if (Array.isArray(value)) {
        total += value.length;
      } else if (value && typeof value === "object") {
        for (const inner of Object.values(value as Record<string, unknown>)) {
          if (Array.isArray(inner)) total += inner.length;
        }
      }
    }
    if (total > 0) return `${total} ${total === 1 ? "rule" : "rules"}`;
    return "Structured rule output present";
  }
  return safeText(rules);
}

export function extractPiiSignal(receipt: ReceiptPayload | null | undefined): string {
  if (!receipt) return "No additional signal detail";
  if (Array.isArray(receipt.pii_types) && receipt.pii_types.length) {
    return receipt.pii_types.join(", ");
  }
  if (receipt.pii_detected === true) return "PII detected; see recorded action";
  return "No additional signal detail";
}

export function extractWorkflowOrigin(receipt: ReceiptPayload | null | undefined): string {
  if (!receipt) return "Direct ANCHOR workflow";
  return safeText(
    receipt["workflow_origin"] || receipt["origin"] || receipt["source"],
    "Direct ANCHOR workflow"
  );
}

export function extractInputKind(receipt: ReceiptPayload | null | undefined): string {
  if (!receipt) return "Source material";
  return safeText(receipt["input_kind"] || receipt["kind"], "Source material");
}

export function extractHumanReview(receipt: ReceiptPayload | null | undefined): string {
  if (!receipt) return "Not recorded in receipt";
  const confirmed = receipt["human_review_confirmed"];
  if (typeof confirmed === "boolean") {
    return confirmed ? "Confirmed" : "Not confirmed";
  }
  const reviewState = receipt["review_state"];
  if (typeof reviewState === "string") return humanizeToken(reviewState);
  return "Not recorded in receipt";
}

export type DecisionKind = "allowed" | "modified" | "replaced" | "other";

export function decisionKind(decision: unknown): DecisionKind {
  const n = String(decision ?? "").toLowerCase();
  if (n === "allowed" || n === "verified" || n === "pass") return "allowed";
  if (n === "modified" || n === "warning" || n === "warn") return "modified";
  if (n === "blocked" || n === "replaced" || n === "flagged") return "replaced";
  return "other";
}

export function decisionToneClass(decision: unknown): string {
  switch (decisionKind(decision)) {
    case "allowed":
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
    case "modified":
      return "border-amber-200 bg-amber-50 text-amber-700";
    case "replaced":
      return "border-rose-200 bg-rose-50 text-rose-700";
    default:
      return "border-slate-200 bg-slate-100 text-slate-700";
  }
}

export function decisionDotClass(decision: unknown): string {
  switch (decisionKind(decision)) {
    case "allowed":
      return "bg-emerald-500";
    case "modified":
      return "bg-amber-500";
    case "replaced":
      return "bg-rose-500";
    default:
      return "bg-slate-500";
  }
}

export function decisionLabel(decision: unknown): string {
  switch (decisionKind(decision)) {
    case "allowed":
      return "Allowed";
    case "modified":
      return "Modified";
    case "replaced":
      return "Replaced";
    default:
      return formatDecision(decision);
  }
}

export function getCreatedAt(receipt: ReceiptPayload | null | undefined): unknown {
  if (!receipt) return undefined;
  return receipt["created_at_utc"] || receipt["created_at"];
}

export function getPolicyHash(receipt: ReceiptPayload | null | undefined): string {
  if (!receipt) return "";
  const value = receipt.policy_hash || receipt.policy_sha256;
  return value ? String(value) : "";
}

export function getNoContentStored(receipt: ReceiptPayload | null | undefined): "Yes" | "No" {
  if (!receipt) return "Yes";
  return receipt.no_content_stored === false ? "No" : "Yes";
}

export function buildInterpretation(receipt: ReceiptPayload | null | undefined): string {
  if (!receipt) {
    return "Select a receipt to review its request-level accountability and metadata-backed governance interpretation.";
  }
  const decision = formatDecision(receipt.decision);
  const mode = prettyMode(receipt.mode);
  const risk = safeText(receipt.risk_grade, "ungraded");
  const piiDetected = receipt.pii_detected === true;
  const piiAction = safeText(receipt.pii_action, "none recorded");
  const policyVersion = safeText(receipt.policy_version, "—");

  if (piiDetected) {
    return `This receipt records a ${mode} workflow with a ${decision.toLowerCase()} governance outcome. PII was detected and the recorded action is ${piiAction}. Review should confirm that the handling remains appropriate before operational use. Policy trace is linked to version ${policyVersion}.`;
  }

  return `This receipt records a ${mode} workflow with a ${decision.toLowerCase()} governance outcome and a ${risk} risk grade. No PII signal is recorded in the receipt metadata. The receipt provides request-level traceability to support review, auditability, and operational confidence without relying on stored raw working content.`;
}
