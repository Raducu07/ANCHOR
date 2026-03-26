type StatusBadgeProps = {
  value: string;
};

export function StatusBadge({ value }: StatusBadgeProps) {
  const raw = String(value || "unknown");
  const normalized = raw.toLowerCase().trim();

  const tone = getTone(normalized);

  return (
    <span
      className={[
        "inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium capitalize tracking-wide",
        tone,
      ].join(" ")}
    >
      {formatLabel(raw)}
    </span>
  );
}

function formatLabel(value: string) {
  return value.replace(/[_-]+/g, " ");
}

function getTone(value: string) {
  if (
    [
      "green",
      "allowed",
      "low",
      "live",
      "proven",
      "established",
      "ready",
      "yes",
      "healthy",
      "ok",
    ].includes(value)
  ) {
    return "border border-emerald-200 bg-emerald-50 text-emerald-700";
  }

  if (
    [
      "amber",
      "bounded",
      "next",
      "pending",
      "medium",
      "med",
      "warning",
      "clinical_note",
      "client_comm",
      "internal_summary",
      "admin",
      "later",
    ].includes(value)
  ) {
    return "border border-amber-200 bg-amber-50 text-amber-700";
  }

  if (
    [
      "red",
      "blocked",
      "high",
      "error",
      "replaced",
      "modified",
      "declined",
      "no",
    ].includes(value)
  ) {
    return "border border-rose-200 bg-rose-50 text-rose-700";
  }

  return "border border-slate-200 bg-slate-100 text-slate-700";
}