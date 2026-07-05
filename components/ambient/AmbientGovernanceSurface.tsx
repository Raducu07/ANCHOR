"use client";

// Fable roadmap-completion experiment - Slice F6 (M6.13 Ambient
// Governance shell, internal preview, extreme caution surface).
//
// Governance shell ONLY:
//   * ANCHOR is the governance layer around ambient/scribe workflows.
//     It is not the scribe, stores no transcripts, no audio, and no
//     note content, and integrates with no vendor.
//   * No transcript upload, no audio upload, no raw clinical text
//     input, no note generation, and no event-creation UI exists here.
//     This surface is metadata list + review gate + posture only.
//   * Backend endpoints return 503 unless the backend ambient flag is
//     enabled; the UI treats that as the normal "ingestion disabled"
//     posture, not an error.
//   * The review gate records a bounded decision category, reviewer,
//     and time - never content.

import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import {
  InternalPreviewBadge,
  InternalPreviewGate,
} from "@/components/experiment/InternalPreviewGate";
import { ApiError } from "@/lib/api";
import {
  AMBIENT_REVIEW_DECISIONS,
  getAmbientSummary,
  listAmbientEvents,
  reviewAmbientEvent,
} from "@/lib/ambientGovernance";
import type {
  AmbientEvent,
  AmbientReviewDecision,
  AmbientReviewStatus,
  AmbientSummaryResponse,
} from "@/lib/ambientGovernance";

const EVENT_TYPE_LABEL: Record<string, string> = {
  consult_recorded: "Consult recorded",
  note_generated: "Note generated",
  note_reviewed_externally: "Note reviewed externally",
  other: "Other",
};

const STATUS_FILTERS: { value: AmbientReviewStatus | ""; label: string }[] = [
  { value: "", label: "All events" },
  { value: "pending_review", label: "Pending review" },
  { value: "reviewed", label: "Reviewed" },
  { value: "discarded", label: "Discarded" },
];

type AmbientAvailability =
  | { kind: "loading" }
  | { kind: "disabled" }
  | { kind: "enabled"; summary: AmbientSummaryResponse }
  | { kind: "error"; message: string };

function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function formatDuration(seconds: number | null): string {
  if (seconds === null) return "—";
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return rest > 0 ? `${minutes}m ${rest}s` : `${minutes}m`;
}

export function AmbientGovernanceSurface() {
  return (
    <InternalPreviewGate title="Ambient governance shell">
      <AmbientGovernanceContent />
    </InternalPreviewGate>
  );
}

function AmbientGovernanceContent() {
  const [availability, setAvailability] = useState<AmbientAvailability>({ kind: "loading" });
  const [summaryRefreshKey, setSummaryRefreshKey] = useState(0);

  useEffect(() => {
    let active = true;

    async function load() {
      try {
        const summary = await getAmbientSummary();
        if (!active) return;
        setAvailability({ kind: "enabled", summary });
      } catch (err: unknown) {
        if (!active) return;
        // 503 is the designed default: ingestion disabled. (A genuine
        // outage also lands here; for an internal preview surface the
        // fail-closed reading is the correct one.)
        if (err instanceof ApiError && err.status === 503) {
          setAvailability({ kind: "disabled" });
        } else {
          setAvailability({
            kind: "error",
            message:
              err instanceof Error ? err.message : "Unable to read ambient governance status.",
          });
        }
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, [summaryRefreshKey]);

  return (
    <div className="space-y-6">
      <div>
        <div className="flex flex-wrap items-center gap-3">
          <p className="text-sm font-medium text-slate-500">Governance</p>
          <InternalPreviewBadge />
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          Ambient governance shell
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          A metadata-only review gate around ambient AI workflows that happen in other tools.
          ANCHOR records that an event occurred and that a human reviewed the outcome — nothing
          more.
        </p>
      </div>

      <Card variant="native" className="border-amber-200">
        <h2 className="text-base font-semibold text-slate-900">Boundary</h2>
        <div className="mt-3 space-y-2 text-sm leading-6 text-slate-700">
          <p>
            ANCHOR is <span className="font-semibold">not an ambient scribe</span> and does not
            become one through this surface. There is no transcript storage, no audio storage,
            no clinical note content, and no note generation anywhere in ANCHOR.
          </p>
          <p>
            Events here are metadata only: a tool label, an event type, a timestamp, an
            optional duration, and an optional SHA-256 reference hash. The review gate records
            a bounded decision category — never what was said or written. The clinical record
            stays in the clinic&rsquo;s own systems, and professional review remains the
            clinic&rsquo;s responsibility.
          </p>
        </div>
      </Card>

      <Card variant="native">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-slate-900">Ingestion status</h2>
            <p className="mt-1 text-sm leading-6 text-slate-600">
              Whether the metadata-only ambient event interface is accepting records at all.
            </p>
          </div>
          <StatusBadge
            value={
              availability.kind === "enabled"
                ? "enabled_non_production"
                : availability.kind === "disabled"
                  ? "blocked"
                  : availability.kind === "error"
                    ? "error"
                    : "pending"
            }
          />
        </div>

        {availability.kind === "loading" ? (
          <Notice tone="neutral">Checking ambient governance status…</Notice>
        ) : availability.kind === "disabled" ? (
          <div className="mt-4 space-y-2 text-sm leading-6 text-slate-600">
            <p className="font-semibold text-slate-900">
              Ambient event ingestion is disabled. This is the default posture.
            </p>
            <p>
              No vendor adapter exists, and enabling the interface requires a backend
              configuration change plus an explicit founder decision with security, legal, and
              clinical-content boundary review first. Nothing on this page can enable it.
            </p>
          </div>
        ) : availability.kind === "error" ? (
          <Notice tone="error">{availability.message}</Notice>
        ) : (
          <>
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              <CountTile label="Pending review" value={availability.summary.pending_review_count} />
              <CountTile label="Reviewed" value={availability.summary.reviewed_count} />
              <CountTile label="Discarded" value={availability.summary.discarded_count} />
            </div>
            <p className="mt-3 text-sm leading-6 text-slate-600">
              Latest event: {formatDateTime(availability.summary.latest_event_at)}
            </p>
            <p className="mt-4 max-w-3xl text-xs leading-5 text-slate-500">
              {availability.summary.ambient_note}
            </p>
          </>
        )}
      </Card>

      {availability.kind === "enabled" ? (
        <AmbientEventList onReviewed={() => setSummaryRefreshKey((key) => key + 1)} />
      ) : null}
    </div>
  );
}

function AmbientEventList({ onReviewed }: { onReviewed: () => void }) {
  const [statusFilter, setStatusFilter] = useState<AmbientReviewStatus | "">("");
  const [events, setEvents] = useState<AmbientEvent[] | null>(null);
  const [note, setNote] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await listAmbientEvents(statusFilter || undefined);
      setEvents(response.events);
      setNote(response.ambient_note);
    } catch (err: unknown) {
      setEvents(null);
      setError(err instanceof Error ? err.message : "Unable to load ambient events.");
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <Card variant="native">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-slate-900">Event metadata</h2>
          <p className="mt-1 text-sm leading-6 text-slate-600">
            Metadata-only records of ambient workflow events, with the human review gate on
            each pending event.
          </p>
        </div>
        <label className="flex flex-col text-xs font-medium text-slate-500">
          Review status
          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value as AmbientReviewStatus | "")}
            className="mt-1 rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-normal text-slate-900"
          >
            {STATUS_FILTERS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      {loading ? (
        <Notice tone="neutral">Loading ambient event metadata…</Notice>
      ) : error ? (
        <Notice tone="error">{error}</Notice>
      ) : events && events.length > 0 ? (
        <div className="mt-4 space-y-4">
          {events.map((event) => (
            <AmbientEventRow
              key={event.ambient_event_id}
              event={event}
              onReviewed={async () => {
                await load();
                onReviewed();
              }}
            />
          ))}
        </div>
      ) : (
        <Notice tone="neutral">No ambient events match the current filter.</Notice>
      )}

      {note ? <p className="mt-4 max-w-3xl text-xs leading-5 text-slate-500">{note}</p> : null}
    </Card>
  );
}

function AmbientEventRow({
  event,
  onReviewed,
}: {
  event: AmbientEvent;
  onReviewed: () => Promise<void>;
}) {
  const [decision, setDecision] = useState<AmbientReviewDecision | "">("");
  const [working, setWorking] = useState(false);
  const [reviewError, setReviewError] = useState<string | null>(null);

  const decisionSpec = AMBIENT_REVIEW_DECISIONS.find((item) => item.value === decision);

  async function handleReview() {
    if (!decision) return;
    setWorking(true);
    setReviewError(null);
    try {
      await reviewAmbientEvent(event.ambient_event_id, decision);
      await onReviewed();
    } catch (err: unknown) {
      setReviewError(
        err instanceof Error ? err.message : "Unable to record the review decision.",
      );
    } finally {
      setWorking(false);
    }
  }

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-slate-900">{event.source_label}</p>
          <p className="mt-1 text-sm leading-6 text-slate-600">
            {EVENT_TYPE_LABEL[event.event_type] ?? event.event_type} · occurred{" "}
            {formatDateTime(event.occurred_at)} · duration {formatDuration(event.duration_seconds)}
          </p>
          {event.workflow_reference_hash ? (
            <p
              className="mt-1 font-mono text-xs text-slate-500"
              title={event.workflow_reference_hash}
            >
              Reference hash {event.workflow_reference_hash.slice(0, 16)}…
            </p>
          ) : null}
        </div>
        <StatusBadge value={event.review_status} />
      </div>

      {event.review_status === "pending_review" ? (
        <div className="mt-4 border-t border-slate-100 pt-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
            Human review gate
          </p>
          <div className="mt-2 flex flex-wrap items-end gap-3">
            <label className="flex min-w-64 flex-col text-xs font-medium text-slate-500">
              Review decision
              <select
                value={decision}
                onChange={(changeEvent) =>
                  setDecision(changeEvent.target.value as AmbientReviewDecision | "")
                }
                className="mt-1 rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-normal text-slate-900"
              >
                <option value="">Select a decision category…</option>
                {AMBIENT_REVIEW_DECISIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <Button onClick={handleReview} disabled={!decision} loading={working} variant="secondary">
              Record review
            </Button>
          </div>
          {decisionSpec ? (
            <p className="mt-2 max-w-2xl text-xs leading-5 text-slate-500">
              {decisionSpec.description}
            </p>
          ) : null}
          {reviewError ? (
            <div className="mt-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
              {reviewError}
            </div>
          ) : null}
        </div>
      ) : (
        <p className="mt-3 text-sm leading-6 text-slate-600">
          {event.review_decision
            ? `Decision: ${
                AMBIENT_REVIEW_DECISIONS.find((item) => item.value === event.review_decision)
                  ?.label ?? event.review_decision
              } · reviewed ${formatDateTime(event.reviewed_at)}`
            : `Recorded ${formatDateTime(event.created_at)}`}
        </p>
      )}
    </div>
  );
}

function Notice({
  tone,
  children,
}: {
  tone: "neutral" | "error";
  children: React.ReactNode;
}) {
  const toneClass =
    tone === "error"
      ? "border-rose-200 bg-rose-50 text-rose-700"
      : "border-slate-200 bg-slate-50 text-slate-600";
  return (
    <div className={`mt-4 rounded-xl border px-4 py-3 text-sm ${toneClass}`}>{children}</div>
  );
}

function CountTile({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-slate-900">{value}</p>
    </div>
  );
}
