"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { AppShell } from "@/components/shell/AppShell";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { apiFetch, ApiError } from "@/lib/api";
import type { ReceiptEnvelope, ReceiptPayload } from "@/lib/types";

export default function ReceiptsPage() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [requestId, setRequestId] = useState(searchParams.get("request_id") ?? "");
  const [receipt, setReceipt] = useState<ReceiptPayload | null>(null);
  const [loading, setLoading] = useState(false);
  const [autoloadAttempted, setAutoloadAttempted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSearch = useMemo(() => requestId.trim().length > 0, [requestId]);

  async function fetchReceipt(targetRequestId: string) {
    const trimmed = targetRequestId.trim();
    if (!trimmed) return;

    try {
      setLoading(true);
      setError(null);

      const response = await apiFetch<ReceiptEnvelope | ReceiptPayload>(
        `/v1/portal/receipt/${encodeURIComponent(trimmed)}`,
      );

      const normalized = "receipt" in response ? response.receipt : response;
      setReceipt(normalized);

      const current = searchParams.get("request_id") ?? "";
      if (current !== trimmed) {
        router.replace(`/receipts?request_id=${encodeURIComponent(trimmed)}`);
      }
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Unable to load receipt.";
      setError(message);
      setReceipt(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const incoming = searchParams.get("request_id") ?? "";
    setRequestId(incoming);

    if (incoming && !autoloadAttempted) {
      setAutoloadAttempted(true);
      void fetchReceipt(incoming);
    }
  }, [searchParams, autoloadAttempted]);

  async function handleLookup() {
    await fetchReceipt(requestId);
  }

  return (
    <AppShell>
      <div className="space-y-6">
        <div>
          <p className="text-sm font-medium text-slate-500">Governance receipts</p>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Receipt viewer</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
            Inspect a clinic-scoped governance receipt by request ID. Receipt views preserve the
            metadata-only posture and surface accountability fields without storing raw prompt or
            output content.
          </p>
        </div>

        <Card>
          <div className="grid gap-4 md:grid-cols-[1fr_auto] md:items-end">
            <Input
              label="Request ID"
              placeholder="Paste a request ID"
              value={requestId}
              onChange={(event) => setRequestId(event.target.value)}
            />
            <Button onClick={handleLookup} loading={loading} disabled={!canSearch || loading}>
              View receipt
            </Button>
          </div>
          {error ? <p className="mt-4 text-sm text-rose-700">{error}</p> : null}
        </Card>

        {receipt ? (
          <>
            <div className="grid gap-4 xl:grid-cols-2">
              <Card>
                <SectionTitle
                  title="Decision summary"
                  description="Primary governance outcome fields for this request."
                />
                <dl className="mt-4 space-y-3 text-sm">
                  <Detail label="Request ID" value={receipt.request_id} />
                  <Detail
                    label="Mode"
                    value={<StatusBadge value={String(receipt.mode ?? "unknown")} />}
                  />
                  <Detail
                    label="Decision"
                    value={<StatusBadge value={String(receipt.decision ?? "unknown")} />}
                  />
                  <Detail
                    label="Risk grade"
                    value={<StatusBadge value={String(receipt.risk_grade ?? "unknown")} />}
                  />
                  <Detail label="Reason code" value={receipt.reason_code} />
                  <Detail label="Governance score" value={formatScore(receipt.governance_score)} />
                </dl>
              </Card>

              <Card>
                <SectionTitle
                  title="Policy trace"
                  description="Versioning and traceability fields supporting audit review."
                />
                <dl className="mt-4 space-y-3 text-sm">
                  <Detail label="Policy version" value={receipt.policy_version} />
                  <Detail label="Neutrality version" value={receipt.neutrality_version} />
                  <Detail
                    label="Policy hash"
                    value={receipt.policy_hash ?? receipt.policy_sha256 ?? "—"}
                  />
                </dl>
              </Card>

              <Card>
                <SectionTitle
                  title="Privacy and accountability"
                  description="Privacy-aware controls and oversight indicators recorded for this request."
                />
                <dl className="mt-4 space-y-3 text-sm">
                  <Detail label="PII detected" value={receipt.pii_detected ? "Yes" : "No"} />
                  <Detail label="PII action" value={receipt.pii_action} />
                  <Detail
                    label="PII types"
                    value={receipt.pii_types?.length ? receipt.pii_types.join(", ") : "None returned"}
                  />
                  <Detail label="Override flag" value={receipt.override_flag ? "Yes" : "No"} />
                  <Detail
                    label="No content stored"
                    value={receipt.no_content_stored ?? true ? "Yes" : "No"}
                  />
                </dl>
              </Card>

              <Card>
                <SectionTitle
                  title="Interpretation note"
                  description="How to read this ANCHOR receipt operationally."
                />
                <div className="mt-4 space-y-3 text-sm leading-6 text-slate-600">
                  <p>
                    This receipt reflects governance metadata only. It is designed to support
                    clinic-scoped auditability, policy review, and privacy-aware operational oversight.
                  </p>
                  <p>
                    Raw prompt and output content are intentionally excluded from this surface under
                    ANCHOR’s current metadata-only product doctrine.
                  </p>
                </div>
              </Card>
            </div>

            <Card>
              <SectionTitle
                title="Related learning"
                description="Use ANCHOR Learn to turn governance understanding into safer day-to-day practice."
              />
              <div className="mt-4 grid gap-4 xl:grid-cols-2">
                <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                  <p className="text-sm font-semibold text-slate-900">
                    Why metadata-only governance matters
                  </p>
                  <p className="mt-2 text-sm leading-6 text-slate-600">
                    Reinforce why ANCHOR provides request-level accountability without storing raw
                    content in routine review surfaces.
                  </p>
                  <div className="mt-3">
                    <Link
                      href="/learn/explainers"
                      className="text-sm font-medium text-slate-900 underline underline-offset-4"
                    >
                      Open explainers
                    </Link>
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                  <p className="text-sm font-semibold text-slate-900">
                    Human review responsibility
                  </p>
                  <p className="mt-2 text-sm leading-6 text-slate-600">
                    Revisit why AI-assisted material still requires staff review, judgment, and
                    accountability before use.
                  </p>
                  <div className="mt-3">
                    <Link
                      href="/learn/cards"
                      className="text-sm font-medium text-slate-900 underline underline-offset-4"
                    >
                      Open microlearning cards
                    </Link>
                  </div>
                </div>
              </div>
            </Card>
          </>
        ) : (
          <Card>
            <p className="text-sm font-medium text-slate-900">No receipt selected</p>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">
              Paste a request ID to inspect a single governance receipt. This is the clearest
              clinic-facing expression of ANCHOR’s metadata-only accountability model.
            </p>
          </Card>
        )}
      </div>
    </AppShell>
  );
}

function SectionTitle({
  title,
  description,
}: {
  title: string;
  description?: string;
}) {
  return (
    <div>
      <h2 className="text-base font-semibold text-slate-900">{title}</h2>
      {description ? <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p> : null}
    </div>
  );
}

function Detail({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-4 border-b border-slate-100 pb-3 last:border-b-0 last:pb-0">
      <dt className="text-slate-500">{label}</dt>
      <dd className="break-all text-slate-900">{value ?? "—"}</dd>
    </div>
  );
}

function formatScore(value: unknown) {
  if (typeof value === "number") return value.toFixed(2);
  return "—";
}