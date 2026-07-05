"use client";

// Fable roadmap-completion experiment - Slice F4 (M5.8 Billing
// Foundations, internal preview, sandbox-only).
//
// Doctrine:
//   * Sandbox-only: no live payment buttons, no checkout, no
//     subscribe-now language, no payment instrument fields. The
//     backend sandbox note is displayed verbatim.
//   * Gated activation states (active_limited / active_verified) are
//     shown as visibly unavailable, never selectable; the backend
//     refuses them regardless.
//   * Admin gate mirrors the backend role set for discoverability
//     only; backend remains the real authority.

import { useEffect, useState, useSyncExternalStore } from "react";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import {
  InternalPreviewBadge,
  InternalPreviewGate,
} from "@/components/experiment/InternalPreviewGate";
import {
  SESSION_SERVER_SNAPSHOT,
  getSessionUserSnapshot,
  subscribeSessionStorage,
} from "@/lib/auth";
import {
  API_SETTABLE_ACTIVATION,
  API_SETTABLE_READINESS,
  GATED_ACTIVATION,
  getBillingState,
  updateBillingState,
} from "@/lib/billingFoundations";
import type { BillingStateResponse } from "@/lib/billingFoundations";

const ADMIN_ROLES = new Set(["admin", "owner", "practice_manager"]);

function formatLabel(value: string) {
  return value.replace(/[_-]+/g, " ");
}

function formatDateTime(value?: string | null): string {
  if (!value) return "Never updated";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

export function BillingFoundationsSurface() {
  return (
    <InternalPreviewGate title="Billing foundations">
      <BillingFoundationsContent />
    </InternalPreviewGate>
  );
}

function BillingFoundationsContent() {
  const user = useSyncExternalStore(
    subscribeSessionStorage,
    getSessionUserSnapshot,
    SESSION_SERVER_SNAPSHOT,
  );
  const isAdmin = Boolean(user && ADMIN_ROLES.has(user.role));

  const [state, setState] = useState<BillingStateResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [planInput, setPlanInput] = useState("");
  const [activationInput, setActivationInput] = useState("");
  const [readinessInput, setReadinessInput] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveFeedback, setSaveFeedback] = useState<
    { kind: "success" | "error"; message: string } | null
  >(null);

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const response = await getBillingState();
        if (!active) return;
        setState(response);
        setPlanInput(response.plan_slug);
        setActivationInput(response.activation_status);
        setReadinessInput(response.billing_readiness);
      } catch (err: unknown) {
        if (!active) return;
        setState(null);
        setError(
          err instanceof Error ? err.message : "Unable to load the sandbox billing state.",
        );
      } finally {
        if (active) setLoading(false);
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, []);

  async function handleSave() {
    setSaving(true);
    setSaveFeedback(null);
    try {
      const response = await updateBillingState({
        plan_slug: planInput || undefined,
        activation_status: activationInput || undefined,
        billing_readiness: readinessInput || undefined,
      });
      setState(response);
      setSaveFeedback({
        kind: "success",
        message: "Sandbox billing state updated.",
      });
    } catch (err: unknown) {
      setSaveFeedback({
        kind: "error",
        message:
          err instanceof Error ? err.message : "Unable to update the sandbox billing state.",
      });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <div className="flex flex-wrap items-center gap-3">
          <p className="text-sm font-medium text-slate-500">Clinic administration</p>
          <InternalPreviewBadge />
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          Billing foundations
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          Sandbox-only billing and activation structure. Nothing on this surface can take a
          payment, store payment details, or activate paid service.
        </p>
      </div>

      {loading ? (
        <Card variant="native">
          <Notice tone="neutral">Loading the sandbox billing state…</Notice>
        </Card>
      ) : error ? (
        <Card variant="native">
          <Notice tone="error">{error}</Notice>
        </Card>
      ) : state ? (
        <>
          <Card variant="native">
            <SectionTitle
              title="Billing readiness state"
              description="The current sandbox posture for this clinic workspace."
            />
            <div className="mt-4 space-y-4">
              <StateRow label="Current plan" value={formatLabel(state.plan_slug)} />
              <StateRow
                label="Activation status"
                value={formatLabel(state.activation_status)}
                badge={state.activation_status}
              />
              <StateRow
                label="Billing readiness"
                value={formatLabel(state.billing_readiness)}
                badge={state.billing_readiness}
              />
              <StateRow
                label="Stripe mode"
                value={`${formatLabel(state.stripe_mode)} — live mode cannot be stored at the schema level`}
                badge={state.stripe_mode}
              />
              <StateRow label="Last updated" value={formatDateTime(state.updated_at)} />
            </div>
            <p className="mt-4 max-w-3xl text-xs leading-5 text-slate-500">
              {state.sandbox_note}
            </p>
          </Card>

          <Card variant="native">
            <SectionTitle
              title="Plan catalogue"
              description="Sandbox plan structure. Prices are deliberately unset while billing remains sandbox-only."
            />
            {state.plans.length > 0 ? (
              <div className="mt-4 grid gap-4 xl:grid-cols-3">
                {state.plans.map((plan) => (
                  <div
                    key={plan.plan_slug}
                    className="flex flex-col rounded-xl border border-slate-200 bg-white p-5 shadow-[0_8px_24px_rgba(42,52,57,0.05)]"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <h3 className="text-base font-semibold capitalize text-slate-900">
                        {plan.title}
                      </h3>
                      {plan.plan_slug === state.plan_slug ? (
                        <StatusBadge value="current" />
                      ) : null}
                    </div>
                    <p className="mt-2 flex-1 text-sm leading-6 text-slate-600">{plan.summary}</p>
                    <p className="mt-3 text-sm font-semibold text-slate-900">
                      {plan.monthly_price_pence === null
                        ? "Pricing not set — sandbox catalogue"
                        : `${(plan.monthly_price_pence / 100).toFixed(2)} ${plan.currency}/month`}
                    </p>
                    <div className="mt-3">
                      <Button variant="secondary" disabled>
                        Unavailable — live billing is not enabled
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <Notice tone="neutral">No sandbox plans are published yet.</Notice>
            )}
          </Card>

          <Card variant="native">
            <SectionTitle
              title="Activation status"
              description="Which activation states exist in the model, and which are reachable in the sandbox."
            />
            <div className="mt-4 space-y-4">
              {API_SETTABLE_ACTIVATION.map((status) => (
                <ActivationRow
                  key={status}
                  status={status}
                  available
                  note={
                    status === "internal_demo"
                      ? "Internal demonstration posture. The default for this workspace."
                      : "Recorded as a pilot candidate for internal planning. Not a paid pilot and not an activation."
                  }
                  current={state.activation_status === status}
                />
              ))}
              {GATED_ACTIVATION.map((status) => (
                <ActivationRow
                  key={status}
                  status={status}
                  available={false}
                  note="Gated. Requires the security and legal gates plus an explicit founder decision; the API refuses this state."
                  current={state.activation_status === status}
                />
              ))}
            </div>
          </Card>

          {isAdmin ? (
            <Card variant="native">
              <SectionTitle
                title="Sandbox state controls"
                description="Admin-only controls for the sandbox posture. Gated states are not offered and are refused by the backend."
              />
              <div className="mt-4 grid gap-4 md:grid-cols-3">
                <label className="flex flex-col text-xs font-medium text-slate-500">
                  Plan
                  <select
                    value={planInput}
                    onChange={(event) => setPlanInput(event.target.value)}
                    className="mt-1 rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-normal text-slate-900"
                  >
                    {state.plans.map((plan) => (
                      <option key={plan.plan_slug} value={plan.plan_slug}>
                        {plan.title}
                      </option>
                    ))}
                    {state.plans.every((plan) => plan.plan_slug !== state.plan_slug) ? (
                      <option value={state.plan_slug}>{formatLabel(state.plan_slug)}</option>
                    ) : null}
                  </select>
                </label>

                <label className="flex flex-col text-xs font-medium text-slate-500">
                  Activation status (sandbox-settable only)
                  <select
                    value={activationInput}
                    onChange={(event) => setActivationInput(event.target.value)}
                    className="mt-1 rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-normal capitalize text-slate-900"
                  >
                    {API_SETTABLE_ACTIVATION.map((status) => (
                      <option key={status} value={status}>
                        {formatLabel(status)}
                      </option>
                    ))}
                  </select>
                </label>

                <label className="flex flex-col text-xs font-medium text-slate-500">
                  Billing readiness
                  <select
                    value={readinessInput}
                    onChange={(event) => setReadinessInput(event.target.value)}
                    className="mt-1 rounded-xl border border-slate-300 bg-white px-3 py-2 text-sm font-normal capitalize text-slate-900"
                  >
                    {API_SETTABLE_READINESS.map((status) => (
                      <option key={status} value={status}>
                        {formatLabel(status)}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <div className="mt-4">
                <Button onClick={handleSave} loading={saving}>
                  Save sandbox state
                </Button>
              </div>
              {saveFeedback ? (
                <div
                  className={[
                    "mt-3 rounded-xl border px-4 py-3 text-sm",
                    saveFeedback.kind === "success"
                      ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                      : "border-rose-200 bg-rose-50 text-rose-700",
                  ].join(" ")}
                >
                  {saveFeedback.message}
                </div>
              ) : null}
            </Card>
          ) : null}

          <Card variant="native">
            <SectionTitle
              title="Live billing controls"
              description="Present in the model, deliberately unavailable here."
            />
            <div className="mt-4 flex flex-wrap gap-3">
              <Button variant="secondary" disabled>
                Enable live billing — unavailable
              </Button>
              <Button variant="secondary" disabled>
                Add payment details — unavailable
              </Button>
            </div>
            <p className="mt-4 max-w-3xl text-sm leading-6 text-slate-600">
              Live billing requires the security and legal gates and an explicit founder
              decision. No payment capability exists in this build: there is no checkout, no
              payment form, and the backend schema cannot record a live Stripe mode.
            </p>
          </Card>
        </>
      ) : null}
    </div>
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
      {description ? (
        <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p>
      ) : null}
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

function StateRow({
  label,
  value,
  badge,
}: {
  label: string;
  value: string;
  badge?: string;
}) {
  return (
    <div className="grid grid-cols-[160px_1fr_auto] items-start gap-4 border-b border-slate-100 pb-4 last:border-b-0 last:pb-0">
      <p className="text-sm text-slate-500">{label}</p>
      <p className="text-sm capitalize text-slate-900">{value}</p>
      <div>{badge ? <StatusBadge value={badge} /> : null}</div>
    </div>
  );
}

function ActivationRow({
  status,
  available,
  note,
  current,
}: {
  status: string;
  available: boolean;
  note: string;
  current: boolean;
}) {
  return (
    <div className="grid gap-2 border-b border-slate-100 pb-4 last:border-b-0 last:pb-0 md:grid-cols-[1fr_auto]">
      <div>
        <p className="text-sm font-semibold capitalize text-slate-900">
          {formatLabel(status)}
          {current ? <span className="ml-2 text-xs font-medium text-slate-500">(current)</span> : null}
        </p>
        <p className="mt-1 text-sm leading-6 text-slate-600">{note}</p>
      </div>
      <div className="md:text-right">
        <StatusBadge value={available ? "sandbox_only" : "blocked"} />
      </div>
    </div>
  );
}
