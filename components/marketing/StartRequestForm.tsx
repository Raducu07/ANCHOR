"use client";

import type { FormEvent } from "react";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { FieldError, SelectField, TextAreaField } from "@/components/marketing/MarketingFormFields";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import {
  startClinicSizeOptions,
  startCurrentAiUseOptions,
  startPreferredPlanOptions,
  startRolloutTimingOptions,
} from "@/lib/marketingContent";
import {
  normalizeStartRequestInput,
  startRequestFieldMap,
  toStartRequestApiPayload,
  type StartRequestErrors,
  type StartRequestPayload,
  validateStartRequestInput,
} from "@/lib/startRequest";
import { submitPublicIntake } from "@/lib/publicIntakeClient";

type StartRequestFormState = StartRequestPayload;

export function StartRequestForm() {
  const router = useRouter();
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [errors, setErrors] = useState<StartRequestErrors>({});
  const [form, setForm] = useState<StartRequestFormState>({
    clinicName: "",
    fullName: "",
    workEmail: "",
    role: "",
    preferredPlan: "",
    clinicSize: "",
    currentAiUse: "",
    rolloutTiming: "",
    phoneNumber: "",
    siteCount: "",
    message: "",
    consent: false,
    sourcePage: "/start",
    utmSource: "",
    utmMedium: "",
    utmCampaign: "",
    utmTerm: "",
    utmContent: "",
    honeypot: "",
  });

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setForm((current) => ({
      ...current,
      utmSource: params.get("utm_source") ?? "",
      utmMedium: params.get("utm_medium") ?? "",
      utmCampaign: params.get("utm_campaign") ?? "",
      utmTerm: params.get("utm_term") ?? "",
      utmContent: params.get("utm_content") ?? "",
    }));
  }, []);

  function update<K extends keyof StartRequestFormState>(key: K, value: StartRequestFormState[K]) {
    setForm((current) => ({ ...current, [key]: value }));
    setErrors((current) => ({ ...current, [key]: undefined }));
    setFormError(null);
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);

    const normalized = normalizeStartRequestInput(form);
    const nextErrors = validateStartRequestInput(normalized);

    if (Object.keys(nextErrors).length > 0) {
      setErrors(nextErrors);
      return;
    }

    try {
      setSubmitting(true);

      const payload = await submitPublicIntake(
        "/v1/public/start-request",
        toStartRequestApiPayload(normalized),
        startRequestFieldMap
      );

      if (!payload.ok) {
        if (payload.errors) {
          setErrors(payload.errors);
        }
        setFormError(payload.error || "We couldn’t submit your request. Please check the highlighted details and try again.");
        return;
      }

      router.push(payload.requestId ? `/start/thanks?request=${encodeURIComponent(payload.requestId)}` : "/start/thanks");
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "We couldn’t submit your request. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card className="rounded-[2rem] p-8">
      <div>
        <h2 className="text-xl font-semibold text-slate-900">Assisted onboarding request</h2>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          Share the clinic setup context and preferred starting path. We’ll use it to shape the right onboarding
          conversation without pretending there is already a live self-serve checkout behind this page.
        </p>
      </div>

      <form className="mt-8 space-y-6" onSubmit={handleSubmit} noValidate>
        <div className="grid gap-4 md:grid-cols-2">
          <FieldError error={errors.clinicName}>
            <Input
              label="Clinic / organisation name"
              value={form.clinicName}
              onChange={(event) => update("clinicName", event.target.value)}
              aria-invalid={Boolean(errors.clinicName)}
            />
          </FieldError>

          <FieldError error={errors.fullName}>
            <Input
              label="Full name"
              value={form.fullName}
              onChange={(event) => update("fullName", event.target.value)}
              aria-invalid={Boolean(errors.fullName)}
            />
          </FieldError>

          <FieldError error={errors.workEmail}>
            <Input
              label="Work email"
              type="email"
              value={form.workEmail}
              onChange={(event) => update("workEmail", event.target.value)}
              aria-invalid={Boolean(errors.workEmail)}
            />
          </FieldError>

          <FieldError error={errors.role}>
            <Input
              label="Role"
              value={form.role}
              onChange={(event) => update("role", event.target.value)}
              aria-invalid={Boolean(errors.role)}
            />
          </FieldError>

          <SelectField
            label="Preferred plan"
            value={form.preferredPlan}
            onChange={(value) => update("preferredPlan", value)}
            options={startPreferredPlanOptions}
            error={errors.preferredPlan}
          />

          <SelectField
            label="Clinic size"
            value={form.clinicSize}
            onChange={(value) => update("clinicSize", value)}
            options={startClinicSizeOptions}
            error={errors.clinicSize}
          />

          <SelectField
            label="Current AI use"
            value={form.currentAiUse}
            onChange={(value) => update("currentAiUse", value)}
            options={startCurrentAiUseOptions}
            error={errors.currentAiUse}
          />

          <SelectField
            label="Target rollout timing"
            value={form.rolloutTiming}
            onChange={(value) => update("rolloutTiming", value)}
            options={startRolloutTimingOptions}
            error={errors.rolloutTiming}
          />

          <Input
            label="Phone number"
            type="tel"
            value={form.phoneNumber ?? ""}
            onChange={(event) => update("phoneNumber", event.target.value)}
          />

          <Input
            label="Number of sites"
            value={form.siteCount ?? ""}
            onChange={(event) => update("siteCount", event.target.value)}
          />
        </div>

        <TextAreaField
          label="Message / notes"
          value={form.message ?? ""}
          onChange={(value) => update("message", value)}
          hint="Optional context about rollout questions, stakeholders, or implementation timing."
        />

        <div className="hidden" aria-hidden="true">
          {/* TODO: Replace this honeypot with a stronger anti-spam control if public traffic increases materially. */}
          <label htmlFor="website-start">Website</label>
          <input
            id="website-start"
            name="website"
            tabIndex={-1}
            autoComplete="off"
            value={form.honeypot ?? ""}
            onChange={(event) => update("honeypot", event.target.value)}
          />
        </div>

        <input type="hidden" name="sourcePage" value={form.sourcePage} readOnly />
        <input type="hidden" name="utmSource" value={form.utmSource ?? ""} readOnly />
        <input type="hidden" name="utmMedium" value={form.utmMedium ?? ""} readOnly />
        <input type="hidden" name="utmCampaign" value={form.utmCampaign ?? ""} readOnly />
        <input type="hidden" name="utmTerm" value={form.utmTerm ?? ""} readOnly />
        <input type="hidden" name="utmContent" value={form.utmContent ?? ""} readOnly />

        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <label className="flex items-start gap-3">
            <input
              type="checkbox"
              checked={form.consent}
              onChange={(event) => update("consent", event.target.checked)}
              className="mt-1 h-4 w-4 rounded border-slate-300 text-slate-900 focus:ring-slate-400"
            />
            <span className="text-sm leading-6 text-slate-700">
              I confirm that ANCHOR may use these details to review and respond to this onboarding request.
            </span>
          </label>
          {errors.consent ? <p className="mt-2 text-sm text-rose-700">{errors.consent}</p> : null}
        </div>

        {formError ? (
          <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">{formError}</div>
        ) : null}

        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="max-w-2xl text-sm leading-6 text-slate-500">
            We’ll use these details only to review and respond to your request. Do not include confidential clinical or client-identifiable information in this form.
          </p>
          <Button type="submit" loading={submitting} className="min-w-[180px]">
            {submitting ? "Submitting request" : "Continue"}
          </Button>
        </div>
      </form>
    </Card>
  );
}
