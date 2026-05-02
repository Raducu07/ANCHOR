"use client";

import type { FormEvent } from "react";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { FieldError, SelectField, TextAreaField } from "@/components/marketing/MarketingFormFields";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import {
  demoBiggestConcernOptions,
  demoClinicSizeOptions,
  demoCurrentAiUseOptions,
  demoPrimaryInterestOptions,
  demoRoleOptions,
} from "@/lib/marketingContent";
import {
  demoRequestFieldMap,
  normalizeDemoRequestInput,
  toDemoRequestApiPayload,
  validateDemoRequestInput,
  type DemoRequestErrors,
  type DemoRequestPayload,
} from "@/lib/demoRequest";
import { submitPublicIntake } from "@/lib/publicIntakeClient";

type DemoRequestFormState = DemoRequestPayload;

export function DemoRequestForm() {
  const router = useRouter();
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [errors, setErrors] = useState<DemoRequestErrors>({});
  const [form, setForm] = useState<DemoRequestFormState>({
    fullName: "",
    workEmail: "",
    clinicName: "",
    role: "",
    currentAiUse: "",
    primaryInterest: "",
    biggestConcern: "",
    clinicSize: "",
    phoneNumber: "",
    message: "",
    consent: false,
    sourcePage: "/demo",
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

  function update<K extends keyof DemoRequestFormState>(key: K, value: DemoRequestFormState[K]) {
    setForm((current) => ({ ...current, [key]: value }));
    setErrors((current) => ({ ...current, [key]: undefined }));
    setFormError(null);
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);

    const normalized = normalizeDemoRequestInput(form);
    const nextErrors = validateDemoRequestInput(normalized);

    if (Object.keys(nextErrors).length > 0) {
      setErrors(nextErrors);
      return;
    }

    try {
      setSubmitting(true);

      const payload = await submitPublicIntake(
        "/v1/public/demo-request",
        toDemoRequestApiPayload(normalized),
        demoRequestFieldMap
      );

      if (!payload.ok) {
        if (payload.errors) {
          setErrors(payload.errors);
        }
        setFormError(payload.error || "We couldn’t submit your request. Please check the highlighted details and try again.");
        return;
      }

      router.push(payload.requestId ? `/demo/thanks?request=${encodeURIComponent(payload.requestId)}` : "/demo/thanks");
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "We couldn’t submit your request. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card className="rounded-[2rem] p-8">
      <div>
        <h2 className="text-xl font-semibold text-slate-900">Walkthrough request form</h2>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          Share a little context and we’ll use it to shape the walkthrough around your clinic’s current AI use, governance
          needs, and operational concerns.
        </p>
      </div>

      <form className="mt-8 space-y-6" onSubmit={handleSubmit} noValidate>
        <div className="grid gap-4 md:grid-cols-2">
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

          <FieldError error={errors.clinicName}>
            <Input
              label="Clinic / organisation name"
              value={form.clinicName}
              onChange={(event) => update("clinicName", event.target.value)}
              aria-invalid={Boolean(errors.clinicName)}
            />
          </FieldError>

          <SelectField label="Role" value={form.role} onChange={(value) => update("role", value)} options={demoRoleOptions} error={errors.role} />
          <SelectField
            label="Current AI use today"
            value={form.currentAiUse}
            onChange={(value) => update("currentAiUse", value)}
            options={demoCurrentAiUseOptions}
            error={errors.currentAiUse}
          />
          <SelectField
            label="Primary interest"
            value={form.primaryInterest}
            onChange={(value) => update("primaryInterest", value)}
            options={demoPrimaryInterestOptions}
            error={errors.primaryInterest}
          />
          <SelectField
            label="Biggest current concern"
            value={form.biggestConcern}
            onChange={(value) => update("biggestConcern", value)}
            options={demoBiggestConcernOptions}
            error={errors.biggestConcern}
          />
          <SelectField
            label="Clinic size"
            value={form.clinicSize ?? ""}
            onChange={(value) => update("clinicSize", value)}
            options={demoClinicSizeOptions}
            required={false}
          />
          <Input
            label="Phone number"
            type="tel"
            value={form.phoneNumber ?? ""}
            onChange={(event) => update("phoneNumber", event.target.value)}
          />
        </div>

        <TextAreaField
          label="Message"
          value={form.message ?? ""}
          onChange={(value) => update("message", value)}
          hint="Optional context you want us to understand before the walkthrough."
        />

        <div className="hidden" aria-hidden="true">
          {/* TODO: Replace this honeypot with a stronger anti-spam control if public traffic increases materially. */}
          <label htmlFor="website">Website</label>
          <input
            id="website"
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
              I confirm that ANCHOR may use these details to review and respond to this walkthrough request.
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
            {submitting ? "Submitting request" : "Request walkthrough"}
          </Button>
        </div>
      </form>
    </Card>
  );
}
