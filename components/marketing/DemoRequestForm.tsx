"use client";

import type { FormEvent } from "react";
import { useState } from "react";
import { FieldError, SelectField, TextAreaField } from "@/components/marketing/MarketingFormFields";
import { marketingSecondaryButtonClass } from "@/components/marketing/MarketingShell";
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
  normalizeDemoRequestInput,
  validateDemoRequestInput,
  type DemoRequestErrors,
  type DemoRequestPayload,
} from "@/lib/demoRequest";

const WALKTHROUGH_EMAIL = "hello@anchorvet.co.uk";

type DemoRequestFormState = DemoRequestPayload;

type EmailDraft = {
  to: string;
  subject: string;
  body: string;
  copyText: string;
  mailtoUrl: string;
};

type CopyState = "idle" | "copied" | "error";

export function DemoRequestForm() {
  const [errors, setErrors] = useState<DemoRequestErrors>({});
  const [emailDraft, setEmailDraft] = useState<EmailDraft | null>(null);
  const [copyState, setCopyState] = useState<CopyState>("idle");
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
    honeypot: "",
  });

  function update<K extends keyof DemoRequestFormState>(key: K, value: DemoRequestFormState[K]) {
    setForm((current) => ({ ...current, [key]: value }));
    setErrors((current) => ({ ...current, [key]: undefined }));
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const normalized = normalizeDemoRequestInput(form);
    const nextErrors = validateDemoRequestInput(normalized);

    if (Object.keys(nextErrors).length > 0) {
      setErrors(nextErrors);
      return;
    }

    // Provider-agnostic, founder-stage route: prepare the email content in-page so
    // the visitor can copy it and send from any email app. Nothing is sent here, no
    // backend is called, and we intentionally do not redirect to /demo/thanks.
    setCopyState("idle");
    setEmailDraft(buildEmailDraft(normalized));
  }

  async function handleCopy(copyText: string) {
    try {
      await navigator.clipboard.writeText(copyText);
      setCopyState("copied");
    } catch {
      setCopyState("error");
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

        <p className="max-w-2xl text-sm leading-6 text-slate-500">
          We’ll use these details only to review and respond to your request. Do not include confidential clinical,
          client-identifiable, patient, password, secret, or unnecessary personal data in this form.
        </p>

        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <p className="max-w-2xl text-sm leading-6 text-slate-500">
            When you submit, we’ll prepare the request as an email you can copy and send from your own email app. Nothing
            is sent automatically.
          </p>
          <Button type="submit" className="min-w-[180px]">
            Prepare email request
          </Button>
        </div>

        {emailDraft ? (
          <div className="rounded-2xl border border-slate-200 bg-slate-50 p-6">
            <h3 className="text-lg font-semibold text-slate-900">Walkthrough request ready</h3>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
              Copy the request details below and send them to {WALKTHROUGH_EMAIL} from your preferred email app. You can
              also try opening your default email app, but some browsers and email clients may not preserve pre-filled
              content.
            </p>

            <dl className="mt-4 space-y-1 text-sm">
              <div className="flex flex-wrap gap-2">
                <dt className="font-medium text-slate-700">To:</dt>
                <dd className="text-slate-900">{emailDraft.to}</dd>
              </div>
              <div className="flex flex-wrap gap-2">
                <dt className="font-medium text-slate-700">Subject:</dt>
                <dd className="text-slate-900">{emailDraft.subject}</dd>
              </div>
            </dl>

            <label className="sr-only" htmlFor="walkthrough-email-body">
              Walkthrough request email details
            </label>
            <textarea
              id="walkthrough-email-body"
              readOnly
              value={emailDraft.copyText}
              rows={18}
              className="mt-4 w-full rounded-2xl border border-slate-200 bg-white p-4 font-mono text-xs leading-5 text-slate-700"
            />

            <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center">
              <Button type="button" onClick={() => handleCopy(emailDraft.copyText)} className="min-w-[180px]">
                {copyState === "copied" ? "Copied" : "Copy request details"}
              </Button>
              <a href={emailDraft.mailtoUrl} className={marketingSecondaryButtonClass("px-5 py-2.5 text-sm")}>
                Open default email app
              </a>
            </div>

            {copyState === "copied" ? (
              <p className="mt-3 text-sm text-emerald-700">
                Copied. Paste it into a new email to {WALKTHROUGH_EMAIL} and send.
              </p>
            ) : null}
            {copyState === "error" ? (
              <p className="mt-3 text-sm text-slate-600">
                Copy did not work in this browser. Select the text in the box above and copy it manually.
              </p>
            ) : null}

            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-500">
              Opening your default email app is optional. If the email app opens without the details, copy the request
              details from this page and paste them manually.
            </p>
          </div>
        ) : null}
      </form>
    </Card>
  );
}

function buildEmailDraft(input: DemoRequestPayload): EmailDraft {
  const subject = input.clinicName
    ? `ANCHOR walkthrough request — ${input.clinicName}`
    : "ANCHOR walkthrough request";

  const body = [
    "Hello ANCHOR,",
    "",
    "I would like to request a short walkthrough of how veterinary clinics can use AI with stronger accountability, safer review, and visible trust surfaces.",
    "",
    "Please use this context to shape the walkthrough around our clinic’s current AI use, governance needs, and operational concerns.",
    "",
    `Full name: ${input.fullName}`,
    `Work email: ${input.workEmail}`,
    `Clinic / organisation name: ${input.clinicName}`,
    `Role: ${input.role}`,
    `Current AI use today: ${input.currentAiUse}`,
    `Primary interest: ${input.primaryInterest}`,
    `Biggest current concern: ${input.biggestConcern}`,
    `Clinic size: ${input.clinicSize ?? ""}`,
    `Phone number: ${input.phoneNumber ?? ""}`,
    `Message: ${input.message ?? ""}`,
    "",
    "Consent:",
    "I confirm that ANCHOR may use these details to review and respond to this walkthrough request.",
    "",
    "Important:",
    "I have not included confidential clinical, client-identifiable, patient, password, secret, or unnecessary personal data.",
  ].join("\n");

  const copyText = `To: ${WALKTHROUGH_EMAIL}\nSubject: ${subject}\n\n${body}`;
  const mailtoUrl = `mailto:${WALKTHROUGH_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;

  return { to: WALKTHROUGH_EMAIL, subject, body, copyText, mailtoUrl };
}
