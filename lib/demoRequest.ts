import { isValidEmail, normalizeString, optionalString, type IntakeTrackingFields } from "@/lib/intake";

export type DemoRequestPayload = IntakeTrackingFields & {
  fullName: string;
  workEmail: string;
  clinicName: string;
  role: string;
  currentAiUse: string;
  primaryInterest: string;
  biggestConcern: string;
  clinicSize?: string;
  phoneNumber?: string;
  message?: string;
  consent: boolean;
};

export type DemoRequestErrors = Partial<Record<keyof DemoRequestPayload, string>>;

export type DemoRequestApiPayload = {
  full_name: string;
  work_email: string;
  clinic_name: string;
  role: string;
  current_ai_use: string;
  primary_interest: string;
  biggest_concern: string;
  consent: boolean;
  source_page: string;
  website?: string;
  clinic_size?: string;
  phone?: string;
  message?: string;
  utm_source?: string;
  utm_medium?: string;
  utm_campaign?: string;
};

export const demoRequestFieldMap: Partial<Record<string, keyof DemoRequestErrors>> = {
  full_name: "fullName",
  work_email: "workEmail",
  clinic_name: "clinicName",
  role: "role",
  current_ai_use: "currentAiUse",
  primary_interest: "primaryInterest",
  biggest_concern: "biggestConcern",
  clinic_size: "clinicSize",
  phone: "phoneNumber",
  message: "message",
  consent: "consent",
  source_page: "sourcePage",
  utm_source: "utmSource",
  utm_medium: "utmMedium",
  utm_campaign: "utmCampaign",
  website: "honeypot",
};

export type DemoRequestStatus = "new" | "contacted" | "booked" | "qualified" | "closed";

export type DemoRequestRecord = {
  id: string;
  created_at: string;
  full_name: string;
  work_email: string;
  clinic_name: string;
  role: string;
  current_ai_use: string;
  primary_interest: string;
  biggest_concern: string;
  clinic_size: string | null;
  phone: string | null;
  message: string | null;
  consent: boolean;
  source_page: string | null;
  utm_source: string | null;
  utm_medium: string | null;
  utm_campaign: string | null;
  utm_term: string | null;
  utm_content: string | null;
  status: DemoRequestStatus;
  notes: string | null;
};

export function normalizeDemoRequestInput(input: Partial<DemoRequestPayload>): DemoRequestPayload {
  return {
    fullName: normalizeString(input.fullName),
    workEmail: normalizeString(input.workEmail),
    clinicName: normalizeString(input.clinicName),
    role: normalizeString(input.role),
    currentAiUse: normalizeString(input.currentAiUse),
    primaryInterest: normalizeString(input.primaryInterest),
    biggestConcern: normalizeString(input.biggestConcern),
    clinicSize: normalizeString(input.clinicSize),
    phoneNumber: normalizeString(input.phoneNumber),
    message: normalizeString(input.message),
    consent: Boolean(input.consent),
    sourcePage: normalizeString(input.sourcePage) || "/demo",
    utmSource: normalizeString(input.utmSource),
    utmMedium: normalizeString(input.utmMedium),
    utmCampaign: normalizeString(input.utmCampaign),
    utmTerm: normalizeString(input.utmTerm),
    utmContent: normalizeString(input.utmContent),
    honeypot: normalizeString(input.honeypot),
  };
}

export function validateDemoRequestInput(input: DemoRequestPayload): DemoRequestErrors {
  const errors: DemoRequestErrors = {};

  if (!input.fullName) errors.fullName = "Enter your full name.";
  if (!input.workEmail) {
    errors.workEmail = "Enter your work email.";
  } else if (!isValidEmail(input.workEmail)) {
    errors.workEmail = "Enter a valid work email.";
  }
  if (!input.clinicName) errors.clinicName = "Enter your clinic or organisation name.";
  if (!input.role) errors.role = "Select or enter your role.";
  if (!input.currentAiUse) errors.currentAiUse = "Tell us how AI is being used today.";
  if (!input.primaryInterest) errors.primaryInterest = "Tell us your primary interest.";
  if (!input.biggestConcern) errors.biggestConcern = "Tell us the biggest current concern.";
  if (!input.consent) errors.consent = "You must confirm consent before submitting.";
  if (input.honeypot) errors.honeypot = "Spam protection triggered.";

  return errors;
}

export function toDemoRequestApiPayload(input: DemoRequestPayload): DemoRequestApiPayload {
  return {
    full_name: input.fullName,
    work_email: input.workEmail,
    clinic_name: input.clinicName,
    role: input.role,
    current_ai_use: input.currentAiUse,
    primary_interest: input.primaryInterest,
    biggest_concern: input.biggestConcern,
    clinic_size: optionalString(input.clinicSize),
    phone: optionalString(input.phoneNumber),
    message: optionalString(input.message),
    consent: input.consent,
    source_page: input.sourcePage,
    utm_source: optionalString(input.utmSource),
    utm_medium: optionalString(input.utmMedium),
    utm_campaign: optionalString(input.utmCampaign),
    website: optionalString(input.honeypot),
  };
}
