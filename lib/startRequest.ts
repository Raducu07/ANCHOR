import { isValidEmail, normalizeString, optionalInteger, optionalString, type IntakeTrackingFields } from "@/lib/intake";

export type StartRequestPayload = IntakeTrackingFields & {
  clinicName: string;
  fullName: string;
  workEmail: string;
  role: string;
  preferredPlan: string;
  clinicSize: string;
  currentAiUse: string;
  rolloutTiming: string;
  phoneNumber?: string;
  siteCount?: string;
  message?: string;
  consent: boolean;
};

export type StartRequestErrors = Partial<Record<keyof StartRequestPayload, string>>;

export type StartRequestApiPayload = {
  clinic_name: string;
  full_name: string;
  work_email: string;
  role: string;
  preferred_plan: string;
  clinic_size: string;
  current_ai_use: string;
  rollout_timing: string;
  consent: boolean;
  source_page: string;
  website?: string;
  phone?: string;
  site_count?: number;
  message?: string;
  utm_source?: string;
  utm_medium?: string;
  utm_campaign?: string;
};

export const startRequestFieldMap: Partial<Record<string, keyof StartRequestErrors>> = {
  clinic_name: "clinicName",
  full_name: "fullName",
  work_email: "workEmail",
  role: "role",
  preferred_plan: "preferredPlan",
  clinic_size: "clinicSize",
  current_ai_use: "currentAiUse",
  rollout_timing: "rolloutTiming",
  phone: "phoneNumber",
  site_count: "siteCount",
  message: "message",
  consent: "consent",
  source_page: "sourcePage",
  utm_source: "utmSource",
  utm_medium: "utmMedium",
  utm_campaign: "utmCampaign",
  website: "honeypot",
};

export type StartRequestStatus = "new" | "contacted" | "onboarding" | "qualified" | "closed";

export type StartRequestRecord = {
  id: string;
  created_at: string;
  clinic_name: string;
  full_name: string;
  work_email: string;
  role: string;
  preferred_plan: string;
  clinic_size: string;
  current_ai_use: string;
  rollout_timing: string;
  phone: string | null;
  site_count: string | null;
  message: string | null;
  consent: boolean;
  source_page: string | null;
  utm_source: string | null;
  utm_medium: string | null;
  utm_campaign: string | null;
  utm_term: string | null;
  utm_content: string | null;
  status: StartRequestStatus;
  notes: string | null;
};

export function normalizeStartRequestInput(input: Partial<StartRequestPayload>): StartRequestPayload {
  return {
    clinicName: normalizeString(input.clinicName),
    fullName: normalizeString(input.fullName),
    workEmail: normalizeString(input.workEmail),
    role: normalizeString(input.role),
    preferredPlan: normalizeString(input.preferredPlan),
    clinicSize: normalizeString(input.clinicSize),
    currentAiUse: normalizeString(input.currentAiUse),
    rolloutTiming: normalizeString(input.rolloutTiming),
    phoneNumber: normalizeString(input.phoneNumber),
    siteCount: normalizeString(input.siteCount),
    message: normalizeString(input.message),
    consent: Boolean(input.consent),
    sourcePage: normalizeString(input.sourcePage) || "/start",
    utmSource: normalizeString(input.utmSource),
    utmMedium: normalizeString(input.utmMedium),
    utmCampaign: normalizeString(input.utmCampaign),
    utmTerm: normalizeString(input.utmTerm),
    utmContent: normalizeString(input.utmContent),
    honeypot: normalizeString(input.honeypot),
  };
}

export function validateStartRequestInput(input: StartRequestPayload): StartRequestErrors {
  const errors: StartRequestErrors = {};

  if (!input.clinicName) errors.clinicName = "Enter your clinic or organisation name.";
  if (!input.fullName) errors.fullName = "Enter your full name.";
  if (!input.workEmail) {
    errors.workEmail = "Enter your work email.";
  } else if (!isValidEmail(input.workEmail)) {
    errors.workEmail = "Enter a valid work email.";
  }
  if (!input.role) errors.role = "Select or enter your role.";
  if (!input.preferredPlan) errors.preferredPlan = "Select your preferred plan.";
  if (!input.clinicSize) errors.clinicSize = "Select your clinic size.";
  if (!input.currentAiUse) errors.currentAiUse = "Tell us the clinic’s current AI use.";
  if (!input.rolloutTiming) errors.rolloutTiming = "Select your target rollout timing.";
  if (!input.consent) errors.consent = "You must confirm consent before submitting.";
  if (input.honeypot) errors.honeypot = "Spam protection triggered.";

  return errors;
}

export function toStartRequestApiPayload(input: StartRequestPayload): StartRequestApiPayload {
  return {
    clinic_name: input.clinicName,
    full_name: input.fullName,
    work_email: input.workEmail,
    role: input.role,
    preferred_plan: input.preferredPlan,
    clinic_size: input.clinicSize,
    current_ai_use: input.currentAiUse,
    rollout_timing: input.rolloutTiming,
    phone: optionalString(input.phoneNumber),
    site_count: optionalInteger(input.siteCount),
    message: optionalString(input.message),
    consent: input.consent,
    source_page: input.sourcePage,
    utm_source: optionalString(input.utmSource),
    utm_medium: optionalString(input.utmMedium),
    utm_campaign: optionalString(input.utmCampaign),
    website: optionalString(input.honeypot),
  };
}
