export type IntakeTrackingFields = {
  sourcePage: string;
  utmSource?: string;
  utmMedium?: string;
  utmCampaign?: string;
  utmTerm?: string;
  utmContent?: string;
  honeypot?: string;
};

export function normalizeString(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

export function isValidEmail(value: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

export function optionalString(value: string | undefined) {
  return value && value.length > 0 ? value : undefined;
}

export function optionalInteger(value: string | undefined) {
  if (!value) return undefined;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : undefined;
}
