import { getAccessToken } from "@/lib/auth";

type ApiFetchOptions = RequestInit & {
  auth?: boolean;
};

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

const API_BASE = (process.env.NEXT_PUBLIC_API_BASE ?? "").replace(/\/$/, "");

export function buildApiUrl(path: string) {
  if (!API_BASE) return path;
  return `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;
}

export function getAuthHeaders() {
  const token = getAccessToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export function normalizeApiErrorMessage(status: number, rawText: string) {
  const text = rawText.trim();
  let parsed: Record<string, unknown> | null = null;

  if (text) {
    try {
      parsed = JSON.parse(text) as Record<string, unknown>;
    } catch {
      parsed = null;
    }
  }

  const detail = typeof parsed?.detail === "string" ? parsed.detail : undefined;

  if (status === 0) {
    return "Unable to reach the ANCHOR API. Check network access, CORS settings, and API base configuration.";
  }
  if (status === 401) return detail ?? "We couldn’t sign you in with those details.";
  if (status === 403) return detail ?? "This clinic account is not currently available. Contact your administrator.";
  if (status === 404) return detail ?? "The requested record could not be found in this clinic workspace.";
  if (status === 429) return detail ?? "Too many requests. Please wait a moment and try again.";
  if (status >= 500) return "ANCHOR is temporarily unavailable. Please try again.";
  return detail ?? text ?? "Request failed.";
}

export async function apiFetch<T>(path: string, options: ApiFetchOptions = {}): Promise<T> {
  const { auth = true, headers, ...rest } = options;

  let response: Response;
  try {
    response = await fetch(buildApiUrl(path), {
      ...rest,
      headers: {
        "Content-Type": "application/json",
        ...(auth ? getAuthHeaders() : {}),
        ...(headers ?? {}),
      },
    });
  } catch {
    throw new ApiError(
      normalizeApiErrorMessage(
        0,
        "Unable to reach the ANCHOR API. Check network access, CORS settings, and API base configuration."
      ),
      0
    );
  }

  if (!response.ok) {
    const text = await response.text();
    throw new ApiError(normalizeApiErrorMessage(response.status, text), response.status);
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return (await response.json()) as T;
  }

  return (await response.text()) as T;
}