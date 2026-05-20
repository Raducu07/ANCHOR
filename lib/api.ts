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

  const rawDetail = parsed?.detail;
  const detail = typeof rawDetail === "string" ? rawDetail : undefined;

  if (status === 0) {
    return "Unable to reach the ANCHOR API. Check network access, CORS settings, and API base configuration.";
  }
  if (status === 401) return detail ?? "We couldn’t sign you in with those details.";
  if (status === 403) return detail ?? "This clinic account is not currently available. Contact your administrator.";
  if (status === 404) return detail ?? "The requested record could not be found in this clinic workspace.";
  if (status === 429) return detail ?? "Too many requests. Please wait a moment and try again.";
  if (status >= 500) return "ANCHOR is temporarily unavailable. Please try again.";

  // 400/422 — FastAPI may return `detail` as a string (preferred) or an
  // array of validation error objects. Render the array as a short summary
  // rather than a raw JSON wall.
  if (Array.isArray(rawDetail)) {
    const messages = rawDetail
      .map((item) => {
        if (!item || typeof item !== "object") return null;
        const entry = item as Record<string, unknown>;
        const msg = typeof entry.msg === "string" ? entry.msg : null;
        const loc = Array.isArray(entry.loc)
          ? entry.loc
              .filter((p) => typeof p === "string" || typeof p === "number")
              .slice(1) // drop the leading "body"/"query" segment
              .join(".")
          : "";
        if (!msg) return null;
        return loc ? `${loc}: ${msg}` : msg;
      })
      .filter((m): m is string => Boolean(m));
    if (messages.length) {
      return messages.length === 1 ? messages[0] : messages.join("; ");
    }
  }

  return detail ?? text ?? "Request failed.";
}

export async function apiFetch<T>(path: string, options: ApiFetchOptions = {}): Promise<T> {
  const { auth = true, headers, ...rest } = options;

  let response: Response;
  try {
    const requestHeaders = new Headers({
      "Content-Type": "application/json",
    });

    if (auth) {
      for (const [key, value] of Object.entries(getAuthHeaders())) {
        requestHeaders.set(key, value);
      }
    }

    if (headers instanceof Headers) {
      headers.forEach((value, key) => requestHeaders.set(key, value));
    } else if (Array.isArray(headers)) {
      headers.forEach(([key, value]) => requestHeaders.set(key, value));
    } else if (headers) {
      for (const [key, value] of Object.entries(headers)) {
        if (typeof value !== "undefined") {
          requestHeaders.set(key, String(value));
        }
      }
    }

    response = await fetch(buildApiUrl(path), {
      ...rest,
      headers: requestHeaders,
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
