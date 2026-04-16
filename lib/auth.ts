import type { LoginResponse, SessionUser } from "@/lib/types";

const TOKEN_KEY = "anchor_access_token";
const SESSION_KEY = "anchor_session_user";

function decodeBase64Url(input: string) {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  return atob(padded);
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    return JSON.parse(decodeBase64Url(parts[1]));
  } catch {
    return null;
  }
}

export function buildSessionFromLoginResponse(payload: LoginResponse, clinicSlug: string, fallbackEmail: string) {
  const token = payload.access_token ?? payload.token;
  if (!token) {
    throw new Error("Login succeeded but no access token was returned.");
  }

  const claims = decodeJwtPayload(token) ?? {};

  const user: SessionUser = {
    clinicId: String(payload.clinic_id ?? claims.clinic_id ?? ""),
    clinicUserId: String(payload.clinic_user_id ?? claims.clinic_user_id ?? claims.sub ?? ""),
    clinicSlug,
    email: String(payload.email ?? claims.email ?? fallbackEmail),
    role: String(payload.role ?? claims.role ?? "clinic_user"),
  };

  return { token, user };
}

export function saveAuthState(token: string, user: SessionUser) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(TOKEN_KEY, token);
  window.localStorage.setItem(SESSION_KEY, JSON.stringify(user));
}

export function clearAuthState() {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(SESSION_KEY);
}

export function getAccessToken() {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function getSessionUser(): SessionUser | null {
  if (typeof window === "undefined") return null;
  const raw = window.localStorage.getItem(SESSION_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as SessionUser;
  } catch {
    return null;
  }
}
