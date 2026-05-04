import { NextResponse } from "next/server";
import {
  createOpsAdminSessionResponse,
  setOpsAdminFlashCookie,
  verifyOpsAdminToken,
} from "@/lib/opsIntake";

export const runtime = "nodejs";

const RATE_LIMIT_MAX_ATTEMPTS = 5;
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;

type AttemptRecord = { count: number; firstAttemptAt: number };
const loginAttempts = new Map<string, AttemptRecord>();

function getClientKey(request: Request): string {
  const forwardedFor = request.headers.get("x-forwarded-for");
  if (forwardedFor) {
    const first = forwardedFor.split(",")[0]?.trim();
    if (first) return first;
  }
  const realIp = request.headers.get("x-real-ip");
  if (realIp) return realIp.trim();
  return "unknown";
}

function isRateLimited(key: string): boolean {
  const now = Date.now();
  const record = loginAttempts.get(key);
  if (!record) return false;
  if (now - record.firstAttemptAt > RATE_LIMIT_WINDOW_MS) {
    loginAttempts.delete(key);
    return false;
  }
  return record.count >= RATE_LIMIT_MAX_ATTEMPTS;
}

function recordFailedAttempt(key: string) {
  const now = Date.now();
  const record = loginAttempts.get(key);
  if (!record || now - record.firstAttemptAt > RATE_LIMIT_WINDOW_MS) {
    loginAttempts.set(key, { count: 1, firstAttemptAt: now });
    return;
  }
  record.count += 1;
}

function clearAttempts(key: string) {
  loginAttempts.delete(key);
}

function buildRedirectUrl(request: Request) {
  return new URL("/ops/admin-login", request.url);
}

export async function POST(request: Request) {
  const contentType = request.headers.get("content-type") ?? "";
  const isJsonRequest = contentType.includes("application/json");
  const clientKey = getClientKey(request);

  if (isRateLimited(clientKey)) {
    if (!isJsonRequest) {
      const response = NextResponse.redirect(buildRedirectUrl(request), { status: 303 });
      return setOpsAdminFlashCookie(response, "rate_limited");
    }
    return NextResponse.json(
      { detail: "Too many attempts. Try again later." },
      { status: 429 }
    );
  }

  let token = "";

  if (isJsonRequest) {
    const payload = (await request.json().catch(() => null)) as { token?: string } | null;
    token = typeof payload?.token === "string" ? payload.token.trim() : "";
  } else {
    const formData = await request.formData().catch(() => null);
    token = typeof formData?.get("token") === "string" ? String(formData.get("token")).trim() : "";
  }

  if (!token) {
    recordFailedAttempt(clientKey);
    if (!isJsonRequest) {
      const response = NextResponse.redirect(buildRedirectUrl(request), { status: 303 });
      return setOpsAdminFlashCookie(response, "missing");
    }

    return NextResponse.json(
      {
        detail: "Enter the internal admin token.",
      },
      { status: 400 }
    );
  }

  const verification = await verifyOpsAdminToken(token);

  if (!verification.ok && verification.reason === "invalid") {
    recordFailedAttempt(clientKey);
    if (!isJsonRequest) {
      const response = NextResponse.redirect(buildRedirectUrl(request), { status: 303 });
      return setOpsAdminFlashCookie(response, "invalid");
    }

    return NextResponse.json(
      {
        detail: "That internal admin token was not accepted.",
      },
      { status: 401 }
    );
  }

  if (!verification.ok) {
    recordFailedAttempt(clientKey);
    if (!isJsonRequest) {
      const response = NextResponse.redirect(buildRedirectUrl(request), { status: 303 });
      return setOpsAdminFlashCookie(response, "unavailable");
    }

    return NextResponse.json(
      {
        detail: "Unable to continue to intake operations right now.",
      },
      { status: 502 }
    );
  }

  clearAttempts(clientKey);

  try {
    const sessionResponse = await createOpsAdminSessionResponse();
    const response = sessionResponse.setToken(token);

    if (!isJsonRequest) {
      const redirectResponse = NextResponse.redirect(
        new URL("/ops/admin-login?verified=1", request.url),
        { status: 303 }
      );
      for (const cookie of response.cookies.getAll()) {
        redirectResponse.cookies.set(cookie);
      }
      return redirectResponse;
    }

    return response;
  } catch (error) {
    console.error("Failed to create ANCHOR ops admin session cookie.", error);

    if (!isJsonRequest) {
      const response = NextResponse.redirect(buildRedirectUrl(request), { status: 303 });
      return setOpsAdminFlashCookie(response, "unavailable");
    }

    return NextResponse.json(
      {
        detail: "Unable to continue to intake operations right now.",
      },
      { status: 502 }
    );
  }
}
