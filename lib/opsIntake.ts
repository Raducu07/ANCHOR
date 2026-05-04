import "server-only";

import { cookies, headers } from "next/headers";
import { NextResponse } from "next/server";

export const OPS_ADMIN_COOKIE_NAME = "ops_admin_session";
export const OPS_ADMIN_FLASH_COOKIE_NAME = "ops_admin_flash";

const SERVER_API_BASE = (process.env.ANCHOR_API_BASE ?? process.env.NEXT_PUBLIC_API_BASE ?? "").replace(/\/$/, "");

function buildServerApiUrl(path: string) {
  if (!SERVER_API_BASE) {
    throw new Error("ANCHOR API base is not configured.");
  }

  return `${SERVER_API_BASE}${path.startsWith("/") ? path : `/${path}`}`;
}

async function buildAdminCookieOptions() {
  const headerStore = await headers();
  const forwardedProto = headerStore.get("x-forwarded-proto");
  const host = headerStore.get("x-forwarded-host") ?? headerStore.get("host") ?? "";
  const hostname = host.split(":")[0].toLowerCase();
  const isLocalhost =
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname === "[::1]" ||
    hostname === "0.0.0.0";
  const secure = !isLocalhost && (forwardedProto === "https" || process.env.NODE_ENV === "production");

  return {
    httpOnly: true,
    sameSite: "strict" as const,
    secure,
    path: "/",
    maxAge: 60 * 60 * 12,
  };
}

function encodeOpsAdminSessionToken(token: string) {
  return `v1.${Buffer.from(token, "utf8").toString("base64url")}`;
}

function decodeOpsAdminSessionToken(value: string) {
  if (!value) return null;

  if (!value.startsWith("v1.")) {
    return value;
  }

  try {
    return Buffer.from(value.slice(3), "base64url").toString("utf8");
  } catch (error) {
    console.warn("Failed to decode ANCHOR ops admin session cookie.", {
      cookiePresent: true,
      cookieLength: value.length,
      errorType: error instanceof Error ? error.name : typeof error,
      errorMessage: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}

export async function getOpsAdminSessionToken() {
  const cookieStore = await cookies();
  const storedValue = cookieStore.get(OPS_ADMIN_COOKIE_NAME)?.value ?? null;
  if (!storedValue) return null;
  return decodeOpsAdminSessionToken(storedValue);
}

export async function getOpsAdminFlashValue() {
  const cookieStore = await cookies();
  return cookieStore.get(OPS_ADMIN_FLASH_COOKIE_NAME)?.value ?? null;
}

export async function verifyOpsAdminToken(token: string) {
  const url = buildServerApiUrl("/v1/admin/intake/summary");

  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
      cache: "no-store",
    });

    if (response.ok) {
      return { ok: true as const };
    }

    if (response.status === 401 || response.status === 403) {
      return { ok: false as const, reason: "invalid" as const };
    }

    const responseBody = await response.text().catch(() => "");
    console.error("ANCHOR ops admin verification upstream failed.", {
      url,
      status: response.status,
      body: responseBody,
      tokenLength: token.length,
    });

    return { ok: false as const, reason: "unavailable" as const };
  } catch (error) {
    console.error("Failed to verify ANCHOR ops admin session.", {
      url,
      tokenLength: token.length,
      errorType: error instanceof Error ? error.name : typeof error,
      errorMessage: error instanceof Error ? error.message : String(error),
    });
    return { ok: false as const, reason: "unavailable" as const };
  }
}

export async function createOpsAdminSessionResponse() {
  const cookieOptions = await buildAdminCookieOptions();
  const response = NextResponse.json({ ok: true });
  return {
    response,
    setToken(token: string) {
      response.cookies.set(OPS_ADMIN_COOKIE_NAME, encodeOpsAdminSessionToken(token), cookieOptions);
      return response;
    },
  };
}

export async function clearOpsAdminSessionResponse() {
  const cookieOptions = await buildAdminCookieOptions();
  const response = NextResponse.json({ ok: true });
  response.cookies.set(OPS_ADMIN_COOKIE_NAME, "", {
    ...cookieOptions,
    maxAge: 0,
  });
  return response;
}

export async function setOpsAdminFlashCookie(
  response: NextResponse,
  value: "invalid" | "missing" | "unavailable" | "rate_limited"
) {
  const cookieOptions = await buildAdminCookieOptions();
  response.cookies.set(OPS_ADMIN_FLASH_COOKIE_NAME, value, {
    ...cookieOptions,
    maxAge: 60,
  });
  return response;
}

export async function clearOpsAdminFlashResponse() {
  const cookieOptions = await buildAdminCookieOptions();
  const response = NextResponse.json({ ok: true });
  response.cookies.set(OPS_ADMIN_FLASH_COOKIE_NAME, "", {
    ...cookieOptions,
    maxAge: 0,
  });
  return response;
}

export async function forwardAdminApiRequest(path: string, init: RequestInit = {}) {
  const token = await getOpsAdminSessionToken();

  if (!token) {
    return NextResponse.json(
      {
        detail: "Internal admin session required.",
      },
      { status: 401 }
    );
  }

  const headers = new Headers(init.headers ?? undefined);
  headers.set("Authorization", `Bearer ${token}`);
  if (!headers.has("Content-Type") && init.body) {
    headers.set("Content-Type", "application/json");
  }

  try {
    const upstreamResponse = await fetch(buildServerApiUrl(path), {
      ...init,
      headers,
      cache: "no-store",
    });

    if (upstreamResponse.status === 401 || upstreamResponse.status === 403) {
      const cookieOptions = await buildAdminCookieOptions();
      const response = NextResponse.json(
        {
          detail: "Internal admin session is invalid or expired.",
        },
        { status: 401 }
      );
      response.cookies.set(OPS_ADMIN_COOKIE_NAME, "", {
        ...cookieOptions,
        maxAge: 0,
      });
      return response;
    }

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      headers: {
        "Content-Type": upstreamResponse.headers.get("content-type") ?? "application/json",
      },
    });
  } catch (error) {
    console.error("Failed to reach ANCHOR admin intake API.", error);
    return NextResponse.json(
      {
        detail: "Unable to reach ANCHOR admin intake services right now.",
      },
      { status: 502 }
    );
  }
}
