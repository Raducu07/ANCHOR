import { NextResponse } from "next/server";
import { forwardAdminApiRequest } from "@/lib/opsIntake";

export const runtime = "nodejs";

const ALLOWED_KINDS = new Set(["demo", "start"]);
const STATUS_MIN_LENGTH = 2;
const STATUS_MAX_LENGTH = 32;

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ kind: string; id: string }> }
) {
  const { kind, id } = await params;

  if (!ALLOWED_KINDS.has(kind)) {
    return NextResponse.json({ detail: "Unsupported intake kind." }, { status: 400 });
  }

  const trimmedId = typeof id === "string" ? id.trim() : "";
  if (!trimmedId) {
    return NextResponse.json({ detail: "Missing intake request id." }, { status: 400 });
  }

  const payload = (await request.json().catch(() => null)) as { status?: unknown } | null;

  if (!payload || typeof payload !== "object") {
    return NextResponse.json({ detail: "Invalid request body." }, { status: 400 });
  }

  const rawStatus = payload.status;
  if (typeof rawStatus !== "string") {
    return NextResponse.json({ detail: "Status is required." }, { status: 400 });
  }

  const status = rawStatus.trim();
  if (status.length < STATUS_MIN_LENGTH || status.length > STATUS_MAX_LENGTH) {
    return NextResponse.json(
      { detail: "Status must be between 2 and 32 characters." },
      { status: 400 }
    );
  }

  return forwardAdminApiRequest(
    `/v1/admin/intake/request/${kind}/${encodeURIComponent(trimmedId)}`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    }
  );
}
