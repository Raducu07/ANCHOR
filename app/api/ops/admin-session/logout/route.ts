import { clearOpsAdminSessionResponse } from "@/lib/opsIntake";

export const runtime = "nodejs";

export async function POST() {
  return clearOpsAdminSessionResponse();
}
