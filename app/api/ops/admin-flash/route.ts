import { clearOpsAdminFlashResponse } from "@/lib/opsIntake";

export const runtime = "nodejs";

export async function POST() {
  return clearOpsAdminFlashResponse();
}
