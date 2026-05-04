import { forwardAdminApiRequest } from "@/lib/opsIntake";

export const runtime = "nodejs";

export async function GET() {
  return forwardAdminApiRequest("/v1/admin/intake/summary");
}
