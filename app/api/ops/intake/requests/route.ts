import { forwardAdminApiRequest } from "@/lib/opsIntake";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const query = url.searchParams.toString();
  return forwardAdminApiRequest(`/v1/admin/intake/requests${query ? `?${query}` : ""}`);
}
