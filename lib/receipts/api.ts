import { apiFetch } from "@/lib/api";
import type { DashboardResponse, ReceiptPayload } from "@/lib/types";

export type RecentSubmission = NonNullable<DashboardResponse["recent_submissions"]>[number] & {
  created_at?: string;
};

export async function fetchReceipt(requestId: string): Promise<ReceiptPayload> {
  const path = `/v1/portal/receipt/${encodeURIComponent(requestId)}`;
  const payload = await apiFetch<unknown>(path);

  if (
    payload &&
    typeof payload === "object" &&
    "receipt" in payload &&
    (payload as { receipt?: unknown }).receipt
  ) {
    return (payload as { receipt: ReceiptPayload }).receipt;
  }

  return payload as ReceiptPayload;
}

export async function fetchRecentSubmissions(): Promise<RecentSubmission[]> {
  const payload = await apiFetch<DashboardResponse>("/v1/portal/dashboard");
  return Array.isArray(payload?.recent_submissions) ? payload.recent_submissions : [];
}
