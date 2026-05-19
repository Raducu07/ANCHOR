import { apiFetch } from "@/lib/api";
import type { AssistantContractResponse, AssistantRunEnvelope, AssistantRunRecord } from "@/lib/types";

export function getAssistantContract() {
  return apiFetch<AssistantContractResponse>("/v1/assistant/contracts");
}

export type AssistantRunRequest = {
  use_case: string;
  intent_summary: string;
};

export async function submitAssistantRun(req: AssistantRunRequest): Promise<AssistantRunRecord> {
  const result = await apiFetch<AssistantRunEnvelope>("/v1/assistant/runs", {
    method: "POST",
    body: JSON.stringify(req),
  });
  const envelope = result as Record<string, unknown>;
  const run = (envelope.run ?? envelope.record) as AssistantRunRecord | undefined;
  return run ?? (result as unknown as AssistantRunRecord);
}
