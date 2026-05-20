import { apiFetch } from "@/lib/api";
import type { AssistantContractResponse, AssistantRunEnvelope, AssistantRunRecord } from "@/lib/types";

export function getAssistantContract() {
  return apiFetch<AssistantContractResponse>("/v1/assistant/contracts");
}

// PR 2A backend contract:
//   POST /v1/assistant/runs accepts only:
//     mode = "client_communication"
//     input.communication_goal      (non-empty)
//     input.clinician_confirmed_facts (non-empty)
//   The backend persists metadata only and returns no generated output.
export const ASSISTANT_MODE_CLIENT_COMMUNICATION = "client_communication" as const;

export type ClientCommunicationInput = {
  communication_goal: string;
  clinician_confirmed_facts: string;
};

export type AssistantRunRequest = {
  mode: typeof ASSISTANT_MODE_CLIENT_COMMUNICATION;
  input: ClientCommunicationInput;
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
