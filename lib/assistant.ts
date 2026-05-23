import { apiFetch } from "@/lib/api";
import type { AssistantContractResponse, AssistantRunEnvelope, AssistantRunRecord } from "@/lib/types";

export function getAssistantContract() {
  return apiFetch<AssistantContractResponse>("/v1/assistant/contracts");
}

// Backend contract (PR 2A + PR 2B):
//   POST /v1/assistant/runs accepts only:
//     mode = "client_communication"
//     input.communication_goal       (non-empty)
//     input.clinician_confirmed_facts (non-empty)
//
//   Persistence is metadata-only (input_sha256, output_sha256, field keys,
//   PII flags, safety flags, governance pointers). Raw input, prompts, and
//   the generated draft are NEVER stored.
//
//   Safe requests may return a transient draft (run_status =
//   "generation_succeeded"). Unsafe clinical requests return
//   run_status = "generation_refused" without invoking the model. Provider
//   failure returns 503.
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
