export type SessionUser = {
  clinicId: string;
  clinicUserId: string;
  clinicSlug: string;
  email: string;
  role: string;
};

export type LoginResponse = {
  access_token?: string;
  token?: string;
  clinic_id?: string;
  clinic_user_id?: string;
  role?: string;
  email?: string;
  [key: string]: unknown;
};

export type DashboardResponse = {
  now_utc?: string;
  trust_state?: {
    health_state?: string;
    reasons?: string[];
    derived_from?: string;
  };
  kpis_24h?: {
    window_hours?: number;
    events_24h?: number;
    events_per_hour?: number;
    interventions_24h?: number;
    intervention_rate_24h?: number;
    pii_warned_24h?: number;
    pii_warned_rate_24h?: number;
    top_mode_24h?: string | null;
    top_route_24h?: string | null;
    derived_from?: string;
  };
  recent_submissions?: Array<{
    request_id?: string;
    clinic_user_id?: string;
    mode?: string;
    decision?: string;
    risk_grade?: string;
    reason_code?: string;
    pii_detected?: boolean;
    created_at?: string;
    created_at_utc?: string;
  }>;
  latest_receipt?: {
    request_id?: string;
    clinic_id?: string;
    clinic_user_id?: string;
    mode?: string;
    decision?: string;
    risk_grade?: string;
    reason_code?: string;
    pii_detected?: boolean;
    pii_action?: string;
    pii_types?: string[];
    policy_version?: number;
    policy_hash?: string;
    policy_id?: string;
    neutrality_version?: string;
    governance_score?: number | null;
    override_flag?: boolean;
    override_reason?: string | null;
    override_at_utc?: string | null;
    receipt_version?: string;
    jwt_iss?: string;
    jwt_aud?: string;
    tenant_isolation?: {
      rls_forced?: boolean;
    };
    no_content_stored?: boolean;
    created_at_utc?: string;
  };
  latest_signed_receipt_url?: string | null;
};

export type GovernanceEventSummary = {
  request_id?: string;
  mode?: string;
  decision?: string;
  risk_grade?: string;
  reason_code?: string;
  created_at?: string;
  created_at_utc?: string;
  pii_detected?: boolean;
  pii_action?: string;
};

export type GovernanceEventListEnvelope = {
  events?: GovernanceEventSummary[];
  items?: GovernanceEventSummary[];
  rows?: GovernanceEventSummary[];
};

export type ReceiptPayload = {
  request_id?: string;
  mode?: string;
  decision?: string;
  risk_grade?: string;
  reason_code?: string;
  created_at?: string;
  created_at_utc?: string;
  governance_score?: number;
  policy_version?: number;
  neutrality_version?: string;
  pii_detected?: boolean;
  pii_action?: string;
  pii_types?: string[];
  override_flag?: boolean;
  policy_hash?: string;
  policy_sha256?: string;
  no_content_stored?: boolean;
  [key: string]: unknown;
};

export type ReceiptEnvelope = {
  receipt: ReceiptPayload;
};

export type TrustState = "green" | "yellow" | "red";
export type TrustSignalQuality = "low" | "moderate" | "strong";

export type TrustSnapshot = {
  snapshot_version: string;
  generated_at: string;
  evidence_window: {
    hours: number;
    from: string;
    to: string;
  };
  clinic: {
    clinic_id: string;
    clinic_name: string;
    clinic_slug: string;
    active_status: boolean;
  };
  governance: {
    policy_version: number;
    policy_versioning: boolean;
    governance_receipts_active: boolean;
    metadata_only_accountability: boolean;
    stores_raw_content: boolean;
    override_model: string;
    events_24h: number;
    interventions_24h: number;
    intervention_rate_24h: number;
  };
  privacy: {
    privacy_controls_active: boolean;
    privacy_controls_label: string;
    hashed_ip_ua_logging: boolean;
    stores_raw_prompt_output: boolean;
    pii_warned_24h: number;
    pii_warned_rate_24h: number;
  };
  tenancy: {
    hard_multi_tenancy: boolean;
    rls_forced: boolean;
    request_scoped_context: boolean;
    clinic_scoped_portal_access: boolean;
    tenant_isolation_testing_in_operating_model: boolean;
  };
  operations: {
    trust_state: TrustState;
    signal_quality: TrustSignalQuality;
    request_count_24h: number;
    events_24h: number;
    interventions_24h: number;
    intervention_rate_24h: number;
    pii_warned_24h: number;
    pii_warned_rate_24h: number;
    rate_5xx: number;
    p95_latency_ms: number;
    gov_replaced_rate: number;
    top_mode_24h: string | null;
    top_route_24h: string | null;
  };
  learning: {
    enabled: boolean;
    cards_available: boolean;
    explainers_available: boolean;
    dashboard_tie_in: boolean;
    receipts_related_learning: boolean;
    recommended_learning: {
      title: string;
      reason: string;
    };
  };
  limitations: string[];
};

export type TrustProfileResponse = {
  clinic_name: string;
  clinic_slug: string;
  trust_state: TrustState;
  policy_version: number;
  governance_receipts_active: boolean;
  privacy_controls_label: string;
  metadata_only_accountability: boolean;
  stores_raw_content: boolean;
  events_24h: number;
  interventions_24h: number;
  intervention_rate_24h: number;
  pii_warned_24h: number;
  pii_warned_rate_24h: number;
  top_mode_24h: string | null;
  top_route_24h: string | null;
  generated_at: string;
  snapshot: TrustSnapshot;
};

export type TrustPostureResponse = {
  generated_at: string;
  headline: string;
  summary: string;
  sections: {
    id: string;
    title: string;
    status: string;
    items: string[];
  }[];
  snapshot: TrustSnapshot;
};

export type TrustPackResponse = {
  generated_at: string;
  pack: {
    artifact_type: string;
    artifact_version: string;
    generated_at: string;
    clinic_name: string;
    trust_state: TrustState;
    sections: {
      id: string;
      title: string;
      body: string;
      bullets: string[];
    }[];
    evidence_window: {
      hours: number;
      from: string;
      to: string;
    };
  };
  snapshot: TrustSnapshot;
};

export type TrustMaterialsResponse = {
  generated_at: string;
  materials: {
    id: string;
    title: string;
    body: string;
  }[];
  notes: string[];
  snapshot: TrustSnapshot;
};

export type IntelligenceRecommendation = {
  type: "learning" | "policy_review" | "privacy_training" | "workflow_guidance";
  priority: "low" | "medium" | "high";
  title: string;
  why: string;
  based_on: {
    dimension: string;
    key: string;
  };
  target_path: string | null;
};

export type IntelligenceHotspot = {
  dimension: string;
  key: string;
  event_count: number;
  event_share: number;
  intervention_count: number;
  intervention_rate: number;
  pii_warned_count: number;
  pii_warned_rate: number;
  recency_spike_ratio: number;
  share_of_all_interventions?: number;
  severity_score: number;
  severity: "low" | "medium" | "high";
  summary: string;
};

export type IntelligenceSummary = {
  generated_at: string;
  window: "7d" | "30d";
  overall: {
    events: number;
    intervention_rate: number;
    pii_warned_rate: number;
    top_mode: string | null;
    top_route: string | null;
    top_reason_code: string | null;
  };
  headline_hotspot: IntelligenceHotspot | null;
  headline_action: IntelligenceRecommendation | null;
};

export type IntelligenceHotspotsResponse = {
  generated_at: string;
  window: "7d" | "30d";
  limit: number;
  items: IntelligenceHotspot[];
};

export type IntelligenceRecommendationsResponse = {
  generated_at: string;
  window: "7d" | "30d";
  items: IntelligenceRecommendation[];
};
// Assistant types â€” M6.1 Assistant Foundation
export type AssistantContractResponse = {
  contract_id?: string;
  contract_version?: string;
  version?: string;
  status?: string;
  storage_policy?: string;
  storage_decision?: string;
  no_raw_content?: boolean;
  metadata_only?: boolean;
  policy_version?: number;
  boundaries?: string[];
  allowed_uses?: string[];
  prohibited_uses?: string[];
  issued_at?: string;
  created_at?: string;
  [key: string]: unknown;
};

export type AssistantRunRecord = {
  run_id?: string;
  request_id?: string;
  contract_version?: string;
  contract_id?: string;
  status?: string;
  storage_decision?: string;
  no_raw_content_stored?: boolean;
  no_content_stored?: boolean;
  policy_version?: number;
  policy_decision?: string;
  risk_grade?: string;
  reason_code?: string;
  mode?: string;
  created_at?: string;
  created_at_utc?: string;
  // PR 2A metadata-only fields
  pii_detected?: boolean;
  pii_types?: string[];
  input_field_keys?: string[];
  review_status?: string;
  output_sha256?: string | null;
  model_provider?: string | null;
  model_name?: string | null;
  generation_enabled?: boolean;
  governance_note?: string;
  // PR 2B governed generation fields. Frontend must tolerate any missing
  // field for backward compatibility with PR 2A-style responses.
  run_status?:
    | "created"
    | "generation_succeeded"
    | "generation_refused"
    | "generation_failed"
    | "output_blocked"
    | string;
  draft?: string | null;
  refused?: boolean;
  // M6.6 — true when the model was invoked but ANCHOR blocked the
  // generated draft before returning it. Distinct from `refused`, which
  // means the model was not invoked at all.
  blocked?: boolean;
  blocked_message?: string | null;
  refusal_reason_codes?: string[];
  safety_flags?: string[];
  // M6.7.1 — policy context. Null when the run was governed by the
  // synthesised default policy; "standard" is the default profile.
  assistant_policy_id?: string | null;
  assistant_policy_version?: number | null;
  assistant_validation_profile?: "standard" | "conservative" | string | null;
  [key: string]: unknown;
};

export type AssistantRunEnvelope = {
  run?: AssistantRunRecord;
  record?: AssistantRunRecord;
  [key: string]: unknown;
};

// M6.3 — Assistant traceability / evidence surface (metadata only).
//
// The trace item is what GET /v1/assistant/runs and GET /v1/assistant/runs/:id
// return. It deliberately has NO `draft` / `input` / `prompt` field — those
// are not stored by the backend and must not be implied by the wire type.

export type AssistantRunTraceItem = {
  run_id: string;
  clinic_id: string;
  clinic_user_id: string;
  mode: string;
  contract_version: string;
  workflow_origin: string;
  input_sha256: string;
  output_sha256: string | null;
  input_field_keys: string[];
  pii_detected: boolean;
  pii_types: string[];
  safety_flags: string[];
  refusal_reason_codes: string[];
  review_status: string;
  run_status:
    | "created"
    | "generation_succeeded"
    | "generation_refused"
    | "generation_failed"
    | "output_blocked"
    | string;
  receipt_id: string | null;
  governance_event_id: string | null;
  model_provider: string | null;
  model_name: string | null;
  // M6.4 — metadata-only human review evidence. Optional for backward
  // compatibility with older deployments / stale clients.
  review_decision?: string | null;
  reviewed_at?: string | null;
  reviewed_by_user_id?: string | null;
  // M6.5 — metadata-only receipt linkage. `receipt_id` is already
  // declared above (M6.3); these complement it.
  has_receipt?: boolean;
  receipt_created_at?: string | null;
  // M6.7.1 — policy context for this run. Null when the run was
  // governed by the synthesised default policy.
  assistant_policy_id?: string | null;
  assistant_policy_version?: number | null;
  assistant_validation_profile?: "standard" | "conservative" | string | null;
  created_at: string;
  updated_at: string | null;
};

// M6.5 — Assistant receipt (metadata only).
export type AssistantRunReceipt = {
  receipt_id: string;
  assistant_run_id: string;
  clinic_id: string;
  created_by_user_id: string;
  receipt_kind: string;
  receipt_version: string;
  storage_policy: string;
  raw_content_stored: boolean;
  prompt_stored: boolean;
  draft_stored: boolean;
  run_status: string;
  review_status: string;
  review_decision?: string | null;
  input_sha256: string;
  output_sha256: string | null;
  mode: string;
  contract_version: string;
  workflow_origin: string;
  pii_detected: boolean;
  pii_types: string[];
  safety_flags: string[];
  refusal_reason_codes: string[];
  model_provider: string | null;
  model_name: string | null;
  // M6.7.1 — policy context snapshot on the receipt. Null on legacy
  // receipts written before policy stamping, and on runs governed by
  // the default policy.
  assistant_policy_id?: string | null;
  assistant_policy_version?: number | null;
  assistant_validation_profile?: "standard" | "conservative" | string | null;
  assistant_run_created_at: string;
  assistant_run_reviewed_at?: string | null;
  assistant_run_reviewed_by_user_id?: string | null;
  receipt_created_at: string;
  created_at: string;
  updated_at?: string | null;
};

export type AssistantRunReceiptResponse = {
  receipt: AssistantRunReceipt;
  run: AssistantRunTraceItem;
  governance_note: string;
};

// M6.4 — review-state PATCH wire types.
export type AssistantReviewStatusInput =
  | "reviewed_approved"
  | "reviewed_rejected"
  | "reviewed_needs_edit";

export type AssistantRunReviewUpdateRequest = {
  review_status: AssistantReviewStatusInput;
};

export type AssistantRunReviewUpdateResponse = AssistantRunDetailResponse;

export type AssistantRunListResponse = {
  runs: AssistantRunTraceItem[];
  limit: number;
};

export type AssistantRunDetailResponse = {
  run: AssistantRunTraceItem;
  storage_policy: string;
  raw_content_stored: boolean;
  draft_stored: boolean;
  prompt_stored: boolean;
  governance_note: string;
};

// M6.7 — Assistant policy / settings.
export type AssistantValidationProfile = "standard" | "conservative";

export type AssistantPolicySettings = {
  id: string | null;
  clinic_id: string | null;
  policy_version: number;
  is_active: boolean;
  is_default: boolean;
  client_communication_enabled: boolean;
  generation_enabled: boolean;
  validation_profile: AssistantValidationProfile | string;
  daily_run_limit_per_clinic: number;
  monthly_run_limit_per_clinic: number;
  require_human_review: boolean;
  allow_receipts_after_review: boolean;
  policy_label: string;
  policy_notes: string | null;
  created_by_user_id: string | null;
  created_at: string | null;
  activated_at: string | null;
};

export type AssistantPolicyResponse = {
  policy: AssistantPolicySettings;
  governance_note: string;
};

export type AssistantPolicyUpdatePayload = {
  client_communication_enabled?: boolean;
  generation_enabled?: boolean;
  validation_profile?: AssistantValidationProfile;
  daily_run_limit_per_clinic?: number;
  monthly_run_limit_per_clinic?: number;
  policy_label?: string;
  policy_notes?: string | null;
};

export type AssistantPolicyHistoryItem = {
  policy_version: number;
  is_active: boolean;
  validation_profile: string;
  client_communication_enabled: boolean;
  generation_enabled: boolean;
  daily_run_limit_per_clinic: number;
  monthly_run_limit_per_clinic: number;
  policy_label: string;
  created_at: string;
  activated_at: string | null;
  superseded_at: string | null;
  created_by_user_id: string | null;
};

export type AssistantPolicyHistoryResponse = {
  items: AssistantPolicyHistoryItem[];
};
