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
  // Phase 2A-2.4 - governance policy aggregate block. Optional for
  // backward compatibility with older snapshots that pre-date the block.
  governance_policy?: GovernancePolicyTrustBlock;
  // Phase 2A-3.4 — RCVS-aligned self-assessment aggregate block. Optional
  // for backward compatibility with snapshots that pre-date the block.
  self_assessment?: TrustSelfAssessmentBlock;
  // Phase 2A-4.4 - client-facing transparency aggregate block. Optional
  // for backward compatibility with snapshots that pre-date the block.
  client_transparency?: TrustClientTransparencyBlock;
  // Phase 2A-5.4 - incident / near-miss aggregate block. Optional for
  // backward compatibility with snapshots that pre-date the block.
  incident_near_miss?: TrustIncidentNearMissBlock;
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
  // Phase 2A-2.4 - also accepted at the response top level for backends
  // that emit governance_policy as a sibling of snapshot rather than
  // inside it. Optional in both locations so either shape compiles.
  governance_policy?: GovernancePolicyTrustBlock;
};

// Phase 2A-3.9B-2 — Trust Pack now includes evidence-closure sections
// (Learning/CPD, governance policy, staff attestation, self-assessment,
// Assistant receipts). Each evidence section may carry honest-disclosure
// flags and, for self-assessment, a metadata-only templates array. All
// flags are optional so legacy/narrative sections still type-check.
export type TrustPackSelfAssessmentTemplate = {
  template_slug: string;
  template_version: string;
  title: string;
  assessment_status: "submitted" | "superseded" | "none" | string;
  latest_submitted_at: string | null;
  total_questions: number;
  answered_questions: number;
  readiness_summary_counts: TrustSelfAssessmentReadinessSummaryCounts;
  linked_evidence_counts: TrustSelfAssessmentLinkedEvidenceCounts;
  gap_count: number;
};

export type TrustPackSection = {
  id: string;
  title: string;
  body: string;
  bullets: string[];
  // Honest-disclosure flags. All optional; present on the corresponding
  // evidence sections only.
  raw_content_included?: boolean;
  raw_policy_body_included?: boolean;
  staff_identifiers_included?: boolean;
  raw_answers_included?: boolean;
  raw_prompt_included?: boolean;
  raw_output_included?: boolean;
  // Self-assessment evidence carries a metadata-only templates array.
  templates?: TrustPackSelfAssessmentTemplate[];
  // Phase 2A-4.4 - client-transparency evidence honest-disclosure flags.
  active_profile_exists?: boolean;
  published_version_exists?: boolean;
  clinical_content_included?: false;
  client_identifiers_included?: false;
  patient_identifiers_included?: false;
};

export type TrustPackResponse = {
  generated_at: string;
  pack: {
    artifact_type: string;
    artifact_version: string;
    generated_at: string;
    clinic_name: string;
    trust_state: TrustState;
    sections: TrustPackSection[];
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
// Assistant types — M6.1 Assistant Foundation
export type AssistantContractItem = {
  mode?: string;
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

export type AssistantContractResponse = {
  contracts: AssistantContractItem[];
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
  // M6.9.3 — present on the identifier-keyed lookup endpoint
  // (GET /v1/assistant/receipts/{identifier}); absent on the existing
  // per-run endpoint (GET /v1/assistant/runs/{run_id}/receipt).
  matched_by?: "receipt_id" | "run_id" | null;
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
  // M6.11.2 — cursor pagination + filter echo. Optional for forward
  // compatibility: a backend that has not yet deployed the new fields
  // simply omits them, and the UI degrades to a single-page view.
  next_cursor?: string | null;
  has_more?: boolean;
  applied_filters?: {
    run_status?: string | null;
    mode?: string | null;
    has_receipt?: boolean | null;
  };
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

// M6.8 — Assistant analytics into Intelligence (metadata-only).
export type AssistantIntelligenceWindow = {
  days: number;
  start_at: string;
  end_at: string;
};

export type AssistantIntelligenceSummary = {
  total_runs: number;
  draft_generated: number;
  refused_before_model_call: number;
  output_blocked: number;
  generation_failed: number;
  generation_disabled_by_policy: number;
  pii_detected: number;
  reviewed: number;
  approved: number;
  needs_edit: number;
  rejected: number;
  receipt_linked: number;
  default_policy_runs: number;
  policy_versioned_runs: number;
};

export type AssistantIntelligenceRates = {
  draft_generated_rate: number;
  refusal_rate: number;
  output_blocked_rate: number;
  pii_detected_rate: number;
  review_completion_rate: number;
  receipt_completion_rate: number;
  approval_rate_among_reviewed: number;
};

export type AssistantIntelligenceFunnel = {
  submitted: number;
  generated_or_refused_or_blocked: number;
  reviewed: number;
  receipt_created: number;
};

export type AssistantIntelligenceCodeCount = {
  code: string;
  count: number;
};

export type AssistantIntelligenceStatusCount = {
  status: string;
  count: number;
};

export type AssistantIntelligenceProfileCount = {
  validation_profile: string;
  count: number;
};

export type AssistantIntelligenceUsageLimits = {
  daily_limit_per_clinic: number;
  monthly_limit_per_clinic: number;
  runs_today: number;
  runs_this_month: number;
  daily_utilization_rate: number;
  monthly_utilization_rate: number;
  source: "assistant_policy" | "default" | string;
};

export type AssistantIntelligenceSummaryResponse = {
  window: AssistantIntelligenceWindow;
  summary: AssistantIntelligenceSummary;
  rates: AssistantIntelligenceRates;
  funnel: AssistantIntelligenceFunnel;
  top_refusal_reasons: AssistantIntelligenceCodeCount[];
  top_safety_flags: AssistantIntelligenceCodeCount[];
  by_status: AssistantIntelligenceStatusCount[];
  by_review_status: AssistantIntelligenceStatusCount[];
  by_validation_profile: AssistantIntelligenceProfileCount[];
  usage_limits: AssistantIntelligenceUsageLimits;
  governance_note: string;
};

// ---------------------------------------------------------------------
// Phase 2A-1 — CPD-Recordable AI Literacy (Learn). Metadata-only.
// Mirrors the backend Pydantic models in Engineering Brief v1.1 §2.2.
// Known enum values are surfaced as string-literal unions to help the
// UI, but kept open with `| string` so a backend catalogue addition does
// not break the client (same tolerance pattern as Assistant run_status).
// ---------------------------------------------------------------------

export type LearningModuleCategory =
  | "literacy"
  | "bias_detection"
  | "ethical_use"
  | "confidentiality"
  | "transparency"
  | "preparation_for_practice"
  | string;

export type LearningRole =
  | "vet"
  | "nurse"
  | "practice_manager"
  | "admin"
  | "reception"
  | "locum"
  | string;

// ANCHOR-curated global catalogue entry (not clinic-scoped).
export type LearningModule = {
  module_id: string;
  module_slug: string;
  version: string;
  title: string;
  summary: string;
  learning_objectives: string[];
  role_applicability: LearningRole[];
  cpd_minutes: number;
  category: LearningModuleCategory;
  rcvs_principle_mappings: string[];
  eu_ai_act_article_mappings: string[];
  content_reference: string;
  is_active: boolean;
};

// Per-user per-clinic completion record. Corrections use the void fields;
// completions are never silently deleted or overwritten.
export type LearningCompletion = {
  completion_id: string;
  user_id: string;
  module_id: string;
  module_version: string;
  completed_at: string;
  acknowledgement_provided: boolean;
  cpd_minutes_credited: number;
  is_voided: boolean;
  void_reason?: string | null;
  voided_at?: string | null;
  voided_by_user_id?: string | null;
};

export type LearningCompletionCreate = {
  module_id: string;
  acknowledgement_provided?: boolean;
};

export type LearningCompletionVoid = {
  void_reason: string;
};

// Derived per-user CPD record (aggregation of non-voided completions).
export type CPDRecord = {
  user_id: string;
  total_modules_completed: number;
  total_cpd_minutes: number;
  first_completion_at: string | null;
  most_recent_completion_at: string | null;
  completions: LearningCompletion[];
};

// Immutable export artefact metadata. The payload itself is served
// separately via the payload endpoint and is NOT carried on this type.
export type CPDExport = {
  export_id: string;
  user_id: string;
  generated_by_user_id: string;
  export_version: string;
  export_hash: string;
  generated_at: string;
};

// The immutable JSON snapshot returned by the payload endpoint. Strictly
// metadata-only — no raw learning content, no clinical content. The index
// signature tolerates additive backend fields without weakening to `any`
// (same pattern as ReceiptPayload).
export type CPDExportPayload = {
  export_version: string;
  clinic_id: string;
  user_id: string;
  generated_by_user_id: string;
  generated_at: string;
  cpd_summary: {
    total_modules_completed: number;
    total_cpd_minutes: number;
    first_completion_at: string | null;
    most_recent_completion_at: string | null;
  };
  completions: LearningCompletion[];
  [key: string]: unknown;
};

// Aggregated learning evidence for the Trust Pack. Aggregates only — no
// per-user data is surfaced here.
export type TrustPackLearningDelta = {
  total_staff_with_completions: number;
  total_cpd_minutes_delivered: number;
  completion_rate_by_role: Record<string, number>;
  bias_detection_completions: number;
  module_catalogue_count: number;
  last_completion_at: string | null;
};

// ---------------------------------------------------------------------
// Phase 2A-2 - Governance Policy Library + Staff Attestation.
// Metadata-only. The frontend never carries raw policy body text,
// clinical content, staff reflections, names, emails, or any scoring /
// pass-fail / competence grading. Endpoints live under
// /v1/governance/policy.
// ---------------------------------------------------------------------

export type PolicyTemplate = {
  template_id: string;
  template_slug: string;
  template_version: string;
  title: string;
  summary: string;
  category: string;
  role_applicability: string[];
  jurisdiction_tags: string[];
  source_basis: string[];
  content_reference: string;
  content_sha256: string | null;
  is_active: boolean;
  superseded_by: string | null;
  created_at: string;
  updated_at: string;
};

export type PolicyTemplateListResponse = {
  templates: PolicyTemplate[];
  governance_note: string;
};

export type ClinicPolicyStatus =
  | "draft"
  | "active"
  | "superseded"
  | "archived"
  | string;

export type ClinicPolicyVersion = {
  clinic_policy_version_id: string;
  policy_template_id: string;
  template_version_snapshot: string;
  clinic_policy_version: number;
  status: ClinicPolicyStatus;
  title_snapshot: string;
  summary_snapshot: string;
  content_sha256_snapshot: string | null;
  effective_from: string | null;
  created_by_user_id: string;
  activated_by_user_id: string | null;
  activated_at: string | null;
  superseded_at: string | null;
  created_at: string;
  updated_at: string;
  template_slug?: string | null;
};

export type ClinicPolicyVersionResponse = {
  policy: ClinicPolicyVersion;
  governance_note: string;
};

export type ClinicPolicyVersionListResponse = {
  policies: ClinicPolicyVersion[];
  limit: number;
  governance_note: string;
};

export type CreateClinicPolicyInput = {
  template_slug: string;
  template_version?: string;
};

export type PolicyAttestation = {
  attestation_id: string;
  clinic_policy_version_id: string;
  user_id: string;
  attestation_statement_version: string;
  acknowledged_at: string;
  acknowledgement_method: string;
  policy_content_sha256_snapshot: string | null;
  is_voided: boolean;
  void_reason: string | null;
  voided_at: string | null;
  voided_by_user_id: string | null;
  created_at: string;
  template_slug?: string | null;
  policy_title_snapshot?: string | null;
  policy_clinic_policy_version?: number | null;
};

export type PolicyAttestationResponse = {
  attestation: PolicyAttestation;
  governance_note: string;
};

export type PolicyAttestationListResponse = {
  attestations: PolicyAttestation[];
  limit: number;
  governance_note: string;
};

export type OutstandingPolicyListResponse = {
  policies: ClinicPolicyVersion[];
  count: number;
  governance_note: string;
};

export type CreatePolicyAttestationInput = {
  attestation_statement_version?: string;
  acknowledgement_method?: string;
};

export type VoidPolicyAttestationInput = {
  void_reason: string;
};

// Aggregate metadata for the Trust posture governance-policy block.
// Aggregates only; no per-user names, emails, or raw policy content.
export type GovernancePolicyTrustAttestationCoverage = {
  attestation_count: number;
  distinct_user_count: number;
  expected_user_count: number;
  outstanding_user_count: number;
  coverage_rate: number;
  most_recent_acknowledged_at: string | null;
};

export type GovernancePolicyTrustActivePolicy = {
  policy_template_id: string;
  clinic_policy_version_id: string;
  clinic_policy_version: number;
  title: string;
  template_slug: string | null;
  activated_at: string | null;
  attestation_coverage: GovernancePolicyTrustAttestationCoverage;
};

export type GovernancePolicyTrustBlock = {
  active_policy_count: number;
  active_policies: GovernancePolicyTrustActivePolicy[];
  total_attestation_count: number;
  total_distinct_users_attested: number;
  expected_user_count: number;
  outstanding_user_count: number;
  average_coverage_rate: number;
  last_policy_update_at: string | null;
  most_recent_acknowledged_at: string | null;
  // Honest disclosure: this block never carries raw policy body text.
  raw_policy_body_included: false;
  governance_note: string;
};

// ---------------------------------------------------------------------
// Phase 2A-3 — RCVS-aligned self-assessment.
// Metadata-only. The frontend never carries raw assessment answers in
// Trust evidence; staff identifiers are not surfaced in the Trust block.
// Endpoints live under /v1/governance/self-assessment.
// ---------------------------------------------------------------------

export type SelfAssessmentAnswerValue =
  | "yes"
  | "partial"
  | "planned"
  | "no"
  | "not_applicable";

export type SelfAssessmentEvidenceLink =
  | "policy_library"
  | "staff_attestation"
  | "learn_cpd"
  | "assistant_receipts"
  | "trust_posture"
  | "manual_review";

export type ClinicSelfAssessmentStatus =
  | "draft"
  | "submitted"
  | "superseded"
  | "archived";

export type SelfAssessmentTemplate = {
  template_id: string;
  template_slug: string;
  template_version: string;
  title: string;
  summary: string;
  rcvs_principle_mappings: string[];
  eu_ai_act_article_mappings: string[];
  is_active: boolean;
  superseded_by: string | null;
  created_at: string;
  updated_at: string;
};

export type SelfAssessmentQuestion = {
  question_id: string;
  template_id: string;
  question_slug: string;
  question_order: number;
  theme: string;
  prompt_text: string;
  guidance_reference: string;
  evidence_link_hints: string[];
  rcvs_principle_mappings: string[];
  eu_ai_act_article_mappings: string[];
  created_at: string;
};

export type SelfAssessmentAnswer = {
  answer_id: string;
  assessment_id: string;
  question_id: string;
  question_slug_snapshot: string;
  answer_value: SelfAssessmentAnswerValue;
  evidence_links: SelfAssessmentEvidenceLink[];
  answered_by_user_id: string;
  answered_at: string;
  created_at: string;
  updated_at: string;
};

export type ClinicSelfAssessment = {
  assessment_id: string;
  clinic_id: string;
  template_id: string;
  template_slug: string;
  template_version_snapshot: string;
  clinic_assessment_version: number;
  status: ClinicSelfAssessmentStatus;
  title_snapshot: string;
  summary_snapshot: string;
  total_questions: number;
  answered_questions: number;
  readiness_summary_counts: TrustSelfAssessmentReadinessSummaryCounts;
  linked_evidence_counts: TrustSelfAssessmentLinkedEvidenceCounts;
  gap_count: number;
  created_by_user_id: string;
  submitted_by_user_id: string | null;
  submitted_at: string | null;
  superseded_at: string | null;
  archived_at: string | null;
  created_at: string;
  updated_at: string;
  answers?: SelfAssessmentAnswer[];
};

export type LatestSelfAssessmentEntry = {
  template_id: string;
  assessment_id: string;
  clinic_assessment_version: number;
  status: ClinicSelfAssessmentStatus;
  template_version_snapshot: string;
  submitted_at: string | null;
  superseded_at: string | null;
  total_questions_snapshot: number;
  answered_questions_snapshot: number;
  readiness_summary_snapshot: TrustSelfAssessmentReadinessSummaryCounts;
  linked_evidence_counts_snapshot: TrustSelfAssessmentLinkedEvidenceCounts;
};

export type SelfAssessmentTemplateListResponse = {
  templates: SelfAssessmentTemplate[];
  governance_note: string;
};

export type SelfAssessmentTemplateDetailResponse = {
  template: SelfAssessmentTemplate;
  questions: SelfAssessmentQuestion[];
  governance_note: string;
};

export type SelfAssessmentQuestionListResponse = {
  questions: SelfAssessmentQuestion[];
  governance_note: string;
};

export type ClinicSelfAssessmentListResponse = {
  assessments: ClinicSelfAssessment[];
  limit: number;
  governance_note: string;
};

export type ClinicSelfAssessmentResponse = {
  assessment: ClinicSelfAssessment;
  governance_note: string;
};

export type LatestSelfAssessmentResponse = {
  latest: LatestSelfAssessmentEntry[];
  governance_note: string;
};

export type SelfAssessmentCreateRequest = {
  template_slug: string;
  template_version?: string;
};

export type SelfAssessmentAnswerUpsertRequest = {
  answer_value: SelfAssessmentAnswerValue;
  evidence_links: SelfAssessmentEvidenceLink[];
};

// Aggregate self-assessment block exposed via Trust posture. Metadata
// only; no raw answers, no staff identifiers, no per-user data.
export type TrustSelfAssessmentReadinessSummaryCounts = {
  yes: number;
  partial: number;
  planned: number;
  no: number;
  not_applicable: number;
};

export type TrustSelfAssessmentLinkedEvidenceCounts = {
  policy_library: number;
  staff_attestation: number;
  learn_cpd: number;
  assistant_receipts: number;
  trust_posture: number;
  manual_review: number;
};

export type TrustSelfAssessmentTemplateEntry = {
  template_slug: string;
  template_version: string;
  title: string;
  assessment_status: "submitted" | "superseded" | "none";
  latest_submitted_at: string | null;
  last_updated_at: string | null;
  clinic_assessment_version: number | null;
  total_questions: number;
  answered_questions: number;
  readiness_summary_counts: TrustSelfAssessmentReadinessSummaryCounts;
  linked_evidence_counts: TrustSelfAssessmentLinkedEvidenceCounts;
  gap_count: number;
};

export type TrustSelfAssessmentBlock = {
  templates: TrustSelfAssessmentTemplateEntry[];
  latest_submitted_at: string | null;
  submitted_assessment_count: number;
  // Honest disclosure: this block never carries raw answers or staff
  // identifiers. Both flags are always false in the live contract.
  raw_answers_included: false;
  staff_identifiers_included: false;
  governance_note: string;
};

// ---------------------------------------------------------------------
// Phase 2A-4 - Client-Facing Transparency Layer.
// Metadata-only. Plain-language disclosure support surface. Not a
// consent form, not a clinical record, not a compliance certificate,
// not legal advice. Endpoints live under
// /v1/governance/client-transparency.
// ---------------------------------------------------------------------

export interface ClientTransparencySectionDefinition {
  key: string;
  heading: string;
}

export interface ClientTransparencyDefaultSections {
  sections: ClientTransparencySectionDefinition[];
}

export interface ClientTransparencyTemplate {
  template_id: string;
  template_slug: string;
  template_version: string;
  title: string;
  summary: string;
  default_sections: ClientTransparencyDefaultSections;
  default_permitted_categories: string[];
  default_prohibited_categories: string[];
  rcvs_principle_mappings: string[];
  eu_ai_act_article_mappings: string[];
  content_reference: string;
  content_sha256: string | null;
  is_active: boolean;
  superseded_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface ClientTransparencyTemplateListResponse {
  templates: ClientTransparencyTemplate[];
  governance_note: string;
}

export interface ClientTransparencyTemplateResponse {
  template: ClientTransparencyTemplate;
  governance_note: string;
}

export type ClientTransparencyProfileStatus =
  | "draft"
  | "active"
  | "superseded"
  | "archived";

export interface ClientTransparencyProfile {
  clinic_profile_id: string;
  client_transparency_template_id: string;
  template_version_snapshot: string;
  clinic_profile_version: number;
  status: ClientTransparencyProfileStatus;
  display_title: string;
  plain_language_summary: string;
  permitted_use_categories: string[];
  prohibited_use_categories: string[];
  human_review_statement_enabled: boolean;
  privacy_statement_enabled: boolean;
  client_explanation_statement_enabled: boolean;
  content_sha256_snapshot: string | null;
  activated_at: string | null;
  superseded_at: string | null;
  effective_from: string | null;
  created_at: string;
  updated_at: string;
}

export interface ClientTransparencyProfileCreateRequest {
  template_slug: string;
  template_version?: string | null;
  display_title: string;
  plain_language_summary: string;
  permitted_use_categories: string[];
  prohibited_use_categories: string[];
  human_review_statement_enabled?: boolean;
  privacy_statement_enabled?: boolean;
  client_explanation_statement_enabled?: boolean;
}

export interface ClientTransparencyProfileUpdateRequest {
  display_title?: string;
  plain_language_summary?: string;
  permitted_use_categories?: string[];
  prohibited_use_categories?: string[];
  human_review_statement_enabled?: boolean;
  privacy_statement_enabled?: boolean;
  client_explanation_statement_enabled?: boolean;
}

export interface ClientTransparencyProfileResponse {
  profile: ClientTransparencyProfile;
  governance_note: string;
}

export interface ClientTransparencyProfileListResponse {
  profiles: ClientTransparencyProfile[];
  limit: number;
  governance_note: string;
}

export type ClientTransparencyPublicationStatus = "published" | "retired";

export interface ClientTransparencyPublicPayload {
  artifact_type: "client_transparency_statement";
  artifact_version: string;
  template_slug: string;
  template_version: string;
  profile_version: number;
  display_title: string;
  plain_language_summary: string;
  permitted_use_categories: string[];
  prohibited_use_categories: string[];
  sections: ClientTransparencySectionDefinition[];
  statements: {
    human_review_required: boolean;
    privacy_boundaries_included: boolean;
    client_explanation_available: boolean;
  };
  // Honest-disclosure interpretation flags. The literal type names
  // include "not_consent_form" / "not_compliance_certificate" / etc;
  // these are disclaimers, not affirmative claims.
  interpretation: {
    not_legal_advice: boolean;
    not_consent_form: boolean;
    not_clinical_record: boolean;
    not_compliance_certificate: boolean;
    human_professional_review_required: boolean;
  };
}

export interface ClientTransparencyPublicVersion {
  public_version_id: string;
  clinic_profile_id: string;
  public_version: number;
  publication_status: ClientTransparencyPublicationStatus;
  generated_public_payload: ClientTransparencyPublicPayload;
  content_hash: string;
  published_at: string;
  retired_at: string | null;
  created_at: string;
}

export interface ClientTransparencyPublicVersionResponse {
  public_version: ClientTransparencyPublicVersion;
  governance_note: string;
}

export interface ClientTransparencyPublicVersionListResponse {
  public_versions: ClientTransparencyPublicVersion[];
  limit: number;
  governance_note: string;
}

// Aggregate client-transparency block exposed via Trust posture.
// Metadata-only; no raw client/patient content, no identifiers, no
// clinical record fields.
export interface TrustClientTransparencyBlock {
  active_profile_exists: boolean;
  active_profile_status: "active" | "none";
  active_profile_version: number | null;
  active_profile_activated_at: string | null;
  active_template_slug: string | null;
  active_template_version: string | null;
  published_version_exists: boolean;
  latest_public_version: number | null;
  latest_publication_status: "published" | "retired" | "none";
  latest_published_at: string | null;
  permitted_categories_count: number;
  prohibited_categories_count: number;
  human_review_statement_enabled: boolean;
  privacy_statement_enabled: boolean;
  client_explanation_statement_enabled: boolean;
  // Honest disclosures. All flags are always false in the live contract.
  raw_content_included: false;
  clinical_content_included: false;
  staff_identifiers_included: false;
  client_identifiers_included: false;
  patient_identifiers_included: false;
  governance_note: string;
}


// ---------------------------------------------------------------------
// Phase 2A-5 - Incident / Near-Miss Logging.
// Metadata-only. Reflective governance learning surface; not blame, not
// a clinical record, not a legal report. Bounded enums only; no
// free-text request or response fields; no client/patient/staff
// identifiers; no raw prompts/outputs or clinical content.
// ---------------------------------------------------------------------

export type IncidentNearMissStatus =
  | "open"
  | "in_review"
  | "actioned"
  | "closed"
  | "voided";

export type IncidentNearMissSeverity =
  | "low"
  | "moderate"
  | "high"
  | "critical";

export type IncidentNearMissCategory =
  | "misleading_output"
  | "inaccurate_output"
  | "unsafe_suggestion"
  | "privacy_or_identifier_risk"
  | "overconfident_output"
  | "missing_human_review"
  | "policy_boundary_issue"
  | "inappropriate_client_communication"
  | "workflow_confusion"
  | "other";

export type IncidentNearMissSource =
  | "assistant_workspace"
  | "external_ai_tool"
  | "ambient_or_scribe"
  | "client_communication"
  | "internal_summary"
  | "clinical_note_support"
  | "other";

export type IncidentNearMissOutcome =
  | "caught_before_use"
  | "corrected_before_use"
  | "used_with_correction"
  | "escalated_for_review"
  | "client_communication_delayed"
  | "clinical_team_reviewed"
  | "other";

export type IncidentNearMissActionTakenCategory =
  | "no_action_required"
  | "additional_review"
  | "staff_briefing"
  | "policy_review"
  | "process_change"
  | "vendor_followup"
  | "other";

export type IncidentNearMissVoidReasonCategory =
  | "duplicate"
  | "wrong_clinic_record"
  | "test_data"
  | "incorrect_metadata"
  | "other";

export interface IncidentNearMissRecord {
  incident_id: string;
  created_by_user_id?: string | null;
  reviewed_by_user_id?: string | null;
  closed_by_user_id?: string | null;
  voided_by_user_id?: string | null;
  status: IncidentNearMissStatus;
  severity: IncidentNearMissSeverity;
  category: IncidentNearMissCategory;
  source: IncidentNearMissSource;
  outcome: IncidentNearMissOutcome;
  action_taken_category: IncidentNearMissActionTakenCategory | null;
  learning_recommended: boolean;
  policy_review_recommended: boolean;
  client_communication_review_recommended: boolean;
  occurred_at: string | null;
  detected_at: string | null;
  reported_at: string;
  reviewed_at: string | null;
  closed_at: string | null;
  voided_at: string | null;
  linked_receipt_id: string | null;
  linked_governance_event_id: string | null;
  linked_assistant_run_id: string | null;
  linked_clinic_policy_version_id: string | null;
  void_reason_category: IncidentNearMissVoidReasonCategory | null;
  created_at: string;
  updated_at: string;
  raw_content_included: false;
  clinical_content_included: false;
  staff_identifiers_included: false;
  client_identifiers_included: false;
  patient_identifiers_included: false;
}

export interface IncidentNearMissCreateRequest {
  category: IncidentNearMissCategory;
  severity: IncidentNearMissSeverity;
  source: IncidentNearMissSource;
  outcome: IncidentNearMissOutcome;
  occurred_at?: string | null;
  detected_at?: string | null;
  action_taken_category?: IncidentNearMissActionTakenCategory | null;
  learning_recommended?: boolean;
  policy_review_recommended?: boolean;
  client_communication_review_recommended?: boolean;
  linked_receipt_id?: string | null;
  linked_governance_event_id?: string | null;
  linked_assistant_run_id?: string | null;
  linked_clinic_policy_version_id?: string | null;
}

export interface IncidentNearMissUpdateRequest {
  category?: IncidentNearMissCategory;
  severity?: IncidentNearMissSeverity;
  source?: IncidentNearMissSource;
  outcome?: IncidentNearMissOutcome;
  occurred_at?: string | null;
  detected_at?: string | null;
  action_taken_category?: IncidentNearMissActionTakenCategory | null;
  learning_recommended?: boolean;
  policy_review_recommended?: boolean;
  client_communication_review_recommended?: boolean;
}

export interface IncidentNearMissReviewRequest {
  next_status?: "in_review" | "actioned" | null;
  action_taken_category?: IncidentNearMissActionTakenCategory | null;
  learning_recommended?: boolean | null;
  policy_review_recommended?: boolean | null;
  client_communication_review_recommended?: boolean | null;
}

export interface IncidentNearMissVoidRequest {
  void_reason_category: IncidentNearMissVoidReasonCategory;
}

export interface IncidentNearMissVocabularyResponse {
  statuses: IncidentNearMissStatus[];
  severities: IncidentNearMissSeverity[];
  categories: IncidentNearMissCategory[];
  sources: IncidentNearMissSource[];
  outcomes: IncidentNearMissOutcome[];
  action_taken_categories: IncidentNearMissActionTakenCategory[];
  void_reason_categories: IncidentNearMissVoidReasonCategory[];
  governance_note: string;
}

export interface IncidentNearMissRecordResponse {
  record: IncidentNearMissRecord;
  governance_note: string;
}

export interface IncidentNearMissRecordListResponse {
  records: IncidentNearMissRecord[];
  limit: number;
  applied_filters?: Record<string, string | number | boolean | null>;
  governance_note: string;
}

export interface IncidentNearMissSummary {
  window_days: number;
  records_total: number;
  records_in_window?: number;
  records_last_30d?: number;
  open_records: number;
  in_review_records: number;
  actioned_records: number;
  closed_records: number;
  voided_records: number;
  high_or_critical_records: number;
  privacy_related_records: number;
  linked_receipt_records: number;
  learning_recommended_count: number;
  policy_review_recommended_count: number;
  client_communication_review_recommended_count: number;
  last_reported_at: string | null;
  raw_content_included: false;
  clinical_content_included: false;
  staff_identifiers_included: false;
  client_identifiers_included: false;
  patient_identifiers_included: false;
}

export interface IncidentNearMissSummaryResponse {
  summary: IncidentNearMissSummary;
  governance_note: string;
}

// Aggregate incident / near-miss block exposed via Trust posture.
// Metadata-only; no record-level rows, no identifiers, no narrative.
export interface TrustIncidentNearMissBlock {
  window_days: number;
  records_total: number;
  records_last_30d: number;
  open_records: number;
  in_review_records: number;
  actioned_records: number;
  closed_records: number;
  voided_records: number;
  high_or_critical_records: number;
  privacy_related_records: number;
  linked_receipt_records: number;
  learning_recommended_count: number;
  policy_review_recommended_count: number;
  client_communication_review_recommended_count: number;
  last_reported_at: string | null;
  raw_content_included: false;
  clinical_content_included: false;
  staff_identifiers_included: false;
  client_identifiers_included: false;
  patient_identifiers_included: false;
  governance_note: string;
}
