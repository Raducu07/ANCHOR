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
  pii_detected?: boolean;
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