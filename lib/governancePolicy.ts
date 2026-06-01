// lib/governancePolicy.ts
//
// Phase 2A-2 - Governance Policy Library + Staff Attestation API client.
//
// Doctrine:
//   * Metadata only. No raw policy body text, clinical content, staff
//     reflections, names, emails, scores, pass/fail, or competence
//     grading is ever sent or stored client-side.
//   * Endpoints are clinic-scoped on the backend (RLS); the frontend
//     does not pass clinic_id explicitly.
//   * Query string parameter names mirror the backend snake_case
//     contract.
//   * Standard apiFetch flow; standard ApiError propagation.

import { apiFetch } from "@/lib/api";
import type {
  ClinicPolicyVersionListResponse,
  ClinicPolicyVersionResponse,
  CreateClinicPolicyInput,
  CreatePolicyAttestationInput,
  OutstandingPolicyListResponse,
  PolicyAttestationListResponse,
  PolicyAttestationResponse,
  PolicyTemplate,
  PolicyTemplateListResponse,
  VoidPolicyAttestationInput,
} from "@/lib/types";

// ----- Policy templates ------------------------------------------------

export function listPolicyTemplates(
  opts: { includeInactive?: boolean; category?: string } = {},
): Promise<PolicyTemplateListResponse> {
  const query = new URLSearchParams();
  if (opts.includeInactive) query.set("include_inactive", "true");
  if (opts.category) query.set("category", opts.category);
  const qs = query.toString();
  const url = qs
    ? `/v1/governance/policy/templates?${qs}`
    : "/v1/governance/policy/templates";
  return apiFetch<PolicyTemplateListResponse>(url);
}

export function getPolicyTemplate(
  templateSlug: string,
): Promise<PolicyTemplate> {
  return apiFetch<PolicyTemplate>(
    `/v1/governance/policy/templates/${encodeURIComponent(templateSlug)}`,
  );
}

// ----- Clinic policy versions -----------------------------------------

export function createClinicPolicy(
  input: CreateClinicPolicyInput,
): Promise<ClinicPolicyVersionResponse> {
  return apiFetch<ClinicPolicyVersionResponse>(
    "/v1/governance/policy/clinic-policies",
    {
      method: "POST",
      body: JSON.stringify(input),
    },
  );
}

export function listClinicPolicies(
  opts: {
    status?: string;
    templateSlug?: string;
    limit?: number;
  } = {},
): Promise<ClinicPolicyVersionListResponse> {
  const query = new URLSearchParams();
  if (opts.status) query.set("status", opts.status);
  if (opts.templateSlug) query.set("template_slug", opts.templateSlug);
  if (typeof opts.limit === "number") query.set("limit", String(opts.limit));
  const qs = query.toString();
  const url = qs
    ? `/v1/governance/policy/clinic-policies?${qs}`
    : "/v1/governance/policy/clinic-policies";
  return apiFetch<ClinicPolicyVersionListResponse>(url);
}

export function listActiveClinicPolicies(): Promise<ClinicPolicyVersionListResponse> {
  return apiFetch<ClinicPolicyVersionListResponse>(
    "/v1/governance/policy/clinic-policies/active",
  );
}

export function activateClinicPolicy(
  clinicPolicyVersionId: string,
): Promise<ClinicPolicyVersionResponse> {
  return apiFetch<ClinicPolicyVersionResponse>(
    `/v1/governance/policy/clinic-policies/${encodeURIComponent(
      clinicPolicyVersionId,
    )}/activate`,
    {
      method: "POST",
      body: JSON.stringify({}),
    },
  );
}

export function archiveClinicPolicy(
  clinicPolicyVersionId: string,
): Promise<ClinicPolicyVersionResponse> {
  return apiFetch<ClinicPolicyVersionResponse>(
    `/v1/governance/policy/clinic-policies/${encodeURIComponent(
      clinicPolicyVersionId,
    )}/archive`,
    {
      method: "POST",
      body: JSON.stringify({}),
    },
  );
}

// ----- Staff attestations ---------------------------------------------

export function listOutstandingPolicyAttestations(): Promise<OutstandingPolicyListResponse> {
  return apiFetch<OutstandingPolicyListResponse>(
    "/v1/governance/policy/me/outstanding",
  );
}

export function attestToClinicPolicy(
  clinicPolicyVersionId: string,
  input: CreatePolicyAttestationInput = {},
): Promise<PolicyAttestationResponse> {
  return apiFetch<PolicyAttestationResponse>(
    `/v1/governance/policy/clinic-policies/${encodeURIComponent(
      clinicPolicyVersionId,
    )}/attest`,
    {
      method: "POST",
      body: JSON.stringify(input),
    },
  );
}

export function listMyPolicyAttestations(
  opts: { includeVoided?: boolean; limit?: number } = {},
): Promise<PolicyAttestationListResponse> {
  const query = new URLSearchParams();
  if (opts.includeVoided) query.set("include_voided", "true");
  if (typeof opts.limit === "number") query.set("limit", String(opts.limit));
  const qs = query.toString();
  const url = qs
    ? `/v1/governance/policy/me/attestations?${qs}`
    : "/v1/governance/policy/me/attestations";
  return apiFetch<PolicyAttestationListResponse>(url);
}

export function listClinicPolicyAttestations(
  opts: {
    clinicPolicyVersionId?: string;
    templateSlug?: string;
    userId?: string;
    includeVoided?: boolean;
    limit?: number;
  } = {},
): Promise<PolicyAttestationListResponse> {
  const query = new URLSearchParams();
  if (opts.clinicPolicyVersionId) {
    query.set("clinic_policy_version_id", opts.clinicPolicyVersionId);
  }
  if (opts.templateSlug) query.set("template_slug", opts.templateSlug);
  if (opts.userId) query.set("user_id", opts.userId);
  if (opts.includeVoided) query.set("include_voided", "true");
  if (typeof opts.limit === "number") query.set("limit", String(opts.limit));
  const qs = query.toString();
  const url = qs
    ? `/v1/governance/policy/attestations?${qs}`
    : "/v1/governance/policy/attestations";
  return apiFetch<PolicyAttestationListResponse>(url);
}

export function voidPolicyAttestation(
  attestationId: string,
  input: VoidPolicyAttestationInput,
): Promise<PolicyAttestationResponse> {
  return apiFetch<PolicyAttestationResponse>(
    `/v1/governance/policy/attestations/${encodeURIComponent(
      attestationId,
    )}/void`,
    {
      method: "POST",
      body: JSON.stringify(input),
    },
  );
}
