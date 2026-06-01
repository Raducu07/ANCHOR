// lib/selfAssessment.ts
//
// Phase 2A-3.4 — RCVS-aligned self-assessment API client.
//
// Doctrine:
//   * Metadata only. No raw answer free-text, clinical content, staff
//     identifiers in Trust evidence, or pass/fail competence grading is
//     ever sent or stored beyond normal API response rendering.
//   * Endpoints are clinic-scoped on the backend (RLS); the frontend
//     does not pass clinic_id explicitly.
//   * Query string parameter names mirror the backend snake_case
//     contract.
//   * Standard apiFetch flow; standard ApiError propagation.
//   * Human review remains required — this client only surfaces
//     readiness evidence and supports governance review.

import { apiFetch } from "@/lib/api";
import type {
  ClinicSelfAssessmentListResponse,
  ClinicSelfAssessmentResponse,
  ClinicSelfAssessmentStatus,
  LatestSelfAssessmentResponse,
  SelfAssessmentAnswerUpsertRequest,
  SelfAssessmentAnswerValue,
  SelfAssessmentCreateRequest,
  SelfAssessmentEvidenceLink,
  SelfAssessmentQuestionListResponse,
  SelfAssessmentTemplateDetailResponse,
  SelfAssessmentTemplateListResponse,
} from "@/lib/types";

const BASE = "/v1/governance/self-assessment";

// ----- Templates ------------------------------------------------------

export function listSelfAssessmentTemplates(): Promise<SelfAssessmentTemplateListResponse> {
  return apiFetch<SelfAssessmentTemplateListResponse>(`${BASE}/templates`);
}

export function getSelfAssessmentTemplate(
  templateSlug: string,
): Promise<SelfAssessmentTemplateDetailResponse> {
  return apiFetch<SelfAssessmentTemplateDetailResponse>(
    `${BASE}/templates/${encodeURIComponent(templateSlug)}`,
  );
}

export function listSelfAssessmentQuestions(
  templateSlug: string,
): Promise<SelfAssessmentQuestionListResponse> {
  return apiFetch<SelfAssessmentQuestionListResponse>(
    `${BASE}/templates/${encodeURIComponent(templateSlug)}/questions`,
  );
}

// ----- Clinic assessments ---------------------------------------------

export function createSelfAssessmentDraft(input: {
  templateSlug: string;
  templateVersion?: string;
}): Promise<ClinicSelfAssessmentResponse> {
  const body: SelfAssessmentCreateRequest = {
    template_slug: input.templateSlug,
  };
  if (input.templateVersion) {
    body.template_version = input.templateVersion;
  }
  return apiFetch<ClinicSelfAssessmentResponse>(`${BASE}/assessments`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function listSelfAssessments(
  opts: { status?: ClinicSelfAssessmentStatus; limit?: number } = {},
): Promise<ClinicSelfAssessmentListResponse> {
  const query = new URLSearchParams();
  if (opts.status) query.set("status", opts.status);
  if (typeof opts.limit === "number") query.set("limit", String(opts.limit));
  const qs = query.toString();
  const url = qs ? `${BASE}/assessments?${qs}` : `${BASE}/assessments`;
  return apiFetch<ClinicSelfAssessmentListResponse>(url);
}

export function getLatestSelfAssessments(): Promise<LatestSelfAssessmentResponse> {
  return apiFetch<LatestSelfAssessmentResponse>(`${BASE}/assessments/latest`);
}

export function getSelfAssessment(
  assessmentId: string,
): Promise<ClinicSelfAssessmentResponse> {
  return apiFetch<ClinicSelfAssessmentResponse>(
    `${BASE}/assessments/${encodeURIComponent(assessmentId)}`,
  );
}

export function upsertSelfAssessmentAnswer(input: {
  assessmentId: string;
  questionSlug: string;
  answerValue: SelfAssessmentAnswerValue;
  evidenceLinks: SelfAssessmentEvidenceLink[];
}): Promise<ClinicSelfAssessmentResponse> {
  const body: SelfAssessmentAnswerUpsertRequest = {
    answer_value: input.answerValue,
    evidence_links: input.evidenceLinks,
  };
  return apiFetch<ClinicSelfAssessmentResponse>(
    `${BASE}/assessments/${encodeURIComponent(
      input.assessmentId,
    )}/answers/${encodeURIComponent(input.questionSlug)}`,
    {
      method: "PUT",
      body: JSON.stringify(body),
    },
  );
}

export function submitSelfAssessment(
  assessmentId: string,
): Promise<ClinicSelfAssessmentResponse> {
  return apiFetch<ClinicSelfAssessmentResponse>(
    `${BASE}/assessments/${encodeURIComponent(assessmentId)}/submit`,
    {
      method: "POST",
      body: JSON.stringify({}),
    },
  );
}

export function archiveSelfAssessment(
  assessmentId: string,
): Promise<ClinicSelfAssessmentResponse> {
  return apiFetch<ClinicSelfAssessmentResponse>(
    `${BASE}/assessments/${encodeURIComponent(assessmentId)}/archive`,
    {
      method: "POST",
      body: JSON.stringify({}),
    },
  );
}
