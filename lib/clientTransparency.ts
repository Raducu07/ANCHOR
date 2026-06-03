// lib/clientTransparency.ts
//
// Phase 2A-4 - Client-Facing Transparency Layer API client.
//
// Doctrine:
//   * Metadata-only. The frontend never carries raw client/patient
//     content, clinical content, transcripts, identifiers, consent
//     text, or compliance-status fields.
//   * Endpoints are clinic-scoped on the backend (RLS); the frontend
//     does not pass clinic_id explicitly.
//   * Query string parameter names mirror the backend snake_case
//     contract.
//   * Standard apiFetch flow; standard ApiError propagation.

import { apiFetch } from "@/lib/api";
import type {
  ClientTransparencyProfileCreateRequest,
  ClientTransparencyProfileListResponse,
  ClientTransparencyProfileResponse,
  ClientTransparencyProfileStatus,
  ClientTransparencyProfileUpdateRequest,
  ClientTransparencyPublicVersionListResponse,
  ClientTransparencyPublicVersionResponse,
  ClientTransparencyPublicationStatus,
  ClientTransparencyTemplateListResponse,
  ClientTransparencyTemplateResponse,
} from "@/lib/types";

const BASE = "/v1/governance/client-transparency";

// ----- Templates ------------------------------------------------------

export function listClientTransparencyTemplates(
  opts: { includeInactive?: boolean } = {},
): Promise<ClientTransparencyTemplateListResponse> {
  const query = new URLSearchParams();
  if (opts.includeInactive) query.set("include_inactive", "true");
  const qs = query.toString();
  const url = qs ? `${BASE}/templates?${qs}` : `${BASE}/templates`;
  return apiFetch<ClientTransparencyTemplateListResponse>(url);
}

export function getClientTransparencyTemplate(
  templateSlug: string,
): Promise<ClientTransparencyTemplateResponse> {
  return apiFetch<ClientTransparencyTemplateResponse>(
    `${BASE}/templates/${encodeURIComponent(templateSlug)}`,
  );
}

// ----- Clinic profiles ------------------------------------------------

export function createClientTransparencyProfile(
  input: ClientTransparencyProfileCreateRequest,
): Promise<ClientTransparencyProfileResponse> {
  return apiFetch<ClientTransparencyProfileResponse>(`${BASE}/profiles`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function listClientTransparencyProfiles(
  opts: { status?: ClientTransparencyProfileStatus; limit?: number } = {},
): Promise<ClientTransparencyProfileListResponse> {
  const query = new URLSearchParams();
  if (opts.status) query.set("status", opts.status);
  if (typeof opts.limit === "number") query.set("limit", String(opts.limit));
  const qs = query.toString();
  const url = qs ? `${BASE}/profiles?${qs}` : `${BASE}/profiles`;
  return apiFetch<ClientTransparencyProfileListResponse>(url);
}

export function getActiveClientTransparencyProfile(): Promise<ClientTransparencyProfileResponse> {
  return apiFetch<ClientTransparencyProfileResponse>(`${BASE}/profiles/active`);
}

export function getClientTransparencyProfile(
  clinicProfileId: string,
): Promise<ClientTransparencyProfileResponse> {
  return apiFetch<ClientTransparencyProfileResponse>(
    `${BASE}/profiles/${encodeURIComponent(clinicProfileId)}`,
  );
}

export function updateClientTransparencyProfile(
  clinicProfileId: string,
  input: ClientTransparencyProfileUpdateRequest,
): Promise<ClientTransparencyProfileResponse> {
  return apiFetch<ClientTransparencyProfileResponse>(
    `${BASE}/profiles/${encodeURIComponent(clinicProfileId)}`,
    {
      method: "PUT",
      body: JSON.stringify(input),
    },
  );
}

export function activateClientTransparencyProfile(
  clinicProfileId: string,
): Promise<ClientTransparencyProfileResponse> {
  return apiFetch<ClientTransparencyProfileResponse>(
    `${BASE}/profiles/${encodeURIComponent(clinicProfileId)}/activate`,
    {
      method: "POST",
      body: JSON.stringify({}),
    },
  );
}

export function archiveClientTransparencyProfile(
  clinicProfileId: string,
): Promise<ClientTransparencyProfileResponse> {
  return apiFetch<ClientTransparencyProfileResponse>(
    `${BASE}/profiles/${encodeURIComponent(clinicProfileId)}/archive`,
    {
      method: "POST",
      body: JSON.stringify({}),
    },
  );
}

export function publishClientTransparencyProfile(
  clinicProfileId: string,
): Promise<ClientTransparencyPublicVersionResponse> {
  return apiFetch<ClientTransparencyPublicVersionResponse>(
    `${BASE}/profiles/${encodeURIComponent(clinicProfileId)}/publish`,
    {
      method: "POST",
      body: JSON.stringify({}),
    },
  );
}

// ----- Public versions ------------------------------------------------

export function getCurrentClientTransparencyPublicVersion(): Promise<ClientTransparencyPublicVersionResponse> {
  return apiFetch<ClientTransparencyPublicVersionResponse>(
    `${BASE}/public/current`,
  );
}

export function listClientTransparencyPublicVersions(
  opts: {
    publicationStatus?: ClientTransparencyPublicationStatus;
    limit?: number;
  } = {},
): Promise<ClientTransparencyPublicVersionListResponse> {
  const query = new URLSearchParams();
  if (opts.publicationStatus) {
    query.set("publication_status", opts.publicationStatus);
  }
  if (typeof opts.limit === "number") query.set("limit", String(opts.limit));
  const qs = query.toString();
  const url = qs
    ? `${BASE}/public/versions?${qs}`
    : `${BASE}/public/versions`;
  return apiFetch<ClientTransparencyPublicVersionListResponse>(url);
}

export function getClientTransparencyPublicVersion(
  publicVersionId: string,
): Promise<ClientTransparencyPublicVersionResponse> {
  return apiFetch<ClientTransparencyPublicVersionResponse>(
    `${BASE}/public/versions/${encodeURIComponent(publicVersionId)}`,
  );
}

export function retireClientTransparencyPublicVersion(
  publicVersionId: string,
): Promise<ClientTransparencyPublicVersionResponse> {
  return apiFetch<ClientTransparencyPublicVersionResponse>(
    `${BASE}/public/versions/${encodeURIComponent(publicVersionId)}/retire`,
    {
      method: "POST",
      body: JSON.stringify({}),
    },
  );
}
