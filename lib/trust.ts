import { apiFetch } from "@/lib/api";
import type {
  TrustMaterialsResponse,
  TrustPackResponse,
  TrustPostureResponse,
  TrustProfileResponse,
} from "@/lib/types";

export function getTrustProfile() {
  return apiFetch<TrustProfileResponse>("/v1/portal/trust/profile");
}

export function getTrustPosture() {
  return apiFetch<TrustPostureResponse>("/v1/portal/trust/posture");
}

export function getTrustPack() {
  return apiFetch<TrustPackResponse>("/v1/portal/trust/pack");
}

export function getTrustMaterials() {
  return apiFetch<TrustMaterialsResponse>("/v1/portal/trust/materials");
}