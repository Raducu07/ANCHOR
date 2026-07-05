// lib/internalPreview.ts
//
// Fable roadmap-completion experiment - frontend gate.
//
// Every surface built in this experiment (assisted onboarding, Learn
// maturity, billing foundations, sustainability governance, ambient
// governance shell, provider posture, and their tiles/links) renders
// only when NEXT_PUBLIC_ANCHOR_INTERNAL_PREVIEW is truthy at build
// time. The flag is unset in every deployed environment, so the
// default is fail-closed: no experimental link, tile, section, or
// fetch exists in the rendered product.
//
// NEXT_PUBLIC_ variables are inlined by Next.js at build time, so this
// is a build-time constant, not a runtime toggle.

const raw = (process.env.NEXT_PUBLIC_ANCHOR_INTERNAL_PREVIEW ?? "")
  .trim()
  .toLowerCase();

export const INTERNAL_PREVIEW_ENABLED =
  raw === "1" || raw === "true" || raw === "yes" || raw === "on";
