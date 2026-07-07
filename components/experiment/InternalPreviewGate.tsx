"use client";

// Fable roadmap-completion experiment - shared internal-preview chrome.
//
// InternalPreviewGate wraps every experimental surface: when the
// NEXT_PUBLIC_ANCHOR_INTERNAL_PREVIEW flag is off (the default in every
// deployed environment) it renders an honest "not enabled" card instead
// of the surface, so nothing experimental is reachable or fetched.
// InternalPreviewBadge marks enabled experimental surfaces so they can
// never be mistaken for launched product.

import Link from "next/link";
import type { ReactNode } from "react";
import { Card } from "@/components/ui/Card";
import { ApiError } from "@/lib/api";
import { INTERNAL_PREVIEW_ENABLED } from "@/lib/internalPreview";

// Pre-merge FIX 3 (5 July 2026 readiness audit): every internal-preview
// surface treats 404/503 from its experiment-branch endpoints as the
// honest "not available on this backend" posture, matching the ambient
// surface's designed behaviour — never as a generic error. Against a
// production backend these endpoints simply do not exist; that is the
// expected posture, not a fault.

export function isPreviewEndpointUnavailable(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 503);
}

export const PREVIEW_ENDPOINT_UNAVAILABLE_MESSAGE =
  "Not available on this backend: the experiment-branch API for this internal-preview " +
  "surface is not present or not enabled in this environment. This is the expected " +
  "posture outside the experiment environment — nothing is wrong, and nothing can be " +
  "enabled from this page.";

export function previewAwareErrorMessage(err: unknown, fallback: string): string {
  if (isPreviewEndpointUnavailable(err)) return PREVIEW_ENDPOINT_UNAVAILABLE_MESSAGE;
  return err instanceof Error ? err.message : fallback;
}

export function PreviewBackendUnavailableCard({ surface }: { surface: string }) {
  return (
    <Card variant="native">
      <h2 className="text-base font-semibold text-slate-900">
        {surface} is not available on this backend
      </h2>
      <p className="mt-2 text-sm leading-6 text-slate-600">
        {PREVIEW_ENDPOINT_UNAVAILABLE_MESSAGE}
      </p>
      <div className="mt-4">
        <Link
          href="/dashboard"
          className="text-sm font-medium text-slate-900 underline underline-offset-4"
        >
          Return to the dashboard
        </Link>
      </div>
    </Card>
  );
}

export function InternalPreviewBadge() {
  return (
    <span className="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-2.5 py-1 text-xs font-medium tracking-wide text-amber-700">
      Internal preview — not live
    </span>
  );
}

export function InternalPreviewGate({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  if (!INTERNAL_PREVIEW_ENABLED) {
    return (
      <div className="mx-auto max-w-3xl">
        <Card variant="native">
          <h1 className="text-xl font-semibold tracking-tight text-slate-900">{title}</h1>
          <p className="mt-2 text-sm leading-6 text-slate-600">
            This surface is part of a gated internal build-ahead experiment and is not
            enabled in this environment. It is not launched product, and enabling it is a
            deliberate founder decision, not a configuration default.
          </p>
          <div className="mt-4">
            <Link
              href="/dashboard"
              className="text-sm font-medium text-slate-900 underline underline-offset-4"
            >
              Return to the dashboard
            </Link>
          </div>
        </Card>
      </div>
    );
  }

  return <>{children}</>;
}
