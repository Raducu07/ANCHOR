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
import { INTERNAL_PREVIEW_ENABLED } from "@/lib/internalPreview";

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
