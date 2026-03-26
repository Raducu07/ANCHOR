"use client";

import { useMemo } from "react";
import { usePathname, useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { clearAuthState } from "@/lib/auth";
import type { SessionUser } from "@/lib/types";

const pageMeta: Record<string, { eyebrow: string; title: string; helper: string }> = {
  "/dashboard": {
    eyebrow: "Clinic workspace",
    title: "Operational governance overview",
    helper: "A calm surface for trust posture, receipts, events, and bounded exports.",
  },
  "/receipts": {
    eyebrow: "Clinic workspace",
    title: "Governance receipt review",
    helper: "Inspect request-level metadata without exposing raw prompt or output content.",
  },
  "/governance-events": {
    eyebrow: "Clinic workspace",
    title: "Governance activity review",
    helper: "Review recent clinic-scoped events and move directly into receipts.",
  },
  "/exports": {
    eyebrow: "Clinic workspace",
    title: "Metadata-only exports",
    helper: "Generate bounded clinic-scoped CSV exports for operational review.",
  },
  "/privacy-policy": {
    eyebrow: "Clinic workspace",
    title: "Privacy and policy posture",
    helper: "Summarize governance boundaries and platform administration direction.",
  },
};

export function TopBar({ user }: { user: SessionUser }) {
  const pathname = usePathname();
  const router = useRouter();

  function handleSignOut() {
    clearAuthState();
    router.replace("/login");
  }

  const meta = useMemo(() => {
    return (
      pageMeta[pathname] ?? {
        eyebrow: "Clinic workspace",
        title: "ANCHOR portal",
        helper: "Clinic-scoped governance, trust, and learning infrastructure.",
      }
    );
  }, [pathname]);

  return (
    <header className="sticky top-0 z-20 border-b border-slate-200/80 bg-white/80 backdrop-blur">
      <div className="px-4 py-4 sm:px-6 lg:px-8">
        <div className="mx-auto flex max-w-[1240px] flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
          <div className="min-w-0">
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
              {meta.eyebrow}
            </p>
            <h2 className="mt-1 text-xl font-semibold tracking-tight text-slate-900">
              {meta.title}
            </h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">
              {meta.helper}
            </p>
          </div>

          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                Clinic workspace
              </p>
              <p className="mt-1 text-sm font-semibold text-slate-900">{user.clinicSlug}</p>
              <p className="mt-1 text-sm text-slate-500">
                {user.email} · {user.role}
              </p>
            </div>

            <Button variant="secondary" onClick={handleSignOut}>
              Sign out
            </Button>
          </div>
        </div>
      </div>
    </header>
  );
}