"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const items = [
  {
    href: "/dashboard",
    label: "Dashboard",
    helper: "Trust-oriented clinic overview",
  },
  {
    href: "/receipts",
    label: "Receipts",
    helper: "Inspect governance receipts",
  },
  {
    href: "/governance-events",
    label: "Governance Events",
    helper: "Review clinic-scoped activity",
  },
  {
    href: "/exports",
    label: "Exports",
    helper: "Generate metadata-only CSVs",
  },
  {
    href: "/privacy-policy",
    label: "Privacy & Policy",
    helper: "Review platform posture",
  },
  {
    href: "/learn",
    label: "Learn",
    helper: "Build safe AI-use literacy",
  },
];

export function SideNav() {
  const pathname = usePathname();

  return (
    <aside className="border-b border-slate-200/80 bg-white/75 backdrop-blur lg:min-h-screen lg:border-b-0 lg:border-r">
      <div className="flex h-full flex-col">
        <div className="px-5 pb-5 pt-6 lg:px-6 lg:pb-6 lg:pt-7">
          <div className="inline-flex items-center rounded-full border border-slate-200 bg-white px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-700 shadow-sm">
            ANCHOR
          </div>

          <div className="mt-5 rounded-3xl border border-slate-200 bg-slate-50/80 p-5">
            <p className="text-sm font-semibold text-slate-900">
              Governance, trust, and learning infrastructure
            </p>
            <p className="mt-2 text-sm leading-6 text-slate-600">
              Safe AI-use oversight for veterinary clinics, with metadata-only accountability and clinic-scoped review.
            </p>
          </div>
        </div>

        <div className="px-4 lg:px-5">
          <p className="px-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">
            Workspace
          </p>

          <nav className="mt-3">
            <ul className="space-y-2">
              {items.map((item) => {
                const active =
                  pathname === item.href || (item.href === "/learn" && pathname.startsWith("/learn"));

                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      className={[
                        "group block rounded-2xl border px-4 py-3 transition",
                        active
                          ? "border-slate-900 bg-slate-900 text-white shadow-sm"
                          : "border-transparent text-slate-700 hover:border-slate-200 hover:bg-white hover:text-slate-900",
                      ].join(" ")}
                    >
                      <div className="flex items-start gap-3">
                        <span
                          className={[
                            "mt-1 h-2.5 w-2.5 rounded-full transition",
                            active ? "bg-white" : "bg-slate-300 group-hover:bg-slate-500",
                          ].join(" ")}
                        />
                        <div className="min-w-0">
                          <p className="text-sm font-semibold">{item.label}</p>
                          <p
                            className={[
                              "mt-1 text-xs leading-5",
                              active ? "text-slate-200" : "text-slate-500 group-hover:text-slate-600",
                            ].join(" ")}
                          >
                            {item.helper}
                          </p>
                        </div>
                      </div>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </nav>
        </div>

        <div className="mt-6 px-5 pb-6 lg:mt-auto lg:px-6 lg:pb-7">
          <div className="rounded-3xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
              Current posture
            </p>
            <p className="mt-2 text-sm leading-6 text-slate-600">
              Metadata-only accountability, clinic-scoped exports, policy traceability, and safe-use learning now form the core operating model.
            </p>
          </div>
        </div>
      </div>
    </aside>
  );
}