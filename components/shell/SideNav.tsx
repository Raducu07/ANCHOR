"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const primaryItems = [
  { href: "/workspace-live", label: "Workspace", icon: "clinical_notes" },
  { href: "/dashboard", label: "Dashboard", icon: "dashboard" },
  { href: "/receipts", label: "Receipts", icon: "receipt_long" },
  { href: "/governance-events", label: "Governance Events", icon: "verified_user" },
  { href: "/learn", label: "Learn", icon: "school" },
  { href: "/trust/profile", label: "Trust", icon: "shield_with_heart" },
  { href: "/intelligence", label: "Intelligence", icon: "psychology" },
  { href: "/exports", label: "Exports", icon: "download" },
];

const secondaryItems = [
  { href: "/settings", label: "Settings", icon: "settings" },
  { href: "/privacy-policy", label: "Privacy / Policy", icon: "policy" },
  { href: "/support", label: "Support", icon: "help_outline" },
];

function isActive(pathname: string, href: string) {
  if (pathname === href) return true;
  if (href === "/workspace-live" && pathname.startsWith("/workspace")) return true;
  if (href === "/learn" && pathname.startsWith("/learn")) return true;
  if (href === "/trust/profile" && pathname.startsWith("/trust")) return true;
  if (href === "/intelligence" && pathname.startsWith("/intelligence")) return true;
  if (href === "/settings" && pathname.startsWith("/settings")) return true;
  if (href === "/support" && pathname.startsWith("/support")) return true;
  return false;
}

export function SideNav() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 z-40 flex h-screen w-64 shrink-0 flex-col border-r border-slate-200/50 bg-slate-50 py-6 font-headline text-sm font-medium">
        <div className="mb-8 px-6">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[#565e74]">anchor</span>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-slate-900">ANCHOR</h1>
              <p className="text-[10px] font-bold uppercase leading-none tracking-widest text-slate-500">
                Veterinary Governance
              </p>
            </div>
          </div>
        </div>

        <nav className="flex-1 space-y-1 overflow-y-auto">
          {primaryItems.map((item) => {
            const active = isActive(pathname, item.href);

            return (
              <Link
                key={item.href}
                href={item.href}
                className={[
                  "flex items-center px-6 py-3 transition-colors",
                  active
                    ? "border-r-2 border-slate-900 bg-slate-200/50 font-bold text-slate-900"
                    : "text-slate-500 hover:bg-slate-200/50 hover:text-slate-700",
                ].join(" ")}
              >
                <span className="material-symbols-outlined mr-3 text-[20px]">{item.icon}</span>
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        <div className="mt-auto px-4">
          <div className="mt-6 space-y-1">
            {secondaryItems.map((item) => {
              const active = isActive(pathname, item.href);

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={[
                    "flex items-center px-2 py-2 transition-colors",
                    active
                      ? "font-semibold text-slate-900"
                      : "text-slate-500 hover:text-slate-700",
                  ].join(" ")}
                >
                  <span className="material-symbols-outlined mr-3 text-[20px]">{item.icon}</span>
                  <span>{item.label}</span>
                </Link>
              );
            })}
          </div>
        </div>

      </aside>
  );
}
