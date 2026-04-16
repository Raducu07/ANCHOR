"use client";

import { useRouter } from "next/navigation";
import { Bell, Search, Settings } from "lucide-react";
import { clearAuthState } from "@/lib/auth";
import type { SessionUser } from "@/lib/types";

function roleLabel(role: string) {
  return role
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function TopBar({ user }: { user: SessionUser }) {
  const router = useRouter();

  function handleSignOut() {
    clearAuthState();
    router.replace("/login");
  }

  return (
    <header className="sticky top-0 z-50 flex h-16 w-full items-center justify-between border-b border-slate-100 bg-white/80 px-8 font-headline text-base shadow-sm backdrop-blur-md">
      <div className="flex flex-1 items-center">
        <div className="relative w-full max-w-xl">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search governance logs, audits, or metadata..."
            className="w-full rounded-lg border-none bg-[#f0f4f7] py-1.5 pl-10 pr-4 text-sm text-[#2a3439] transition-all placeholder:text-slate-500 focus:ring-1 focus:ring-[#565e74]"
          />
        </div>
      </div>

      <div className="ml-6 flex items-center gap-6">
        <button className="text-slate-500 transition-transform hover:text-slate-700 active:scale-95">
          <Bell className="h-5 w-5" />
        </button>

        <button className="text-slate-500 transition-transform hover:text-slate-700 active:scale-95">
          <Settings className="h-5 w-5" />
        </button>

        <div className="h-6 w-px bg-slate-300/40" />

        <div className="flex items-center gap-3">
          <div className="text-right">
            <p className="text-xs font-bold leading-none text-slate-900">
              {user.email.split("@")[0]}
            </p>
            <p className="text-[10px] text-slate-500">{roleLabel(user.role)}</p>
          </div>

          <div className="flex h-9 w-9 items-center justify-center rounded-full border border-slate-300/20 bg-slate-200 text-[10px] font-bold text-slate-700">
            {user.email.charAt(0).toUpperCase()}
          </div>
        </div>

        <button
          type="button"
          onClick={handleSignOut}
          className="text-[10px] font-bold uppercase tracking-[0.18em] text-[#565e74] transition-colors hover:text-[#4a5268]"
        >
          Sign Out
        </button>
      </div>
    </header>
  );
}