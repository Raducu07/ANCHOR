"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { clearAuthState } from "@/lib/auth";
import type { SessionUser } from "@/lib/types";

const DEFAULT_AVATAR_URL =
  "https://lh3.googleusercontent.com/aida-public/AB6AXuCnbGKz0TR_w7R7vfsdlOaArbM6Ka9P4NxHiCDCVu9tUHvElC9ITX3XsjBMrYZAIv3n-S06ghZKu1BTKIbpwbNIHkKoVMCo2ETSVZB_Lp6Km6Jd_5xHoQ3zB8HXdy_1_AQMQHMaheRN7A7BSx1SZUq6yajARax2RDSLTFq-h59_vYF75fpi0P3BPE4AjWoXtE8_7Ha9IjlxtIhWjqmdQAs1gQOxFyv2ganm7lmdG5dTZxehwGb8EPX2ZU_4Pa6iXRFWnROk2MISg4nq";

function getAccountDisplay(user: SessionUser) {
  const extendedUser = user as SessionUser & {
    display_name?: string;
    display_role?: string;
    avatar_url?: string;
  };

  return {
    name:
      typeof extendedUser.display_name === "string" && extendedUser.display_name.trim()
        ? extendedUser.display_name.trim()
        : "Clinic User",
    role:
      typeof extendedUser.display_role === "string" && extendedUser.display_role.trim()
        ? extendedUser.display_role.trim()
        : "Team member",
    avatarUrl:
      typeof extendedUser.avatar_url === "string" && extendedUser.avatar_url.trim()
        ? extendedUser.avatar_url.trim()
        : DEFAULT_AVATAR_URL,
  };
}

export function TopBar({ user }: { user: SessionUser }) {
  const router = useRouter();
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const account = getAccountDisplay(user);

  useEffect(() => {
    function handlePointerDown(event: MouseEvent) {
      if (!menuRef.current?.contains(event.target as Node)) {
        setMenuOpen(false);
      }
    }

    function handleEscape(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setMenuOpen(false);
      }
    }

    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleEscape);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleEscape);
    };
  }, []);

  function handleSignOut() {
    clearAuthState();
    router.replace("/login");
  }

  return (
    <header className="sticky top-0 z-50 flex h-16 w-full items-center justify-between border-b border-slate-100 bg-white/80 px-8 font-headline text-base shadow-sm backdrop-blur-md">
      <div className="flex flex-1 items-center">
        <div className="relative w-full max-w-xl">
          <span className="material-symbols-outlined pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-xl text-slate-500">
            search
          </span>
          <input
            type="text"
            placeholder="Search governance logs, audits, or metadata..."
            className="w-full rounded-lg border-none bg-[#f0f4f7] py-1.5 pl-10 pr-4 text-sm text-[#2a3439] transition-all placeholder:text-slate-500 focus:ring-1 focus:ring-[#565e74]"
          />
        </div>
      </div>

      <div className="ml-6 flex items-center gap-6">
        <button className="text-slate-500 transition-transform hover:text-slate-700 active:scale-95">
          <span className="material-symbols-outlined">notifications</span>
        </button>

        <button className="text-slate-500 transition-transform hover:text-slate-700 active:scale-95">
          <span className="material-symbols-outlined">settings</span>
        </button>

        <div className="h-6 w-px bg-slate-300/30" />

        <div className="relative" ref={menuRef}>
          <button
            type="button"
            onClick={() => setMenuOpen((open) => !open)}
            className="group flex cursor-pointer items-center gap-3"
            aria-haspopup="menu"
            aria-expanded={menuOpen}
          >
            <div className="text-right">
              <p className="text-xs font-bold leading-none text-slate-900">{account.name}</p>
              <p className="text-[10px] text-slate-500">{account.role}</p>
            </div>

            <img
              alt="User Avatar"
              className="h-9 w-9 rounded-full border border-slate-300/20 object-cover grayscale-[0.2]"
              src={account.avatarUrl}
            />
          </button>

          {menuOpen ? (
            <div className="absolute right-0 top-12 z-30 min-w-[140px] rounded-lg border border-slate-200/80 bg-white p-1 shadow-[0_12px_28px_rgba(42,52,57,0.08)]">
              <button
                type="button"
                onClick={handleSignOut}
                className="w-full rounded-md px-3 py-2 text-left text-sm font-medium text-slate-700 hover:bg-slate-100"
              >
                Sign out
              </button>
            </div>
          ) : null}
        </div>
      </div>
    </header>
  );
}
