"use client";

import { useEffect, useSyncExternalStore } from "react";
import type { ReactNode } from "react";
import { useRouter } from "next/navigation";
import {
  SESSION_SERVER_SNAPSHOT,
  getSessionUserSnapshot,
  subscribeSessionStorage,
} from "@/lib/auth";
import { SideNav } from "./SideNav";
import { TopBar } from "./TopBar";

export function AppShell({ children }: { children: ReactNode }) {
  const router = useRouter();
  // Session is read via useSyncExternalStore so React handles the
  // server/client snapshot divergence safely. getServerSnapshot returns
  // null, so the server renders the placeholder and the client either
  // hydrates to the same placeholder (no session) or to the full shell
  // (session present) without a setState-in-effect.
  const user = useSyncExternalStore(
    subscribeSessionStorage,
    getSessionUserSnapshot,
    SESSION_SERVER_SNAPSHOT,
  );

  // Effect handles ONLY the redirect side-effect — no local setState.
  useEffect(() => {
    if (!user) {
      // Build a same-origin returnTo from the current browser location so
      // LoginForm can send the user back to the page they requested. Reading
      // window here (effect-only, client-only) avoids useSearchParams/
      // usePathname and the Suspense/prerender constraints those impose.
      const here =
        window.location.pathname + window.location.search + window.location.hash;
      const target =
        here && here !== "/login"
          ? `/login?returnTo=${encodeURIComponent(here)}`
          : "/login";
      router.replace(target);
    }
  }, [user, router]);

  if (!user) {
    return <div className="min-h-screen bg-[#f7f9fb]" />;
  }

  return (
    <>
      <link
        rel="stylesheet"
        href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap"
      />
      <style jsx global>{`
        .font-headline {
          font-family: "Manrope", sans-serif;
        }

        .material-symbols-outlined {
          font-variation-settings: "FILL" 0, "wght" 400, "GRAD" 0, "opsz" 24;
          font-family: "Material Symbols Outlined";
          font-weight: normal;
          font-style: normal;
          font-size: 24px;
          line-height: 1;
          letter-spacing: normal;
          text-transform: none;
          display: inline-block;
          white-space: nowrap;
          word-wrap: normal;
          direction: ltr;
          -webkit-font-smoothing: antialiased;
        }
      `}</style>

      <div className="min-h-screen bg-[#f7f9fb] text-[#191c1e]">
      <SideNav />

      <div className="pl-64">
        <TopBar user={user} />

        <main className="min-h-[calc(100vh-4rem)] bg-[#f7f9fb] px-8 py-8">
          {children}
        </main>
      </div>
      </div>
    </>
  );
}
