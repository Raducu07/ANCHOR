"use client";

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { useRouter } from "next/navigation";
import { getSessionUser } from "@/lib/auth";
import type { SessionUser } from "@/lib/types";
import { SideNav } from "./SideNav";
import { TopBar } from "./TopBar";

export function AppShell({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [user, setUser] = useState<SessionUser | null>(null);

  useEffect(() => {
    const sessionUser = getSessionUser();
    if (!sessionUser) {
      router.replace("/login");
      return;
    }

    setUser(sessionUser);
    setReady(true);
  }, [router]);

  if (!ready || !user) {
    return <div className="min-h-screen bg-[#f7f9fb]" />;
  }

  return (
    <div className="min-h-screen bg-[#f7f9fb] text-[#191c1e]">
      <SideNav />

      <div className="pl-64">
        <TopBar user={user} />

        <main className="min-h-[calc(100vh-4rem)] bg-[#f7f9fb] px-8 py-8">
          {children}
        </main>
      </div>

      <div className="pointer-events-none fixed inset-0 z-[-1] opacity-[0.02]">
        <div
          className="absolute inset-0"
          style={{
            backgroundImage:
              "radial-gradient(#2a3439 0.5px, transparent 0.5px)",
            backgroundSize: "32px 32px",
          }}
        />
      </div>
    </div>
  );
}