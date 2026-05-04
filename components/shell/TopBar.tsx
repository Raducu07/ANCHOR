"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { apiFetch } from "@/lib/api";
import { clearAuthState } from "@/lib/auth";
import type { DashboardResponse, SessionUser } from "@/lib/types";

const DEFAULT_AVATAR_URL =
  "https://lh3.googleusercontent.com/aida-public/AB6AXuCnbGKz0TR_w7R7vfsdlOaArbM6Ka9P4NxHiCDCVu9tUHvElC9ITX3XsjBMrYZAIv3n-S06ghZKu1BTKIbpwbNIHkKoVMCo2ETSVZB_Lp6Km6Jd_5xHoQ3zB8HXdy_1_AQMQHMaheRN7A7BSx1SZUq6yajARax2RDSLTFq-h59_vYF75fpi0P3BPE4AjWoXtE8_7Ha9IjlxtIhWjqmdQAs1gQOxFyv2ganm7lmdG5dTZxehwGb8EPX2ZU_4Pa6iXRFWnROk2MISg4nq";

type NotificationItem = {
  id?: string;
  requestId?: string;
  createdAt?: string;
  title: string;
  body: string;
  href: string;
};

function getNotificationKey(item: NotificationItem, index: number) {
  return item.id ?? item.requestId ?? (item.createdAt ? `${item.createdAt}-${index}` : `${item.href}-${item.title}-${index}`);
}

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

function buildNotificationItems(data: DashboardResponse | null) {
  const items: NotificationItem[] = [];
  const recentSubmissions = Array.isArray(data?.recent_submissions) ? data.recent_submissions : [];

  for (const submission of recentSubmissions.slice(0, 4)) {
    const requestId = submission.request_id?.slice(0, 8);
    const receiptHref = submission.request_id
      ? `/receipts?request_id=${encodeURIComponent(submission.request_id)}`
      : "/receipts";
    if (submission.pii_detected) {
      items.push({
        requestId: submission.request_id,
        createdAt: submission.created_at_utc,
        title: `PII was detected in ${formatMode(submission.mode)}`,
        body: requestId
          ? `Recent receipt ${requestId} includes a privacy warning that may need review.`
          : "A recent receipt includes a privacy warning that may need review.",
        href: receiptHref,
      });
      continue;
    }

    items.push({
      requestId: submission.request_id,
      createdAt: submission.created_at_utc,
      title: `${formatMode(submission.mode)} was ${formatDecision(submission.decision)}`,
      body: requestId
        ? `Receipt ${requestId} is available for review in the clinic ledger.`
        : "A recent receipt is available for review in the clinic ledger.",
      href: receiptHref,
    });
  }

  if (items.length === 0 && data?.latest_receipt?.request_id) {
    items.push({
      requestId: data.latest_receipt.request_id,
      title: "Latest receipt remains available for review",
      body: `Request ${data.latest_receipt.request_id.slice(0, 8)} can be opened from the Receipts surface.`,
      href: `/receipts?request_id=${encodeURIComponent(data.latest_receipt.request_id)}`,
    });
  }

  return items;
}

function formatMode(mode: string | undefined) {
  if (!mode) return "recent governance activity";
  return mode
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatDecision(decision: string | undefined) {
  if (!decision) return "reviewed";
  return decision.toLowerCase();
}

export function TopBar({ user }: { user: SessionUser }) {
  const router = useRouter();
  const [menuOpen, setMenuOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [activityState, setActivityState] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [activityData, setActivityData] = useState<DashboardResponse | null>(null);
  const [activityError, setActivityError] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const notificationsRef = useRef<HTMLDivElement | null>(null);
  const activityInFlightRef = useRef(false);
  const activityReadyRef = useRef(false);
  const account = getAccountDisplay(user);
  const notificationItems = buildNotificationItems(activityData);

  useEffect(() => {
    function handlePointerDown(event: MouseEvent) {
      const target = event.target as Node;
      if (!menuRef.current?.contains(target)) {
        setMenuOpen(false);
      }
      if (!notificationsRef.current?.contains(target)) {
        setNotificationsOpen(false);
      }
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setMenuOpen(false);
        setNotificationsOpen(false);
      }
    }

    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, []);

  useEffect(() => {
    if (!notificationsOpen) return;
    if (activityReadyRef.current) return;
    if (activityInFlightRef.current) return;

    activityInFlightRef.current = true;
    let active = true;
    setActivityState("loading");
    setActivityError(null);

    async function loadActivity() {
      try {
        const dashboard = await apiFetch<DashboardResponse>("/v1/portal/dashboard");
        if (!active) return;
        activityReadyRef.current = true;
        setActivityData(dashboard);
        setActivityState("ready");
      } catch {
        if (!active) return;
        setActivityData(null);
        setActivityError("Recent clinic activity is not available in the topbar right now.");
        setActivityState("error");
      } finally {
        activityInFlightRef.current = false;
      }
    }

    void loadActivity();

    return () => {
      active = false;
    };
  }, [notificationsOpen]);

  function handleSignOut() {
    clearAuthState();
    router.replace("/login");
  }

  function navigateTo(href: string) {
    setNotificationsOpen(false);
    setMenuOpen(false);
    router.push(href);
  }

  return (
    <>
      <header className="sticky top-0 z-50 flex h-16 w-full items-center justify-between border-b border-slate-100 bg-white/80 px-8 font-headline text-base shadow-sm backdrop-blur-md">
        <div className="flex max-w-xl flex-1 items-center">
          <div className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-slate-600">
            <span
              aria-hidden="true"
              className="material-symbols-outlined text-base text-slate-500"
            >
              shield_with_heart
            </span>
            <span>Clinic-scoped governance workspace</span>
          </div>
        </div>

        <div className="ml-6 flex items-center gap-6">
          <div className="relative" ref={notificationsRef}>
            <button
              type="button"
              onClick={() => {
                setNotificationsOpen((open) => !open);
                setMenuOpen(false);
              }}
              aria-haspopup="dialog"
              aria-expanded={notificationsOpen}
              className="text-slate-500 transition-transform hover:text-slate-700 active:scale-95"
            >
              <span className="material-symbols-outlined">notifications</span>
            </button>

            {notificationsOpen ? (
              <div className="absolute right-0 top-12 z-30 w-[360px] max-w-[calc(100vw-3rem)] overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-[0_18px_40px_rgba(15,23,42,0.08)]">
                <div className="border-b border-slate-100 px-4 py-4">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <p className="text-sm font-semibold text-slate-900">Recent clinic activity</p>
                      <p className="mt-1 text-sm leading-6 text-slate-600">
                        A lightweight topbar view into real activity signals already available in ANCHOR.
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => navigateTo("/notifications")}
                      className="rounded-full border border-slate-200 px-3 py-1 text-xs font-semibold text-slate-700 transition hover:bg-slate-50"
                    >
                      Open page
                    </button>
                  </div>
                </div>

                <div className="max-h-[320px] overflow-y-auto p-3">
                  {activityState === "loading" ? (
                    <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-4 text-sm text-slate-600">
                      Loading recent clinic activity...
                    </div>
                  ) : activityError ? (
                    <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-4 text-sm text-slate-600">
                      {activityError}
                    </div>
                  ) : notificationItems.length > 0 ? (
                    <div className="space-y-2">
                      {notificationItems.map((item, index) => (
                        <button
                          key={getNotificationKey(item, index)}
                          type="button"
                          onClick={() => navigateTo(item.href)}
                          className="block w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-4 text-left transition hover:border-slate-300 hover:bg-white"
                        >
                          <p className="text-sm font-semibold text-slate-900">{item.title}</p>
                          <p className="mt-1 text-sm leading-6 text-slate-600">{item.body}</p>
                        </button>
                      ))}
                    </div>
                  ) : (
                    <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-4 text-sm leading-6 text-slate-600">
                      No recent clinic-user activity has been surfaced here yet. Check Governance Events or Receipts for the
                      strongest current signals.
                    </div>
                  )}
                </div>
              </div>
            ) : null}
          </div>

          <button
            type="button"
            onClick={() => navigateTo("/settings")}
            className="text-slate-500 transition-transform hover:text-slate-700 active:scale-95"
          >
            <span className="material-symbols-outlined">settings</span>
          </button>

          <div className="h-6 w-px bg-slate-300/30" />

          <div className="relative" ref={menuRef}>
            <button
              type="button"
              onClick={() => {
                setMenuOpen((open) => !open);
                setNotificationsOpen(false);
              }}
              className="group flex cursor-pointer items-center gap-3"
              aria-haspopup="menu"
              aria-expanded={menuOpen}
            >
              <div className="text-right">
                <p className="text-xs font-bold leading-none text-slate-900">{account.name}</p>
                <p className="text-[10px] text-slate-500">{account.role}</p>
              </div>

              {/* eslint-disable-next-line @next/next/no-img-element */}
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
    </>
  );
}
