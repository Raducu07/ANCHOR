"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

const API_BASE = (process.env.NEXT_PUBLIC_API_BASE ?? "").replace(/\/$/, "");

const stitchHtml = `
<!DOCTYPE html>
<html class="light" lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>ANCHOR | Operational Governance Overview</title>
  <script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"><\/script>
  <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet"/>
  <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
  <script>
    tailwind.config = {
      darkMode: "class",
      theme: {
        extend: {
          colors: {
            "inverse-on-surface": "#9a9d9f",
            "on-secondary-container": "#455367",
            "background": "#f7f9fb",
            "primary-fixed": "#dae2fd",
            "surface-tint": "#565e74",
            "secondary-container": "#d5e3fd",
            "surface-container-high": "#e1e9ee",
            "primary-dim": "#4a5268",
            "tertiary-container": "#91feef",
            "primary-container": "#dae2fd",
            "on-error": "#fff7f6",
            "secondary-fixed": "#d5e3fd",
            "on-secondary": "#f8f8ff",
            "surface-variant": "#d9e4ea",
            "tertiary-dim": "#005e56",
            "secondary": "#526075",
            "inverse-primary": "#dae2fd",
            "on-background": "#2a3439",
            "primary-fixed-dim": "#ccd4ee",
            "surface-dim": "#cfdce3",
            "outline-variant": "#a9b4b9",
            "error-container": "#fe8983",
            "on-tertiary-fixed": "#004e47",
            "surface-container-low": "#f0f4f7",
            "error": "#9f403d",
            "on-primary-fixed": "#373f54",
            "error-dim": "#4e0309",
            "primary": "#565e74",
            "on-tertiary": "#e2fff9",
            "surface-container-lowest": "#ffffff",
            "on-surface": "#2a3439",
            "on-primary": "#f7f7ff",
            "on-secondary-fixed": "#324054",
            "on-secondary-fixed-variant": "#4e5c71",
            "inverse-surface": "#0b0f10",
            "tertiary": "#006b62",
            "on-tertiary-container": "#006259",
            "on-surface-variant": "#566166",
            "surface-container": "#e8eff3",
            "secondary-dim": "#465469",
            "tertiary-fixed-dim": "#83efe1",
            "on-primary-container": "#4a5167",
            "surface": "#f7f9fb",
            "outline": "#717c82",
            "tertiary-fixed": "#91feef",
            "on-tertiary-fixed-variant": "#006d64",
            "surface-container-highest": "#d9e4ea",
            "on-error-container": "#752121",
            "surface-bright": "#f7f9fb",
            "secondary-fixed-dim": "#c7d5ee",
            "on-primary-fixed-variant": "#535b71"
          },
          borderRadius: {
            "DEFAULT": "0.125rem",
            "lg": "0.25rem",
            "xl": "0.5rem",
            "full": "0.75rem"
          },
          boxShadow: {
            "soft": "0 12px 28px rgba(42,52,57,0.06)",
            "glow": "0 18px 40px rgba(86,94,116,0.16)"
          },
          fontFamily: {
            "headline": ["Manrope"],
            "body": ["Inter"],
            "label": ["Inter"]
          }
        },
      },
    };
  <\/script>
  <style>
    body { font-family: 'Inter', sans-serif; margin: 0; -webkit-font-smoothing: antialiased; }
    .font-manrope { font-family: 'Manrope', sans-serif; }
    .material-symbols-outlined {
      font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24;
      font-family: 'Material Symbols Outlined';
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
      user-select: none;
      vertical-align: middle;
    }
    .soft-ring {
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.65);
    }
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: #f0f4f7; }
    ::-webkit-scrollbar-thumb { background: #ccd4ee; border-radius: 10px; }
  </style>
</head>
<body class="bg-background text-on-surface flex min-h-screen">
  <aside class="flex flex-col h-full py-6 bg-slate-50 h-screen w-64 border-r border-slate-200/50 font-manrope text-sm font-medium sticky top-0 shrink-0">
    <div class="px-6 mb-8">
      <div class="flex items-center gap-2">
        <span aria-hidden="true" class="material-symbols-outlined text-primary">anchor</span>
        <div>
          <h1 class="text-xl font-bold tracking-tight text-slate-900 font-manrope">ANCHOR</h1>
          <p class="text-[10px] uppercase tracking-widest text-on-surface-variant font-bold">Veterinary Governance</p>
        </div>
      </div>
    </div>

    <nav class="flex-1 space-y-1">
      <a data-anchor-route href="/workspace-live" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span aria-hidden="true" class="material-symbols-outlined">clinical_notes</span>
        <span>Workspace</span>
      </a>
      <a data-anchor-route href="/dashboard" class="flex items-center px-6 py-3 space-x-3 text-slate-900 font-bold border-r-2 border-slate-900 bg-slate-200/50 transition-all duration-200">
        <span aria-hidden="true" class="material-symbols-outlined">dashboard</span>
        <span>Dashboard</span>
      </a>
      <a data-anchor-route href="/receipts" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span aria-hidden="true" class="material-symbols-outlined">receipt_long</span>
        <span>Receipts</span>
      </a>
      <a data-anchor-route href="/governance-events" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span aria-hidden="true" class="material-symbols-outlined">verified_user</span>
        <span>Governance Events</span>
      </a>
      <a data-anchor-route href="/exports" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span aria-hidden="true" class="material-symbols-outlined">download</span>
        <span>Exports</span>
      </a>
      <a data-anchor-route href="/learn" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span aria-hidden="true" class="material-symbols-outlined">school</span>
        <span>Learn</span>
      </a>
      <a data-anchor-route href="/trust/profile" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span aria-hidden="true" class="material-symbols-outlined">shield_with_heart</span>
        <span>Trust</span>
      </a>
      <a data-anchor-route href="/intelligence" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span aria-hidden="true" class="material-symbols-outlined">psychology</span>
        <span>Intelligence</span>
      </a>
    </nav>

    <div class="mt-auto px-4">
      <div class="mt-6 space-y-1">
        <a data-anchor-route class="flex items-center px-2 py-2 space-x-3 text-slate-500 hover:text-slate-700 transition-colors" href="/settings">
          <span aria-hidden="true" class="material-symbols-outlined">settings</span>
          <span>Settings</span>
        </a>
        <a data-anchor-route class="flex items-center px-2 py-2 space-x-3 text-slate-500 hover:text-slate-700 transition-colors" href="/privacy-policy">
          <span aria-hidden="true" class="material-symbols-outlined">policy</span>
          <span>Privacy &amp; Policy</span>
        </a>
        <a data-anchor-route class="flex items-center px-2 py-2 space-x-3 text-slate-500 hover:text-slate-700 transition-colors" href="/support">
          <span aria-hidden="true" class="material-symbols-outlined">help_outline</span>
          <span>Support</span>
        </a>
      </div>
    </div>
  </aside>

  <div class="flex-1 flex flex-col">
    <header class="flex justify-between items-center w-full px-8 h-16 sticky top-0 z-50 bg-white/80 backdrop-blur-md border-b border-slate-100 font-manrope text-base shadow-sm">
      <div class="flex items-center flex-1 max-w-xl">
        <div class="relative w-full">
          <span aria-hidden="true" class="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-xl">search</span>
          <input class="w-full pl-10 pr-4 py-1.5 bg-surface-container-low border-none focus:ring-1 focus:ring-primary rounded-lg text-sm text-on-surface transition-all" placeholder="Search governance logs, audits, or metadata..." type="text"/>
        </div>
      </div>

      <div class="flex items-center gap-6">
        <button class="text-on-surface-variant hover:text-on-surface transition-transform active:scale-95">
          <span aria-hidden="true" class="material-symbols-outlined">notifications</span>
        </button>
        <button class="text-on-surface-variant hover:text-on-surface transition-transform active:scale-95">
          <span aria-hidden="true" class="material-symbols-outlined">settings</span>
        </button>
        <div class="h-6 w-[1px] bg-outline-variant/30"></div>

        <div id="profile-menu-anchor" class="relative">
          <button id="profile-menu-button" type="button" class="flex items-center gap-3 cursor-pointer group">
            <div class="text-right">
              <p id="profile-name" class="text-xs font-bold leading-none">Sarah Miller</p>
              <p id="profile-role" class="text-[10px] text-on-surface-variant">Practice Manager</p>
            </div>
            <img
              id="profile-avatar-img"
              alt="User Avatar"
              class="w-9 h-9 rounded-full object-cover grayscale-[0.2] border border-outline-variant/20"
              src="https://lh3.googleusercontent.com/aida-public/AB6AXuCnbGKz0TR_w7R7vfsdlOaArbM6Ka9P4NxHiCDCVu9tUHvElC9ITX3XsjBMrYZAIv3n-S06ghZKu1BTKIbpwbNIHkKoVMCo2ETSVZB_Lp6Km6Jd_5xHoQ3zB8HXdy_1_AQMQHMaheRN7A7BSx1SZUq6yajARax2RDSLTFq-h59_vYF75fpi0P3BPE4AjWoXtE8_7Ha9IjlxtIhWjqmdQAs1gQOxFyv2ganm7lmdG5dTZxehwGb8EPX2ZU_4Pa6iXRFWnROk2MISg4nq"
            />
          </button>
          <div id="profile-menu" class="hidden absolute right-0 top-12 z-30 min-w-[140px] rounded-lg border border-outline-variant/20 bg-white p-1 shadow-soft">
            <button id="sign-out-button" type="button" class="w-full rounded-md px-3 py-2 text-left text-sm font-medium text-on-surface hover:bg-surface-container-low">Sign out</button>
          </div>
        </div>
      </div>
    </header>

    <main class="p-8 max-w-[1480px] mx-auto w-full">
      <div class="mb-10">
        <h2 class="text-3xl font-extrabold tracking-tight font-manrope text-on-surface mb-1">Operational governance overview</h2>
        <p class="text-on-surface-variant text-sm leading-relaxed max-w-3xl">
          A calm leadership-facing surface for trust posture, institutional governance activity, receipts, learning signals, and intelligence.
        </p>

        <div class="flex flex-wrap gap-2 mt-6">
          <span class="inline-flex items-center rounded-full bg-surface-container-high px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider text-on-surface-variant">
            <span class="mr-1.5 h-1.5 w-1.5 rounded-full bg-on-surface-variant"></span>
            TRUST STATE (<span id="hero-trust-letter">A</span>)
          </span>
          <span class="inline-flex items-center rounded-full bg-surface-container-high px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider text-on-surface-variant">
            MODE: CLINIC-SCOPED
          </span>
          <span class="inline-flex items-center rounded-full bg-surface-container-high px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider text-on-surface-variant">
            EVENTS 24H (<span id="hero-events">0</span>)
          </span>
        </div>

        <div class="flex gap-3 mt-6">
          <button id="refresh-dashboard-button" class="px-5 py-2.5 bg-tertiary-fixed text-primary text-sm font-bold rounded-md shadow-soft hover:opacity-90 transition-all border border-white/40 soft-ring active:scale-[0.98]">
            Refresh dashboard
          </button>
          <button data-anchor-route="/workspace-live" class="px-6 py-2.5 bg-gradient-to-br from-primary to-primary-dim text-white text-sm font-bold rounded-md shadow-glow transition-all hover:opacity-95 active:scale-[0.98]">
            Open Workspace
          </button>
        </div>
      </div>

      <div class="grid grid-cols-12 gap-10">
        <div class="col-span-8 space-y-8">
          <section class="bg-surface-container-lowest rounded-xl p-8 border border-outline-variant/15 shadow-soft soft-ring">
            <div class="mb-8 flex justify-between items-start">
              <div>
                <span class="block text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-1">Governance Telemetry</span>
                <h3 class="font-manrope font-bold text-xl tracking-tight">24-hour governance activity</h3>
              </div>
              <div class="flex gap-2">
                <span class="rounded bg-surface-container px-2 py-0.5 text-[10px] font-bold uppercase text-on-surface-variant">CLINIC-SCOPED</span>
                <span class="rounded bg-tertiary/10 px-2 py-0.5 text-[10px] font-bold uppercase text-tertiary">LIVE SURFACE</span>
              </div>
            </div>

            <div class="mb-10 grid grid-cols-2 gap-4 md:grid-cols-4">
              <div class="rounded-lg border border-outline-variant/10 bg-surface-container-low p-4">
                <p class="mb-1 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">EVENTS</p>
                <p id="kpi-events" class="font-manrope text-3xl font-extrabold tracking-tight text-on-surface">0</p>
              </div>
              <div class="rounded-lg border border-outline-variant/10 bg-surface-container-low p-4">
                <p class="mb-1 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">INTERVENTIONS</p>
                <p id="kpi-interventions" class="font-manrope text-3xl font-extrabold tracking-tight text-on-surface">0</p>
              </div>
              <div class="rounded-lg border border-outline-variant/10 bg-surface-container-low p-4">
                <p class="mb-1 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">PII WARNED</p>
                <p id="kpi-pii" class="font-manrope text-3xl font-extrabold tracking-tight text-error">0</p>
              </div>
              <div class="rounded-lg border border-outline-variant/10 bg-surface-container-low p-4">
                <p class="mb-1 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">TOP MODE</p>
                <p id="kpi-top-mode" class="mt-1 font-manrope text-sm font-bold leading-tight text-on-surface">—</p>
              </div>
            </div>

            <div class="grid gap-10 md:grid-cols-2">
              <div class="space-y-4">
                <h4 class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">OPERATING SNAPSHOT</h4>
                <div class="space-y-3">
                  <div class="flex justify-between items-center border-b border-outline-variant/10 py-1 text-xs">
                    <span class="text-on-surface-variant">Events per hour</span>
                    <span id="snapshot-events-per-hour" class="font-bold text-on-surface">0.0</span>
                  </div>
                  <div class="flex justify-between items-center border-b border-outline-variant/10 py-1 text-xs">
                    <span class="text-on-surface-variant">Intervention rate</span>
                    <span id="snapshot-intervention-rate" class="font-bold text-on-surface">0.00%</span>
                  </div>
                  <div class="flex justify-between items-center border-b border-outline-variant/10 py-1 text-xs">
                    <span class="text-on-surface-variant">PII warned rate</span>
                    <span id="snapshot-pii-rate" class="font-bold text-on-surface">0.00%</span>
                  </div>
                </div>
              </div>

              <div class="space-y-4">
                <h4 class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">CURRENT ROUTE PICTURE</h4>
                <div class="space-y-3">
                  <div class="flex justify-between items-center border-b border-outline-variant/10 py-1 text-xs">
                    <span class="text-on-surface-variant">Top route</span>
                    <span id="route-top" class="font-bold text-on-surface">—</span>
                  </div>
                  <div class="flex justify-between items-center border-b border-outline-variant/10 py-1 text-xs">
                    <span class="text-on-surface-variant">Snapshot time</span>
                    <span id="route-time" class="font-bold text-on-surface">—</span>
                  </div>
                  <div class="flex justify-between items-center border-b border-outline-variant/10 py-1 text-xs">
                    <span class="text-on-surface-variant">Window</span>
                    <span class="font-bold text-on-surface">Rolling 24h</span>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section class="bg-surface-container-lowest rounded-xl p-8 border border-outline-variant/15 shadow-soft soft-ring">
            <div class="mb-8">
              <span class="block text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-1">Accountability Surfaces</span>
              <h3 class="font-manrope font-bold text-xl tracking-tight">Recent governance receipts</h3>
            </div>

            <div class="overflow-x-auto">
              <table class="w-full text-left">
                <thead>
                  <tr class="border-b border-surface-container-low text-[10px] font-bold uppercase tracking-wider text-on-surface-variant">
                    <th class="pb-4">REQUEST ID</th>
                    <th class="pb-4">MODE</th>
                    <th class="pb-4">DECISION</th>
                    <th class="pb-4">PII</th>
                    <th class="pb-4 text-right">RECEIPT</th>
                  </tr>
                </thead>
                <tbody id="receipts-body" class="divide-y divide-surface-container-low">
                  <tr>
                    <td colspan="5" class="py-8 text-sm text-on-surface-variant">Loading receipts…</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <div class="grid md:grid-cols-2 gap-8">
            <div class="bg-surface-container-lowest rounded-xl p-8 border border-outline-variant/15 shadow-soft soft-ring">
              <h4 class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-6">Recommended learning</h4>
              <div class="space-y-6">
                <a id="learning-primary-link" class="group flex items-center gap-4" href="/learn/cards/privacy-safe-ai-use" data-anchor-route="/learn/cards/privacy-safe-ai-use">
                  <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-surface-container-low text-primary transition-all group-hover:bg-primary group-hover:text-white">
                    <span id="learning-primary-icon" aria-hidden="true" class="material-symbols-outlined text-xl">book</span>
                  </div>
                  <div>
                    <div id="learning-primary-title" class="text-sm font-bold text-on-surface">PII Redaction Thresholds</div>
                    <div id="learning-primary-meta" class="mt-0.5 text-[10px] font-bold uppercase tracking-wide text-on-surface-variant">OPEN MICROLEARNING CARD • 5M</div>
                  </div>
                </a>

                <a id="learning-secondary-link" class="group flex items-center gap-4" href="/learn/explainers" data-anchor-route="/learn/explainers">
                  <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-surface-container-low text-primary transition-all group-hover:bg-primary group-hover:text-white">
                    <span aria-hidden="true" class="material-symbols-outlined text-xl">play_circle</span>
                  </div>
                  <div>
                    <div class="text-sm font-bold text-on-surface">Navigating the Receipt Ledger</div>
                    <div class="mt-0.5 text-[10px] font-bold uppercase tracking-wide text-on-surface-variant">OPEN EXPLAINER • 3M VIDEO</div>
                  </div>
                </a>
              </div>
            </div>

            <div class="flex flex-col justify-between rounded-xl bg-slate-900 p-8 text-white">
              <div>
                <div class="mb-6 flex justify-between items-start">
                  <h4 class="text-[10px] font-bold uppercase tracking-widest text-slate-400">RECOMMENDED NEXT ACTION</h4>
                  <span id="next-action-priority" class="rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide bg-amber-500 text-white">MEDIUM PRIORITY</span>
                </div>
                <p id="next-action-text" class="mb-8 text-[13px] font-medium leading-relaxed text-slate-300">
                  Review the most relevant recent receipt.
                </p>
              </div>
              <button id="review-receipt-button" class="inline-flex w-full items-center justify-center rounded-lg bg-white py-2.5 text-xs font-bold uppercase tracking-widest text-slate-950 transition-colors hover:bg-slate-100">
                REVIEW RECEIPT
              </button>
            </div>
          </div>
        </div>

        <div class="col-span-4 space-y-6">
          <div class="bg-slate-900 text-white rounded-xl p-8 relative overflow-hidden shadow-xl">
            <div class="relative z-10">
              <div class="mb-10 flex items-center gap-5">
                <div class="relative flex h-20 w-20 items-center justify-center rounded-full border-[6px] border-primary/20 bg-white/5">
                  <div class="absolute inset-0 rounded-full border-t-2 border-white/30 animate-[spin_6s_linear_infinite]"></div>
                  <span id="trust-letter-card" class="text-4xl font-black text-white">A</span>
                </div>
                <div>
                  <div class="mb-1 text-[10px] font-bold uppercase tracking-[0.2em] text-slate-400">TRUST POSTURE</div>
                  <div class="font-manrope text-xl font-bold">Clinic-Scoped</div>
                </div>
              </div>

              <ul id="trust-bullets" class="space-y-4">
                <li class="flex items-start gap-3">
                  <span aria-hidden="true" class="material-symbols-outlined text-tertiary text-lg">check_circle</span>
                  <span class="text-[13px] leading-tight tracking-tight text-slate-300">Clinic-scoped governance is active across current portal surfaces.</span>
                </li>
                <li class="flex items-start gap-3">
                  <span aria-hidden="true" class="material-symbols-outlined text-tertiary text-lg">check_circle</span>
                  <span class="text-[13px] leading-tight tracking-tight text-slate-300">Receipt-backed accountability remains visible without raw-content storage.</span>
                </li>
                <li class="flex items-start gap-3">
                  <span aria-hidden="true" class="material-symbols-outlined text-tertiary text-lg">check_circle</span>
                  <span class="text-[13px] leading-tight tracking-tight text-slate-300">Human review remains assumed before operational use.</span>
                </li>
              </ul>
            </div>
          </div>

          <div class="bg-surface-container-lowest rounded-xl p-6 border border-outline-variant/15 shadow-soft soft-ring">
            <div class="mb-6 flex justify-between items-start">
              <h4 class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">INTELLIGENCE SNAPSHOT</h4>
              <span id="intelligence-severity" class="rounded px-2 py-0.5 text-[10px] font-bold uppercase bg-tertiary/10 text-tertiary">LOW</span>
            </div>

            <div class="mb-8">
              <div class="mb-2 flex items-center gap-2">
                <span aria-hidden="true" class="material-symbols-outlined text-primary text-[18px]">location_on</span>
                <span id="hotspot-label" class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">HOTSPOT: NO HOTSPOT</span>
              </div>
              <p id="hotspot-summary" class="text-xs font-medium leading-relaxed text-on-surface">
                No prominent hotspot surfaced in the selected intelligence window.
              </p>
            </div>

            <div class="grid grid-cols-2 gap-2">
              <div class="rounded-lg border border-outline-variant/5 bg-surface-container-low p-3">
                <p class="mb-0.5 text-[9px] font-bold uppercase text-outline-variant">EVENT SHARE</p>
                <p id="hotspot-metric-a" class="text-base font-bold text-on-surface">—</p>
              </div>
              <div class="rounded-lg border border-outline-variant/5 bg-surface-container-low p-3">
                <p class="mb-0.5 text-[9px] font-bold uppercase text-outline-variant">RECENCY SPIKE</p>
                <p id="hotspot-metric-b" class="text-base font-bold text-on-surface">—</p>
              </div>
            </div>
          </div>

          <div class="space-y-2">
            <button data-anchor-route="/workspace-live" class="group flex w-full items-center justify-between rounded-xl border border-outline-variant/15 bg-surface-container-lowest px-4 py-3 transition-all hover:bg-surface-container-low">
              <div class="flex items-center gap-3">
                <span aria-hidden="true" class="material-symbols-outlined text-primary text-[20px]">terminal</span>
                <span class="text-[13px] font-bold text-on-surface">Open Workspace</span>
              </div>
              <span aria-hidden="true" class="material-symbols-outlined text-outline transition-transform group-hover:translate-x-0.5 text-[18px]">chevron_right</span>
            </button>
            <button data-anchor-route="/receipts" class="group flex w-full items-center justify-between rounded-xl border border-outline-variant/15 bg-surface-container-lowest px-4 py-3 transition-all hover:bg-surface-container-low">
              <div class="flex items-center gap-3">
                <span aria-hidden="true" class="material-symbols-outlined text-primary text-[20px]">receipt_long</span>
                <span class="text-[13px] font-bold text-on-surface">Open receipt viewer</span>
              </div>
              <span aria-hidden="true" class="material-symbols-outlined text-outline transition-transform group-hover:translate-x-0.5 text-[18px]">chevron_right</span>
            </button>
            <button data-anchor-route="/intelligence" class="group flex w-full items-center justify-between rounded-xl border border-outline-variant/15 bg-surface-container-lowest px-4 py-3 transition-all hover:bg-surface-container-low">
              <div class="flex items-center gap-3">
                <span aria-hidden="true" class="material-symbols-outlined text-primary text-[20px]">psychology</span>
                <span class="text-[13px] font-bold text-on-surface">Open Intelligence</span>
              </div>
              <span aria-hidden="true" class="material-symbols-outlined text-outline transition-transform group-hover:translate-x-0.5 text-[18px]">chevron_right</span>
            </button>
            <button data-anchor-route="/learn" class="group flex w-full items-center justify-between rounded-xl border border-outline-variant/15 bg-surface-container-lowest px-4 py-3 transition-all hover:bg-surface-container-low">
              <div class="flex items-center gap-3">
                <span aria-hidden="true" class="material-symbols-outlined text-primary text-[20px]">school</span>
                <span class="text-[13px] font-bold text-on-surface">Open Learn</span>
              </div>
              <span aria-hidden="true" class="material-symbols-outlined text-outline transition-transform group-hover:translate-x-0.5 text-[18px]">chevron_right</span>
            </button>
            <button data-anchor-route="/exports" class="group flex w-full items-center justify-between rounded-xl border border-outline-variant/15 bg-surface-container-lowest px-4 py-3 transition-all hover:bg-surface-container-low">
              <div class="flex items-center gap-3">
                <span aria-hidden="true" class="material-symbols-outlined text-primary text-[20px]">download</span>
                <span class="text-[13px] font-bold text-on-surface">Export governance data</span>
              </div>
              <span aria-hidden="true" class="material-symbols-outlined text-outline transition-transform group-hover:translate-x-0.5 text-[18px]">chevron_right</span>
            </button>
          </div>

          <div class="space-y-3 pt-2">
            <div class="flex items-center gap-4 rounded-xl bg-surface-container-low px-5 py-4 border-l-2 border-primary/40">
              <span aria-hidden="true" class="material-symbols-outlined text-primary text-[20px]">shield</span>
              <div>
                <h4 class="mb-0.5 text-[9px] font-bold uppercase tracking-widest text-on-surface-variant">PRINCIPLE 01</h4>
                <p class="text-xs font-bold text-on-surface">Metadata-only accountability</p>
              </div>
            </div>

            <div class="flex items-center gap-4 rounded-xl bg-surface-container-low px-5 py-4 border-l-2 border-primary/40">
              <span aria-hidden="true" class="material-symbols-outlined text-primary text-[20px]">visibility</span>
              <div>
                <h4 class="mb-0.5 text-[9px] font-bold uppercase tracking-widest text-on-surface-variant">PRINCIPLE 02</h4>
                <p class="text-xs font-bold text-on-surface">Operational clarity</p>
              </div>
            </div>

            <div class="flex items-center gap-4 rounded-xl bg-surface-container-low px-5 py-4 border-l-2 border-primary/40">
              <span aria-hidden="true" class="material-symbols-outlined text-primary text-[20px]">integration_instructions</span>
              <div>
                <h4 class="mb-0.5 text-[9px] font-bold uppercase tracking-widest text-on-surface-variant">PRINCIPLE 03</h4>
                <p class="text-xs font-bold text-on-surface">Product coherence</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
  </div>

<script>
  (function () {
    const API_BASE = ${JSON.stringify(API_BASE)};

    const $ = (id) => document.getElementById(id);

    const els = {
      profileName: $("profile-name"),
      profileRole: $("profile-role"),
      profileAvatarImg: $("profile-avatar-img"),
      profileMenuButton: $("profile-menu-button"),
      profileMenu: $("profile-menu"),
      signOutButton: $("sign-out-button"),

      refreshButton: $("refresh-dashboard-button"),
      heroTrustLetter: $("hero-trust-letter"),
      heroEvents: $("hero-events"),

      kpiEvents: $("kpi-events"),
      kpiInterventions: $("kpi-interventions"),
      kpiPii: $("kpi-pii"),
      kpiTopMode: $("kpi-top-mode"),

      snapshotEventsPerHour: $("snapshot-events-per-hour"),
      snapshotInterventionRate: $("snapshot-intervention-rate"),
      snapshotPiiRate: $("snapshot-pii-rate"),

      routeTop: $("route-top"),
      routeTime: $("route-time"),

      receiptsBody: $("receipts-body"),

      learningPrimaryLink: $("learning-primary-link"),
      learningPrimaryIcon: $("learning-primary-icon"),
      learningPrimaryTitle: $("learning-primary-title"),
      learningPrimaryMeta: $("learning-primary-meta"),

      nextActionPriority: $("next-action-priority"),
      nextActionText: $("next-action-text"),
      reviewReceiptButton: $("review-receipt-button"),

      trustLetterCard: $("trust-letter-card"),
      trustBullets: $("trust-bullets"),

      intelligenceSeverity: $("intelligence-severity"),
      hotspotLabel: $("hotspot-label"),
      hotspotSummary: $("hotspot-summary"),
      hotspotMetricA: $("hotspot-metric-a"),
      hotspotMetricB: $("hotspot-metric-b")
    };

    const state = {
      latestActionHref: "/receipts"
    };

    function getAuthHeaders() {
      const token = localStorage.getItem("anchor_access_token");
      return token ? { Authorization: "Bearer " + token } : {};
    }

    function apiUrl(path) {
      if (!API_BASE) return path;
      return API_BASE + (path.startsWith("/") ? path : "/" + path);
    }

    function navigateParent(href, options) {
      try {
        if (window.parent && window.parent !== window) {
          window.parent.postMessage({ type: "anchor:navigate", href: href, replace: !!(options && options.replace) }, "*");
          return;
        }
      } catch (error) {
        console.warn("Parent navigation bridge failed", error);
      }
      if (options && options.replace) {
        window.location.replace(href);
      } else {
        window.location.href = href;
      }
    }

    function requestParentSignOut() {
      try {
        if (window.parent && window.parent !== window) {
          window.parent.postMessage({ type: "anchor:signout" }, "*");
          return;
        }
      } catch (error) {
        console.warn("Parent sign-out bridge failed", error);
      }
      try {
        localStorage.removeItem("anchor_access_token");
        localStorage.removeItem("anchor_session_user");
      } catch {}
      window.location.replace("/login");
    }

    function safeText(value, fallback) {
      if (fallback === undefined) fallback = "—";
      if (value === null || value === undefined || value === "") return fallback;
      return String(value);
    }

    function safeNumber(value, fallback) {
      if (fallback === undefined) fallback = 0;
      return typeof value === "number" && Number.isFinite(value) ? value : fallback;
    }

    function formatInteger(value) {
      if (typeof value !== "number" || !Number.isFinite(value)) return "—";
      return new Intl.NumberFormat("en-GB").format(value);
    }

    function formatPercent(value) {
      if (typeof value !== "number" || !Number.isFinite(value)) return "—";
      return (value * 100).toFixed(2) + "%";
    }

    function formatDecimal(value, places) {
      if (places === undefined) places = 1;
      if (typeof value !== "number" || !Number.isFinite(value)) return "—";
      return value.toFixed(places);
    }

    function formatSnapshotTime(value) {
      if (!value) return "—";
      const d = new Date(String(value));
      if (Number.isNaN(d.getTime())) return String(value);
      return new Intl.DateTimeFormat("en-GB", {
        day: "2-digit",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false
      }).format(d);
    }

    function humanizeToken(value) {
      const text = safeText(value, "—");
      return text.replace(/_/g, " ").replace(/\\b\\w/g, function (char) {
        return char.toUpperCase();
      });
    }

    function prettyMode(value) {
      const raw = safeText(value, "—");
      const normalized = raw.toLowerCase().trim();
      const map = {
        client_comm: "Client communication",
        client_communication: "Client communication",
        clinical_note: "Clinical note",
        clinical_note_baseline: "Clinical note baseline",
        internal_summary: "Internal summary"
      };
      return map[normalized] || humanizeToken(raw);
    }

    function extractTrustState(raw) {
      const candidate = raw && raw.trust_state;
      if (typeof candidate === "string") return candidate;
      if (candidate && typeof candidate === "object") {
        if (typeof candidate.health_state === "string") return candidate.health_state;
        if (typeof candidate.state === "string") return candidate.state;
        if (typeof candidate.value === "string") return candidate.value;
      }
      return "unknown";
    }

    function extractTrustReasons(raw) {
      const candidate = raw && raw.trust_state;
      if (candidate && typeof candidate === "object" && Array.isArray(candidate.reasons)) {
        return candidate.reasons.map(function (x) {
          return safeText(x, "");
        }).filter(Boolean);
      }
      return [];
    }

    function trustLetter(value) {
      const normalized = String(value || "").toLowerCase().trim();
      if (normalized === "green") return "A";
      if (normalized === "yellow" || normalized === "amber") return "B";
      if (normalized === "red") return "C";
      return "A";
    }

    function escapeHtml(value) {
      return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }

    function decisionBadge(decision) {
      const normalized = String(decision || "").toLowerCase();
      if (normalized === "allowed" || normalized === "verified" || normalized === "pass") {
        return '<span class="inline-flex rounded px-2 py-0.5 text-[10px] font-bold uppercase bg-tertiary/10 text-tertiary">' + escapeHtml(safeText(decision).toUpperCase()) + "</span>";
      }
      if (normalized === "modified" || normalized === "warning" || normalized === "warn") {
        return '<span class="inline-flex rounded px-2 py-0.5 text-[10px] font-bold uppercase bg-amber-100 text-amber-800">' + escapeHtml(safeText(decision).toUpperCase()) + "</span>";
      }
      if (normalized === "blocked" || normalized === "replaced" || normalized === "flagged") {
        return '<span class="inline-flex rounded px-2 py-0.5 text-[10px] font-bold uppercase bg-error/10 text-error">' + escapeHtml(safeText(decision).toUpperCase()) + "</span>";
      }
      return '<span class="inline-flex rounded px-2 py-0.5 text-[10px] font-bold uppercase bg-surface-container-high text-on-surface-variant">' + escapeHtml(safeText(decision).toUpperCase()) + "</span>";
    }

    function priorityBadgeClass(priority) {
      const normalized = String(priority || "").toLowerCase();
      if (normalized === "high") return "rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide bg-error text-white";
      if (normalized === "medium") return "rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide bg-amber-500 text-white";
      if (normalized === "low") return "rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide bg-tertiary text-white";
      return "rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide bg-primary text-white";
    }

    function severityClass(severity) {
      const normalized = String(severity || "").toLowerCase();
      if (normalized === "high") return "rounded px-2 py-0.5 text-[10px] font-bold uppercase bg-error/10 text-error";
      if (normalized === "medium") return "rounded px-2 py-0.5 text-[10px] font-bold uppercase bg-amber-100 text-amber-800";
      return "rounded px-2 py-0.5 text-[10px] font-bold uppercase bg-tertiary/10 text-tertiary";
    }

    function hotspotLabel(hotspot) {
      if (!hotspot) return "HOTSPOT: NO HOTSPOT";
      return "HOTSPOT: " + String(hotspot.dimension || "signal").toUpperCase() + "-" + String(hotspot.key || "unknown").toUpperCase();
    }

    function closeMenus() {
      els.profileMenu.classList.add("hidden");
    }

    function setUserFromSession() {
      try {
        const raw = localStorage.getItem("anchor_session_user");
        if (!raw) return;
        const user = JSON.parse(raw);

        if (user && typeof user.display_name === "string" && user.display_name.trim()) {
          els.profileName.textContent = user.display_name.trim();
        }

        if (user && typeof user.display_role === "string" && user.display_role.trim()) {
          els.profileRole.textContent = user.display_role.trim();
        }

        if (user && typeof user.avatar_url === "string" && user.avatar_url.trim()) {
          els.profileAvatarImg.src = user.avatar_url.trim();
        }
      } catch (error) {
        console.warn("Unable to read session user", error);
      }
    }

    function bindNavigation() {
      document.querySelectorAll("[data-anchor-route]").forEach(function (node) {
        node.addEventListener("click", function (event) {
          event.preventDefault();
          const href = node.getAttribute("data-anchor-route") || node.getAttribute("href") || "/dashboard";
          navigateParent(href);
        });
      });
    }

    function renderTrustBullets(reasons) {
      const cleaned = (Array.isArray(reasons) ? reasons : [])
        .map(function (item) { return humanizeToken(item); })
        .filter(function (item) { return item && item !== "—"; });

      const bullets = cleaned.length >= 3
        ? cleaned.slice(0, 3)
        : [
            "Clinic-scoped governance is active across current portal surfaces.",
            "Receipt-backed accountability remains visible without raw-content storage.",
            "Human review remains assumed before operational use."
          ];

      els.trustBullets.innerHTML = bullets.map(function (item) {
        return '<li class="flex items-start gap-3">' +
          '<span aria-hidden="true" class="material-symbols-outlined text-tertiary text-lg">check_circle</span>' +
          '<span class="text-[13px] leading-tight tracking-tight text-slate-300">' + escapeHtml(item) + "</span>" +
        "</li>";
      }).join("");
    }

    function renderReceipts(recent) {
      const rows = Array.isArray(recent) ? recent.slice(0, 3) : [];

      if (!rows.length) {
        els.receiptsBody.innerHTML =
          '<tr><td colspan="5" class="py-8 text-sm text-on-surface-variant">No recent governance receipts available.</td></tr>';
        bindNavigation();
        return;
      }

      els.receiptsBody.innerHTML = rows.map(function (item) {
        const requestId = safeText(item.request_id, "");
        const modeText = prettyMode(item.mode);
        const decisionText = safeText(item.decision, "—");
        const piiDetected = !!item.pii_detected;
        const receiptHref = requestId ? "/receipts?request_id=" + encodeURIComponent(requestId) : "/receipts";

        return '<tr class="group transition-colors hover:bg-surface-container-low/30">' +
          '<td class="py-4 text-xs font-mono font-bold text-on-surface">' + escapeHtml(requestId || "—") + "</td>" +
          '<td class="py-4 text-xs font-medium text-on-surface">' + escapeHtml(modeText) + "</td>" +
          '<td class="py-4">' + decisionBadge(decisionText) + "</td>" +
          '<td class="py-4 text-[11px] ' + (piiDetected ? "font-semibold uppercase tracking-tight text-error" : "italic text-on-surface-variant") + '">' +
            (piiDetected ? "Detected" : "Not detected") +
          "</td>" +
          '<td class="py-4 text-right">' +
            '<a data-anchor-route="' + receiptHref + '" href="' + receiptHref + '" class="inline-flex items-center gap-1 text-xs font-bold text-primary hover:underline">' +
              'Open link <span aria-hidden="true" class="material-symbols-outlined text-[14px]">open_in_new</span>' +
            '</a>' +
          "</td>" +
        "</tr>";
      }).join("");

      bindNavigation();
    }

    function applyData(dashboard, intelligence) {
      const kpis = dashboard && dashboard.kpis_24h ? dashboard.kpis_24h : {};
      const recent = Array.isArray(dashboard && dashboard.recent_submissions) ? dashboard.recent_submissions : [];
      const trustState = extractTrustState(dashboard);
      const trustReasons = extractTrustReasons(dashboard);
      const trustGrade = trustLetter(trustState);

      const events = safeNumber(kpis.events_24h, 0);
      const interventions = safeNumber(kpis.interventions_24h, 0);
      const piiWarned = safeNumber(kpis.pii_warned_24h, 0);
      const topMode = safeText(kpis.top_mode_24h, "—");
      const topRoute = safeText(kpis.top_route_24h, "—");
      const eventsPerHour = safeNumber(kpis.events_per_hour, 0);
      const interventionRate = safeNumber(kpis.intervention_rate_24h, 0);
      const piiWarnedRate = safeNumber(kpis.pii_warned_rate_24h, 0);

      els.heroTrustLetter.textContent = trustGrade;
      els.trustLetterCard.textContent = trustGrade;
      els.heroEvents.textContent = formatInteger(events);

      els.kpiEvents.textContent = formatInteger(events);
      els.kpiInterventions.textContent = formatInteger(interventions);
      els.kpiPii.textContent = piiWarned > 0 ? String(piiWarned).padStart(2, "0") : formatInteger(piiWarned);
      els.kpiTopMode.textContent = prettyMode(topMode);

      els.snapshotEventsPerHour.textContent = formatDecimal(eventsPerHour, 1);
      els.snapshotInterventionRate.textContent = formatPercent(interventionRate);
      els.snapshotPiiRate.textContent = formatPercent(piiWarnedRate);

      els.routeTop.textContent = topRoute;
      els.routeTime.textContent = formatSnapshotTime((dashboard && dashboard.now_utc) || (intelligence && intelligence.generated_at));

      renderReceipts(recent);
      renderTrustBullets(trustReasons);

      const headlineHotspot = intelligence && intelligence.headline_hotspot ? intelligence.headline_hotspot : null;
      const headlineAction = intelligence && intelligence.headline_action ? intelligence.headline_action : null;

      if (headlineAction && (headlineAction.type === "learning" || headlineAction.type === "privacy_training")) {
        els.learningPrimaryTitle.textContent = safeText(headlineAction.title, "PII Redaction Thresholds");
        els.learningPrimaryMeta.textContent = "OPEN MICROLEARNING CARD";
        els.learningPrimaryLink.setAttribute("href", headlineAction.target_path || "/learn/cards/privacy-safe-ai-use");
        els.learningPrimaryLink.setAttribute("data-anchor-route", headlineAction.target_path || "/learn/cards/privacy-safe-ai-use");
        els.learningPrimaryIcon.textContent = "book";
      } else {
        els.learningPrimaryTitle.textContent = "PII Redaction Thresholds";
        els.learningPrimaryMeta.textContent = "OPEN MICROLEARNING CARD • 5M";
        els.learningPrimaryLink.setAttribute("href", "/learn/cards/privacy-safe-ai-use");
        els.learningPrimaryLink.setAttribute("data-anchor-route", "/learn/cards/privacy-safe-ai-use");
        els.learningPrimaryIcon.textContent = "book";
      }

      const priorityReceipt = (function () {
        if (!recent.length) return null;
        const piiFirst = recent.find(function (item) { return !!item.pii_detected; });
        if (piiFirst) return piiFirst;
        const nonAllowed = recent.find(function (item) {
          const decision = safeText(item.decision, "").toLowerCase();
          return decision !== "allowed" && decision !== "pass";
        });
        if (nonAllowed) return nonAllowed;
        return recent[0];
      })();

      const priorityReceiptId = safeText(priorityReceipt && priorityReceipt.request_id, "");
      let actionHref = "/receipts";
      if (headlineAction && headlineAction.target_path) {
        actionHref = headlineAction.target_path;
      } else if (priorityReceiptId) {
        actionHref = "/receipts?request_id=" + encodeURIComponent(priorityReceiptId);
      }

      let actionPriority = "low";
      if (headlineAction && headlineAction.priority) {
        actionPriority = headlineAction.priority;
      } else if (priorityReceipt && !!priorityReceipt.pii_detected) {
        actionPriority = "high";
      } else if (piiWarned > 0) {
        actionPriority = "medium";
      }

      let nextActionText = "Review recent governance activity and confirm whether any receipt requires follow-up.";
      if (headlineAction && headlineAction.why) {
        nextActionText = safeText(headlineAction.why);
      } else if (priorityReceipt && !!priorityReceipt.pii_detected && priorityReceiptId) {
        nextActionText = "Review the PII intervention detected in receipt " + priorityReceiptId + ". Potential identifying detail requires human review before operational use.";
      } else if (piiWarned > 0) {
        nextActionText = "PII warnings exceed advisory thresholds in the selected period.";
      } else if (priorityReceiptId) {
        nextActionText = "Review the governance activity attached to receipt " + priorityReceiptId + " and confirm whether any follow-up is required before use.";
      }

      els.nextActionPriority.className = priorityBadgeClass(actionPriority);
      els.nextActionPriority.textContent = humanizeToken(actionPriority) + " PRIORITY";
      els.nextActionText.textContent = nextActionText;
      state.latestActionHref = actionHref;

      els.intelligenceSeverity.className = severityClass(headlineHotspot && headlineHotspot.severity ? headlineHotspot.severity : "low");
      els.intelligenceSeverity.textContent = headlineHotspot ? humanizeToken(headlineHotspot.severity) : "Nominal";
      els.hotspotLabel.textContent = hotspotLabel(headlineHotspot);
      els.hotspotSummary.textContent = headlineHotspot
        ? safeText(headlineHotspot.summary)
        : "No prominent hotspot surfaced in the selected intelligence window.";
      els.hotspotMetricA.textContent = headlineHotspot ? formatPercent(headlineHotspot.event_share) : "—";
      els.hotspotMetricB.textContent = headlineHotspot ? formatDecimal(headlineHotspot.recency_spike_ratio, 1) + "x" : "—";
    }

    async function loadDashboard() {
      els.refreshButton.disabled = true;
      els.refreshButton.textContent = "Refreshing...";

      try {
        const [dashboardResult, intelligenceResult] = await Promise.allSettled([
          fetch(apiUrl("/v1/portal/dashboard"), {
            headers: {
              "Content-Type": "application/json",
              ...getAuthHeaders()
            }
          }),
          fetch(apiUrl("/v1/portal/intelligence/summary?window=30d"), {
            headers: {
              "Content-Type": "application/json",
              ...getAuthHeaders()
            }
          })
        ]);

        if (dashboardResult.status !== "fulfilled") {
          throw new Error("Unable to load dashboard.");
        }

        if (!dashboardResult.value.ok) {
          const raw = await dashboardResult.value.text();
          throw new Error(raw || "Unable to load dashboard.");
        }

        const dashboard = await dashboardResult.value.json();

        let intelligence = null;
        if (intelligenceResult.status === "fulfilled" && intelligenceResult.value.ok) {
          intelligence = await intelligenceResult.value.json();
        }

        applyData(dashboard, intelligence);
      } catch (error) {
        console.error(error);
        els.receiptsBody.innerHTML =
          '<tr><td colspan="5" class="py-8 text-sm text-error">Dashboard unavailable.</td></tr>';
      } finally {
        els.refreshButton.disabled = false;
        els.refreshButton.textContent = "Refresh dashboard";
      }
    }

    els.refreshButton.addEventListener("click", function () {
      loadDashboard();
    });

    els.reviewReceiptButton.addEventListener("click", function () {
      navigateParent(state.latestActionHref || "/receipts");
    });

    els.profileMenuButton.addEventListener("click", function (event) {
      event.stopPropagation();
      const willOpen = els.profileMenu.classList.contains("hidden");
      closeMenus();
      if (willOpen) els.profileMenu.classList.remove("hidden");
    });

    els.signOutButton.addEventListener("click", function () {
      requestParentSignOut();
    });

    document.addEventListener("click", function () {
      closeMenus();
    });

    bindNavigation();
    setUserFromSession();
    loadDashboard();
  })();
<\/script>

</body>
</html>
`;

function decodeBase64Url(input: string) {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  return atob(padded);
}

function readTokenExpiry(token: string | null): number | null {
  if (!token) return null;
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    const payload = JSON.parse(decodeBase64Url(parts[1])) as { exp?: number };
    return typeof payload.exp === "number" ? payload.exp : null;
  } catch {
    return null;
  }
}

export default function DashboardPage() {
  const router = useRouter();
  const [authReady, setAuthReady] = useState(false);
  const [isAuthed, setIsAuthed] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined") return;

    const evaluateAuth = () => {
      const token = window.localStorage.getItem("anchor_access_token");
      const exp = readTokenExpiry(token);
      const expired = typeof exp === "number" ? Date.now() >= exp * 1000 : false;
      const authed = !!token && !expired;
      setIsAuthed(authed);
      setAuthReady(true);
      if (!authed) {
        router.replace("/login");
      }
    };

    const onMessage = (event: MessageEvent) => {
      const data = event.data as { type?: string; href?: string; replace?: boolean } | null;
      if (!data || typeof data !== "object") return;

      if (data.type === "anchor:signout") {
        try {
          window.localStorage.removeItem("anchor_access_token");
          window.localStorage.removeItem("anchor_session_user");
        } catch {}
        setIsAuthed(false);
        router.replace("/login");
        return;
      }

      if (data.type === "anchor:navigate" && data.href) {
        if (data.replace) {
          router.replace(data.href);
        } else {
          router.push(data.href);
        }
      }
    };

    evaluateAuth();
    window.addEventListener("message", onMessage);
    window.addEventListener("storage", evaluateAuth);

    return () => {
      window.removeEventListener("message", onMessage);
      window.removeEventListener("storage", evaluateAuth);
    };
  }, [router]);

  const html = useMemo(() => stitchHtml, []);

  if (!authReady) {
    return <div className="h-screen w-full bg-white" />;
  }

  if (!isAuthed) {
    return null;
  }

  return (
    <div className="h-screen w-full bg-white">
      <iframe
        title="Dashboard Stitch"
        srcDoc={html}
        className="h-full w-full border-0"
        sandbox="allow-scripts allow-same-origin"
      />
    </div>
  );
}