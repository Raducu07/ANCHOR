"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";

const API_BASE = (process.env.NEXT_PUBLIC_API_BASE ?? "").replace(/\/$/, "");

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

function buildHtml(apiBase: string, initialRequestId: string) {
  return `<!DOCTYPE html>
<html class="light" lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>ANCHOR | Receipts</title>
  <script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
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
  </script>
  <style>
    body { font-family: "Inter", sans-serif; margin: 0; -webkit-font-smoothing: antialiased; }
    .font-manrope { font-family: "Manrope", sans-serif; }
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
    .soft-ring { box-shadow: inset 0 1px 0 rgba(255,255,255,0.65); }
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
      <a data-anchor-route href="/dashboard" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span aria-hidden="true" class="material-symbols-outlined">dashboard</span>
        <span>Dashboard</span>
      </a>
      <a data-anchor-route href="/receipts" class="flex items-center px-6 py-3 space-x-3 text-slate-900 font-bold border-r-2 border-slate-900 bg-slate-200/50 transition-all duration-200">
        <span aria-hidden="true" class="material-symbols-outlined">receipt_long</span>
        <span>Receipts</span>
      </a>
      <a data-anchor-route href="/governance-events" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span aria-hidden="true" class="material-symbols-outlined">verified_user</span>
        <span>Governance Events</span>
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
      <a data-anchor-route href="/exports" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span aria-hidden="true" class="material-symbols-outlined">download</span>
        <span>Exports</span>
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
          <input class="w-full pl-10 pr-4 py-1.5 bg-surface-container-low border-none focus:ring-1 focus:ring-primary rounded-lg text-sm text-on-surface transition-all" placeholder="Search request ID, mode, or metadata..." type="text"/>
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
              <p id="profile-name" class="text-xs font-bold leading-none">Clinic User</p>
              <p id="profile-role" class="text-[10px] text-on-surface-variant">Team member</p>
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
        <h2 class="text-3xl font-extrabold tracking-tight font-manrope text-on-surface mb-1">Receipts</h2>
        <p class="text-on-surface-variant text-sm leading-relaxed max-w-3xl">
          Request-level accountability, traceability, and metadata-backed governance review.
        </p>

        <div class="flex flex-wrap gap-2 mt-6">
          <span class="inline-flex items-center rounded-full bg-surface-container-high px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider text-on-surface-variant">
            <span class="mr-1.5 h-1.5 w-1.5 rounded-full bg-on-surface-variant"></span>
            RECEIPT STATUS (<span id="hero-status-chip">READY</span>)
          </span>
          <span class="inline-flex items-center rounded-full bg-surface-container-high px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider text-on-surface-variant">
            NO CONTENT STORED (<span id="hero-no-content">YES</span>)
          </span>
          <span class="inline-flex items-center rounded-full bg-surface-container-high px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider text-on-surface-variant">
            SELECTED MODE (<span id="hero-mode-chip">—</span>)
          </span>
        </div>

        <div class="flex gap-3 mt-6">
          <button id="refresh-page-button" class="px-5 py-2.5 bg-tertiary-fixed text-primary text-sm font-bold rounded-md shadow-soft hover:opacity-90 transition-all border border-white/40 soft-ring active:scale-[0.98]">
            Refresh receipts
          </button>
          <button id="export-selected-button" class="px-5 py-2.5 bg-gradient-to-br from-primary to-primary-dim text-white text-sm font-bold rounded-md shadow-glow transition-all hover:opacity-95 active:scale-[0.98]">
            Export metadata
          </button>
        </div>
      </div>

      <div class="max-w-7xl mb-10 bg-surface-container-low p-4 rounded-xl flex flex-wrap items-end gap-4 shadow-soft soft-ring">
        <div class="flex-1 min-w-[240px]">
          <label class="block text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-2 ml-1">Request ID</label>
          <input id="request-id-input" class="w-full bg-white border-none rounded-lg px-4 py-2.5 text-sm font-mono font-bold text-primary shadow-sm focus:ring-1 focus:ring-primary/40 outline-none" placeholder="Paste a request ID or load a recent receipt" type="text"/>
        </div>

        <div class="w-[170px]">
          <label class="block text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-2 ml-1">Recent period</label>
          <div class="relative">
            <input class="w-full bg-white border-none rounded-lg px-4 py-2.5 text-sm shadow-sm cursor-default" readonly type="text" value="Rolling 24h"/>
            <span aria-hidden="true" class="material-symbols-outlined absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-[18px]">schedule</span>
          </div>
        </div>

        <div class="w-[170px]">
          <label class="block text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-2 ml-1">Filter mode</label>
          <select id="mode-filter-select" class="w-full bg-white border-none rounded-lg px-4 py-2.5 text-sm shadow-sm focus:ring-1 focus:ring-primary/40 outline-none">
            <option value="all">All modes</option>
            <option value="internal_summary">Internal summary</option>
            <option value="client_comm">Client communication</option>
            <option value="clinical_note">Clinical note drafting</option>
          </select>
        </div>

        <div class="pt-1">
          <button id="load-receipt-button" class="bg-primary text-on-primary px-6 py-2.5 rounded-lg font-bold text-sm tracking-tight flex items-center gap-2 shadow-sm">
            <span aria-hidden="true" class="material-symbols-outlined text-[18px]">open_in_new</span>
            Load receipt
          </button>
        </div>
      </div>

      <div class="grid grid-cols-12 gap-10">
        <div class="col-span-8 space-y-8">
          <section class="bg-surface-container-lowest p-8 rounded-xl border border-outline-variant/15 shadow-soft soft-ring">
            <div class="flex justify-between items-start mb-8">
              <div>
                <span class="text-[10px] font-extrabold text-primary uppercase tracking-[0.2em] mb-2 block">Governance Receipt</span>
                <h3 id="summary-request-id" class="text-2xl font-bold font-manrope text-on-surface">—</h3>
                <p id="summary-created-at" class="text-sm text-on-surface-variant font-mono mt-1 opacity-70">Created at —</p>
              </div>
              <div class="text-right">
                <div id="summary-decision-badge" class="inline-flex items-center gap-2 px-3 py-1 bg-tertiary/10 text-tertiary rounded-lg border border-tertiary/20">
                  <span class="w-2 h-2 rounded-full bg-tertiary"></span>
                  <span class="text-xs font-bold uppercase tracking-wider">Awaiting selection</span>
                </div>
              </div>
            </div>

            <div class="grid grid-cols-2 gap-y-8 gap-x-12">
              <div class="space-y-1">
                <label class="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest block opacity-60">Processing mode</label>
                <p id="summary-mode" class="text-sm font-semibold text-on-surface">—</p>
              </div>
              <div class="space-y-1">
                <label class="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest block opacity-60">Decision</label>
                <p id="summary-decision" class="text-sm font-semibold text-on-surface">—</p>
              </div>
              <div class="space-y-1">
                <label class="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest block opacity-60">Risk grade</label>
                <p id="summary-risk-grade" class="text-sm font-semibold text-on-surface">—</p>
              </div>
              <div class="space-y-1">
                <label class="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest block opacity-60">Neutrality version</label>
                <p id="summary-neutrality-version" class="text-sm font-mono font-semibold text-on-surface">—</p>
              </div>
              <div class="space-y-1">
                <label class="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest block opacity-60">PII detected</label>
                <p id="summary-pii-detected" class="text-sm font-semibold text-on-surface">—</p>
              </div>
              <div class="space-y-1">
                <label class="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest block opacity-60">PII action</label>
                <p id="summary-pii-action" class="text-sm font-semibold text-on-surface">—</p>
              </div>
              <div class="space-y-1">
                <label class="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest block opacity-60">Policy version</label>
                <p id="summary-policy-version" class="text-sm font-semibold text-on-surface">—</p>
              </div>
              <div class="space-y-1">
                <label class="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest block opacity-60">Governance score</label>
                <p id="summary-governance-score" class="text-sm font-semibold text-on-surface">—</p>
              </div>
              <div class="space-y-1">
                <label class="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest block opacity-60">Receipt status</label>
                <p id="summary-receipt-status" class="text-sm font-semibold text-on-surface">—</p>
              </div>
              <div class="space-y-1">
                <label class="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest block opacity-60">No content stored</label>
                <p id="summary-no-content-stored" class="text-sm font-semibold text-on-surface">Yes</p>
              </div>
            </div>
          </section>

          <section class="bg-surface-container-low p-8 rounded-xl border border-outline-variant/15 shadow-soft soft-ring">
            <h4 class="text-sm font-bold font-manrope uppercase tracking-widest text-on-surface mb-6 flex items-center gap-2">
              <span aria-hidden="true" class="material-symbols-outlined text-lg">history</span>
              Traceability
            </h4>

            <div class="space-y-6">
              <div class="bg-surface-container-lowest p-5 rounded-lg border border-outline-variant/10">
                <div class="flex items-center justify-between mb-2">
                  <span class="text-[11px] font-bold text-on-surface-variant opacity-60 uppercase">Policy hash</span>
                  <button id="copy-hash-button" class="text-primary hover:text-primary-dim transition-colors">
                    <span aria-hidden="true" class="material-symbols-outlined text-lg">content_copy</span>
                  </button>
                </div>
                <p id="trace-policy-hash" class="font-mono text-xs text-on-secondary-container break-all leading-relaxed bg-surface-container p-3 rounded">—</p>
              </div>

              <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h5 class="text-[10px] font-extrabold text-on-surface-variant uppercase mb-3">Governance detail</h5>
                  <div class="space-y-3 text-xs">
                    <div class="flex justify-between gap-4 border-b border-outline-variant/10 py-2">
                      <span class="text-on-surface-variant">Rules fired</span>
                      <span id="trace-rules-fired" class="font-bold text-on-surface text-right">—</span>
                    </div>
                    <div class="flex justify-between gap-4 border-b border-outline-variant/10 py-2">
                      <span class="text-on-surface-variant">Signal detail</span>
                      <span id="trace-signal-detail" class="font-bold text-on-surface text-right">—</span>
                    </div>
                    <div class="flex justify-between gap-4 border-b border-outline-variant/10 py-2">
                      <span class="text-on-surface-variant">Workflow origin</span>
                      <span id="trace-workflow-origin" class="font-bold text-on-surface text-right">—</span>
                    </div>
                    <div class="flex justify-between gap-4 py-2">
                      <span class="text-on-surface-variant">Input kind</span>
                      <span id="trace-input-kind" class="font-bold text-on-surface text-right">—</span>
                    </div>
                  </div>
                </div>

                <div>
                  <h5 class="text-[10px] font-extrabold text-on-surface-variant uppercase mb-3">Review state</h5>
                  <div class="space-y-3 text-xs">
                    <div class="flex justify-between gap-4 border-b border-outline-variant/10 py-2">
                      <span class="text-on-surface-variant">Human review</span>
                      <span id="trace-human-review" class="font-bold text-on-surface text-right">Not recorded in receipt</span>
                    </div>
                    <div class="flex justify-between gap-4 border-b border-outline-variant/10 py-2">
                      <span class="text-on-surface-variant">Metadata model</span>
                      <span id="trace-metadata-model" class="font-bold text-on-surface text-right">Metadata-only accountability</span>
                    </div>
                    <div class="rounded-lg bg-surface-container px-4 py-3 mt-3">
                      <p id="trace-reminder" class="text-[11px] leading-5 text-on-surface-variant">
                        This receipt supports review, traceability, and governance visibility without storing raw prompt or raw output content by default.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section class="border-l-4 border-primary/10 pl-8 py-2">
            <h4 class="text-sm font-bold font-manrope text-on-surface mb-4">Interpretation</h4>
            <p id="interpretation-text" class="text-on-surface-variant leading-relaxed font-body text-[15px] max-w-3xl italic">
              Select a receipt to review its request-level accountability and metadata-backed governance interpretation.
            </p>
          </section>

          <section class="space-y-6">
            <div class="flex items-center justify-between">
              <h4 class="text-lg font-bold font-manrope text-on-surface">Recent receipts ledger</h4>
              <button id="open-exports-button" data-anchor-route="/exports" class="text-xs font-bold text-primary hover:underline">
                Open exports
              </button>
            </div>

            <div class="bg-surface-container-lowest rounded-xl overflow-hidden shadow-soft soft-ring border border-outline-variant/10">
              <table class="w-full text-left border-collapse">
                <thead>
                  <tr class="bg-surface-container-low text-[10px] font-extrabold uppercase tracking-[0.15em] text-on-surface-variant">
                    <th class="px-6 py-4">Request ID</th>
                    <th class="px-6 py-4">Mode</th>
                    <th class="px-6 py-4">Decision</th>
                    <th class="px-6 py-4">PII</th>
                    <th class="px-6 py-4">Time</th>
                    <th class="px-6 py-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody id="recent-receipts-body" class="divide-y divide-surface-container">
                  <tr>
                    <td colspan="6" class="px-6 py-8 text-sm text-on-surface-variant">Loading recent receipts…</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        </div>

        <div class="col-span-4 space-y-6">
          <div class="bg-slate-900 text-white rounded-xl p-8 relative overflow-hidden shadow-xl">
            <div class="relative z-10">
              <span aria-hidden="true" class="material-symbols-outlined text-3xl mb-4">anchor</span>
              <h3 class="text-xl font-bold font-manrope mb-2">Receipt trust posture</h3>
              <p id="status-card-text" class="text-xs text-on-primary/70 leading-relaxed font-body mb-6">
                Governance receipts provide request-level traceability, policy visibility, and reviewable metadata for safe operational use.
              </p>
              <ul id="status-card-bullets" class="space-y-3 text-[12px] text-slate-300">
                <li class="flex items-start gap-2"><span aria-hidden="true" class="material-symbols-outlined text-tertiary text-[18px]">check_circle</span><span>Metadata-only accountability remains the default doctrine.</span></li>
                <li class="flex items-start gap-2"><span aria-hidden="true" class="material-symbols-outlined text-tertiary text-[18px]">check_circle</span><span>Human review remains expected before operational use.</span></li>
                <li class="flex items-start gap-2"><span aria-hidden="true" class="material-symbols-outlined text-tertiary text-[18px]">check_circle</span><span>Policy trace and receipt status stay visible at request level.</span></li>
              </ul>
              <div class="pt-4 mt-6 border-t border-white/10 flex items-center justify-between">
                <span id="status-card-label" class="text-[10px] font-bold uppercase tracking-widest">Posture: Ready</span>
                <span aria-hidden="true" class="material-symbols-outlined text-sm">shield</span>
              </div>
            </div>
          </div>

          <div class="space-y-4">
            <h4 class="text-[11px] font-extrabold uppercase tracking-widest text-on-surface-variant opacity-60 px-1">Recommended actions</h4>
            <div class="space-y-2">
              <button id="open-learning-button" class="w-full text-left p-4 bg-surface-container-low hover:bg-surface-container transition-colors rounded-lg flex items-center justify-between group">
                <div class="flex items-center gap-3">
                  <span aria-hidden="true" class="material-symbols-outlined text-primary">school</span>
                  <span class="text-sm font-semibold">Open related learning</span>
                </div>
                <span aria-hidden="true" class="material-symbols-outlined text-sm opacity-0 group-hover:opacity-100 -translate-x-2 group-hover:translate-x-0 transition-all">arrow_forward</span>
              </button>

              <button id="open-intelligence-button" data-anchor-route="/intelligence" class="w-full text-left p-4 bg-surface-container-low hover:bg-surface-container transition-colors rounded-lg flex items-center justify-between group">
                <div class="flex items-center gap-3">
                  <span aria-hidden="true" class="material-symbols-outlined text-primary">psychology</span>
                  <span class="text-sm font-semibold">Open intelligence</span>
                </div>
                <span aria-hidden="true" class="material-symbols-outlined text-sm opacity-0 group-hover:opacity-100 -translate-x-2 group-hover:translate-x-0 transition-all">arrow_forward</span>
              </button>

              <button id="export-bundle-button" class="w-full text-left p-4 bg-surface-container-low hover:bg-surface-container transition-colors rounded-lg flex items-center justify-between group">
                <div class="flex items-center gap-3">
                  <span aria-hidden="true" class="material-symbols-outlined text-primary">file_export</span>
                  <span class="text-sm font-semibold">Export metadata bundle</span>
                </div>
                <span aria-hidden="true" class="material-symbols-outlined text-sm opacity-0 group-hover:opacity-100 -translate-x-2 group-hover:translate-x-0 transition-all">arrow_forward</span>
              </button>

              <button id="open-trust-button" data-anchor-route="/trust/profile" class="w-full text-left p-4 bg-surface-container-low hover:bg-surface-container transition-colors rounded-lg flex items-center justify-between group">
                <div class="flex items-center gap-3">
                  <span aria-hidden="true" class="material-symbols-outlined text-primary">shield_with_heart</span>
                  <span class="text-sm font-semibold">Open trust profile</span>
                </div>
                <span aria-hidden="true" class="material-symbols-outlined text-sm opacity-0 group-hover:opacity-100 -translate-x-2 group-hover:translate-x-0 transition-all">arrow_forward</span>
              </button>
            </div>
          </div>

          <div class="p-6 bg-surface-container-high/40 rounded-xl">
            <h4 class="text-[11px] font-extrabold uppercase tracking-widest text-on-surface mb-4">Platform quick actions</h4>
            <div class="grid grid-cols-2 gap-3">
              <button data-anchor-route="/dashboard" class="bg-surface-container-lowest p-3 rounded-lg flex flex-col items-center text-center hover:shadow-md transition-shadow">
                <span aria-hidden="true" class="material-symbols-outlined text-primary-dim mb-1">dashboard</span>
                <span class="text-[10px] font-bold">Dashboard</span>
              </button>
              <button data-anchor-route="/workspace-live" class="bg-surface-container-lowest p-3 rounded-lg flex flex-col items-center text-center hover:shadow-md transition-shadow">
                <span aria-hidden="true" class="material-symbols-outlined text-primary-dim mb-1">clinical_notes</span>
                <span class="text-[10px] font-bold">Workspace</span>
              </button>
              <button data-anchor-route="/intelligence" class="bg-surface-container-lowest p-3 rounded-lg flex flex-col items-center text-center hover:shadow-md transition-shadow">
                <span aria-hidden="true" class="material-symbols-outlined text-primary-dim mb-1">psychology</span>
                <span class="text-[10px] font-bold">Intelligence</span>
              </button>
              <button data-anchor-route="/trust/profile" class="bg-surface-container-lowest p-3 rounded-lg flex flex-col items-center text-center hover:shadow-md transition-shadow">
                <span aria-hidden="true" class="material-symbols-outlined text-primary-dim mb-1">shield_with_heart</span>
                <span class="text-[10px] font-bold">Trust</span>
              </button>
            </div>
          </div>

          <div class="space-y-3">
            <div class="p-4 border border-outline-variant/10 rounded-lg bg-surface-container-lowest">
              <div class="flex items-start gap-3">
                <span aria-hidden="true" class="material-symbols-outlined text-primary text-lg">database</span>
                <div>
                  <p class="text-xs font-bold text-on-surface">Metadata-only accountability</p>
                  <p class="text-[10px] text-on-surface-variant mt-1">Receipts persist governance metadata rather than raw working content by default.</p>
                </div>
              </div>
            </div>

            <div class="p-4 border border-outline-variant/10 rounded-lg bg-surface-container-lowest">
              <div class="flex items-start gap-3">
                <span aria-hidden="true" class="material-symbols-outlined text-primary text-lg">person</span>
                <div>
                  <p class="text-xs font-bold text-on-surface">Human review before use</p>
                  <p class="text-[10px] text-on-surface-variant mt-1">Receipts support review and traceability; staff still confirm operational use.</p>
                </div>
              </div>
            </div>

            <div class="p-4 border border-outline-variant/10 rounded-lg bg-surface-container-lowest">
              <div class="flex items-start gap-3">
                <span aria-hidden="true" class="material-symbols-outlined text-primary text-lg">account_tree</span>
                <div>
                  <p class="text-xs font-bold text-on-surface">Traceable governance decisions</p>
                  <p class="text-[10px] text-on-surface-variant mt-1">Each receipt ties request metadata to policy, decision, and reviewable governance context.</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
  </div>

<script>
(function () {
  const API_BASE = ${JSON.stringify(apiBase)};
  const INITIAL_REQUEST_ID = ${JSON.stringify(initialRequestId)};

  const $ = (id) => document.getElementById(id);

  const els = {
    profileName: $("profile-name"),
    profileRole: $("profile-role"),
    profileAvatarImg: $("profile-avatar-img"),
    profileMenuButton: $("profile-menu-button"),
    profileMenu: $("profile-menu"),
    signOutButton: $("sign-out-button"),

    refreshPageButton: $("refresh-page-button"),
    exportSelectedButton: $("export-selected-button"),
    exportBundleButton: $("export-bundle-button"),

    requestIdInput: $("request-id-input"),
    loadReceiptButton: $("load-receipt-button"),
    modeFilterSelect: $("mode-filter-select"),

    heroStatusChip: $("hero-status-chip"),
    heroNoContent: $("hero-no-content"),
    heroModeChip: $("hero-mode-chip"),

    summaryRequestId: $("summary-request-id"),
    summaryCreatedAt: $("summary-created-at"),
    summaryDecisionBadge: $("summary-decision-badge"),
    summaryMode: $("summary-mode"),
    summaryDecision: $("summary-decision"),
    summaryRiskGrade: $("summary-risk-grade"),
    summaryNeutralityVersion: $("summary-neutrality-version"),
    summaryPiiDetected: $("summary-pii-detected"),
    summaryPiiAction: $("summary-pii-action"),
    summaryPolicyVersion: $("summary-policy-version"),
    summaryGovernanceScore: $("summary-governance-score"),
    summaryReceiptStatus: $("summary-receipt-status"),
    summaryNoContentStored: $("summary-no-content-stored"),

    tracePolicyHash: $("trace-policy-hash"),
    traceRulesFired: $("trace-rules-fired"),
    traceSignalDetail: $("trace-signal-detail"),
    traceWorkflowOrigin: $("trace-workflow-origin"),
    traceInputKind: $("trace-input-kind"),
    traceHumanReview: $("trace-human-review"),
    traceMetadataModel: $("trace-metadata-model"),
    traceReminder: $("trace-reminder"),
    copyHashButton: $("copy-hash-button"),

    interpretationText: $("interpretation-text"),
    recentReceiptsBody: $("recent-receipts-body"),

    statusCardText: $("status-card-text"),
    statusCardBullets: $("status-card-bullets"),
    statusCardLabel: $("status-card-label"),

    openLearningButton: $("open-learning-button"),
    openIntelligenceButton: $("open-intelligence-button"),
    openTrustButton: $("open-trust-button"),
    openExportsButton: $("open-exports-button")
  };

  const state = {
    selectedRequestId: INITIAL_REQUEST_ID || "",
    selectedReceipt: null,
    recentReceipts: [],
    filteredMode: "all"
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

  function formatTimestamp(value) {
    if (!value) return "—";
    const d = new Date(String(value));
    if (Number.isNaN(d.getTime())) return String(value);
    return new Intl.DateTimeFormat("en-GB", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
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
      clinical_note: "Clinical note drafting",
      clinical_note_baseline: "Clinical note drafting",
      internal_summary: "Internal summary"
    };
    return map[normalized] || humanizeToken(raw);
  }

  function formatDecision(value) {
    return humanizeToken(value);
  }

  function formatPiiDetected(value) {
    if (value === true) return "Yes";
    if (value === false) return "No";
    return "—";
  }

  function formatScore(value) {
    if (typeof value !== "number" || !Number.isFinite(value)) return "—";
    return value.toFixed(1);
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function summarizeRules(rules) {
    if (!rules) return "No rule detail recorded";
    if (Array.isArray(rules)) return rules.length + (rules.length === 1 ? " rule" : " rules");
    if (typeof rules === "object") {
      let total = 0;
      Object.keys(rules).forEach(function (key) {
        const value = rules[key];
        if (Array.isArray(value)) total += value.length;
        if (value && typeof value === "object") {
          Object.keys(value).forEach(function (subKey) {
            if (Array.isArray(value[subKey])) total += value[subKey].length;
          });
        }
      });
      if (total > 0) return total + (total === 1 ? " rule" : " rules");
      return "Structured rule output present";
    }
    return safeText(rules);
  }

  function extractPiiSignal(receipt) {
    if (!receipt) return "No additional signal detail";
    if (Array.isArray(receipt.pii_types) && receipt.pii_types.length) {
      return receipt.pii_types.join(", ");
    }
    if (receipt.pii_detected === true) return "PII detected; see recorded action";
    return "No additional signal detail";
  }

  function extractWorkflowOrigin(receipt) {
    return safeText(receipt && (receipt.workflow_origin || receipt.origin || receipt.source), "Direct ANCHOR workflow");
  }

  function extractInputKind(receipt) {
    return safeText(receipt && (receipt.input_kind || receipt.kind), "Source material");
  }

  function extractHumanReview(receipt) {
    if (!receipt) return "Not recorded in receipt";
    if (typeof receipt.human_review_confirmed === "boolean") {
      return receipt.human_review_confirmed ? "Confirmed" : "Not confirmed";
    }
    if (typeof receipt.review_state === "string") return humanizeToken(receipt.review_state);
    return "Not recorded in receipt";
  }

  function decisionBadgeHtml(decision) {
    const normalized = String(decision || "").toLowerCase();
    if (normalized === "allowed" || normalized === "verified" || normalized === "pass") {
      return '<span class="w-2 h-2 rounded-full bg-tertiary"></span><span class="text-xs font-bold uppercase tracking-wider">Allowed</span>';
    }
    if (normalized === "modified" || normalized === "warning" || normalized === "warn") {
      return '<span class="w-2 h-2 rounded-full bg-amber-500"></span><span class="text-xs font-bold uppercase tracking-wider">Modified</span>';
    }
    if (normalized === "blocked" || normalized === "replaced" || normalized === "flagged") {
      return '<span class="w-2 h-2 rounded-full bg-error"></span><span class="text-xs font-bold uppercase tracking-wider">Replaced</span>';
    }
    return '<span class="w-2 h-2 rounded-full bg-primary"></span><span class="text-xs font-bold uppercase tracking-wider">' + escapeHtml(formatDecision(decision)) + "</span>";
  }

  function decisionTone(decision) {
    const normalized = String(decision || "").toLowerCase();
    if (normalized === "allowed" || normalized === "verified" || normalized === "pass") {
      return "text-tertiary bg-tertiary/10 border-tertiary/20";
    }
    if (normalized === "modified" || normalized === "warning" || normalized === "warn") {
      return "text-amber-800 bg-amber-100 border-amber-200";
    }
    if (normalized === "blocked" || normalized === "replaced" || normalized === "flagged") {
      return "text-error bg-error/10 border-error/20";
    }
    return "text-primary bg-primary/10 border-primary/20";
  }

  function buildInterpretation(receipt) {
    if (!receipt) {
      return "Select a receipt to review its request-level accountability and metadata-backed governance interpretation.";
    }

    const decision = formatDecision(receipt.decision);
    const mode = prettyMode(receipt.mode);
    const risk = safeText(receipt.risk_grade, "ungraded");
    const piiDetected = receipt.pii_detected === true;
    const piiAction = safeText(receipt.pii_action, "none recorded");
    const policyVersion = safeText(receipt.policy_version, "—");

    if (piiDetected) {
      return "This receipt records a " + mode + " workflow with a " + decision.toLowerCase() + " governance outcome. PII was detected and the recorded action is " + piiAction + ". Review should confirm that the handling remains appropriate before operational use. Policy trace is linked to version " + policyVersion + ".";
    }

    return "This receipt records a " + mode + " workflow with a " + decision.toLowerCase() + " governance outcome and a " + risk + " risk grade. No PII signal is recorded in the receipt metadata. The receipt provides request-level traceability to support review, auditability, and operational confidence without relying on stored raw working content.";
  }

  function renderStatusCard(receipt) {
    if (!receipt) {
      els.statusCardText.textContent = "Governance receipts provide request-level traceability, policy visibility, and reviewable metadata for safe operational use.";
      els.statusCardLabel.textContent = "Posture: Ready";
      els.statusCardBullets.innerHTML =
        '<li class="flex items-start gap-2"><span aria-hidden="true" class="material-symbols-outlined text-tertiary text-[18px]">check_circle</span><span>Metadata-only accountability remains the default doctrine.</span></li>' +
        '<li class="flex items-start gap-2"><span aria-hidden="true" class="material-symbols-outlined text-tertiary text-[18px]">check_circle</span><span>Human review remains expected before operational use.</span></li>' +
        '<li class="flex items-start gap-2"><span aria-hidden="true" class="material-symbols-outlined text-tertiary text-[18px]">check_circle</span><span>Policy trace and receipt status stay visible at request level.</span></li>';
      return;
    }

    els.statusCardText.textContent =
      "Selected receipt " + safeText(receipt.request_id, "—") + " remains reviewable through governance metadata, decision trace, and policy reference.";

    els.statusCardLabel.textContent = "Posture: " + formatDecision(receipt.decision);

    els.statusCardBullets.innerHTML =
      '<li class="flex items-start gap-2"><span aria-hidden="true" class="material-symbols-outlined text-tertiary text-[18px]">check_circle</span><span>Mode: ' + escapeHtml(prettyMode(receipt.mode)) + '</span></li>' +
      '<li class="flex items-start gap-2"><span aria-hidden="true" class="material-symbols-outlined text-tertiary text-[18px]">check_circle</span><span>Policy version: ' + escapeHtml(safeText(receipt.policy_version, "—")) + '</span></li>' +
      '<li class="flex items-start gap-2"><span aria-hidden="true" class="material-symbols-outlined text-tertiary text-[18px]">check_circle</span><span>No content stored: ' + escapeHtml(receipt.no_content_stored === false ? "No" : "Yes") + '</span></li>';
  }

  function renderRecentReceipts() {
    const rows = state.filteredMode === "all"
      ? state.recentReceipts
      : state.recentReceipts.filter(function (item) {
          return String(item.mode || "").toLowerCase() === state.filteredMode;
        });

    if (!rows.length) {
      els.recentReceiptsBody.innerHTML =
        '<tr><td colspan="6" class="px-6 py-8 text-sm text-on-surface-variant">No recent receipts available for the current filter.</td></tr>';
      return;
    }

    els.recentReceiptsBody.innerHTML = rows.slice(0, 8).map(function (item) {
      const requestId = safeText(item.request_id, "");
      const decision = safeText(item.decision, "—");
      const piiDetected = !!item.pii_detected;
      return '<tr class="hover:bg-surface-container/30 transition-colors">' +
        '<td class="px-6 py-5 text-xs font-mono font-bold text-primary">' + escapeHtml(requestId || "—") + "</td>" +
        '<td class="px-6 py-5 text-xs text-on-surface">' + escapeHtml(prettyMode(item.mode)) + "</td>" +
        '<td class="px-6 py-5"><span class="inline-flex text-[10px] font-bold px-2 py-0.5 rounded border ' + decisionTone(decision) + '">' + escapeHtml(formatDecision(decision).toUpperCase()) + "</span></td>" +
        '<td class="px-6 py-5 text-[11px] ' + (piiDetected ? "text-error font-semibold uppercase" : "text-on-surface-variant italic") + '">' + (piiDetected ? "Detected" : "Not detected") + "</td>" +
        '<td class="px-6 py-5 text-[11px] text-on-surface-variant">' + escapeHtml(formatTimestamp(item.created_at_utc || item.created_at)) + "</td>" +
        '<td class="px-6 py-5 text-right"><button class="text-[11px] font-bold text-primary hover:text-primary-dim view-receipt-btn" data-request-id="' + escapeHtml(requestId) + '">View</button></td>' +
      "</tr>";
    }).join("");

    Array.from(document.querySelectorAll(".view-receipt-btn")).forEach(function (button) {
      button.addEventListener("click", function () {
        const requestId = button.getAttribute("data-request-id") || "";
        els.requestIdInput.value = requestId;
        loadSelectedReceipt(requestId, true);
      });
    });
  }

  function renderReceipt(receipt) {
    state.selectedReceipt = receipt || null;

    if (!receipt) {
      els.summaryRequestId.textContent = "—";
      els.summaryCreatedAt.textContent = "Created at —";
      els.summaryDecisionBadge.className = "inline-flex items-center gap-2 px-3 py-1 bg-tertiary/10 text-tertiary rounded-lg border border-tertiary/20";
      els.summaryDecisionBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-tertiary"></span><span class="text-xs font-bold uppercase tracking-wider">Awaiting selection</span>';
      els.summaryMode.textContent = "—";
      els.summaryDecision.textContent = "—";
      els.summaryRiskGrade.textContent = "—";
      els.summaryNeutralityVersion.textContent = "—";
      els.summaryPiiDetected.textContent = "—";
      els.summaryPiiAction.textContent = "—";
      els.summaryPolicyVersion.textContent = "—";
      els.summaryGovernanceScore.textContent = "—";
      els.summaryReceiptStatus.textContent = "—";
      els.summaryNoContentStored.textContent = "Yes";

      els.tracePolicyHash.textContent = "—";
      els.traceRulesFired.textContent = "—";
      els.traceSignalDetail.textContent = "—";
      els.traceWorkflowOrigin.textContent = "—";
      els.traceInputKind.textContent = "—";
      els.traceHumanReview.textContent = "Not recorded in receipt";
      els.traceMetadataModel.textContent = "Metadata-only accountability";
      els.traceReminder.textContent = "This receipt supports review, traceability, and governance visibility without storing raw prompt or raw output content by default.";

      els.interpretationText.textContent = buildInterpretation(null);

      els.heroStatusChip.textContent = "READY";
      els.heroNoContent.textContent = "YES";
      els.heroModeChip.textContent = "—";

      renderStatusCard(null);
      return;
    }

    const decision = safeText(receipt.decision, "—");
    const noContentStored = receipt.no_content_stored === false ? "No" : "Yes";

    els.summaryRequestId.textContent = safeText(receipt.request_id, "—");
    els.summaryCreatedAt.textContent = "Created at " + formatTimestamp(receipt.created_at_utc || receipt.created_at);
    els.summaryDecisionBadge.className = "inline-flex items-center gap-2 px-3 py-1 rounded-lg border " + decisionTone(decision);
    els.summaryDecisionBadge.innerHTML = decisionBadgeHtml(decision);

    els.summaryMode.textContent = prettyMode(receipt.mode);
    els.summaryDecision.textContent = formatDecision(decision);
    els.summaryRiskGrade.textContent = humanizeToken(receipt.risk_grade);
    els.summaryNeutralityVersion.textContent = safeText(receipt.neutrality_version, "—");
    els.summaryPiiDetected.textContent = formatPiiDetected(receipt.pii_detected);
    els.summaryPiiAction.textContent = humanizeToken(receipt.pii_action);
    els.summaryPolicyVersion.textContent = safeText(receipt.policy_version, "—");
    els.summaryGovernanceScore.textContent = formatScore(receipt.governance_score);
    els.summaryReceiptStatus.textContent = receipt.request_id ? "Active" : "Pending";
    els.summaryNoContentStored.textContent = noContentStored;

    els.tracePolicyHash.textContent = safeText(receipt.policy_hash || receipt.policy_sha256, "—");
    els.traceRulesFired.textContent = summarizeRules(receipt.rules_fired);
    els.traceSignalDetail.textContent = extractPiiSignal(receipt);
    els.traceWorkflowOrigin.textContent = extractWorkflowOrigin(receipt);
    els.traceInputKind.textContent = extractInputKind(receipt);
    els.traceHumanReview.textContent = extractHumanReview(receipt);
    els.traceMetadataModel.textContent = "Metadata-only accountability";
    els.traceReminder.textContent = "Receipt review should confirm whether the governance outcome, PII handling, and downstream operational use remain appropriate for this request.";

    els.interpretationText.textContent = buildInterpretation(receipt);

    els.heroStatusChip.textContent = receipt.request_id ? "ACTIVE" : "READY";
    els.heroNoContent.textContent = noContentStored.toUpperCase();
    els.heroModeChip.textContent = prettyMode(receipt.mode).toUpperCase();

    renderStatusCard(receipt);
  }

  async function fetchReceipt(requestId) {
    const response = await fetch(apiUrl("/v1/portal/receipt/" + encodeURIComponent(requestId)), {
      headers: {
        "Content-Type": "application/json",
        ...getAuthHeaders()
      }
    });

    if (!response.ok) {
      const raw = await response.text();
      throw new Error(raw || "Unable to load receipt.");
    }

    const payload = await response.json();
    return payload && payload.receipt ? payload.receipt : payload;
  }

  async function exportCurrentReceipt() {
    if (!state.selectedReceipt) return;
    const blob = new Blob([JSON.stringify({ receipt: state.selectedReceipt }, null, 2)], {
      type: "application/json"
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "anchor-receipt-" + safeText(state.selectedReceipt.request_id, "selected") + ".json";
    a.click();
    URL.revokeObjectURL(url);
  }

  async function copyHash() {
    const text = safeText(els.tracePolicyHash.textContent, "");
    if (!text || text === "—") return;
    await navigator.clipboard.writeText(text);
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
        const href = node.getAttribute("data-anchor-route") || node.getAttribute("href") || "/receipts";
        navigateParent(href);
      });
    });
  }

  async function loadDashboardRecent() {
    const response = await fetch(apiUrl("/v1/portal/dashboard"), {
      headers: {
        "Content-Type": "application/json",
        ...getAuthHeaders()
      }
    });

    if (!response.ok) {
      const raw = await response.text();
      throw new Error(raw || "Unable to load recent receipts.");
    }

    const payload = await response.json();
    state.recentReceipts = Array.isArray(payload && payload.recent_submissions) ? payload.recent_submissions : [];
    renderRecentReceipts();

    if (!state.selectedRequestId && state.recentReceipts.length && state.recentReceipts[0].request_id) {
      state.selectedRequestId = String(state.recentReceipts[0].request_id);
      els.requestIdInput.value = state.selectedRequestId;
    }
  }

  async function loadSelectedReceipt(requestId, replaceUrl) {
    const clean = String(requestId || "").trim();
    if (!clean) {
      renderReceipt(null);
      return;
    }

    try {
      els.loadReceiptButton.disabled = true;
      els.loadReceiptButton.textContent = "Loading...";
      const receipt = await fetchReceipt(clean);
      state.selectedRequestId = clean;
      renderReceipt(receipt);
      if (replaceUrl) {
        navigateParent("/receipts?request_id=" + encodeURIComponent(clean), { replace: true });
      }
    } catch (error) {
      console.error(error);
      renderReceipt(null);
      els.interpretationText.textContent = error instanceof Error ? error.message : "Unable to load receipt.";
    } finally {
      els.loadReceiptButton.disabled = false;
      els.loadReceiptButton.textContent = "Load receipt";
    }
  }

  async function refreshAll() {
    try {
      els.refreshPageButton.disabled = true;
      els.refreshPageButton.textContent = "Refreshing...";
      await loadDashboardRecent();
      if (state.selectedRequestId) {
        await loadSelectedReceipt(state.selectedRequestId, false);
      }
    } catch (error) {
      console.error(error);
      els.recentReceiptsBody.innerHTML =
        '<tr><td colspan="6" class="px-6 py-8 text-sm text-error">Unable to load receipts.</td></tr>';
    } finally {
      els.refreshPageButton.disabled = false;
      els.refreshPageButton.textContent = "Refresh receipts";
    }
  }

  els.profileMenuButton.addEventListener("click", function (event) {
    event.stopPropagation();
    const willOpen = els.profileMenu.classList.contains("hidden");
    els.profileMenu.classList.add("hidden");
    if (willOpen) els.profileMenu.classList.remove("hidden");
  });

  els.signOutButton.addEventListener("click", function () {
    requestParentSignOut();
  });

  document.addEventListener("click", function () {
    els.profileMenu.classList.add("hidden");
  });

  els.modeFilterSelect.addEventListener("change", function () {
    state.filteredMode = els.modeFilterSelect.value || "all";
    renderRecentReceipts();
  });

  els.loadReceiptButton.addEventListener("click", function () {
    loadSelectedReceipt(els.requestIdInput.value, true);
  });

  els.requestIdInput.addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
      event.preventDefault();
      loadSelectedReceipt(els.requestIdInput.value, true);
    }
  });

  els.refreshPageButton.addEventListener("click", function () {
    refreshAll();
  });

  els.exportSelectedButton.addEventListener("click", function () {
    exportCurrentReceipt().catch(console.error);
  });

  els.exportBundleButton.addEventListener("click", function () {
    exportCurrentReceipt().catch(console.error);
  });

  els.copyHashButton.addEventListener("click", function () {
    copyHash().catch(console.error);
  });

  els.openLearningButton.addEventListener("click", function () {
    const href = state.selectedReceipt && state.selectedReceipt.pii_detected
      ? "/learn/cards/privacy-safe-ai-use"
      : "/learn/cards/governance-basics";
    navigateParent(href);
  });

  bindNavigation();
  setUserFromSession();
  if (INITIAL_REQUEST_ID) {
    els.requestIdInput.value = INITIAL_REQUEST_ID;
    state.selectedRequestId = INITIAL_REQUEST_ID;
  }
  renderReceipt(null);
  refreshAll();
})();
</script>
</body>
</html>`;
}

export default function ReceiptsPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const requestId = searchParams.get("request_id") ?? "";

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

  const html = useMemo(() => buildHtml(API_BASE, requestId), [requestId]);

  if (!authReady) {
    return <div className="h-screen w-full bg-white" />;
  }

  if (!isAuthed) {
    return null;
  }

  return (
    <div className="h-screen w-full bg-white">
      <iframe
        key={requestId || "receipts"}
        title="Receipts Stitch"
        srcDoc={html}
        className="h-full w-full border-0"
        sandbox="allow-scripts allow-same-origin"
      />
    </div>
  );
}
