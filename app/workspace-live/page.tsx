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
  <title>ANCHOR | Workspace</title>
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
    body { font-family: 'Inter', sans-serif; margin: 0; }
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
    }
    .soft-ring {
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.65);
    }
  </style>
</head>
<body class="bg-background text-on-surface flex min-h-screen">
  <aside class="flex flex-col h-full py-6 bg-slate-50 h-screen w-64 border-r border-slate-200/50 font-manrope text-sm font-medium sticky top-0">
    <div class="px-6 mb-8">
      <div class="flex items-center gap-2">
        <span class="material-symbols-outlined text-primary">anchor</span>
        <div>
          <h1 class="text-xl font-bold tracking-tight text-slate-900 font-manrope">ANCHOR</h1>
          <p class="text-[10px] uppercase tracking-widest text-on-surface-variant font-bold">Veterinary Governance</p>
        </div>
      </div>
    </div>

    <nav class="flex-1 space-y-1">
      <a data-anchor-route href="/workspace-live" class="flex items-center px-6 py-3 space-x-3 text-slate-900 font-bold border-r-2 border-slate-900 bg-slate-200/50 transition-all duration-200">
        <span class="material-symbols-outlined">clinical_notes</span>
        <span>Workspace</span>
      </a>
      <a data-anchor-route href="/dashboard" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span class="material-symbols-outlined">dashboard</span>
        <span>Dashboard</span>
      </a>
      <a data-anchor-route href="/receipts" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span class="material-symbols-outlined">receipt_long</span>
        <span>Receipts</span>
      </a>
      <a data-anchor-route href="/governance-events" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span class="material-symbols-outlined">verified_user</span>
        <span>Governance Events</span>
      </a>
      <a data-anchor-route href="/learn" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span class="material-symbols-outlined">school</span>
        <span>Learn</span>
      </a>
      <a data-anchor-route href="/trust/profile" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span class="material-symbols-outlined">shield_with_heart</span>
        <span>Trust</span>
      </a>
      <a data-anchor-route href="/intelligence" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span class="material-symbols-outlined">psychology</span>
        <span>Intelligence</span>
      </a>
      <a data-anchor-route href="/exports" class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors">
        <span class="material-symbols-outlined">download</span>
        <span>Exports</span>
      </a>
    </nav>

    <div class="mt-auto px-4">
      <div class="mt-6 space-y-1">
        <a data-anchor-route class="flex items-center px-2 py-2 space-x-3 text-slate-500 hover:text-slate-700 transition-colors" href="/settings">
          <span class="material-symbols-outlined">settings</span>
          <span>Settings</span>
        </a>
        <a data-anchor-route class="flex items-center px-2 py-2 space-x-3 text-slate-500 hover:text-slate-700 transition-colors" href="/privacy-policy">
          <span class="material-symbols-outlined">policy</span>
          <span>Privacy &amp; Policy</span>
        </a>
        <a data-anchor-route class="flex items-center px-2 py-2 space-x-3 text-slate-500 hover:text-slate-700 transition-colors" href="/support">
          <span class="material-symbols-outlined">help_outline</span>
          <span>Support</span>
        </a>
      </div>
    </div>
  </aside>

  <div class="flex-1 flex flex-col">
    <header class="flex justify-between items-center w-full px-8 h-16 sticky top-0 z-50 bg-white/80 backdrop-blur-md border-b border-slate-100 font-manrope text-base shadow-sm">
      <div class="flex items-center flex-1 max-w-xl">
        <div class="relative w-full">
          <span class="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-xl">search</span>
          <input class="w-full rounded-lg border border-slate-300/70 bg-[#f0f4f7] py-1.5 pl-10 pr-4 text-sm text-[#2a3439] outline-none transition-all placeholder:text-slate-500 focus:border-[#7c63c9] focus:outline-none focus:ring-2 focus:ring-[rgba(124,99,201,0.18)] focus-visible:border-[#7c63c9] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[rgba(124,99,201,0.18)]" placeholder="Search workspace, audits, or metadata..." type="text"/>
        </div>
      </div>

      <div class="flex items-center gap-6">
        <button data-anchor-route="/notifications" class="text-on-surface-variant hover:text-on-surface transition-transform active:scale-95">
          <span class="material-symbols-outlined">notifications</span>
        </button>
        <button data-anchor-route="/settings" class="text-on-surface-variant hover:text-on-surface transition-transform active:scale-95">
          <span class="material-symbols-outlined">settings</span>
        </button>
        <div class="h-6 w-[1px] bg-outline-variant/30"></div>

        <div id="profile-menu-anchor" class="relative">
          <button id="profile-menu-button" type="button" class="flex items-center gap-3 cursor-pointer group">
            <div class="text-right">
              <p id="profile-name" class="text-xs font-bold leading-none">Clinic User</p>
              <p id="profile-role" class="text-[10px] text-on-surface-variant">Team member</p>
            </div>
            <img id="profile-avatar-img" alt="User Avatar" class="w-9 h-9 rounded-full object-cover grayscale-[0.2] border border-outline-variant/20" src="https://lh3.googleusercontent.com/aida-public/AB6AXuCnbGKz0TR_w7R7vfsdlOaArbM6Ka9P4NxHiCDCVu9tUHvElC9ITX3XsjBMrYZAIv3n-S06ghZKu1BTKIbpwbNIHkKoVMCo2ETSVZB_Lp6Km6Jd_5xHoQ3zB8HXdy_1_AQMQHMaheRN7A7BSx1SZUq6yajARax2RDSLTFq-h59_vYF75fpi0P3BPE4AjWoXtE8_7Ha9IjlxtIhWjqmdQAs1gQOxFyv2ganm7lmdG5dTZxehwGb8EPX2ZU_4Pa6iXRFWnROk2MISg4nq"/>
          </button>
          <div id="profile-menu" class="hidden absolute right-0 top-12 z-30 min-w-[140px] rounded-lg border border-outline-variant/20 bg-white p-1 shadow-soft">
            <button id="sign-out-button" type="button" class="w-full rounded-md px-3 py-2 text-left text-sm font-medium text-on-surface hover:bg-surface-container-low">Sign out</button>
          </div>
        </div>
      </div>
    </header>

    <main class="p-8 max-w-[1480px] mx-auto w-full">
      <div class="mb-10">
        <h2 class="text-3xl font-extrabold tracking-tight font-manrope text-on-surface mb-1">Workspace</h2>
        <p class="text-on-surface-variant text-sm flex items-center gap-2">
          <span class="w-2 h-2 rounded-full bg-tertiary"></span>
          Governed drafting and safe AI-use support for clinic workflows
        </p>
      </div>

      <div class="grid grid-cols-12 gap-10">
        <div class="col-span-8 space-y-8">
          <div class="grid grid-cols-2 gap-6">
            <div class="bg-surface-container-lowest p-6 rounded-xl border border-outline-variant/12 shadow-soft soft-ring relative">
              <label class="block text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-3">Staff role</label>
              <button id="staff-role-button" type="button" class="w-full flex items-center justify-between p-3 bg-surface-container-low rounded-lg border border-transparent hover:border-primary/20 cursor-pointer transition-all text-left">
                <div class="flex items-center gap-3">
                  <span class="material-symbols-outlined text-primary">person</span>
                  <span id="staff-role-value" class="text-sm font-semibold">Practice Manager</span>
                </div>
                <span class="material-symbols-outlined text-on-surface-variant">expand_more</span>
              </button>
              <div id="staff-role-menu" class="hidden absolute left-6 right-6 top-[92px] z-20 rounded-lg border border-outline-variant/20 bg-white shadow-soft p-1">
                <button type="button" data-role-option="Practice Manager" class="role-option-btn w-full rounded-md px-3 py-2 text-left text-sm font-medium text-on-surface hover:bg-surface-container-low">Practice Manager</button>
                <button type="button" data-role-option="Clinician" class="role-option-btn w-full rounded-md px-3 py-2 text-left text-sm font-medium text-on-surface hover:bg-surface-container-low">Clinician</button>
                <button type="button" data-role-option="Receptionist / Front desk" class="role-option-btn w-full rounded-md px-3 py-2 text-left text-sm font-medium text-on-surface hover:bg-surface-container-low">Receptionist / Front desk</button>
                <button type="button" data-role-option="Practice / Admin staff" class="role-option-btn w-full rounded-md px-3 py-2 text-left text-sm font-medium text-on-surface hover:bg-surface-container-low">Practice / Admin staff</button>
              </div>
            </div>

            <div class="bg-surface-container-lowest p-6 rounded-xl border border-outline-variant/12 shadow-soft soft-ring relative">
              <label class="block text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-3">Workflow mode</label>
              <button id="workflow-mode-button" type="button" class="w-full flex items-center justify-between p-3 bg-surface-container-low rounded-lg border border-transparent hover:border-primary/20 cursor-pointer transition-all text-left">
                <div class="flex items-center gap-3">
                  <span class="material-symbols-outlined text-primary">gavel</span>
                  <span id="workflow-mode-value" class="text-sm font-semibold">Internal governance review</span>
                </div>
                <span class="material-symbols-outlined text-on-surface-variant">expand_more</span>
              </button>
              <div id="workflow-mode-menu" class="hidden absolute left-6 right-6 top-[92px] z-20 rounded-lg border border-outline-variant/20 bg-white shadow-soft p-1">
                <button type="button" data-mode-option="Internal governance review" class="mode-option-btn w-full rounded-md px-3 py-2 text-left text-sm font-medium text-on-surface hover:bg-surface-container-low">Internal governance review</button>
                <button type="button" data-mode-option="Internal summary" class="mode-option-btn w-full rounded-md px-3 py-2 text-left text-sm font-medium text-on-surface hover:bg-surface-container-low">Internal summary</button>
                <button type="button" data-mode-option="Client communication" class="mode-option-btn w-full rounded-md px-3 py-2 text-left text-sm font-medium text-on-surface hover:bg-surface-container-low">Client communication</button>
                <button type="button" data-mode-option="Clinical note drafting" class="mode-option-btn w-full rounded-md px-3 py-2 text-left text-sm font-medium text-on-surface hover:bg-surface-container-low">Clinical note drafting</button>
              </div>
            </div>
          </div>

          <section class="bg-surface-container-lowest p-8 rounded-xl border border-outline-variant/10 shadow-[0_18px_40px_rgba(42,52,57,0.07)] soft-ring">
            <div class="flex justify-between items-center mb-6">
              <h3 class="font-manrope font-bold text-lg">Source material</h3>
            </div>
            <div class="relative">
              <textarea id="source-material" class="w-full bg-surface-container-low border-none rounded-lg p-4 text-sm text-on-surface focus:ring-1 focus:ring-primary placeholder:text-on-surface-variant/50" placeholder="Paste draft content, notes, transcript excerpts, or operational text for governed review." rows="6"></textarea>
            </div>
            <p class="mt-4 text-[11px] text-on-surface-variant italic">Privacy-aware handling is applied during governed review. Metadata-only accountability remains the default doctrine. Always confirm the output before operational use.</p>
          </section>

          <section class="bg-surface-container-lowest p-8 rounded-xl border border-outline-variant/12 shadow-soft soft-ring">
            <h3 class="font-manrope font-bold text-lg mb-6">Review settings</h3>
            <div class="space-y-4">
              <div class="flex items-start gap-4">
                <div class="w-8 h-8 rounded-full bg-surface-container flex items-center justify-center flex-shrink-0">
                  <span class="text-xs font-bold font-manrope">01</span>
                </div>
                <div class="flex-1">
                  <p class="text-sm font-semibold mb-1">Instruction</p>
                  <input id="instruction-input" class="w-full bg-transparent border-b border-outline-variant/30 focus:border-primary text-sm py-1 focus:ring-0" type="text" value="Refine for internal staff handover, preserve meaning, and keep the summary concise, clear, and reviewable."/>
                </div>
              </div>

              <div class="flex items-start gap-4 pt-4">
                <div class="w-8 h-8 rounded-full bg-surface-container flex items-center justify-center flex-shrink-0">
                  <span class="text-xs font-bold font-manrope">02</span>
                </div>
                <div class="flex-1">
                  <p class="text-sm font-semibold mb-1">Review boundaries</p>
                  <div class="flex flex-wrap gap-2">
                    <span class="inline-flex items-center rounded-full border border-primary/12 bg-primary/10 px-3 py-1 text-[11px] font-bold uppercase tracking-wide text-primary">Standard Privacy</span>
                    <span class="inline-flex items-center rounded-full border border-tertiary/15 bg-tertiary/10 px-3 py-1 text-[11px] font-bold uppercase tracking-wide text-tertiary">Receipt-backed traceability</span>
                    <span class="inline-flex items-center rounded-full border border-outline-variant/12 bg-surface-container px-3 py-1 text-[11px] font-bold uppercase tracking-wide text-on-surface-variant">Metadata-only accountability</span>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section class="bg-surface-container-lowest rounded-xl border border-outline-variant/10 shadow-[0_18px_40px_rgba(42,52,57,0.07)] soft-ring overflow-hidden">
            <div class="px-8 py-6 border-b border-outline-variant/10">
              <div class="flex items-start justify-between gap-4">
                <div>
                  <h3 class="font-manrope font-bold text-lg">Governed result</h3>
                  <p class="text-xs text-on-surface-variant mt-1">Governed output will appear here after a completed run.</p>
                </div>
                <span id="run-badge" class="inline-flex items-center gap-1 rounded-full border border-primary/12 bg-primary/10 px-3 py-1 text-[11px] font-bold uppercase tracking-wide text-primary">
                  <span class="material-symbols-outlined text-sm">verified</span>
                  <span id="run-badge-text">Awaiting run</span>
                </span>
              </div>
            </div>

            <div class="p-8">
              <div id="governed-result-panel" class="min-h-[260px] rounded-xl border border-dashed border-outline-variant/25 bg-gradient-to-br from-surface-container-lowest to-surface-container-low p-6 flex flex-col justify-between">
                <div>
                  <div class="w-10 h-10 rounded-full bg-primary/10 text-primary flex items-center justify-center mb-4">
                    <span class="material-symbols-outlined">description</span>
                  </div>
                  <p class="text-sm font-semibold text-on-surface mb-2">Governed output destination</p>
                  <div id="governed-output-text" class="hidden mt-4 rounded-lg border border-outline-variant/20 bg-white/70 px-4 py-4 text-sm leading-6 text-on-surface whitespace-pre-wrap"></div>
                  <p class="text-sm text-on-surface-variant leading-6 max-w-2xl">
                    Governed output will appear here after a completed run. This panel is reserved for the reviewed result, ready for receipt-backed accountability and operational follow-on actions.
                  </p>
                </div>

                <div class="mt-8 grid grid-cols-2 gap-4">
                  <div class="rounded-lg bg-white/80 border border-outline-variant/15 px-4 py-3">
                    <p class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-1">Run state</p>
                    <p id="run-state-value" class="text-sm font-semibold text-on-surface">Ready to process</p>
                  </div>
                  <div class="rounded-lg bg-white/80 border border-outline-variant/15 px-4 py-3">
                    <p class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-1">Output status</p>
                    <p id="output-status-value" class="text-sm font-semibold text-on-surface">No governed output yet</p>
                  </div>
                </div>
              </div>

              <div class="mt-6 rounded-xl border border-outline-variant/15 bg-surface-container-low px-5 py-4 flex items-start gap-4">
                <input id="human-review" type="checkbox" class="mt-1 h-4 w-4 rounded border-outline-variant text-primary focus:ring-primary"/>
                <label for="human-review" class="text-sm leading-6">
                  <span class="block font-semibold text-on-surface">Confirm human review before operational use</span>
                  <span class="block text-on-surface-variant text-[13px] mt-1">Required before governed output is copied forward, exported, or used operationally.</span>
                </label>
              </div>
            </div>
          </section>

          <div class="flex flex-wrap justify-end gap-4 pt-2">
            <button id="new-workflow-button" class="px-8 py-3 bg-white text-on-surface font-bold rounded-md shadow-soft hover:bg-surface-container-low transition-all flex items-center gap-2 border border-outline-variant/20 soft-ring">
              <span class="material-symbols-outlined text-[18px] text-primary">add</span>
              New governed workflow
            </button>
            <button id="draft-receipt-button" class="px-8 py-3 bg-surface-container-low text-on-surface-variant font-bold rounded-md border border-outline-variant/15 hover:bg-surface-container transition-colors">
              Draft Receipt
            </button>
            <button id="run-anchor-button" class="px-10 py-3 bg-gradient-to-r from-primary to-primary-dim text-white font-bold rounded-md shadow-glow flex items-center gap-2 hover:opacity-95 border border-white/10 soft-ring">
              <span class="material-symbols-outlined">lock_person</span>
              Run through ANCHOR
            </button>
          </div>
        </div>

        <div class="col-span-4 space-y-6">
          <div class="bg-surface-container-lowest rounded-xl p-6 border border-outline-variant/12 shadow-soft soft-ring">
            <h4 class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-5">Current context</h4>
            <div class="space-y-4">
              <div class="flex justify-between items-start text-sm">
                <div>
                  <p class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-1">Active role</p>
                  <p id="context-role-value" class="font-semibold text-on-surface">Practice Manager</p>
                </div>
                <span class="material-symbols-outlined text-primary">badge</span>
              </div>
              <div class="flex justify-between items-start text-sm">
                <div>
                  <p class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-1">Workflow mode</p>
                  <p id="context-mode-value" class="font-semibold text-on-surface">Internal governance review</p>
                </div>
                <span class="material-symbols-outlined text-primary">gavel</span>
              </div>
              <div class="flex justify-between items-start text-sm">
                <div>
                  <p class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-1">Session status</p>
                  <p id="session-status-text" class="font-semibold text-on-surface">Ready for governed workflow</p>
                </div>
                <span id="session-status-badge" class="inline-flex items-center gap-1 rounded-full border border-tertiary/15 bg-tertiary/10 px-3 py-1 text-[11px] font-bold uppercase tracking-wide text-tertiary">Ready</span>
              </div>
            </div>
          </div>

          <div class="bg-surface-container-low rounded-xl p-6 border border-outline-variant/14 shadow-[0_10px_24px_rgba(42,52,57,0.05)] soft-ring">
            <h4 class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-4">Governance summary</h4>
            <div class="space-y-3">
              <div class="flex justify-between items-center text-xs py-1 border-b border-outline-variant/10">
                <span class="font-medium text-on-surface-variant">Decision</span>
                <span id="decision-value" class="font-bold text-on-surface">—</span>
              </div>
              <div class="flex justify-between items-center text-xs py-1 border-b border-outline-variant/10">
                <span class="font-medium text-on-surface-variant">Risk grade</span>
                <span id="risk-grade-value" class="font-bold">—</span>
              </div>
              <div class="flex justify-between items-center text-xs py-1 border-b border-outline-variant/10">
                <span class="font-medium text-on-surface-variant">PII detected</span>
                <span id="pii-detected-value" class="font-bold">—</span>
              </div>
              <div class="flex justify-between items-center text-xs py-1 border-b border-outline-variant/10">
                <span class="font-medium text-on-surface-variant">PII action</span>
                <span id="pii-action-value" class="font-bold">—</span>
              </div>
              <div class="flex justify-between items-center text-xs py-1 border-b border-outline-variant/10">
                <span class="font-medium text-on-surface-variant">Governance score</span>
                <span id="governance-score-value" class="font-bold">—</span>
              </div>
              <div class="flex justify-between items-center text-xs py-1 border-b border-outline-variant/10">
                <span class="font-medium text-on-surface-variant">Policy version</span>
                <span id="policy-version-value" class="font-bold">—</span>
              </div>
              <div class="flex justify-between items-center text-xs py-1">
                <span class="font-medium text-on-surface-variant">Neutrality version</span>
                <span id="neutrality-version-value" class="font-bold">—</span>
              </div>
            </div>
            <div class="mt-4 pt-4 border-t border-outline-variant/10">
              <div class="flex justify-between items-start gap-3 text-xs">
                <span class="font-medium text-on-surface-variant">No content stored</span>
                <span id="no-content-stored-value" class="font-bold text-on-surface">Yes</span>
              </div>
              <div class="mt-2 text-[11px] leading-5 text-on-surface-variant">
                <span class="font-semibold text-on-surface">Metadata-only governance</span>
              </div>
              <div class="mt-4">
                <p class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-2">PII types / signal detail</p>
                <p id="signal-detail-value" class="text-[11px] leading-5 text-on-surface-variant">Additional signal detail will appear here when available from the receipt.</p>
              </div>
            </div>
          </div>

          <div class="bg-surface-container-lowest rounded-xl p-6 border border-outline-variant/12 shadow-soft soft-ring">
            <h4 class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-5">Recommended next</h4>
            <div class="rounded-lg border border-outline-variant/12 bg-surface-container-low px-4 py-4 mb-4">
              <p class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-2">Receipt actions</p>
              <p id="receipt-actions-text" class="text-sm text-on-surface-variant leading-6">Receipt actions will appear after a governed run.</p>
            </div>

            <div class="space-y-3">
              <a id="open-intelligence-link" href="/intelligence" class="group flex items-center justify-between rounded-lg border border-outline-variant/15 bg-white px-4 py-3 text-sm font-semibold text-on-surface hover:border-primary/20 hover:bg-surface-container-low transition-all">
                <span>Open Intelligence</span>
                <span class="material-symbols-outlined text-on-surface-variant group-hover:text-primary transition-colors">arrow_forward</span>
              </a>
              <a id="open-learning-link" href="/learn/cards/governance-basics" class="group flex items-center justify-between rounded-lg border border-outline-variant/15 bg-white px-4 py-3 text-sm font-semibold text-on-surface hover:border-primary/20 hover:bg-surface-container-low transition-all">
                <span>Open related learning</span>
                <span class="material-symbols-outlined text-on-surface-variant group-hover:text-primary transition-colors">arrow_forward</span>
              </a>
            </div>
          </div>

          <div class="bg-surface-container-lowest rounded-xl p-6 border border-outline-variant/12 shadow-soft soft-ring">
            <h4 class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-6">Traceability</h4>
            <div class="space-y-4">
              <div>
                <p class="text-[10px] font-bold text-on-surface-variant uppercase mb-1">Request ID</p>
                <p id="request-id-value" class="text-sm font-bold font-manrope">—</p>
              </div>
              <div>
                <p class="text-[10px] font-bold text-on-surface-variant uppercase mb-1">Created at</p>
                <p id="created-at-value" class="text-sm font-medium">—</p>
              </div>
              <div>
                <p class="text-[10px] font-bold text-on-surface-variant uppercase mb-1">Policy hash</p>
                <p id="policy-hash-value" class="text-[10px] font-mono text-on-surface-variant truncate">—</p>
              </div>
              <div class="flex justify-between items-center">
                <div>
                  <p class="text-[10px] font-bold text-on-surface-variant uppercase mb-1">Rules fired</p>
                  <p id="rules-fired-value" class="text-sm font-bold">—</p>
                </div>
                <div class="text-right">
                  <p class="text-[10px] font-bold text-on-surface-variant uppercase mb-1">Receipt available</p>
                  <p id="receipt-available-value" class="text-sm font-bold text-on-surface">Pending</p>
                </div>
              </div>
            </div>
          </div>

          <div class="bg-slate-900 text-white rounded-xl overflow-hidden shadow-[0_20px_44px_rgba(15,23,42,0.28)]">
            <div class="p-6 bg-slate-800/50 flex justify-between items-center">
              <div>
                <p class="text-[10px] font-bold tracking-widest opacity-60">RECEIPT PREVIEW</p>
                <p id="receipt-preview-title" class="text-xs font-bold font-manrope">DRAFT_PREVIEW</p>
              </div>
              <span class="material-symbols-outlined text-tertiary-fixed">qr_code_2</span>
            </div>

            <div class="p-6 space-y-4">
              <div class="flex justify-between items-center text-[11px] border-b border-white/10 pb-2">
                <span class="opacity-60">Request ID</span>
                <span id="receipt-request-id">—</span>
              </div>
              <div class="flex justify-between items-center text-[11px] border-b border-white/10 pb-2">
                <span class="opacity-60">Policy version</span>
                <span id="receipt-policy-version">—</span>
              </div>
              <div class="flex justify-between items-center text-[11px] border-b border-white/10 pb-2">
                <span class="opacity-60">Neutrality version</span>
                <span id="receipt-neutrality-version">—</span>
              </div>

              <div class="flex justify-between items-center text-[11px] border-b border-white/10 pb-2">
                <span class="opacity-60">No content stored</span>
                <span id="receipt-no-content-stored">Yes</span>
              </div>
              <div class="flex justify-between items-center text-[11px] border-b border-white/10 pb-2">
                <span class="opacity-60">Human review confirmed</span>
                <span id="receipt-human-review">No</span>
              </div>

              <div class="grid grid-cols-2 gap-2 pt-2">
                <button id="open-receipt-button" class="py-2 px-3 bg-tertiary-fixed/90 text-primary text-[10px] font-bold rounded flex items-center justify-center gap-1 hover:opacity-90 border border-white/10">
                  <span class="material-symbols-outlined text-sm">open_in_new</span>
                  Open receipt
                </button>
                <button id="export-metadata-button" class="py-2 px-3 bg-white/10 text-white/90 text-[10px] font-bold rounded flex items-center justify-center gap-1 hover:bg-white/16">
                  <span class="material-symbols-outlined text-sm">download</span>
                  Export metadata
                </button>
                <button id="receipt-copy-button" class="py-2 px-3 bg-white/10 text-white/90 text-[10px] font-bold rounded flex items-center justify-center gap-1 hover:bg-white/16">
                  <span class="material-symbols-outlined text-sm">content_copy</span>
                  Copy governed result
                </button>
                <button id="receipt-draft-button" class="py-2 px-3 bg-white/10 text-white/90 text-[10px] font-bold rounded flex items-center justify-center gap-1 hover:bg-white/16">
                  <span class="material-symbols-outlined text-sm">draft</span>
                  Draft Receipt
                </button>
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
    const MODE_MAP = {
      "Client communication": "client_comm",
      "Clinical note drafting": "clinical_note",
      "Internal governance review": "internal_summary",
      "Internal summary": "internal_summary"
    };
    const INSTRUCTION_PRESETS = {
      "Internal governance review": "Refine for internal staff handover, preserve meaning, and keep the summary concise, clear, and reviewable.",
      "Internal summary": "Summarise clearly for internal staff handover, preserve meaning, and keep the output concise and reviewable.",
      "Client communication": "Improve clarity and structure, preserve meaning, keep a professional tone, and make the message suitable for client communication.",
      "Clinical note drafting": "Refine for structured clinical note drafting, preserve meaning, and keep the output professional, concise, and reviewable."
    };

    const $ = (id) => document.getElementById(id);
    const els = {
      source: $("source-material"),
      instruction: $("instruction-input"),
      runBtn: $("run-anchor-button"),
      newBtn: $("new-workflow-button"),
      draftBtn: $("draft-receipt-button"),
      openReceiptBtn: $("open-receipt-button"),
      exportBtn: $("export-metadata-button"),
      copyBtn: $("receipt-copy-button"),
      receiptDraftBtn: $("receipt-draft-button"),
      review: $("human-review"),
      runBadge: $("run-badge"),
      runBadgeText: $("run-badge-text"),
      runState: $("run-state-value"),
      outputStatus: $("output-status-value"),
      governedOutput: $("governed-output-text"),
      decision: $("decision-value"),
      riskGrade: $("risk-grade-value"),
      piiDetected: $("pii-detected-value"),
      piiAction: $("pii-action-value"),
      governanceScore: $("governance-score-value"),
      policyVersion: $("policy-version-value"),
      neutralityVersion: $("neutrality-version-value"),
      noContentStored: $("no-content-stored-value"),
      signalDetail: $("signal-detail-value"),
      requestId: $("request-id-value"),
      createdAt: $("created-at-value"),
      policyHash: $("policy-hash-value"),
      rulesFired: $("rules-fired-value"),
      receiptAvailable: $("receipt-available-value"),
      receiptTitle: $("receipt-preview-title"),
      receiptRequestId: $("receipt-request-id"),
      receiptPolicyVersion: $("receipt-policy-version"),
      receiptNeutralityVersion: $("receipt-neutrality-version"),
      receiptNoContentStored: $("receipt-no-content-stored"),
      receiptHumanReview: $("receipt-human-review"),
      receiptActionsText: $("receipt-actions-text"),
      openLearning: $("open-learning-link"),
      openIntelligence: $("open-intelligence-link"),
      contextRole: $("context-role-value"),
      contextMode: $("context-mode-value"),
      sessionText: $("session-status-text"),
      sessionBadge: $("session-status-badge"),
      roleValue: $("staff-role-value"),
      modeValue: $("workflow-mode-value"),
      roleBtn: $("staff-role-button"),
      modeBtn: $("workflow-mode-button"),
      roleMenu: $("staff-role-menu"),
      modeMenu: $("workflow-mode-menu"),
      profileName: $("profile-name"),
      profileRole: $("profile-role"),
      profileAvatarImg: $("profile-avatar-img"),
      profileBtn: $("profile-menu-button"),
      profileMenu: $("profile-menu"),
      signOutBtn: $("sign-out-button")
    };

    const state = {
      resultText: "",
      requestId: null,
      receipt: null,
      assist: null,
      running: false
    };

    function getActiveRequestId() {
      return state.requestId || (state.receipt && state.receipt.request_id) || null;
    }

    function setReceiptActionMessage(message) {
      if (!els.receiptActionsText) return;
      els.receiptActionsText.textContent = message;
    }

    function getAuthHeaders() {
      const token = localStorage.getItem('anchor_access_token');
      return token ? { Authorization: 'Bearer ' + token } : {};
    }

    function apiUrl(path) {
      if (!API_BASE) return path;
      return API_BASE + (path.startsWith('/') ? path : '/' + path);
    }

    function navigateParent(href, options) {
      try {
        if (window.parent && window.parent !== window) {
          window.parent.postMessage({ type: 'anchor:navigate', href: href, replace: !!(options && options.replace) }, '*');
          return;
        }
      } catch (error) {
        console.warn('Parent navigation bridge failed', error);
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
          window.parent.postMessage({ type: 'anchor:signout' }, '*');
          return;
        }
      } catch (error) {
        console.warn('Parent sign-out bridge failed', error);
      }
      try {
        localStorage.removeItem('anchor_access_token');
        localStorage.removeItem('anchor_session_user');
      } catch (error) {
        console.warn('Sign out cleanup failed', error);
      }
      window.location.replace('/login');
    }

    function setRunVisual(status, text) {
      els.runBadgeText.textContent = text;
      els.runState.textContent = status;
      if (text === 'Running...') {
        els.runBadge.className = 'inline-flex items-center gap-1 px-3 py-1.5 rounded-full bg-slate-100 text-slate-700 text-[11px] font-bold';
      } else if (text === 'Failed') {
        els.runBadge.className = 'inline-flex items-center gap-1 px-3 py-1.5 rounded-full bg-red-50 text-red-700 text-[11px] font-bold';
      } else if (text === 'Complete') {
        els.runBadge.className = 'inline-flex items-center gap-1 px-3 py-1.5 rounded-full bg-tertiary/10 text-tertiary text-[11px] font-bold';
      } else {
        els.runBadge.className = 'inline-flex items-center gap-1 px-3 py-1.5 rounded-full bg-primary/10 text-primary text-[11px] font-bold';
      }
    }

    function setText(el, value, fallback = '—') {
      if (!el) return;
      const text = value === undefined || value === null || value === '' ? fallback : String(value);
      el.textContent = text;
    }

    function formatDate(value) {
      if (!value) return '—';
      const d = new Date(value);
      if (isNaN(d.getTime())) return String(value);
      return d.toLocaleString();
    }

    function mapMode(display) {
      return MODE_MAP[display] || 'internal_summary';
    }

    function closeMenus() {
      els.roleMenu.classList.add('hidden');
      els.modeMenu.classList.add('hidden');
      els.profileMenu.classList.add('hidden');
    }

    function maybeUpdateInstructionPreset(modeLabel) {
      const current = (els.instruction.value || '').trim();
      const knownPresetValues = Object.values(INSTRUCTION_PRESETS);
      if (!current || knownPresetValues.includes(current)) {
        els.instruction.value = INSTRUCTION_PRESETS[modeLabel] || INSTRUCTION_PRESETS["Internal governance review"];
      }
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

    function setRole(label) {
      els.roleValue.textContent = label;
      els.contextRole.textContent = label;
    }

    function setMode(label) {
      els.modeValue.textContent = label;
      els.contextMode.textContent = label;
      maybeUpdateInstructionPreset(label);
    }

    function setSessionReady(text, badgeText) {
      els.sessionText.textContent = text;
      els.sessionBadge.textContent = badgeText;
    }

    function applyReviewGate() {
      const activeRequestId = getActiveRequestId();
      const canReview = !!activeRequestId;
      const canOperationalise = !!state.resultText && !!activeRequestId && !!els.review.checked;
      els.draftBtn.disabled = !canReview;
      els.openReceiptBtn.disabled = !canReview;
      els.receiptDraftBtn.disabled = !canReview;
      els.exportBtn.disabled = !canOperationalise;
      els.copyBtn.disabled = !canOperationalise;
      els.receiptHumanReview.textContent = els.review.checked ? 'Yes' : 'No';
      els.exportBtn.style.opacity = canOperationalise ? '1' : '0.55';
      els.copyBtn.style.opacity = canOperationalise ? '1' : '0.55';
      els.openReceiptBtn.style.opacity = canReview ? '1' : '0.55';
      els.draftBtn.style.opacity = canReview ? '1' : '0.55';
      els.receiptDraftBtn.style.opacity = canReview ? '1' : '0.55';
    }

    function resetWorkspace() {
      state.resultText = '';
      state.requestId = null;
      state.receipt = null;
      state.assist = null;
      state.running = false;
      els.source.value = '';
      els.review.checked = false;
      els.governedOutput.classList.add('hidden');
      els.governedOutput.textContent = '';
      els.outputStatus.textContent = 'No governed output yet';
      setRunVisual('Ready to process', 'Awaiting run');
      setText(els.decision, null);
      setText(els.riskGrade, null);
      setText(els.piiDetected, null);
      setText(els.piiAction, null);
      setText(els.governanceScore, null);
      setText(els.policyVersion, null);
      setText(els.neutralityVersion, null);
      setText(els.requestId, null);
      setText(els.createdAt, null);
      setText(els.policyHash, null);
      setText(els.rulesFired, null);
      setText(els.receiptAvailable, 'Pending');
      setText(els.receiptRequestId, null);
      setText(els.receiptPolicyVersion, null);
      setText(els.receiptNeutralityVersion, null);
      setText(els.receiptTitle, 'DRAFT_PREVIEW', 'DRAFT_PREVIEW');
      els.receiptNoContentStored.textContent = 'Yes';
      els.receiptActionsText.textContent = 'Receipt actions will appear after a governed run.';
      els.signalDetail.textContent = 'Additional signal detail will appear here when available from the receipt.';
      els.noContentStored.textContent = 'Yes';
      setSessionReady('Ready for governed workflow', 'Ready');
      els.openLearning.href = '/learn/cards/governance-basics';
      setRole('Practice Manager');
      setMode('Internal governance review');
      closeMenus();
      applyReviewGate();
    }

    function hydrateFromReceipt(receipt) {
      if (!receipt) return;
      state.receipt = receipt;
      setText(els.decision, receipt.decision);
      setText(els.riskGrade, receipt.risk_grade);
      setText(els.piiDetected, receipt.pii_detected === undefined ? null : (receipt.pii_detected ? 'Yes' : 'No'));
      setText(els.piiAction, receipt.pii_action);
      setText(els.governanceScore, receipt.governance_score);
      setText(els.policyVersion, receipt.policy_version);
      setText(els.neutralityVersion, receipt.neutrality_version);
      setText(els.requestId, receipt.request_id);
      setText(els.createdAt, formatDate(receipt.created_at_utc || receipt.created_at));
      setText(els.policyHash, receipt.policy_hash || receipt.policy_sha256);
      const rules = receipt.rules_fired;
      let rulesText = '—';
      if (Array.isArray(rules)) {
        rulesText = String(rules.length);
      } else if (rules && typeof rules === 'object') {
        try {
          const outputRules = rules.output && Array.isArray(rules.output.triggered_rule_ids)
            ? rules.output.triggered_rule_ids.length
            : null;
          if (typeof outputRules === 'number' && outputRules > 0) {
            rulesText = String(outputRules);
          } else {
            rulesText = String(Object.keys(rules).length);
          }
        } catch {}
      }
      setText(els.rulesFired, rulesText, '—');
      setText(els.receiptAvailable, receipt.request_id ? 'Active' : 'Pending');
      setText(els.receiptRequestId, receipt.request_id ? '#' + receipt.request_id : null);
      setText(els.receiptPolicyVersion, receipt.policy_version);
      setText(els.receiptNeutralityVersion, receipt.neutrality_version);
      els.receiptNoContentStored.textContent = receipt.no_content_stored === false ? 'No' : 'Yes';
      els.noContentStored.textContent = receipt.no_content_stored === false ? 'No' : 'Yes';
      const piiTypes = Array.isArray(receipt.pii_types) ? receipt.pii_types : [];
      els.signalDetail.textContent = piiTypes.length ? piiTypes.join(', ') : 'Additional signal detail will appear here when available from the receipt.';
      els.receiptActionsText.textContent = receipt.request_id ? 'Receipt actions are now available for this governed run.' : 'Receipt actions will appear after a governed run.';
      els.receiptTitle.textContent = receipt.request_id ? 'RECEIPT_' + String(receipt.request_id).slice(0,8) : 'DRAFT_PREVIEW';
      if (piiTypes.length || receipt.pii_detected) {
        els.openLearning.href = '/learn/cards/privacy-safe-ai-use';
      } else {
        els.openLearning.href = '/learn/cards/governance-basics';
      }
      applyReviewGate();
    }

    async function fetchReceipt(requestId) {
      const response = await fetch(apiUrl('/v1/portal/receipt/' + requestId), {
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders()
        }
      });
      if (!response.ok) throw new Error(await response.text() || 'Unable to load receipt');
      const data = await response.json();
      return data && data.receipt ? data.receipt : data;
    }

    async function handleRun() {
      const source = els.source.value.trim();
      const instruction = els.instruction.value.trim();
      const role = els.roleValue?.textContent?.trim() || 'Practice Manager';
      const modeDisplay = els.modeValue?.textContent?.trim() || 'Internal governance review';
      const mode = mapMode(modeDisplay);

      if (!source) {
        alert('Add source material before running ANCHOR.');
        return;
      }

      state.running = true;
      setRunVisual('Running through ANCHOR…', 'Running...');
      els.outputStatus.textContent = 'Running through ANCHOR…';
      setSessionReady('Run in progress', 'Running');
      applyReviewGate();

      const payload = {
        mode,
        role,
        instruction,
        text: source,
        input: source,
        input_text: source,
        source_material: source,
        source_text: source,
        prompt: source,
        content: source,
        workflow_origin: 'direct_anchor_workspace',
        input_kind: 'source_material'
      };

      try {
        const response = await fetch(apiUrl('/v1/portal/assist'), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...getAuthHeaders()
          },
          body: JSON.stringify(payload)
        });

        if (!response.ok) {
          const raw = await response.text();
          throw new Error(raw || 'ANCHOR could not complete this run.');
        }

        const data = await response.json();
        state.assist = data;
        state.resultText = data.final_text ?? data.output ?? data.governed_output ?? data.result ?? data.rewritten_text ?? data.assistant_output ?? data.text ?? '';
        state.requestId = data.request_id ?? data.receipt?.request_id ?? null;

        if (state.resultText) {
          els.governedOutput.textContent = state.resultText;
          els.governedOutput.classList.remove('hidden');
          els.outputStatus.textContent = 'Governed output ready';
        } else {
          els.governedOutput.classList.add('hidden');
          els.outputStatus.textContent = 'Run completed without governed output text';
        }

        setRunVisual('Governed result ready', 'Complete');
        setSessionReady('Governed result ready', 'Complete');

        const provisional = {
          request_id: state.requestId,
          decision: data.decision,
          risk_grade: data.risk_grade,
          pii_detected: data.pii_detected,
          pii_action: data.pii_action,
          pii_types: data.pii_types,
          governance_score: data.governance_score,
          policy_version: data.policy_version,
          neutrality_version: data.neutrality_version,
          policy_hash: data.policy_hash || data.policy_sha256,
          rules_fired: data.rules_fired,
          no_content_stored: data.no_content_stored ?? true,
          created_at_utc: data.created_at_utc || data.created_at
        };
        hydrateFromReceipt(provisional);

        if (state.requestId) {
          try {
            const receipt = await fetchReceipt(state.requestId);
            hydrateFromReceipt({ ...provisional, ...(receipt || {}) });
          } catch (receiptError) {
            console.warn('Receipt fetch failed', receiptError);
          }
        }
      } catch (error) {
        console.error(error);
        setRunVisual('Run failed', 'Failed');
        els.outputStatus.textContent = 'Run failed';
        setSessionReady('Run failed', 'Attention');
        els.governedOutput.classList.remove('hidden');
        els.governedOutput.textContent = error instanceof Error ? error.message : 'ANCHOR could not complete this run.';
      } finally {
        state.running = false;
        applyReviewGate();
      }
    }

    async function exportMetadata() {
      const activeRequestId = getActiveRequestId();
      if (!activeRequestId) {
        setReceiptActionMessage('Export metadata becomes available after a governed run creates a receipt.');
        return;
      }
      if (!els.review.checked) {
        setReceiptActionMessage('Confirm human review before exporting receipt metadata.');
        return;
      }
      try {
        const receipt = state.receipt || (await fetchReceipt(activeRequestId));
        state.receipt = receipt;
        const blob = new Blob([JSON.stringify({ receipt }, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'anchor-receipt-' + activeRequestId + '.json';
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 0);
        setReceiptActionMessage('Receipt metadata exported for this governed run.');
      } catch (error) {
        console.error(error);
        setReceiptActionMessage('Metadata export could not be completed right now.');
      }
    }

    function openReceipt() {
      const activeRequestId = getActiveRequestId();
      if (!activeRequestId) {
        setReceiptActionMessage('Open receipt becomes available after a governed run creates a receipt.');
        return;
      }
      navigateParent('/receipts?request_id=' + encodeURIComponent(activeRequestId));
    }

    function draftReceipt() {
      const activeRequestId = getActiveRequestId();
      if (!activeRequestId) {
        setReceiptActionMessage('Draft Receipt becomes available after a governed run creates a receipt.');
        return;
      }
      navigateParent('/receipts?request_id=' + encodeURIComponent(activeRequestId));
    }

    function signOut() {
      requestParentSignOut();
    }

    async function copyResult() {
      if (!state.resultText) {
        setReceiptActionMessage('Copy governed result becomes available after ANCHOR produces governed output.');
        return;
      }
      if (!els.review.checked) {
        setReceiptActionMessage('Confirm human review before copying governed output.');
        return;
      }

      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(state.resultText);
        } else {
          const copyField = document.createElement('textarea');
          copyField.value = state.resultText;
          copyField.setAttribute('readonly', 'true');
          copyField.style.position = 'fixed';
          copyField.style.opacity = '0';
          document.body.appendChild(copyField);
          copyField.select();
          const copied = document.execCommand('copy');
          document.body.removeChild(copyField);
          if (!copied) {
            throw new Error('Clipboard copy was rejected');
          }
        }

        els.copyBtn.innerHTML = '<span class="material-symbols-outlined text-sm">check</span>Copied governed result';
        setReceiptActionMessage('Governed result copied to clipboard.');
        setTimeout(() => {
          els.copyBtn.innerHTML = '<span class="material-symbols-outlined text-sm">content_copy</span>Copy governed result';
        }, 1200);
      } catch (error) {
        console.error(error);
        setReceiptActionMessage('Copy governed result could not access the clipboard in this browser context.');
      }
    }

    document.querySelectorAll('[data-anchor-route]').forEach(function (link) {
      link.addEventListener('click', function (event) {
        event.preventDefault();
        const href = link.getAttribute('data-anchor-route') || link.getAttribute('href') || '/workspace-live';
        navigateParent(href);
      });
    });

    els.runBtn.addEventListener('click', handleRun);
    els.newBtn.addEventListener('click', resetWorkspace);
    els.review.addEventListener('change', applyReviewGate);
    els.openReceiptBtn.addEventListener('click', openReceipt);
    els.draftBtn.addEventListener('click', draftReceipt);
    els.receiptDraftBtn.addEventListener('click', draftReceipt);
    els.exportBtn.addEventListener('click', exportMetadata);
    els.copyBtn.addEventListener('click', copyResult);

    els.roleBtn.addEventListener('click', function (event) {
      event.stopPropagation();
      const willOpen = els.roleMenu.classList.contains('hidden');
      closeMenus();
      if (willOpen) els.roleMenu.classList.remove('hidden');
    });

    els.modeBtn.addEventListener('click', function (event) {
      event.stopPropagation();
      const willOpen = els.modeMenu.classList.contains('hidden');
      closeMenus();
      if (willOpen) els.modeMenu.classList.remove('hidden');
    });

    document.querySelectorAll('.role-option-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        setRole(btn.getAttribute('data-role-option') || 'Practice Manager');
        closeMenus();
      });
    });

    document.querySelectorAll('.mode-option-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        setMode(btn.getAttribute('data-mode-option') || 'Internal governance review');
        closeMenus();
      });
    });

    els.profileBtn.addEventListener('click', function (event) {
      event.stopPropagation();
      const willOpen = els.profileMenu.classList.contains('hidden');
      closeMenus();
      if (willOpen) els.profileMenu.classList.remove('hidden');
    });

    els.signOutBtn.addEventListener('click', signOut);

    if (els.openLearning) {
      els.openLearning.addEventListener('click', function (event) {
        event.preventDefault();
        navigateParent(els.openLearning.getAttribute('href') || '/learn/cards/governance-basics');
      });
    }

    if (els.openIntelligence) {
      els.openIntelligence.addEventListener('click', function (event) {
        event.preventDefault();
        navigateParent('/intelligence');
      });
    }

    document.addEventListener('click', function () {
      closeMenus();
    });

    setUserFromSession();

    document.addEventListener('keydown', (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
        event.preventDefault();
        handleRun();
      }
      if (event.key === 'Escape') {
        closeMenus();
      }
    });

    resetWorkspace();
  })();
</script>

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

export default function WorkspaceStitchPage() {
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
        title="Workspace Stitch"
        srcDoc={html}
        className="h-full w-full border-0"
        sandbox="allow-scripts allow-same-origin allow-downloads"
      />
    </div>
  );
}
