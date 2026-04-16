"use client";

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
    .audit-line::before {
      content: '';
      position: absolute;
      left: 11px;
      top: 24px;
      bottom: -24px;
      width: 1.5px;
      background-color: #a9b4b9;
      opacity: 0.2;
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
      <a class="flex items-center px-6 py-3 space-x-3 text-slate-900 font-bold border-r-2 border-slate-900 bg-slate-200/50 transition-all duration-200" href="#">
        <span class="material-symbols-outlined">clinical_notes</span>
        <span>Workspace</span>
      </a>
      <a class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors" href="#">
        <span class="material-symbols-outlined">dashboard</span>
        <span>Dashboard</span>
      </a>
      <a class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors" href="#">
        <span class="material-symbols-outlined">receipt_long</span>
        <span>Receipts</span>
      </a>
      <a class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors" href="#">
        <span class="material-symbols-outlined">verified_user</span>
        <span>Governance Events</span>
      </a>
      <a class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors" href="#">
        <span class="material-symbols-outlined">school</span>
        <span>Learn</span>
      </a>
      <a class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors" href="#">
        <span class="material-symbols-outlined">shield_with_heart</span>
        <span>Trust</span>
      </a>
      <a class="flex items-center px-6 py-3 space-x-3 text-slate-500 hover:text-slate-700 hover:bg-slate-200/50 transition-colors" href="#">
        <span class="material-symbols-outlined">psychology</span>
        <span>Intelligence</span>
      </a>
    </nav>

    <div class="mt-auto px-4">
      <button class="w-full py-2.5 px-4 bg-gradient-to-r from-primary to-primary-dim text-white rounded-md font-bold shadow-sm flex items-center justify-center gap-2 hover:opacity-90 transition-all text-center leading-tight">
        <span class="material-symbols-outlined text-[18px]">add</span>
        New governed workflow
      </button>

      <div class="mt-6 space-y-1">
        <a class="flex items-center px-2 py-2 space-x-3 text-slate-500 hover:text-slate-700 transition-colors" href="#">
          <span class="material-symbols-outlined">settings</span>
          <span>Settings</span>
        </a>
        <a class="flex items-center px-2 py-2 space-x-3 text-slate-500 hover:text-slate-700 transition-colors" href="#">
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
          <span class="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-xl">search</span>
          <input class="w-full pl-10 pr-4 py-1.5 bg-surface-container-low border-none focus:ring-1 focus:ring-primary rounded-lg text-sm text-on-surface transition-all" placeholder="Search workspace, audits, or metadata..." type="text"/>
        </div>
      </div>

      <div class="flex items-center gap-6">
        <button class="text-on-surface-variant hover:text-on-surface transition-transform active:scale-95">
          <span class="material-symbols-outlined">notifications</span>
        </button>
        <button class="text-on-surface-variant hover:text-on-surface transition-transform active:scale-95">
          <span class="material-symbols-outlined">settings</span>
        </button>
        <div class="h-6 w-[1px] bg-outline-variant/30"></div>

        <div class="flex items-center gap-3 cursor-pointer group">
          <div class="text-right">
            <p class="text-xs font-bold leading-none">Sarah Miller</p>
            <p class="text-[10px] text-on-surface-variant">Practice Manager</p>
          </div>
          <img alt="User Avatar" class="w-9 h-9 rounded-full object-cover grayscale-[0.2] border border-outline-variant/20" src="https://lh3.googleusercontent.com/aida-public/AB6AXuCnbGKz0TR_w7R7vfsdlOaArbM6Ka9P4NxHiCDCVu9tUHvElC9ITX3XsjBMrYZAIv3n-S06ghZKu1BTKIbpwbNIHkKoVMCo2ETSVZB_Lp6Km6Jd_5xHoQ3zB8HXdy_1_AQMQHMaheRN7A7BSx1SZUq6yajARax2RDSLTFq-h59_vYF75fpi0P3BPE4AjWoXtE8_7Ha9IjlxtIhWjqmdQAs1gQOxFyv2ganm7lmdG5dTZxehwGb8EPX2ZU_4Pa6iXRFWnROk2MISg4nq"/>
        </div>
      </div>
    </header>

    <main class="p-8 max-w-[1440px] mx-auto w-full">
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
            <div class="bg-surface-container-lowest p-6 rounded-xl border border-outline-variant/15">
              <label class="block text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-3">Staff role</label>
              <div class="flex items-center justify-between p-3 bg-surface-container-low rounded-lg border border-transparent hover:border-primary/20 cursor-pointer transition-all">
                <div class="flex items-center gap-3">
                  <span class="material-symbols-outlined text-primary">person</span>
                  <span class="text-sm font-semibold">Practice Manager</span>
                </div>
                <span class="material-symbols-outlined text-on-surface-variant">expand_more</span>
              </div>
            </div>

            <div class="bg-surface-container-lowest p-6 rounded-xl border border-outline-variant/15">
              <label class="block text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-3">Workflow mode</label>
              <div class="flex items-center justify-between p-3 bg-surface-container-low rounded-lg border border-transparent hover:border-primary/20 cursor-pointer transition-all">
                <div class="flex items-center gap-3">
                  <span class="material-symbols-outlined text-primary">gavel</span>
                  <span class="text-sm font-semibold">Internal governance review</span>
                </div>
                <span class="material-symbols-outlined text-on-surface-variant">expand_more</span>
              </div>
            </div>
          </div>

          <section class="bg-surface-container-lowest p-8 rounded-xl border border-outline-variant/15">
            <div class="flex justify-between items-center mb-6">
              <h3 class="font-manrope font-bold text-lg">Source material</h3>
            </div>
            <div class="relative">
              <textarea class="w-full bg-surface-container-low border-none rounded-lg p-4 text-sm text-on-surface focus:ring-1 focus:ring-primary placeholder:text-on-surface-variant/50" placeholder="Paste draft content, notes, transcript excerpts, or operational text for governed review." rows="6"></textarea>
            </div>
            <p class="mt-4 text-[11px] text-on-surface-variant italic">Privacy-aware handling is applied during governed review. Always confirm the output before operational use.</p>
          </section>

          <section class="bg-surface-container-lowest p-8 rounded-xl border border-outline-variant/15">
            <h3 class="font-manrope font-bold text-lg mb-6">Review settings</h3>
            <div class="space-y-4">
              <div class="flex items-start gap-4">
                <div class="w-8 h-8 rounded-full bg-surface-container flex items-center justify-center flex-shrink-0">
                  <span class="text-xs font-bold font-manrope">01</span>
                </div>
                <div class="flex-1">
                  <p class="text-sm font-semibold mb-1">Instruction</p>
                  <input class="w-full bg-transparent border-b border-outline-variant/30 focus:border-primary text-sm py-1 focus:ring-0" type="text" value="Extract session summary for staff records"/>
                </div>
              </div>

              <div class="flex items-start gap-4 pt-4">
                <div class="w-8 h-8 rounded-full bg-surface-container flex items-center justify-center flex-shrink-0">
                  <span class="text-xs font-bold font-manrope">02</span>
                </div>
                <div class="flex-1">
                  <p class="text-sm font-semibold mb-1">Review boundaries</p>
                  <div class="flex gap-2">
                    <span class="px-3 py-1.5 bg-primary/10 text-primary text-[11px] font-bold rounded-full">Standard Privacy</span>
                    <span class="px-3 py-1.5 bg-tertiary/10 text-tertiary text-[11px] font-bold rounded-full">Audit Log Active</span>
                    <span class="px-3 py-1.5 bg-surface-container text-on-surface-variant text-[11px] font-bold rounded-full cursor-pointer hover:bg-surface-variant">+ Add Boundary</span>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <div class="flex justify-end gap-4 pt-4">
            <button class="px-8 py-3 bg-surface-container-highest text-on-surface font-bold rounded-md hover:bg-surface-variant transition-colors">
              Draft Receipt
            </button>
            <button class="px-10 py-3 bg-gradient-to-r from-primary to-primary-dim text-white font-bold rounded-md shadow-lg shadow-primary/20 flex items-center gap-2 hover:opacity-95">
              <span class="material-symbols-outlined">lock_person</span>
              Run through ANCHOR
            </button>
          </div>
        </div>

        <div class="col-span-4 space-y-6">
          <div class="bg-surface-container-low rounded-xl p-6 border border-outline-variant/15">
            <h4 class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-4">Governance summary</h4>
            <div class="space-y-3">
              <div class="flex justify-between items-center text-xs py-1 border-b border-outline-variant/10">
                <span class="font-medium text-on-surface-variant">Decision</span>
                <span class="font-bold text-tertiary">Approved</span>
              </div>
              <div class="flex justify-between items-center text-xs py-1 border-b border-outline-variant/10">
                <span class="font-medium text-on-surface-variant">Risk grade</span>
                <span class="font-bold">Standard</span>
              </div>
              <div class="flex justify-between items-center text-xs py-1 border-b border-outline-variant/10">
                <span class="font-medium text-on-surface-variant">PII action</span>
                <span class="font-bold">Anonymized</span>
              </div>
              <div class="flex justify-between items-center text-xs py-1 border-b border-outline-variant/10">
                <span class="font-medium text-on-surface-variant">Policy version</span>
                <span class="font-bold">v2.4</span>
              </div>
              <div class="flex justify-between items-center text-xs py-1">
                <span class="font-medium text-on-surface-variant">Neutrality version</span>
                <span class="font-bold">v1.1</span>
              </div>
            </div>
          </div>

          <div class="bg-surface-container-lowest rounded-xl p-6 border border-outline-variant/15">
            <h4 class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-6">Traceability</h4>
            <div class="space-y-4">
              <div>
                <p class="text-[10px] font-bold text-on-surface-variant uppercase mb-1">Request ID</p>
                <p class="text-sm font-bold font-manrope">ANC-99201</p>
              </div>
              <div>
                <p class="text-[10px] font-bold text-on-surface-variant uppercase mb-1">Created at</p>
                <p class="text-sm font-medium">2024-08-02 09:42:10 AM</p>
              </div>
              <div>
                <p class="text-[10px] font-bold text-on-surface-variant uppercase mb-1">Policy hash</p>
                <p class="text-[10px] font-mono text-on-surface-variant truncate">0x82f9c...a1e7b</p>
              </div>
              <div class="flex justify-between items-center">
                <div>
                  <p class="text-[10px] font-bold text-on-surface-variant uppercase mb-1">Rules fired</p>
                  <p class="text-sm font-bold">12</p>
                </div>
                <div class="text-right">
                  <p class="text-[10px] font-bold text-on-surface-variant uppercase mb-1">Receipt available</p>
                  <p class="text-sm font-bold text-tertiary">Active</p>
                </div>
              </div>
            </div>
          </div>

          <div class="bg-slate-900 text-white rounded-xl overflow-hidden shadow-xl">
            <div class="p-6 bg-slate-800/50 flex justify-between items-center">
              <div>
                <p class="text-[10px] font-bold tracking-widest opacity-60">RECEIPT PREVIEW</p>
                <p class="text-xs font-bold font-manrope">DRAFT_2024_08_02_X</p>
              </div>
              <span class="material-symbols-outlined text-tertiary-fixed">qr_code_2</span>
            </div>

            <div class="p-6 space-y-4">
              <div class="flex justify-between items-center text-[11px] border-b border-white/10 pb-2">
                <span class="opacity-60">Request ID</span>
                <span>#ANC-99201</span>
              </div>
              <div class="flex justify-between items-center text-[11px] border-b border-white/10 pb-2">
                <span class="opacity-60">Policy version</span>
                <span>v2.4</span>
              </div>
              <div class="flex justify-between items-center text-[11px] border-b border-white/10 pb-2">
                <span class="opacity-60">Neutrality version</span>
                <span>v1.1</span>
              </div>

              <div class="grid grid-cols-2 gap-2 pt-2">
                <button class="py-2 px-3 bg-tertiary-fixed text-primary text-[10px] font-bold rounded flex items-center justify-center gap-1 hover:opacity-90">
                  <span class="material-symbols-outlined text-sm">open_in_new</span>
                  Open receipt
                </button>
                <button class="py-2 px-3 bg-white/10 text-white text-[10px] font-bold rounded flex items-center justify-center gap-1 hover:bg-white/20">
                  <span class="material-symbols-outlined text-sm">download</span>
                  Export metadata
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
  </div>
</body>
</html>
`;

export default function WorkspaceStitchPage() {
  return (
    <div className="h-screen w-full bg-white">
      <iframe
        title="Workspace Stitch"
        srcDoc={stitchHtml}
        className="h-full w-full border-0"
        sandbox="allow-scripts allow-same-origin"
      />
    </div>
  );
}