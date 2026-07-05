"use client";

// Fable roadmap-completion experiment - Slice F7 (M6.12 provider /
// connector posture, internal preview).
//
// The backend connector layer (assistant_provider.py on the backend
// experiment branch) exposes NO portal API for provider posture, so
// this surface is a static, truthful posture display - it fetches
// nothing and can toggle nothing.
//
// Wording controls (Readiness Map v1.1 section 2):
//   * "architected for vendor-neutrality" / "vendor-neutral over time"
//     - future-tense only. The live path is Anthropic-coupled and
//     live generation is production-off.
//   * No present-tense "vendor-neutral" / "multi-provider" /
//     "provider-agnostic" claims. No live provider toggle; the
//     selector below is permanently disabled and clearly marked
//     unavailable.

import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import {
  InternalPreviewBadge,
  InternalPreviewGate,
} from "@/components/experiment/InternalPreviewGate";

export function ProviderPostureSurface() {
  return (
    <InternalPreviewGate title="AI provider posture">
      <ProviderPostureContent />
    </InternalPreviewGate>
  );
}

function ProviderPostureContent() {
  return (
    <div className="space-y-6">
      <div>
        <div className="flex flex-wrap items-center gap-3">
          <p className="text-sm font-medium text-slate-500">Clinic administration</p>
          <InternalPreviewBadge />
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          AI provider posture
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          How ANCHOR&rsquo;s generation architecture is wired today, stated plainly. ANCHOR is
          architected for vendor-neutrality and intends to be vendor-neutral over time; it is
          not vendor-neutral as a current capability.
        </p>
      </div>

      <Card variant="native">
        <SectionTitle
          title="Current posture"
          description="The architecture facts as they stand on this build."
        />
        <div className="mt-4 space-y-4">
          <PostureRow
            title="Live generation"
            status="blocked"
            note="Production-off. The live Workspace generation path stays off until the local/staging safety gate passes; deterministic governed generation is the current behaviour."
          />
          <PostureRow
            title="Live-path provider coupling"
            status="anthropic_coupled"
            note="The live generation path, where enabled outside production, is built on the Anthropic API. Anthropic becomes a subprocessor only if live generation is ever enabled."
          />
          <PostureRow
            title="Connector layer"
            status="gated"
            note="A provider adapter interface exists code-wise behind the generation path. Production permits the Anthropic adapter only; widening that allow-list is a founder decision requiring legal and subprocessor coverage, not a configuration change."
          />
          <PostureRow
            title="Provider switching"
            status="blocked"
            note="Disabled. A second adapter exists code-wise for non-production experiments only; it cannot be selected in production and is not reachable from this portal."
          />
        </div>
      </Card>

      <Card variant="native">
        <SectionTitle
          title="Provider selection"
          description="Present in the architecture, deliberately unavailable here."
        />
        <div className="mt-4 max-w-md">
          <label className="flex flex-col text-xs font-medium text-slate-500">
            Generation provider
            <select
              disabled
              value="anthropic"
              className="mt-1 cursor-not-allowed rounded-xl border border-slate-200 bg-slate-100 px-3 py-2 text-sm font-normal text-slate-400"
            >
              <option value="anthropic">Anthropic (architecture default)</option>
            </select>
          </label>
          <p className="mt-2 text-xs leading-5 text-slate-500">
            Unavailable — provider switching is not enabled. Enabling any alternative provider
            requires an explicit founder decision with security, legal, and subprocessor
            review; it is not an environment setting and cannot be changed from this portal.
          </p>
        </div>
      </Card>

      <Card variant="native">
        <SectionTitle
          title="What vendor-neutrality means here"
          description="The forward-looking intent, without overstating the present."
        />
        <div className="mt-4 space-y-3 text-sm leading-6 text-slate-600">
          <p>
            ANCHOR&rsquo;s governance surfaces — receipts, review states, policies, learning
            evidence, and trust posture — are deliberately provider-independent: they describe
            AI use without depending on which model produced a draft. Output-safety validation
            runs on every live draft regardless of provider, by construction.
          </p>
          <p>
            That architecture is what &ldquo;architected for vendor-neutrality&rdquo; means: the
            product is built so it can become vendor-neutral over time. Today, the only
            production-permitted generation path is Anthropic-coupled and remains
            production-off, and ANCHOR should not be described as vendor-neutral,
            multi-provider, or provider-agnostic in the present tense.
          </p>
        </div>
      </Card>
    </div>
  );
}

function SectionTitle({
  title,
  description,
}: {
  title: string;
  description?: string;
}) {
  return (
    <div>
      <h2 className="text-base font-semibold text-slate-900">{title}</h2>
      {description ? (
        <p className="mt-1 text-sm leading-6 text-slate-600">{description}</p>
      ) : null}
    </div>
  );
}

function PostureRow({
  title,
  status,
  note,
}: {
  title: string;
  status: string;
  note: string;
}) {
  return (
    <div className="grid gap-2 border-b border-slate-100 pb-4 last:border-b-0 last:pb-0 md:grid-cols-[1fr_auto]">
      <div>
        <p className="text-sm font-semibold text-slate-900">{title}</p>
        <p className="mt-1 text-sm leading-6 text-slate-600">{note}</p>
      </div>
      <div className="md:text-right">
        <StatusBadge value={status} />
      </div>
    </div>
  );
}
