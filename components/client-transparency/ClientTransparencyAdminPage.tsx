"use client";

// Phase 2A-4.6 - Client Transparency admin page (clinic-admin only).
//
// Metadata-only doctrine:
//   * The profile is a plain-language client-facing AI-use disclosure
//     support surface. It is not legal advice, a consent form, a
//     clinical record, or a compliance certificate.
//   * Bounded category enums only; no clinical case content; no client
//     or patient identifiers; no raw prompts/outputs.
//   * The three statement flags are backend-locked true. The frontend
//     surfaces them as locked badges and never sends false.
//   * Publish/version UI is intentionally deferred to Phase 2A-4.7.
//   * Frontend admin gate is UX hardening only; backend remains the
//     real authorization control.

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  useSyncExternalStore,
} from "react";
import { ApiError } from "@/lib/api";
import {
  SESSION_SERVER_SNAPSHOT,
  getSessionUserSnapshot,
  subscribeSessionStorage,
} from "@/lib/auth";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { StatusBadge } from "@/components/ui/StatusBadge";
import {
  activateClientTransparencyProfile,
  archiveClientTransparencyProfile,
  createClientTransparencyProfile,
  getActiveClientTransparencyProfile,
  listClientTransparencyProfiles,
  listClientTransparencyTemplates,
  updateClientTransparencyProfile,
} from "@/lib/clientTransparency";
import type {
  ClientTransparencyProfile,
  ClientTransparencyProfileCreateRequest,
  ClientTransparencyProfileUpdateRequest,
  ClientTransparencyTemplate,
} from "@/lib/types";

const ADMIN_ROLES = new Set(["admin", "owner", "practice_manager"]);

const TEMPLATE_SLUG = "client_ai_use_transparency_v1";

const DEFAULT_DISPLAY_TITLE = "How we use AI in our clinic";

const DEFAULT_PLAIN_LANGUAGE_SUMMARY =
  "Our clinic may use AI tools to support administrative work, internal summarisation, " +
  "and drafting client communications from clinician-confirmed information. AI is not " +
  "used to replace veterinary judgement, diagnosis, prescribing, treatment planning, " +
  "or autonomous clinical decisions. Human review remains required.";

function formatDateTime(value?: string | null): string {
  if (!value) return "Not set";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function formatTag(value: string): string {
  return value.replace(/[_-]+/g, " ");
}

function errorMessageFromUnknown(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    // Map known backend error codes to safe clinic-facing copy.
    const msg = err.message ?? "";
    if (
      err.status === 400 &&
      /client_transparency_invalid_category/i.test(msg)
    ) {
      return "One or more selected categories is not valid for this template.";
    }
    if (err.status === 400 && /client_transparency_text_blocked/i.test(msg)) {
      return (
        "The profile text may include details that should not be used in " +
        "this disclosure. Remove identifiers or case-specific content and " +
        "try again."
      );
    }
    if (err.status === 409) {
      return "Only draft profiles can be edited.";
    }
    if (err.status === 401 || err.status === 403) {
      return "Admin access required to change client transparency settings.";
    }
    if (err.message) return err.message;
  }
  if (err instanceof Error) return err.message;
  return fallback;
}

type ActionFeedback = { kind: "success" | "error"; message: string } | null;

type DraftFormState = {
  displayTitle: string;
  plainLanguageSummary: string;
  permitted: string[];
  prohibited: string[];
};

function emptyDraftForm(template: ClientTransparencyTemplate | null): DraftFormState {
  return {
    displayTitle: DEFAULT_DISPLAY_TITLE,
    plainLanguageSummary: DEFAULT_PLAIN_LANGUAGE_SUMMARY,
    permitted: template ? [...template.default_permitted_categories] : [],
    prohibited: template ? [...template.default_prohibited_categories] : [],
  };
}

function draftFormFromProfile(p: ClientTransparencyProfile): DraftFormState {
  return {
    displayTitle: p.display_title,
    plainLanguageSummary: p.plain_language_summary,
    permitted: [...p.permitted_use_categories],
    prohibited: [...p.prohibited_use_categories],
  };
}

function validateDraftForm(form: DraftFormState): string | null {
  if (!form.displayTitle.trim()) return "A display title is required.";
  if (!form.plainLanguageSummary.trim()) return "A plain-language summary is required.";
  if (form.permitted.length === 0)
    return "Select at least one permitted-use category.";
  if (form.prohibited.length === 0)
    return "Select at least one prohibited-use category.";
  return null;
}

export function ClientTransparencyAdminPage() {
  const sessionUser = useSyncExternalStore(
    subscribeSessionStorage,
    getSessionUserSnapshot,
    SESSION_SERVER_SNAPSHOT,
  );
  const isAdmin = Boolean(sessionUser?.role && ADMIN_ROLES.has(sessionUser.role));

  const [template, setTemplate] = useState<ClientTransparencyTemplate | null>(null);
  const [templateLoading, setTemplateLoading] = useState(false);
  const [templateError, setTemplateError] = useState<string | null>(null);

  const [activeProfile, setActiveProfile] = useState<ClientTransparencyProfile | null>(null);
  const [activeLoading, setActiveLoading] = useState(false);
  const [activeError, setActiveError] = useState<string | null>(null);

  const [profiles, setProfiles] = useState<ClientTransparencyProfile[] | null>(null);
  const [profilesLoading, setProfilesLoading] = useState(false);
  const [profilesError, setProfilesError] = useState<string | null>(null);

  const [feedback, setFeedback] = useState<ActionFeedback>(null);

  // Create-draft form state.
  const [createForm, setCreateForm] = useState<DraftFormState>(() =>
    emptyDraftForm(null),
  );
  const [creating, setCreating] = useState(false);
  const [createFormError, setCreateFormError] = useState<string | null>(null);

  // Edit-draft form state — keyed by profile id.
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<DraftFormState | null>(null);
  const [savingEdit, setSavingEdit] = useState(false);
  const [editFormError, setEditFormError] = useState<string | null>(null);

  const [actingOnProfileId, setActingOnProfileId] = useState<string | null>(null);

  const loadTemplate = useCallback(async () => {
    setTemplateLoading(true);
    setTemplateError(null);
    try {
      const result = await listClientTransparencyTemplates();
      const found =
        (result.templates ?? []).find((t) => t.template_slug === TEMPLATE_SLUG) ??
        result.templates?.[0] ??
        null;
      setTemplate(found);
      setCreateForm((prev) => {
        // Initialise defaults from the loaded template only if the user
        // has not yet typed anything meaningful.
        const isUntouched =
          prev.displayTitle === DEFAULT_DISPLAY_TITLE &&
          prev.plainLanguageSummary === DEFAULT_PLAIN_LANGUAGE_SUMMARY &&
          prev.permitted.length === 0 &&
          prev.prohibited.length === 0;
        return isUntouched ? emptyDraftForm(found) : prev;
      });
    } catch (err) {
      setTemplate(null);
      setTemplateError(
        errorMessageFromUnknown(err, "Client transparency templates could not be loaded."),
      );
    } finally {
      setTemplateLoading(false);
    }
  }, []);

  const loadActiveProfile = useCallback(async () => {
    setActiveLoading(true);
    setActiveError(null);
    try {
      const result = await getActiveClientTransparencyProfile();
      setActiveProfile(result.profile ?? null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setActiveProfile(null);
      } else if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        setActiveProfile(null);
      } else {
        setActiveError(
          errorMessageFromUnknown(err, "The active profile could not be loaded."),
        );
      }
    } finally {
      setActiveLoading(false);
    }
  }, []);

  const loadProfiles = useCallback(async () => {
    setProfilesLoading(true);
    setProfilesError(null);
    try {
      const result = await listClientTransparencyProfiles({ limit: 25 });
      setProfiles(result.profiles ?? []);
    } catch (err) {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        setProfiles([]);
      } else {
        setProfiles(null);
        setProfilesError(
          errorMessageFromUnknown(err, "Client transparency profiles could not be loaded."),
        );
      }
    } finally {
      setProfilesLoading(false);
    }
  }, []);

  const reloadAll = useCallback(async () => {
    await Promise.all([loadActiveProfile(), loadProfiles()]);
  }, [loadActiveProfile, loadProfiles]);

  useEffect(() => {
    void loadTemplate();
    void loadActiveProfile();
    void loadProfiles();
  }, [loadTemplate, loadActiveProfile, loadProfiles]);

  // ---------- Create draft ---------------------------------------------

  async function handleCreateDraft() {
    if (!isAdmin) return;
    setFeedback(null);
    const validationError = validateDraftForm(createForm);
    if (validationError) {
      setCreateFormError(validationError);
      return;
    }
    setCreateFormError(null);
    setCreating(true);
    try {
      const body: ClientTransparencyProfileCreateRequest = {
        template_slug: TEMPLATE_SLUG,
        template_version: template?.template_version,
        display_title: createForm.displayTitle.trim(),
        plain_language_summary: createForm.plainLanguageSummary.trim(),
        permitted_use_categories: createForm.permitted,
        prohibited_use_categories: createForm.prohibited,
        human_review_statement_enabled: true,
        privacy_statement_enabled: true,
        client_explanation_statement_enabled: true,
      };
      await createClientTransparencyProfile(body);
      setFeedback({
        kind: "success",
        message:
          "Draft client transparency profile created. Review and activate when ready.",
      });
      await reloadAll();
    } catch (err) {
      setFeedback({
        kind: "error",
        message: errorMessageFromUnknown(
          err,
          "Unable to create the draft profile.",
        ),
      });
    } finally {
      setCreating(false);
    }
  }

  // ---------- Edit draft -----------------------------------------------

  function startEdit(profile: ClientTransparencyProfile) {
    setEditingId(profile.clinic_profile_id);
    setEditForm(draftFormFromProfile(profile));
    setEditFormError(null);
  }

  function cancelEdit() {
    setEditingId(null);
    setEditForm(null);
    setEditFormError(null);
  }

  async function handleSaveEdit(profileId: string) {
    if (!isAdmin || !editForm) return;
    setFeedback(null);
    const validationError = validateDraftForm(editForm);
    if (validationError) {
      setEditFormError(validationError);
      return;
    }
    setEditFormError(null);
    setSavingEdit(true);
    try {
      const body: ClientTransparencyProfileUpdateRequest = {
        display_title: editForm.displayTitle.trim(),
        plain_language_summary: editForm.plainLanguageSummary.trim(),
        permitted_use_categories: editForm.permitted,
        prohibited_use_categories: editForm.prohibited,
        human_review_statement_enabled: true,
        privacy_statement_enabled: true,
        client_explanation_statement_enabled: true,
      };
      await updateClientTransparencyProfile(profileId, body);
      setFeedback({ kind: "success", message: "Draft profile updated." });
      setEditingId(null);
      setEditForm(null);
      await reloadAll();
    } catch (err) {
      setFeedback({
        kind: "error",
        message: errorMessageFromUnknown(err, "Unable to update the draft profile."),
      });
    } finally {
      setSavingEdit(false);
    }
  }

  // ---------- Activate / archive ---------------------------------------

  async function handleActivate(profile: ClientTransparencyProfile) {
    if (!isAdmin) return;
    setFeedback(null);
    setActingOnProfileId(profile.clinic_profile_id);
    try {
      await activateClientTransparencyProfile(profile.clinic_profile_id);
      setFeedback({
        kind: "success",
        message:
          "Profile activated as the clinic's active client transparency configuration. A publish step follows separately.",
      });
      await reloadAll();
    } catch (err) {
      setFeedback({
        kind: "error",
        message: errorMessageFromUnknown(err, "Unable to activate this profile."),
      });
    } finally {
      setActingOnProfileId(null);
    }
  }

  async function handleArchive(profile: ClientTransparencyProfile) {
    if (!isAdmin) return;
    if (typeof window !== "undefined") {
      const ok = window.confirm(
        "Archive this profile? Archived profiles cannot be edited or activated.",
      );
      if (!ok) return;
    }
    setFeedback(null);
    setActingOnProfileId(profile.clinic_profile_id);
    try {
      await archiveClientTransparencyProfile(profile.clinic_profile_id);
      setFeedback({ kind: "success", message: "Profile archived." });
      await reloadAll();
    } catch (err) {
      setFeedback({
        kind: "error",
        message: errorMessageFromUnknown(err, "Unable to archive this profile."),
      });
    } finally {
      setActingOnProfileId(null);
    }
  }

  // ---------- Derived ---------------------------------------------------

  const sortedProfiles = useMemo(() => {
    if (!profiles) return [];
    return [...profiles].sort((a, b) => {
      const aT = new Date(a.updated_at).getTime();
      const bT = new Date(b.updated_at).getTime();
      return bT - aT;
    });
  }, [profiles]);

  // ---------- Render ----------------------------------------------------

  return (
    <div className="space-y-6">
      <div>
        <p className="text-sm font-medium text-slate-500">Clinic administration</p>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          Client transparency
        </h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
          Configure a plain-language AI-use transparency statement for client
          communication. Human professional review remains required.
        </p>
      </div>

      <Card variant="native">
        <SectionTitle title="About this surface" />
        <ul className="mt-3 list-disc space-y-1 pl-5 text-sm leading-6 text-slate-700">
          <li>
            This profile supports plain-language client communication about
            bounded, human-reviewed AI use.
          </li>
          <li>
            It is not legal advice, a consent form, a clinical record, or a
            compliance certificate.
          </li>
          <li>
            The clinic remains responsible for the final wording shown to clients.
          </li>
          <li>Metadata-only governance evidence. Human review remains required.</li>
        </ul>
      </Card>

      {feedback ? (
        <div
          className={[
            "rounded-xl border px-4 py-3 text-sm",
            feedback.kind === "success"
              ? "border-emerald-200 bg-emerald-50 text-emerald-700"
              : "border-rose-200 bg-rose-50 text-rose-700",
          ].join(" ")}
          role="status"
        >
          {feedback.message}
        </div>
      ) : null}

      {/* ---------- Active profile ---------- */}
      <Card variant="native">
        <SectionTitle
          title="Current active profile"
          description="The clinic's active client transparency configuration, if one has been activated."
        />
        {activeLoading && !activeProfile ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading active profile...
          </p>
        ) : activeError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {activeError}
          </p>
        ) : !activeProfile ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No active client transparency profile yet.
          </p>
        ) : (
          <ProfileSummaryBlock profile={activeProfile} highlight />
        )}
      </Card>

      {/* ---------- Template ---------- */}
      <Card variant="native">
        <SectionTitle
          title="Template"
          description="ANCHOR-curated client transparency template."
        />
        {templateLoading && !template ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading template...
          </p>
        ) : templateError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {templateError}
          </p>
        ) : !template ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No client transparency template is available.
          </p>
        ) : (
          <TemplateBlock template={template} />
        )}
      </Card>

      {/* ---------- Create draft ---------- */}
      {isAdmin && template ? (
        <Card variant="native">
          <SectionTitle
            title="Create draft profile"
            description="Configure a new draft. Activation is a separate step; publishing follows later."
          />
          <div className="mt-4 space-y-4">
            <DraftFormFields
              form={createForm}
              template={template}
              onChange={setCreateForm}
              disabled={creating}
              idPrefix="create"
            />
            {createFormError ? (
              <p className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
                {createFormError}
              </p>
            ) : null}
            <div className="flex flex-wrap items-center gap-3">
              <Button
                onClick={() => void handleCreateDraft()}
                loading={creating}
                disabled={creating}
              >
                Create draft
              </Button>
              <span className="text-xs text-slate-500">
                Statement flags below are locked enabled in this template.
              </span>
            </div>
          </div>
        </Card>
      ) : !isAdmin ? (
        <Card variant="native">
          <SectionTitle title="Admin access required" />
          <p className="mt-3 text-sm leading-6 text-slate-700">
            Admin access is required to create, edit, activate, or archive
            client transparency profiles. The information above remains
            visible.
          </p>
        </Card>
      ) : null}

      {/* ---------- Profiles list ---------- */}
      <Card variant="native">
        <SectionTitle
          title="Profiles"
          description="Drafts, active, superseded, and archived profiles for this clinic."
        />
        {profilesLoading && !profiles ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Loading profiles...
          </p>
        ) : profilesError ? (
          <p className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {profilesError}
          </p>
        ) : sortedProfiles.length === 0 ? (
          <p className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            No client transparency profiles yet for this clinic.
          </p>
        ) : (
          <ul className="mt-4 space-y-3">
            {sortedProfiles.map((p) => {
              const isEditing = editingId === p.clinic_profile_id;
              const isBusy = actingOnProfileId === p.clinic_profile_id;
              const canEdit = isAdmin && p.status === "draft";
              const canActivate = isAdmin && p.status === "draft";
              const canArchive =
                isAdmin && (p.status === "draft" || p.status === "superseded");

              return (
                <li
                  key={p.clinic_profile_id}
                  className="rounded-xl border border-slate-200 bg-slate-50 p-4"
                >
                  <ProfileSummaryBlock profile={p} />

                  {isEditing && editForm && template ? (
                    <div className="mt-4 space-y-4">
                      <DraftFormFields
                        form={editForm}
                        template={template}
                        onChange={setEditForm}
                        disabled={savingEdit}
                        idPrefix={`edit-${p.clinic_profile_id}`}
                      />
                      {editFormError ? (
                        <p className="rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
                          {editFormError}
                        </p>
                      ) : null}
                      <div className="flex flex-wrap gap-2">
                        <Button
                          onClick={() => void handleSaveEdit(p.clinic_profile_id)}
                          loading={savingEdit}
                          disabled={savingEdit}
                        >
                          Save draft
                        </Button>
                        <Button
                          variant="secondary"
                          onClick={cancelEdit}
                          disabled={savingEdit}
                        >
                          Cancel
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {canEdit ? (
                        <Button
                          onClick={() => startEdit(p)}
                          disabled={isBusy || Boolean(editingId)}
                        >
                          Edit draft
                        </Button>
                      ) : null}
                      {canActivate ? (
                        <Button
                          variant="secondary"
                          onClick={() => void handleActivate(p)}
                          loading={isBusy}
                          disabled={isBusy || Boolean(editingId)}
                        >
                          Activate profile
                        </Button>
                      ) : null}
                      {canArchive ? (
                        <Button
                          variant="secondary"
                          onClick={() => void handleArchive(p)}
                          loading={isBusy}
                          disabled={isBusy || Boolean(editingId)}
                        >
                          Archive
                        </Button>
                      ) : null}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------

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

function Pill({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center rounded-full border border-slate-200 bg-white px-2 py-0.5 text-xs font-medium capitalize text-slate-600">
      {label}
    </span>
  );
}

function PillGroup({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="mt-3">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
        {label}
      </p>
      <div className="mt-2 flex flex-wrap gap-2">
        {items.length === 0 ? (
          <span className="text-xs text-slate-500">None</span>
        ) : (
          items.map((item) => (
            <span
              key={item}
              className="inline-flex items-center rounded-full border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium capitalize text-slate-700"
            >
              {item.replace(/[_-]+/g, " ")}
            </span>
          ))
        )}
      </div>
    </div>
  );
}

function DetailLine({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="flex flex-wrap items-baseline gap-x-2 text-xs text-slate-600">
      <span className="font-medium text-slate-500">{label}:</span>
      <span className="text-slate-700">{value}</span>
    </div>
  );
}

function StatementFlagBadge({
  label,
  enabled,
}: {
  label: string;
  enabled: boolean;
}) {
  return (
    <span
      className={[
        "inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium",
        enabled
          ? "border-emerald-200 bg-emerald-50 text-emerald-700"
          : "border-slate-200 bg-white text-slate-600",
      ].join(" ")}
    >
      {label}: {enabled ? "Enabled" : "Disabled"}
    </span>
  );
}

function TemplateBlock({ template }: { template: ClientTransparencyTemplate }) {
  const sectionHeadings =
    template.default_sections?.sections?.map((s) => s.heading) ?? [];
  return (
    <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h3 className="text-sm font-semibold text-slate-900">{template.title}</h3>
        <StatusBadge value={template.is_active ? "active" : "inactive"} />
      </div>
      <p className="mt-2 text-sm leading-6 text-slate-600">{template.summary}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        <Pill label={`v${template.template_version}`} />
        <Pill label={`Slug: ${template.template_slug}`} />
      </div>
      {sectionHeadings.length > 0 ? (
        <PillGroup label="Default section headings" items={sectionHeadings} />
      ) : null}
      <PillGroup
        label="Default permitted categories"
        items={template.default_permitted_categories}
      />
      <PillGroup
        label="Default prohibited categories"
        items={template.default_prohibited_categories}
      />
      {template.rcvs_principle_mappings.length > 0 ? (
        <PillGroup label="RCVS mappings" items={template.rcvs_principle_mappings} />
      ) : null}
      {template.eu_ai_act_article_mappings.length > 0 ? (
        <PillGroup
          label="AI Act article mappings"
          items={template.eu_ai_act_article_mappings}
        />
      ) : null}
    </div>
  );
}

function ProfileSummaryBlock({
  profile,
  highlight,
}: {
  profile: ClientTransparencyProfile;
  highlight?: boolean;
}) {
  return (
    <div
      className={[
        "rounded-xl border p-4",
        highlight
          ? "border-emerald-200 bg-emerald-50"
          : "border-slate-200 bg-white",
      ].join(" ")}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-semibold text-slate-900">
            {profile.display_title}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            Profile v{profile.clinic_profile_version} - template v
            {profile.template_version_snapshot}
          </p>
        </div>
        <StatusBadge value={profile.status} />
      </div>
      <p className="mt-2 text-sm leading-6 text-slate-700">
        {profile.plain_language_summary}
      </p>
      <div className="mt-3 grid gap-1 sm:grid-cols-2">
        <DetailLine label="Created" value={formatDateTime(profile.created_at)} />
        <DetailLine label="Updated" value={formatDateTime(profile.updated_at)} />
        <DetailLine
          label="Activated"
          value={formatDateTime(profile.activated_at)}
        />
        <DetailLine
          label="Superseded"
          value={formatDateTime(profile.superseded_at)}
        />
        <DetailLine
          label="Permitted categories"
          value={String(profile.permitted_use_categories.length)}
        />
        <DetailLine
          label="Prohibited categories"
          value={String(profile.prohibited_use_categories.length)}
        />
      </div>
      <PillGroup
        label="Permitted use categories"
        items={profile.permitted_use_categories}
      />
      <PillGroup
        label="Prohibited use categories"
        items={profile.prohibited_use_categories}
      />
      <div className="mt-3 flex flex-wrap gap-2">
        <StatementFlagBadge
          label="Human review statement"
          enabled={profile.human_review_statement_enabled}
        />
        <StatementFlagBadge
          label="Privacy statement"
          enabled={profile.privacy_statement_enabled}
        />
        <StatementFlagBadge
          label="Client explanation statement"
          enabled={profile.client_explanation_statement_enabled}
        />
      </div>
    </div>
  );
}

function DraftFormFields({
  form,
  template,
  onChange,
  disabled,
  idPrefix,
}: {
  form: DraftFormState;
  template: ClientTransparencyTemplate;
  onChange: (next: DraftFormState) => void;
  disabled: boolean;
  idPrefix: string;
}) {
  const titleId = `${idPrefix}-title`;
  const summaryId = `${idPrefix}-summary`;
  const permittedOptions = template.default_permitted_categories;
  const prohibitedOptions = template.default_prohibited_categories;

  function togglePermitted(value: string) {
    const present = form.permitted.includes(value);
    onChange({
      ...form,
      permitted: present
        ? form.permitted.filter((v) => v !== value)
        : [...form.permitted, value],
    });
  }
  function toggleProhibited(value: string) {
    const present = form.prohibited.includes(value);
    onChange({
      ...form,
      prohibited: present
        ? form.prohibited.filter((v) => v !== value)
        : [...form.prohibited, value],
    });
  }

  return (
    <div className="space-y-4">
      <div>
        <label
          htmlFor={titleId}
          className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500"
        >
          Display title
        </label>
        <input
          id={titleId}
          type="text"
          value={form.displayTitle}
          onChange={(e) => onChange({ ...form, displayTitle: e.target.value })}
          disabled={disabled}
          className="mt-1 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm focus:border-slate-400 focus:outline-none"
        />
      </div>

      <div>
        <label
          htmlFor={summaryId}
          className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500"
        >
          Plain-language summary
        </label>
        <textarea
          id={summaryId}
          value={form.plainLanguageSummary}
          onChange={(e) =>
            onChange({ ...form, plainLanguageSummary: e.target.value })
          }
          disabled={disabled}
          rows={6}
          className="mt-1 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 shadow-sm focus:border-slate-400 focus:outline-none"
        />
        <p className="mt-1 text-xs text-slate-500">
          Avoid client or patient identifiers, case-specific content, and
          clinical findings.
        </p>
      </div>

      <fieldset>
        <legend className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Permitted use categories
        </legend>
        <div className="mt-2 flex flex-wrap gap-2">
          {permittedOptions.map((opt) => {
            const checked = form.permitted.includes(opt);
            return (
              <label
                key={opt}
                className={[
                  "inline-flex cursor-pointer items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium transition",
                  checked
                    ? "border-slate-900 bg-slate-900 text-white"
                    : "border-slate-200 bg-white text-slate-700 hover:border-slate-300",
                  disabled ? "cursor-not-allowed opacity-60" : "",
                ].join(" ")}
              >
                <input
                  type="checkbox"
                  className="sr-only"
                  checked={checked}
                  disabled={disabled}
                  onChange={() => togglePermitted(opt)}
                />
                {formatTag(opt)}
              </label>
            );
          })}
        </div>
      </fieldset>

      <fieldset>
        <legend className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Prohibited use categories
        </legend>
        <div className="mt-2 flex flex-wrap gap-2">
          {prohibitedOptions.map((opt) => {
            const checked = form.prohibited.includes(opt);
            return (
              <label
                key={opt}
                className={[
                  "inline-flex cursor-pointer items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium transition",
                  checked
                    ? "border-slate-900 bg-white text-slate-900"
                    : "border-slate-200 bg-white text-slate-600 hover:border-slate-300",
                  disabled ? "cursor-not-allowed opacity-60" : "",
                ].join(" ")}
              >
                <input
                  type="checkbox"
                  className="h-3.5 w-3.5"
                  checked={checked}
                  disabled={disabled}
                  onChange={() => toggleProhibited(opt)}
                />
                {formatTag(opt)}
              </label>
            );
          })}
        </div>
      </fieldset>

      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
          Statement flags
        </p>
        <div className="mt-2 flex flex-wrap gap-2">
          <StatementFlagBadge label="Human review statement" enabled />
          <StatementFlagBadge label="Privacy statement" enabled />
          <StatementFlagBadge label="Client explanation statement" enabled />
        </div>
        <p className="mt-1 text-xs text-slate-500">
          These statement flags are locked enabled for this template.
        </p>
      </div>
    </div>
  );
}
