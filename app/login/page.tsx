import { LoginForm } from "@/components/auth/LoginForm";

export default function LoginPage() {
  return (
    <main className="min-h-screen bg-slate-50">
      <div className="mx-auto grid min-h-screen max-w-7xl grid-cols-1 lg:grid-cols-2">
        <section className="flex items-center border-b border-slate-200 px-6 py-12 lg:border-b-0 lg:border-r lg:px-12 xl:px-16">
          <div className="max-w-xl space-y-8">
            <div className="space-y-4">
              <div className="inline-flex items-center rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-medium uppercase tracking-[0.18em] text-slate-600">
                ANCHOR
              </div>
              <h1 className="text-3xl font-semibold tracking-tight text-slate-900 sm:text-4xl">
                Clinic governance workspace
              </h1>
              <p className="max-w-lg text-base leading-7 text-slate-600">
                Governance, trust, and learning infrastructure for safe AI use in veterinary clinics.
              </p>
            </div>

            <div className="grid gap-4 sm:grid-cols-3">
              <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                <p className="text-sm font-medium text-slate-900">Metadata-only governance</p>
                <p className="mt-2 text-sm leading-6 text-slate-600">
                  Oversight without storing raw prompts or outputs.
                </p>
              </div>
              <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                <p className="text-sm font-medium text-slate-900">Tenant-isolated access</p>
                <p className="mt-2 text-sm leading-6 text-slate-600">
                  Clinic-scoped workspaces with hardened backend controls.
                </p>
              </div>
              <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                <p className="text-sm font-medium text-slate-900">Audit-friendly receipts</p>
                <p className="mt-2 text-sm leading-6 text-slate-600">
                  Trust surfaces built for operational review and accountability.
                </p>
              </div>
            </div>
          </div>
        </section>

        <section className="flex items-center justify-center px-6 py-12 lg:px-12 xl:px-16">
          <div className="w-full max-w-md">
            <LoginForm />
          </div>
        </section>
      </div>
    </main>
  );
}
