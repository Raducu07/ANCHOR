import type { Metadata } from "next";
import { Card } from "@/components/ui/Card";
import { getOpsAdminFlashValue, getOpsAdminSessionToken, verifyOpsAdminToken } from "@/lib/opsIntake";
import { AdminLoginForm } from "@/components/ops/AdminLoginForm";

export const metadata: Metadata = {
  title: "ANCHOR | Internal admin access",
  robots: { index: false, follow: false },
};

function mapLoginError(value: string | null) {
  if (value === "invalid") {
    return "That internal admin token was not accepted.";
  }

  if (value === "missing") {
    return "Enter the internal admin token.";
  }

  if (value === "unavailable") {
    return "Unable to continue to intake operations right now.";
  }

  if (value === "rate_limited") {
    return "Too many attempts. Try again later.";
  }

  return null;
}

type SearchParams = Record<string, string | string[] | undefined>;

export default async function OpsAdminLoginPage({
  searchParams,
}: {
  searchParams?: Promise<SearchParams>;
}) {
  await searchParams;

  const token = await getOpsAdminSessionToken();
  const flashValue = await getOpsAdminFlashValue();
  const initialError = mapLoginError(flashValue);

  let sessionActive = false;
  if (token) {
    const verification = await verifyOpsAdminToken(token);
    if (verification.ok) {
      sessionActive = true;
    }
  }

  const showVerified = sessionActive;

  return (
    <main className="min-h-screen bg-slate-50 px-4 py-16 text-slate-800 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-4xl">
        <div className="mb-10">
          <p className="text-sm font-bold uppercase tracking-[0.18em] text-slate-500">Internal access</p>
          <h1 className="mt-3 text-4xl font-bold tracking-tight text-slate-950">Internal admin access</h1>
          <p className="mt-4 max-w-2xl text-lg leading-8 text-slate-600">
            This page is for internal ANCHOR operations access only.
          </p>
        </div>

        <div className="grid gap-6 lg:grid-cols-[0.95fr_1.05fr]">
          <Card className="rounded-[2rem] p-8">
            <h2 className="text-xl font-semibold text-slate-900">What this access is for</h2>
            <div className="mt-6 space-y-3">
              {[
                "Verify your internal ANCHOR admin session.",
                "Sign in once to establish a short-lived, server-only admin cookie.",
                "Open the read-only ops intake viewer once your session is verified.",
              ].map((item) => (
                <div key={item} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4 text-sm font-medium text-slate-700">
                  {item}
                </div>
              ))}
            </div>
          </Card>

          {showVerified ? (
            <Card className="rounded-[2rem] p-8">
              <h2 className="text-xl font-semibold text-emerald-700">Session verified</h2>
              <p className="mt-3 text-sm leading-6 text-slate-700">
                Admin session is active. You can open the read-only intake viewer.
              </p>
              <a
                href="/ops/intake"
                className="mt-6 inline-flex items-center justify-center rounded-2xl bg-slate-900 px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-slate-800"
              >
                Open ops intake
              </a>
            </Card>
          ) : (
            <AdminLoginForm initialError={initialError} />
          )}
        </div>
      </div>
    </main>
  );
}
