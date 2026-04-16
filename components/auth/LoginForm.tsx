"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { apiFetch, ApiError } from "@/lib/api";
import { buildSessionFromLoginResponse, getAccessToken, saveAuthState } from "@/lib/auth";
import type { LoginResponse } from "@/lib/types";

export function LoginForm() {
  const router = useRouter();
  const [clinicSlug, setClinicSlug] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (getAccessToken()) {
      router.replace("/workspace-live");
    }
  }, [router]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await apiFetch<LoginResponse>("/v1/clinic/auth/login", {
        method: "POST",
        auth: false,
        body: JSON.stringify({
          clinic_slug: clinicSlug.trim(),
          email: email.trim(),
          password,
        }),
      });

      const session = buildSessionFromLoginResponse(
        response,
        clinicSlug.trim(),
        email.trim()
      );

      saveAuthState(session.token, session.user);
      router.replace("/workspace-live");
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("ANCHOR is temporarily unavailable. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="rounded-3xl p-8 shadow-sm">
      <div className="space-y-2">
        <h2 className="text-2xl font-semibold tracking-tight text-slate-900">
          Secure clinic access
        </h2>
        <p className="text-sm leading-6 text-slate-600">
          Sign in to your clinic-scoped governance workspace.
        </p>
      </div>

      <form className="mt-8 space-y-4" onSubmit={handleSubmit}>
        <Input
          label="Clinic slug"
          placeholder="your-clinic"
          value={clinicSlug}
          onChange={(event) => setClinicSlug(event.target.value)}
          autoComplete="organization"
          required
        />
        <Input
          label="Email"
          type="email"
          placeholder="name@clinic.com"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          autoComplete="email"
          required
        />
        <Input
          label="Password"
          type="password"
          placeholder="Enter your password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoComplete="current-password"
          required
        />

        {error ? (
          <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {error}
          </div>
        ) : null}

        <Button type="submit" className="w-full" loading={loading} disabled={loading}>
          Sign in
        </Button>
      </form>

      <div className="mt-6 space-y-2 text-sm text-slate-500">
        <p>Having trouble signing in? Contact your clinic administrator.</p>
        <p>Access is clinic-scoped and activity is governed through metadata-only oversight.</p>
      </div>
    </Card>
  );
}