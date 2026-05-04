"use client";

import { useEffect } from "react";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";

export function AdminLoginForm({ initialError }: { initialError?: string | null }) {
  useEffect(() => {
    if (!initialError) return;

    void fetch("/api/ops/admin-flash", {
      method: "POST",
    });
  }, [initialError]);

  return (
    <Card className="rounded-[2rem] p-8">
      <h2 className="text-xl font-semibold text-slate-900">Internal admin access</h2>
      <p className="mt-2 text-sm leading-6 text-slate-600">
        This page is for internal ANCHOR operations access only.
      </p>

      <form className="mt-8 space-y-6" action="/api/ops/admin-session" method="post">
        <Input
          label="Admin token"
          name="token"
          type="password"
          autoComplete="current-password"
          placeholder="Enter internal admin token"
          required
        />

        {initialError ? (
          <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {initialError}
          </div>
        ) : null}

        <Button type="submit" className="w-full">
          Verify admin session
        </Button>
      </form>
    </Card>
  );
}
