import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { getOpsAdminSessionToken, verifyOpsAdminToken } from "@/lib/opsIntake";
import { OpsIntakeClient } from "@/components/ops/OpsIntakeClient";

export const metadata: Metadata = {
  title: "ANCHOR | Ops intake (read-only)",
  robots: { index: false, follow: false },
};

export default async function OpsIntakePage() {
  const token = await getOpsAdminSessionToken();

  if (!token) {
    redirect("/ops/admin-login");
  }

  const verification = await verifyOpsAdminToken(token);
  if (!verification.ok && verification.reason === "invalid") {
    redirect("/ops/admin-login");
  }

  return <OpsIntakeClient />;
}
