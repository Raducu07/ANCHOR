import { AppShell } from "@/components/shell/AppShell";
import { GovernancePolicyAdminPage } from "@/components/policies/GovernancePolicyAdminPage";

export default function PoliciesRoute() {
  return (
    <AppShell>
      <GovernancePolicyAdminPage />
    </AppShell>
  );
}
