import { AppShell } from "@/components/shell/AppShell";
import { PolicyAttestationStatusPage } from "@/components/policies/PolicyAttestationStatusPage";

export default function PolicyAttestationsRoute() {
  return (
    <AppShell>
      <PolicyAttestationStatusPage />
    </AppShell>
  );
}
