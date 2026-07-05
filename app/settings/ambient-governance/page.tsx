import { AppShell } from "@/components/shell/AppShell";
import { AmbientGovernanceSurface } from "@/components/ambient/AmbientGovernanceSurface";

export default function AmbientGovernanceRoute() {
  return (
    <AppShell>
      <AmbientGovernanceSurface />
    </AppShell>
  );
}
