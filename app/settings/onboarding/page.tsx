import { AppShell } from "@/components/shell/AppShell";
import { OnboardingReadinessSurface } from "@/components/onboarding/OnboardingReadinessSurface";

export default function OnboardingSettingsRoute() {
  return (
    <AppShell>
      <OnboardingReadinessSurface />
    </AppShell>
  );
}
