import { AppShell } from "@/components/shell/AppShell";
import { SelfAssessmentAdminPage } from "@/components/self-assessment/SelfAssessmentAdminPage";

export default function SelfAssessmentRoute() {
  return (
    <AppShell>
      <SelfAssessmentAdminPage />
    </AppShell>
  );
}
