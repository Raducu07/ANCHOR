import { AppShell } from "@/components/shell/AppShell";
import { ClientTransparencyAdminPage } from "@/components/client-transparency/ClientTransparencyAdminPage";

export default function ClientTransparencyRoute() {
  return (
    <AppShell>
      <ClientTransparencyAdminPage />
    </AppShell>
  );
}
