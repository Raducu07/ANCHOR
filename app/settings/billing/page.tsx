import { AppShell } from "@/components/shell/AppShell";
import { BillingFoundationsSurface } from "@/components/billing/BillingFoundationsSurface";

export default function BillingFoundationsRoute() {
  return (
    <AppShell>
      <BillingFoundationsSurface />
    </AppShell>
  );
}
