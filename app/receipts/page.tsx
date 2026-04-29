import { AppShell } from "@/components/shell/AppShell";
import { ReceiptsPage } from "@/components/receipts/ReceiptsPage";

type ReceiptsRouteProps = {
  searchParams: Promise<{
    request_id?: string | string[];
  }>;
};

export default async function ReceiptsRoute({ searchParams }: ReceiptsRouteProps) {
  const params = await searchParams;
  const requestIdParam = params.request_id;
  const requestId = typeof requestIdParam === "string" ? requestIdParam : "";

  return (
    <AppShell>
      <ReceiptsPage initialRequestId={requestId} />
    </AppShell>
  );
}