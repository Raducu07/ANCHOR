import { AppShell } from "@/components/shell/AppShell";
import { ReceiptsPage } from "@/components/receipts/ReceiptsPage";

export default async function ReceiptsRoute(props: PageProps<"/receipts">) {
  const searchParams = await props.searchParams;
  const requestId = typeof searchParams.request_id === "string" ? searchParams.request_id : "";

  return (
    <AppShell>
      <ReceiptsPage initialRequestId={requestId} />
    </AppShell>
  );
}
