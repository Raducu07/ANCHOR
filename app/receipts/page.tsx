import { AppShell } from "@/components/shell/AppShell";
import { ReceiptsPage } from "@/components/receipts/ReceiptsPage";

type ReceiptsRouteProps = {
  searchParams: Promise<{
    request_id?: string | string[];
    assistantRunId?: string | string[];
    assistantReceiptId?: string | string[];
  }>;
};

function firstString(value: string | string[] | undefined): string {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && typeof value[0] === "string") return value[0];
  return "";
}

export default async function ReceiptsRoute({ searchParams }: ReceiptsRouteProps) {
  const params = await searchParams;
  const requestId = firstString(params.request_id);
  const assistantRunId = firstString(params.assistantRunId);
  const assistantReceiptId = firstString(params.assistantReceiptId);

  return (
    <AppShell>
      <ReceiptsPage
        initialRequestId={requestId}
        initialAssistantRunId={assistantRunId}
        initialAssistantReceiptId={assistantReceiptId}
      />
    </AppShell>
  );
}