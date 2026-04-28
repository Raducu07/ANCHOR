import type { ReceiptPayload } from "@/lib/types";
import { safeText } from "@/lib/receipts/formatters";

export function exportReceiptAsJson(receipt: ReceiptPayload): void {
  const blob = new Blob([JSON.stringify({ receipt }, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `anchor-receipt-${safeText(receipt.request_id, "selected")}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}
