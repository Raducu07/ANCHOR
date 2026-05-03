"use client";

import { marketingTertiaryButtonClass } from "@/components/marketing/MarketingShell";

export function OpenAssistantButton({
  className = "",
  label = "Ask about ANCHOR",
}: {
  className?: string;
  label?: string;
}) {
  return (
    <button
      type="button"
      onClick={() => window.dispatchEvent(new CustomEvent("anchor-assistant:open"))}
      className={marketingTertiaryButtonClass(className)}
    >
      {label}
    </button>
  );
}
