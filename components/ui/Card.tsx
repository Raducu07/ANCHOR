import type { HTMLAttributes, ReactNode } from "react";

type CardVariant = "default" | "native";

type CardProps = HTMLAttributes<HTMLDivElement> & {
  children?: ReactNode;
  variant?: CardVariant;
};

const VARIANT_CLASS: Record<CardVariant, string> = {
  default:
    "rounded-3xl border border-slate-200/80 bg-white/90 p-6 shadow-[0_8px_30px_rgba(15,23,42,0.04)] backdrop-blur-sm",
  native:
    "rounded-xl border border-slate-200/80 bg-white p-8 shadow-[0_18px_40px_rgba(42,52,57,0.07)]",
};

export function Card({
  children,
  className = "",
  variant = "default",
  ...props
}: CardProps) {
  return (
    <div className={[VARIANT_CLASS[variant], className].join(" ")} {...props}>
      {children}
    </div>
  );
}
