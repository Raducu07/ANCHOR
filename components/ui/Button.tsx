import type { ButtonHTMLAttributes, ReactNode } from "react";

export type ButtonVariant = "primary" | "secondary" | "ghost";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  children: ReactNode;
  variant?: ButtonVariant;
  loading?: boolean;
};

const BUTTON_BASE_CLASS =
  "inline-flex items-center justify-center rounded-2xl px-4 py-2.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60";

const BUTTON_VARIANT_CLASSNAME: Record<ButtonVariant, string> = {
  primary:
    "border border-slate-900 bg-slate-900 text-white shadow-[0_18px_36px_rgba(15,23,42,0.12)] hover:border-slate-800 hover:bg-slate-800",
  secondary:
    "border border-slate-200 bg-white text-slate-900 shadow-[inset_0_1px_0_rgba(255,255,255,0.6)] hover:bg-slate-50",
  ghost: "border border-transparent bg-transparent text-slate-600 hover:bg-slate-100 hover:text-slate-900",
};

export function getButtonChromeClasses(variant: ButtonVariant = "primary") {
  return [BUTTON_BASE_CLASS, BUTTON_VARIANT_CLASSNAME[variant]].join(" ");
}

export function Button({
  children,
  variant = "primary",
  loading = false,
  disabled,
  className = "",
  type = "button",
  ...props
}: ButtonProps) {
  const isDisabled = disabled || loading;

  return (
    <button
      type={type}
      disabled={isDisabled}
      className={[
        getButtonChromeClasses(variant),
        className,
      ].join(" ")}
      {...props}
    >
      {loading ? "Working..." : children}
    </button>
  );
}
