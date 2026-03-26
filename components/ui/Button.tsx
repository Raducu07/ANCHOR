import type { ButtonHTMLAttributes, ReactNode } from "react";

type ButtonVariant = "primary" | "secondary" | "ghost";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  children: ReactNode;
  variant?: ButtonVariant;
  loading?: boolean;
};

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

  const variantClass =
    variant === "secondary"
      ? "bg-white text-slate-900 border border-slate-300 hover:bg-slate-50"
      : variant === "ghost"
        ? "bg-transparent text-slate-700 border border-transparent hover:bg-slate-100"
        : "bg-slate-900 text-white border border-slate-900 hover:bg-slate-800";

  return (
    <button
      type={type}
      disabled={isDisabled}
      className={[
        "inline-flex items-center justify-center rounded-2xl px-4 py-2.5 text-sm font-medium transition",
        "disabled:cursor-not-allowed disabled:opacity-60",
        variantClass,
        className,
      ].join(" ")}
      {...props}
    >
      {loading ? "Working..." : children}
    </button>
  );
}