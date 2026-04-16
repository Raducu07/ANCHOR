"use client";

import Link from "next/link";
import type { ButtonHTMLAttributes, ReactNode } from "react";

function cn(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(" ");
}

type Tone = "neutral" | "indigo" | "success" | "warning" | "danger";

const toneClassMap: Record<Tone, string> = {
  neutral: "border-[#ddd7ef]/70 bg-[#f7f5fc] text-[#5f5782]",
  indigo: "border-[#d7cdf7]/80 bg-[#f3effb] text-[#4f44e2]",
  success: "border-[#cfead8]/80 bg-[#f4fbf6] text-[#1f7a45]",
  warning: "border-[#f1dfb8]/80 bg-[#fffaf1] text-[#9a6400]",
  danger: "border-[#f1d3d8]/80 bg-[#fff7f8] text-[#b6475f]",
};

export function AnchorPageContainer({ children }: { children: ReactNode }) {
  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(79,68,226,0.06),_transparent_34%),#f8f9fc] text-[#191c1e]">
      <div className="mx-auto max-w-7xl px-6 py-8 md:px-8 lg:px-10">
        {children}
      </div>
    </main>
  );
}

export function AnchorHero({
  badges,
  title,
  description,
  stats,
  actions,
}: {
  badges?: string[];
  title: string;
  description: string;
  stats?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className="overflow-hidden rounded-lg border border-[#c7c5d3]/15 bg-[linear-gradient(135deg,#4f44e2_0%,#6b63ef_38%,#9490ff_100%)] shadow-[0_12px_40px_rgba(79,68,226,0.06)]">
      <div className="bg-[linear-gradient(180deg,rgba(255,255,255,0.10),rgba(255,255,255,0.04))] px-8 py-8 text-white md:px-10 md:py-10">
        <div className="flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-4xl">
            {badges?.length ? (
              <div className="mb-4 flex flex-wrap gap-2">
                {badges.map((badge) => (
                  <AnchorHeroPill key={badge}>{badge}</AnchorHeroPill>
                ))}
              </div>
            ) : null}

            <h1 className="max-w-4xl font-headline text-3xl font-extrabold leading-tight tracking-[-0.02em] text-white md:text-5xl">
              {title}
            </h1>

            <p className="mt-4 max-w-3xl text-sm leading-6 text-white/95 md:text-base">
              {description}
            </p>

            {actions ? <div className="mt-6 flex flex-wrap gap-3">{actions}</div> : null}
          </div>

          {stats ? (
            <div className="grid gap-4 sm:grid-cols-3 lg:min-w-[540px]">{stats}</div>
          ) : null}
        </div>
      </div>
    </section>
  );
}

export function AnchorHeroPill({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex rounded-full border border-white/25 bg-white/14 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.08em] text-white">
      {children}
    </span>
  );
}

export function AnchorHeroStat({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: string;
  tone?: Tone;
}) {
  const background =
    tone === "neutral"
      ? "border-white/20 bg-white/96 text-[#191c1e]"
      : tone === "indigo"
        ? "border-[#e8e1fb]/90 bg-white/96 text-[#191c1e]"
        : tone === "success"
          ? "border-[#dcefe2]/90 bg-white/96 text-[#191c1e]"
          : tone === "warning"
            ? "border-[#f3e5c4]/90 bg-white/96 text-[#191c1e]"
            : "border-[#f2dde1]/90 bg-white/96 text-[#191c1e]";

  return (
    <div
      className={cn(
        "rounded px-7 py-5 shadow-[0_8px_20px_rgba(16,12,40,0.04)] backdrop-blur-sm",
        "border",
        background
      )}
    >
      <div className="text-[11px] font-semibold uppercase tracking-[0.04em] text-[#575072]">
        {label}
      </div>
      <div className="mt-1.5 text-[16px] font-semibold leading-6 text-[#191c1e]">
        {value}
      </div>
    </div>
  );
}

export function AnchorSectionCard({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "rounded-lg bg-white p-7 shadow-[0_12px_40px_rgba(79,68,226,0.06)]",
        "border border-[#c7c5d3]/15",
        className
      )}
    >
      {children}
    </div>
  );
}

export function AnchorSectionHeader({
  step,
  title,
  description,
}: {
  step?: string;
  title: string;
  description?: string;
}) {
  return (
    <div>
      {step ? (
        <div className="text-[12px] font-semibold uppercase tracking-[0.04em] text-[#4f44e2]">
          Step {step}
        </div>
      ) : null}
      <h2 className="mt-2 font-headline text-xl font-extrabold leading-7 tracking-[-0.01em] text-[#191c1e]">
        {title}
      </h2>
      {description ? (
        <p className="mt-2 text-sm leading-6 text-[#4f486e]">{description}</p>
      ) : null}
    </div>
  );
}

export function AnchorFieldLabel({ children }: { children: ReactNode }) {
  return (
    <div className="text-sm font-semibold uppercase tracking-[0.04em] text-[#4f44e2]">
      {children}
    </div>
  );
}

export function AnchorSmallBadge({ children }: { children: ReactNode }) {
  return (
    <span className="rounded-full border border-[#c7c5d3]/20 bg-[#fbfaff] px-3 py-1 text-xs font-medium text-[#4f486e]">
      {children}
    </span>
  );
}

export function AnchorContextTag({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: Tone;
}) {
  return (
    <span
      className={cn(
        "inline-flex rounded-full border px-3.5 py-1 text-[11px] font-medium tracking-[0.02em]",
        toneClassMap[tone]
      )}
    >
      {children}
    </span>
  );
}

export function AnchorSelectableCard({
  active,
  onClick,
  title,
  description,
}: {
  active: boolean;
  onClick: () => void;
  title: string;
  description: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "rounded border px-7 py-4 text-left transition-all",
        active
          ? "border-[#9490ff]/45 bg-[#f6f2fd] shadow-[0_10px_24px_rgba(108,84,234,0.05)]"
          : "border-[#c7c5d3]/20 bg-white hover:bg-[#fbfaff]"
      )}
    >
      <div className="text-sm font-semibold leading-6 text-[#191c1e]">{title}</div>
      <div className="mt-1 text-[13px] leading-5 text-[#4f486e]">{description}</div>
    </button>
  );
}

export function AnchorStatusPill({
  children,
  tone = "neutral",
  className,
}: {
  children: ReactNode;
  tone?: Tone;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "rounded-full border px-3.5 py-1 text-[11px] font-semibold uppercase tracking-[0.03em]",
        toneClassMap[tone],
        className
      )}
    >
      {children}
    </span>
  );
}

export function AnchorMetric({
  label,
  value,
  helper,
}: {
  label: string;
  value: string | number;
  helper?: string;
}) {
  return (
    <div className="rounded border border-[#c7c5d3]/20 bg-[#fbfaff] px-6 py-4">
      <div className="text-xs font-semibold uppercase tracking-[0.04em] text-[#615a82]">
        {label}
      </div>
      <div className="mt-1.5 text-sm font-medium leading-6 text-[#191c1e]">{value}</div>
      {helper ? <div className="mt-2 text-xs leading-5 text-[#4f486e]">{helper}</div> : null}
    </div>
  );
}

export function AnchorSoftPanel({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "rounded border border-[#c7c5d3]/20 bg-[#fbfaff] px-6 py-5",
        className
      )}
    >
      {children}
    </div>
  );
}

export function AnchorDetail({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-4 border-b border-[#c7c5d3]/15 pb-4 last:border-b-0 last:pb-0">
      <dt className="text-sm text-[#615a82]">{label}</dt>
      <dd className="text-sm text-[#191c1e]">{value}</dd>
    </div>
  );
}

export function AnchorActionLink({
  href,
  children,
}: {
  href: string;
  children: ReactNode;
}) {
  return (
    <Link
      href={href}
      className="rounded border border-[#c7c5d3]/20 bg-white px-5 py-3 text-sm font-medium text-[#221a4c] transition hover:bg-[#fbfaff]"
    >
      {children}
    </Link>
  );
}

export function AnchorQuickLink({
  href,
  title,
  description,
}: {
  href: string;
  title: string;
  description: string;
}) {
  return (
    <Link
      href={href}
      className="block rounded-lg border border-[#c7c5d3]/20 bg-[#fbfaff] px-6 py-4 transition hover:bg-white"
    >
      <p className="text-sm font-semibold leading-6 text-[#191c1e]">{title}</p>
      <p className="mt-1 text-sm leading-6 text-[#4f486e]">{description}</p>
    </Link>
  );
}

export function AnchorPrimaryButton({
  children,
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className={cn(
        "inline-flex min-h-[44px] min-w-[220px] items-center justify-center rounded bg-[linear-gradient(90deg,#4f44e2_0%,#9490ff_100%)] px-6 py-3 text-sm font-semibold text-white shadow-[0_12px_40px_rgba(79,68,226,0.12)] transition hover:opacity-95 disabled:cursor-not-allowed disabled:opacity-60",
        className
      )}
    >
      {children}
    </button>
  );
}

export function AnchorSecondaryButton({
  children,
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className={cn(
        "inline-flex min-h-[44px] min-w-[220px] items-center justify-center rounded bg-[#e7e8eb] px-6 py-3 text-sm font-semibold text-[#191c1e] transition hover:bg-[#e1e2e5] disabled:cursor-not-allowed disabled:opacity-60",
        className
      )}
    >
      {children}
    </button>
  );
}

export function AnchorEmptyState({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="rounded border border-dashed border-[#c7c5d3]/25 bg-[#fbfaff] px-5 py-3 text-sm text-[#4f486e]">
      <div className="font-medium text-[#191c1e]">{title}</div>
      <div className="mt-1 leading-6">{description}</div>
    </div>
  );
}