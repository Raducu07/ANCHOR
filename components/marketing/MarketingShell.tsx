import Link from "next/link";
import type { ReactNode } from "react";
import { AnchorAssistant } from "@/components/marketing/AnchorAssistant";

export function MarketingShell({
  children,
  primaryCtaHref = "/#workflow",
  primaryCtaLabel = "See the workflow",
}: {
  children: ReactNode;
  primaryCtaHref?: string;
  primaryCtaLabel?: string;
}) {
  return (
    <main className="min-h-screen bg-slate-50 text-slate-800">
      <header className="fixed inset-x-0 top-0 z-50 border-b border-slate-200 bg-white/90 backdrop-blur-md">
        <div className="mx-auto flex h-20 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          <Link href="/" className="text-2xl font-extrabold tracking-tight text-slate-950">
            ANCHOR
          </Link>

          <nav className="hidden items-center gap-8 md:flex">
            <Link className="text-sm font-medium text-slate-600 transition-colors hover:text-slate-950" href="/#workflow">
              How it works
            </Link>
            <Link className="text-sm font-medium text-slate-600 transition-colors hover:text-slate-950" href="/#platform">
              Platform
            </Link>
            <Link className="text-sm font-medium text-slate-600 transition-colors hover:text-slate-950" href="/#trust">
              Trust
            </Link>
            <Link className="text-sm font-medium text-slate-600 transition-colors hover:text-slate-950" href="/#boundaries">
              Boundaries
            </Link>
          </nav>

          <div className="flex items-center gap-3 sm:gap-4">
            <Link href="/login" className="hidden text-sm font-medium text-slate-600 transition-colors hover:text-slate-950 sm:block">
              Sign In
            </Link>
            <Link href={primaryCtaHref} className={marketingPrimaryButtonClass("px-5 py-2.5 text-sm")}>
              {primaryCtaLabel}
            </Link>
          </div>
        </div>
      </header>

      <div className="pt-20">{children}</div>

      <footer className="border-t border-slate-200 bg-slate-50 px-4 py-12 sm:px-6 lg:px-8">
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-6 md:flex-row">
          <div className="text-xl font-bold tracking-tight text-slate-950">ANCHOR</div>
          <div className="text-sm text-slate-500">Copyright 2026 ANCHOR Veterinary Governance. All rights reserved.</div></div>
      </footer>

      <AnchorAssistant />
    </main>
  );
}

export function SectionHeading({
  eyebrow,
  title,
  body,
  align = "left",
}: {
  eyebrow?: string;
  title: string;
  body?: string;
  align?: "left" | "center";
}) {
  return (
    <div className={align === "center" ? "mx-auto max-w-3xl text-center" : "max-w-3xl"}>
      {eyebrow ? (
        <p className="mb-3 text-sm font-bold uppercase tracking-[0.2em] text-slate-500">{eyebrow}</p>
      ) : null}
      <h1 className="text-4xl font-bold tracking-tight text-slate-950 md:text-5xl">{title}</h1>
      {body ? <p className="mt-4 whitespace-pre-line text-lg leading-8 text-slate-600">{body}</p> : null}
    </div>
  );
}

export function marketingPrimaryButtonClass(extraClassName = "") {
  return [
    "inline-flex items-center justify-center rounded-xl bg-slate-950 font-semibold text-white shadow-sm transition-colors hover:bg-slate-800",
    extraClassName,
  ].join(" ");
}

export function marketingSecondaryButtonClass(extraClassName = "") {
  return [
    "inline-flex items-center justify-center rounded-xl border border-slate-200 bg-white font-semibold text-slate-700 shadow-sm transition-colors hover:bg-slate-50",
    extraClassName,
  ].join(" ");
}

export function marketingTertiaryButtonClass(extraClassName = "") {
  return [
    "inline-flex items-center justify-center rounded-xl border border-slate-200/70 bg-white/80 font-semibold text-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.04)] transition-colors hover:border-slate-300 hover:bg-slate-50 hover:text-slate-700",
    extraClassName,
  ].join(" ");
}
