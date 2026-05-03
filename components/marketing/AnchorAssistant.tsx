"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { answerAnchorQuestion } from "@/lib/anchorAssistant";
import { anchorAssistantQuickPrompts } from "@/lib/anchorAssistantContent";

type ChatMessage = {
  role: "user" | "assistant";
  text: string;
  cta?: {
    label: string;
    href: string;
  };
};

export function AnchorAssistant() {
  const [open, setOpen] = useState(false);
  const [question, setQuestion] = useState("");
  const [nearFooter, setNearFooter] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      text: "Ask about ANCHOR's governed workflows, trust surfaces, onboarding, or product boundaries.",
    },
  ]);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const footer = document.querySelector("footer");
    if (!footer) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        setNearFooter(entry.isIntersecting);
      },
      {
        rootMargin: "0px 0px 140px 0px",
      }
    );

    observer.observe(footer);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    function handleOpenAssistant() {
      setOpen(true);
    }

    window.addEventListener("anchor-assistant:open", handleOpenAssistant);
    return () => window.removeEventListener("anchor-assistant:open", handleOpenAssistant);
  }, []);

  useEffect(() => {
    if (!open) return;

    messagesEndRef.current?.scrollIntoView({
      behavior: "smooth",
      block: "end",
    });
  }, [messages, open]);

  function submitQuestion(rawQuestion: string) {
    const trimmed = rawQuestion.trim();
    if (!trimmed) return;

    const reply = answerAnchorQuestion(trimmed);

    setMessages((current) => [
      ...current,
      { role: "user", text: trimmed },
      { role: "assistant", text: reply.answer, cta: reply.suggestedCta },
    ]);
    setQuestion("");
  }

  return (
    <div
      className={[
        "fixed z-[60]",
        open
          ? "w-[min(21.5rem,calc(100vw-1.5rem))] sm:w-[min(23rem,calc(100vw-2rem))]"
          : "w-auto",
      ].join(" ")}
      style={{
        right: "max(0.75rem, calc((100vw - 80rem) / 2 + 2rem))",
        bottom: nearFooter ? "9.75rem" : "2rem",
      }}
    >
      {open ? (
        <div className="overflow-hidden rounded-[1.75rem] border border-slate-200/90 bg-white shadow-[0_24px_80px_rgba(15,23,42,0.12)] ring-1 ring-slate-950/5">
          <div className="flex items-center justify-between border-b border-slate-200 bg-slate-950 px-5 py-3.5 text-white">
            <div>
              <p className="text-sm font-semibold tracking-[0.01em]">Ask about ANCHOR</p>
              <p className="mt-1 text-[11px] uppercase tracking-[0.16em] text-slate-300/90">
                Grounded product guidance only
              </p>
            </div>
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="rounded-full border border-white/12 bg-white/5 px-3 py-1 text-[11px] font-medium uppercase tracking-[0.14em] text-white/90 transition hover:bg-white/10"
            >
              Close
            </button>
          </div>

          <div className="max-h-[25rem] space-y-4 overflow-y-auto px-5 py-4">
            <div className="flex flex-wrap gap-2">
              {anchorAssistantQuickPrompts.map((prompt) => (
                <button
                  key={prompt}
                  type="button"
                  onClick={() => submitQuestion(prompt)}
                  className="rounded-full border border-slate-200/80 bg-slate-50/80 px-2.5 py-1 text-[11px] font-medium text-slate-700 transition hover:bg-slate-100"
                >
                  {prompt}
                </button>
              ))}
            </div>

            {messages.map((message, index) => (
              <div
                key={`${message.role}-${index}`}
                className={message.role === "assistant" ? "mr-8" : "ml-8"}
              >
                <div
                  className={[
                    "rounded-2xl px-4 py-3 text-sm leading-6 shadow-sm",
                    message.role === "assistant"
                      ? "border border-slate-200 bg-slate-50/90 text-slate-700"
                      : "bg-slate-950 text-white",
                  ].join(" ")}
                >
                  {message.text}
                </div>
                {message.cta ? (
                  <Link
                    href={message.cta.href}
                    className="mt-2 inline-flex text-xs font-semibold text-slate-700 underline decoration-slate-300 underline-offset-4"
                  >
                    {message.cta.label}
                  </Link>
                ) : null}
              </div>
            ))}
            <div ref={messagesEndRef} />
          </div>

          <form
            className="border-t border-slate-200 px-5 py-4"
            onSubmit={(event) => {
              event.preventDefault();
              submitQuestion(question);
            }}
          >
            <label className="sr-only" htmlFor="anchor-assistant-question">
              Ask about ANCHOR
            </label>
            <textarea
              id="anchor-assistant-question"
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              placeholder="Ask about ANCHOR's workflow, trust surfaces, or onboarding..."
              className="min-h-[84px] w-full resize-none rounded-2xl border border-slate-300 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm transition placeholder:text-slate-400 focus:border-slate-400"
            />
            <div className="mt-3 flex items-center justify-between gap-3">
              <p className="text-xs leading-5 text-slate-500">
                This assistant answers product questions about ANCHOR only.
              </p>
              <button
                type="submit"
                className="inline-flex items-center justify-center rounded-xl bg-slate-950 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-slate-800"
              >
                Ask
              </button>
            </div>
          </form>
        </div>
      ) : (
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="inline-flex h-9 items-center justify-center rounded-full border border-slate-800/60 bg-slate-950/95 px-3 text-xs font-semibold text-white shadow-[0_8px_18px_rgba(15,23,42,0.18)] transition hover:bg-slate-900"
        >
          Ask ANCHOR
        </button>
      )}
    </div>
  );
}
