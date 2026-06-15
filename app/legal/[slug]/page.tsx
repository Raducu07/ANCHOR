import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { LegalPageShell } from "@/components/legal/LegalPageShell";
import { Card } from "@/components/ui/Card";
import { getLegalPage, listLegalPages } from "@/lib/legal/legalContent";

type PageProps = {
  params: Promise<{ slug: string }>;
};

export function generateStaticParams() {
  return listLegalPages().map((page) => ({ slug: page.slug }));
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { slug } = await params;
  const page = getLegalPage(slug);
  if (!page) {
    return {};
  }
  return {
    title: `${page.title} | ANCHOR Legal & Trust`,
    description: page.summary,
  };
}

export default async function LegalDocumentPage({ params }: PageProps) {
  const { slug } = await params;
  const page = getLegalPage(slug);
  if (!page) {
    notFound();
  }

  return (
    <LegalPageShell
      title={page.title}
      subtitle={page.subtitle}
      meta={{
        version: page.version,
        statusLabel: page.statusLabel,
        stage: page.stage,
        lastUpdated: page.lastUpdated,
      }}
    >
      <p className="text-base leading-7 text-slate-700">{page.summary}</p>

      {page.sections.map((section) => (
        <section key={section.heading} className="space-y-3">
          <h2 className="text-xl font-semibold text-slate-900">{section.heading}</h2>
          {section.body?.map((paragraph, index) => (
            <p key={index} className="text-sm leading-6 text-slate-600">
              {paragraph}
            </p>
          ))}
          {section.bullets ? (
            <ul className="space-y-2">
              {section.bullets.map((bullet) => (
                <li key={bullet} className="flex items-start text-sm leading-6 text-slate-600">
                  <span className="mr-3 mt-2 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-slate-400" />
                  <span>{bullet}</span>
                </li>
              ))}
            </ul>
          ) : null}
        </section>
      ))}

      {page.related && page.related.length > 0 ? (
        <Card variant="native" className="p-6">
          <h2 className="text-sm font-semibold uppercase tracking-[0.16em] text-slate-500">Related pages</h2>
          <div className="mt-4 flex flex-col gap-3">
            {page.related.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                className="block rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm font-semibold text-slate-900 transition hover:border-slate-300 hover:bg-white"
              >
                {link.label}
              </Link>
            ))}
          </div>
        </Card>
      ) : null}
    </LegalPageShell>
  );
}
