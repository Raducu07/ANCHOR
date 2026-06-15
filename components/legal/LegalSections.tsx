import type { LegalSection } from "@/lib/legal/legalContent";

// Renders an array of legal content sections using the same calm markup as the
// registry-backed /legal/[slug] pages, so Slice 2 pages stay visually consistent.
export function LegalSections({ sections }: { sections: LegalSection[] }) {
  return (
    <>
      {sections.map((section) => (
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
    </>
  );
}
