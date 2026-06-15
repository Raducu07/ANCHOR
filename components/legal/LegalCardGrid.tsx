import Link from "next/link";
import { Card } from "@/components/ui/Card";

export type LegalCardItem = {
  href: string;
  title: string;
  subtitle: string;
};

export function LegalCardGrid({ items }: { items: LegalCardItem[] }) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {items.map((item) => (
        <Link key={item.href} href={item.href} className="group block">
          <Card
            variant="native"
            className="h-full p-6 transition hover:border-slate-300 hover:shadow-[0_24px_50px_rgba(42,52,57,0.10)]"
          >
            <h3 className="text-base font-semibold text-slate-900">{item.title}</h3>
            <p className="mt-2 text-sm leading-6 text-slate-600">{item.subtitle}</p>
            <span className="mt-4 inline-block text-sm font-medium text-slate-500 transition group-hover:text-slate-900">
              Read more
            </span>
          </Card>
        </Link>
      ))}
    </div>
  );
}
