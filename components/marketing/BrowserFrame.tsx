import Image from "next/image";

export function BrowserFrame({
  alt,
  imageSrc,
  imageClassName,
  compact = false,
  priority = false,
}: {
  alt: string;
  imageSrc: string;
  imageClassName?: string;
  compact?: boolean;
  priority?: boolean;
}) {
  return (
    <div
      className={`overflow-hidden border border-slate-200 bg-slate-50 shadow-[0_18px_36px_-12px_rgba(15,23,42,0.18),0_8px_16px_-8px_rgba(15,23,42,0.08)] ${
        compact ? "rounded-xl" : "rounded-2xl"
      }`}
    >
      <div className="relative w-full aspect-[22/10]">
        <Image
          src={imageSrc}
          alt={alt}
          fill
          priority={priority}
          className={`object-cover object-top ${imageClassName ?? ""}`}
        />
      </div>
    </div>
  );
}
