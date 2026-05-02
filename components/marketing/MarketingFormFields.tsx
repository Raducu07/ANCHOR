import type { ReactNode } from "react";

export const marketingFieldClassName =
  "w-full rounded-2xl border border-slate-300 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm transition placeholder:text-slate-400 focus:border-slate-400";

export function FieldError({
  children,
  error,
}: {
  children: ReactNode;
  error?: string;
}) {
  return (
    <div>
      {children}
      {error ? <p className="mt-2 text-sm text-rose-700">{error}</p> : null}
    </div>
  );
}

export function SelectField({
  label,
  value,
  onChange,
  options,
  error,
  required = true,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: readonly string[];
  error?: string;
  required?: boolean;
}) {
  return (
    <div>
      <label className="block text-sm font-medium text-slate-700">{label}</label>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className={`${marketingFieldClassName} mt-2`}
        aria-invalid={Boolean(error)}
      >
        <option value="">{required ? `Select ${label.toLowerCase()}` : `Optional ${label.toLowerCase()}`}</option>
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
      {error ? <p className="mt-2 text-sm text-rose-700">{error}</p> : null}
    </div>
  );
}

export function TextAreaField({
  label,
  value,
  onChange,
  hint,
  error,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  hint?: string;
  error?: string;
}) {
  return (
    <div>
      <label className="block text-sm font-medium text-slate-700">{label}</label>
      <textarea
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className={`${marketingFieldClassName} mt-2 min-h-[120px] resize-y`}
        aria-invalid={Boolean(error)}
      />
      {hint ? <p className="mt-2 text-sm text-slate-500">{hint}</p> : null}
      {error ? <p className="mt-2 text-sm text-rose-700">{error}</p> : null}
    </div>
  );
}
