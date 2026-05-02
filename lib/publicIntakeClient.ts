import { buildApiUrl } from "@/lib/api";

type ValidationIssue = {
  loc?: Array<string | number>;
  msg?: string;
  type?: string;
};

type PublicIntakeResponse<TFieldErrors> = {
  ok: boolean;
  requestId?: string;
  request_id?: string;
  errors?: TFieldErrors;
  error?: string;
  detail?: unknown;
};

type PublicIntakeResult<TFieldErrors> = {
  ok: boolean;
  requestId?: string;
  errors?: TFieldErrors;
  error?: string;
};

async function parseJsonSafely<T>(response: Response): Promise<T | null> {
  try {
    return (await response.json()) as T;
  } catch {
    return null;
  }
}

function isValidationIssueArray(detail: unknown): detail is ValidationIssue[] {
  return Array.isArray(detail);
}

function buildFriendlyErrorMessage(detail: unknown) {
  if (typeof detail === "string" && detail.trim()) {
    return detail;
  }

  return "We couldn’t submit your request. Please check the highlighted details and try again.";
}

function mapValidationErrors<TFieldErrors extends object>(
  detail: unknown,
  fieldMap: Partial<Record<string, keyof TFieldErrors>>
) {
  if (!isValidationIssueArray(detail)) return undefined;

  const mapped = {} as Partial<Record<keyof TFieldErrors, string>>;

  for (const issue of detail) {
    const loc = Array.isArray(issue.loc) ? issue.loc : [];
    const lastSegment = typeof loc[loc.length - 1] === "string" ? String(loc[loc.length - 1]) : null;
    const targetField = lastSegment ? fieldMap[lastSegment] : undefined;

    if (targetField && issue.msg && !mapped[targetField]) {
      mapped[targetField] = issue.msg as Partial<Record<keyof TFieldErrors, string>>[keyof TFieldErrors];
    }
  }

  return Object.keys(mapped).length > 0 ? (mapped as TFieldErrors) : undefined;
}

export async function submitPublicIntake<TPayload extends object, TFieldErrors extends object>(
  path: string,
  payload: TPayload,
  fieldMap: Partial<Record<string, keyof TFieldErrors>> = {}
): Promise<PublicIntakeResult<TFieldErrors>> {
  const response = await fetch(buildApiUrl(path), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const parsed = await parseJsonSafely<PublicIntakeResponse<TFieldErrors>>(response);

  if (!response.ok) {
    const mappedErrors =
      parsed?.errors ?? mapValidationErrors<TFieldErrors>(parsed?.detail, fieldMap);

    return {
      ok: false,
      errors: mappedErrors,
      error: parsed?.error ?? buildFriendlyErrorMessage(parsed?.detail),
    };
  }

  return {
    ok: Boolean(parsed?.ok ?? true),
    requestId: parsed?.requestId ?? parsed?.request_id,
  };
}
