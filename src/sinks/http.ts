import { ZKS_KEYCHAIN_SERVICE, type Keychain } from "../platform/keychain.ts";
import type { SecretBuffer } from "../secret/secret-buffer.ts";
import { SinkError } from "./types.ts";

const REQUEST_TIMEOUT_MS = 30_000;

/** Reads a provider token from the Keychain, runs fn, then zeroes the token. */
export async function withToken<T>(
  keychain: Keychain,
  account: string,
  fn: (token: string) => Promise<T>,
): Promise<T> {
  const token: SecretBuffer | null = await keychain.get(ZKS_KEYCHAIN_SERVICE, account);
  if (!token || token.length === 0) {
    throw new SinkError("missing_token", `no ${account} token in the Keychain; run \`zks auth set ${account}\``);
  }
  try {
    return await fn(token.reveal());
  } finally {
    token.dispose();
  }
}

export interface JsonResponse {
  status: number;
  ok: boolean;
  body: unknown;
}

/** Sends a JSON request (no body when body is undefined) and parses the response. Network errors become SinkError without details. */
export async function requestJson(
  fetchFn: typeof fetch,
  provider: string,
  method: string,
  url: string,
  headers: Record<string, string>,
  body?: unknown,
): Promise<JsonResponse> {
  let response: Response;
  try {
    response = await fetchFn(url, {
      method,
      headers: body === undefined ? headers : { "content-type": "application/json", ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    throw new SinkError(`${provider}_unreachable`, `${provider} API request failed`);
  }
  const text = await response.text().catch(() => "");
  let parsed: unknown = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }
  return { status: response.status, ok: response.ok, body: parsed };
}

/** POSTs JSON and parses the response. */
export function postJson(
  fetchFn: typeof fetch,
  provider: string,
  url: string,
  headers: Record<string, string>,
  body: unknown,
): Promise<JsonResponse> {
  return requestJson(fetchFn, provider, "POST", url, headers, body);
}

/** Provider error codes are short identifiers; anything else is dropped. */
export function safeCode(value: unknown): string | undefined {
  return typeof value === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(value) ? value : undefined;
}
