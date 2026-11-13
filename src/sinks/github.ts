import sodium from "libsodium-wrappers";
import type { GithubTarget } from "../policy/types.ts";
import { SecretBuffer } from "../secret/secret-buffer.ts";
import { requestJson, type JsonResponse } from "./http.ts";
import { SinkError, providerTime, type Sink, type SinkContext } from "./types.ts";

/** The only GitHub host zks talks to; gh's config (hosts, http_unix_socket) is never used for writes. */
export const GITHUB_API = "https://api.github.com";
const KEY_ID = /^[A-Za-z0-9_-]{1,64}$/;

/** Reads the `gh auth login` token for github.com. Only `gh auth token` runs; gh never sees a value. */
async function readToken(ctx: SinkContext): Promise<SecretBuffer> {
  const gh = ctx.tools.gh;
  const res = gh ? await ctx.exec(gh, ["auth", "token", "--hostname", "github.com"], { timeoutMs: 30_000 }).catch(() => null) : null;
  if (!res) throw new SinkError("github_unavailable", "GitHub CLI (gh) is not available");
  let end = res.stdout.length;
  while (end > 0 && (res.stdout[end - 1] === 0x0a || res.stdout[end - 1] === 0x0d)) end--;
  const copy = Buffer.from(res.stdout.subarray(0, end));
  res.stdout.fill(0);
  if (res.code !== 0 || copy.length === 0) {
    copy.fill(0);
    throw new SinkError("missing_token", "no GitHub login; run `gh auth login`");
  }
  return SecretBuffer.adopt(copy);
}

function failed(res: JsonResponse): SinkError {
  return new SinkError("github_failed", `GitHub HTTP ${res.status}`, res.status);
}

/** Seals the value with the repository (or environment) public key: libsodium crypto_box_seal. */
async function seal(value: SecretBuffer, publicKey: string): Promise<string> {
  await sodium.ready;
  const plain = Buffer.from(value.reveal(), "utf8");
  try {
    const key = sodium.from_base64(publicKey, sodium.base64_variants.ORIGINAL);
    return sodium.to_base64(sodium.crypto_box_seal(plain, key), sodium.base64_variants.ORIGINAL);
  } finally {
    plain.fill(0);
  }
}

/**
 * GitHub Actions secrets (sensitive, sealed-box encrypted) or variables (plain) through the
 * REST API at api.github.com, authenticated with the token of your `gh auth login` session.
 */
function baseUrl(target: GithubTarget): string {
  const [owner, repo] = target.repo.split("/") as [string, string];
  return (
    `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}` +
    (target.environment ? `/environments/${encodeURIComponent(target.environment)}` : "/actions")
  );
}

function headersFor(token: SecretBuffer): Record<string, string> {
  return {
    authorization: `Bearer ${token.reveal()}`,
    accept: "application/vnd.github+json",
    "x-github-api-version": "2022-11-28",
    "user-agent": "zks",
  };
}

export const githubSink: Sink = {
  async apply(op, value, ctx) {
    const base = baseUrl(op.target as GithubTarget);
    const name = encodeURIComponent(op.name);

    const token = await readToken(ctx);
    try {
      const headers = headersFor(token);
      const call = (method: string, url: string, body?: unknown) => requestJson(ctx.fetch, "github", method, url, headers, body);

      if (op.variable.sensitive) {
        const keyRes = await call("GET", `${base}/secrets/public-key`);
        const publicKey = keyRes.body as { key_id?: unknown; key?: unknown } | null;
        if (!keyRes.ok) throw failed(keyRes);
        if (typeof publicKey?.key_id !== "string" || !KEY_ID.test(publicKey.key_id) || typeof publicKey.key !== "string") {
          throw failed(keyRes);
        }
        const encrypted = await seal(value, publicKey.key).catch(() => {
          throw failed(keyRes);
        });
        const put = await call("PUT", `${base}/secrets/${name}`, { encrypted_value: encrypted, key_id: publicKey.key_id });
        if (put.status !== 201 && put.status !== 204) throw failed(put);
        return { version: publicKey.key_id };
      }

      const variable = { name: op.name, value: value.reveal() };
      const patch = await call("PATCH", `${base}/variables/${name}`, variable);
      if (patch.ok) return {};
      if (patch.status !== 404) throw failed(patch);
      const post = await call("POST", `${base}/variables`, variable);
      if (!post.ok) throw failed(post);
      return {};
    } finally {
      token.dispose();
    }
  },

  /** GET secrets/{name} (metadata only) or variables/{name}: only updated_at is kept; 404 is missing. */
  async lastModified(op, ctx) {
    const kind = op.variable.sensitive ? "secrets" : "variables";
    const url = `${baseUrl(op.target as GithubTarget)}/${kind}/${encodeURIComponent(op.name)}`;
    const token = await readToken(ctx);
    let res: JsonResponse;
    try {
      res = await requestJson(ctx.fetch, "github", "GET", url, headersFor(token));
    } finally {
      token.dispose();
    }
    if (res.status === 404) return { status: "missing" };
    if (!res.ok) throw failed(res);
    const time = providerTime((res.body as { updated_at?: unknown } | null)?.updated_at);
    return time === null ? { status: "unsupported", reason: "GitHub returned no updated_at for this name" } : { status: "found", time };
  },
};
