import { createHmac, randomBytes as nodeRandomBytes, timingSafeEqual } from "node:crypto";
import { canonicalJson } from "../audit/store.ts";
import { ZKS_KEYCHAIN_SERVICE, type Keychain } from "../platform/keychain.ts";
import { SecretBuffer } from "../secret/secret-buffer.ts";
import type { Operation } from "./types.ts";

/** Keychain account (service "zks") holding the HMAC key that signs trust.json. */
export const TRUST_HMAC_ACCOUNT = "trust-hmac";

export interface TrustedDestination {
  key: string;
  addedAt: string;
  addedBy: string;
}

/** ~/.config/zks/trust.json: destinations whose writes skip the approval dialog. */
export interface TrustFile {
  version: 1;
  destinations: TrustedDestination[];
  /** HMAC-SHA256 hex of canonical {version, destinations} with the Keychain trust-hmac key. */
  mac: string;
}

export interface TrustState {
  /** False when the file exists but is unparsable, unsigned or its signature does not match. */
  valid: boolean;
  /** Empty whenever valid is false: a tampered store trusts nothing. */
  destinations: TrustedDestination[];
}

export interface TrustIo {
  keychain: Keychain;
  readTrust(): Promise<TrustFile | null>;
  writeTrust(file: TrustFile): Promise<void>;
  randomBytes?: (size: number) => Buffer;
}

/**
 * The scope "Always allow" trusts: a GitHub owner, a Vercel team (or the personal account),
 * an AWS profile + role + region, a Railway project or a Supabase project.
 */
export function trustKeyOf(op: Operation): string {
  const target = op.target;
  switch (target.provider) {
    case "github":
      return `github:${(target.repo.split("/")[0] as string).toLowerCase()}`;
    case "vercel":
      return `vercel:${target.teamId ?? "personal"}`;
    case "aws-ssm":
    case "aws-sm":
      return `aws:${target.profile ?? "default"}:${target.roleArn ?? "no-role"}:${target.region}`;
    case "railway":
      return `railway:${target.projectId}`;
    case "supabase":
      return `supabase:${target.projectRef}`;
  }
}

export function describeTrustKey(key: string): string {
  const parts = key.split(":");
  const [provider, first] = parts;
  if (first === undefined || first === "") return "unknown destination";
  switch (provider) {
    case "github":
      return `GitHub owner ${first} (every repository)`;
    case "vercel":
      return first === "personal" ? "Vercel personal account" : `Vercel team ${first}`;
    case "aws": {
      if (parts.length < 4) return "unknown destination";
      const role = parts.slice(2, -1).join(":");
      const region = parts[parts.length - 1];
      return `AWS profile ${first}, ${role === "no-role" ? "no role" : `role ${role}`}, region ${region} (SSM and Secrets Manager)`;
    }
    case "railway":
      return `Railway project ${first}`;
    case "supabase":
      return `Supabase project ${first}`;
    default:
      return "unknown destination";
  }
}

/** canonicalJson sorts the top-level keys; each entry is built with its keys already sorted. */
function signedText(destinations: TrustedDestination[]): string {
  return canonicalJson({
    version: 1,
    destinations: destinations.map((d) => ({ addedAt: d.addedAt, addedBy: d.addedBy, key: d.key })),
  });
}

function sign(key: SecretBuffer, destinations: TrustedDestination[]): string {
  return createHmac("sha256", key.reveal()).update(signedText(destinations)).digest("hex");
}

const isDestination = (d: unknown): d is TrustedDestination =>
  typeof d === "object" &&
  d !== null &&
  typeof (d as TrustedDestination).key === "string" &&
  typeof (d as TrustedDestination).addedAt === "string" &&
  typeof (d as TrustedDestination).addedBy === "string";

/** Reads and verifies trust.json. A missing file is an empty valid store; anything else unverified trusts nothing. */
export async function loadTrust(io: TrustIo): Promise<TrustState> {
  const file = (await io.readTrust()) as unknown;
  if (file === null) return { valid: true, destinations: [] };
  const invalid: TrustState = { valid: false, destinations: [] };
  const f = file as Partial<TrustFile> | undefined;
  if (typeof f !== "object" || f === null || f.version !== 1 || !Array.isArray(f.destinations) || !f.destinations.every(isDestination)) {
    return invalid;
  }
  if (typeof f.mac !== "string" || !/^[0-9a-f]{64}$/.test(f.mac)) return invalid;
  const key = await io.keychain.get(ZKS_KEYCHAIN_SERVICE, TRUST_HMAC_ACCOUNT);
  if (!key || key.length === 0) return invalid;
  try {
    const expected = Buffer.from(sign(key, f.destinations), "hex");
    if (!timingSafeEqual(expected, Buffer.from(f.mac, "hex"))) return invalid;
  } finally {
    key.dispose();
  }
  return { valid: true, destinations: f.destinations.map((d) => ({ key: d.key, addedAt: d.addedAt, addedBy: d.addedBy })) };
}

/** Signs and writes trust.json, creating the Keychain HMAC key (32 random bytes) on first use. */
export async function saveTrust(io: TrustIo, destinations: TrustedDestination[]): Promise<void> {
  let key = await io.keychain.get(ZKS_KEYCHAIN_SERVICE, TRUST_HMAC_ACCOUNT);
  if (!key || key.length === 0) {
    const random = (io.randomBytes ?? nodeRandomBytes)(32);
    key = SecretBuffer.fromString(random.toString("hex"));
    random.fill(0);
    await io.keychain.set(ZKS_KEYCHAIN_SERVICE, TRUST_HMAC_ACCOUNT, key);
  }
  try {
    await io.writeTrust({ version: 1, destinations, mac: sign(key, destinations) });
  } finally {
    key.dispose();
  }
}
