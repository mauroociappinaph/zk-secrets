export const PROVIDERS = ["vercel", "aws-ssm", "aws-sm", "github", "railway", "supabase"] as const;
export type Provider = (typeof PROVIDERS)[number];

export const VERCEL_ENVIRONMENTS = ["production", "preview", "development"] as const;
export type VercelEnvironment = (typeof VERCEL_ENVIRONMENTS)[number];

export interface VercelTarget {
  provider: "vercel";
  projectId: string;
  teamId?: string;
  environments: VercelEnvironment[];
  gitBranch?: string;
}

export interface AwsTargetBase {
  region: string;
  prefix: string;
  profile?: string;
  roleArn?: string;
  kmsKeyId?: string;
}

export interface AwsSsmTarget extends AwsTargetBase {
  provider: "aws-ssm";
}

export interface AwsSmTarget extends AwsTargetBase {
  provider: "aws-sm";
}

export interface GithubTarget {
  provider: "github";
  repo: string;
  environment?: string;
}

export interface RailwayTarget {
  provider: "railway";
  projectId: string;
  environmentId: string;
  serviceId?: string;
  tokenType?: "account" | "project";
  skipDeploys?: boolean;
}

export interface SupabaseTarget {
  provider: "supabase";
  projectRef: string;
}

export type TargetConfig =
  | VercelTarget
  | AwsSsmTarget
  | AwsSmTarget
  | GithubTarget
  | RailwayTarget
  | SupabaseTarget;

export const GENERATE_FORMATS = ["random", "uuid", "jwt-secret", "password", "rsa-private-key", "ed25519-private-key"] as const;
export type GenerateFormat = (typeof GENERATE_FORMATS)[number];

export interface GenerateSource {
  kind: "generate";
  /** Default "random": `bytes` random bytes in `encoding`. */
  format?: GenerateFormat;
  /** random only. */
  bytes?: number;
  encoding?: "base64url" | "hex";
  /** password only. */
  length?: number;
  lower?: boolean;
  upper?: boolean;
  digits?: boolean;
  symbols?: boolean;
  /** rsa-private-key only. */
  bits?: 2048 | 3072 | 4096;
}

export type SourceSpec =
  | { kind: "op"; ref: string }
  | { kind: "keychain"; service: string; account: string }
  | { kind: "prompt" }
  | GenerateSource
  | { kind: "dotenv"; path: string; key?: string }
  /** SPKI PEM public key of another variable's generated private key. */
  | { kind: "public-key"; of: string }
  /** `${NAME}` raw, `${NAME:url}` percent-encoded, `$${` a literal `${`. */
  | { kind: "template"; template: string };

export type SourceKind = SourceSpec["kind"] | "literal";

export interface VariableSpec {
  sensitive: boolean;
  description?: string;
  source?: SourceSpec;
  /** Literal value, allowed only for non-sensitive env vars. */
  value?: string;
  targets: string[];
}

export interface Policy {
  version: 1;
  project: string;
  targets: Record<string, TargetConfig>;
  variables: Record<string, VariableSpec>;
}

/** One variable written to one target. */
export interface Operation {
  name: string;
  targetKey: string;
  target: TargetConfig;
  variable: VariableSpec;
  sourceKind: SourceKind;
}
