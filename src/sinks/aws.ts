import { CreateSecretCommand, DescribeSecretCommand, PutSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { DescribeParametersCommand, PutParameterCommand } from "@aws-sdk/client-ssm";
import type { AwsSmTarget, AwsSsmTarget } from "../policy/types.ts";
import { safeCode } from "./http.ts";
import { SinkError, providerTime, type Sink } from "./types.ts";

interface AwsErrorShape {
  name?: unknown;
  $metadata?: { httpStatusCode?: number };
}

function toSinkError(error: unknown): SinkError {
  if (error instanceof SinkError) return error;
  const shape = (error ?? {}) as AwsErrorShape;
  const code = safeCode(shape.name) ?? "aws_error";
  return new SinkError(code, `AWS ${code}`, shape.$metadata?.httpStatusCode);
}

/** SSM Parameter Store: SecureString for secrets (optionally with a customer KMS key), String otherwise. */
export const awsSsmSink: Sink = {
  async apply(op, value, ctx) {
    const target = op.target as AwsSsmTarget;
    const sensitive = op.variable.sensitive;
    try {
      const out = (await ctx.aws.ssm(target).send(
        new PutParameterCommand({
          Name: `${target.prefix}${op.name}`,
          Value: value.reveal(),
          Type: sensitive ? "SecureString" : "String",
          KeyId: sensitive && target.kmsKeyId ? target.kmsKeyId : undefined,
          Overwrite: true,
        }),
      )) as { Version?: number };
      return out.Version !== undefined ? { version: String(out.Version) } : {};
    } catch (error) {
      throw toSinkError(error);
    }
  },

  /** DescribeParameters with an exact Name filter: metadata only, the value is never requested. */
  async lastModified(op, ctx) {
    const target = op.target as AwsSsmTarget;
    const name = `${target.prefix}${op.name}`;
    let out: { Parameters?: Array<{ Name?: unknown; LastModifiedDate?: unknown }> };
    try {
      out = (await ctx.aws.ssm(target).send(
        new DescribeParametersCommand({ ParameterFilters: [{ Key: "Name", Option: "Equals", Values: [name] }] }),
      )) as typeof out;
    } catch (error) {
      throw toSinkError(error);
    }
    const found = (out.Parameters ?? []).find((p) => p.Name === name);
    if (!found) return { status: "missing" };
    const time = providerTime(found.LastModifiedDate);
    return time === null ? { status: "unsupported", reason: "AWS returned no LastModifiedDate" } : { status: "found", time };
  },
};

/** Secrets Manager: new version of an existing secret, or create it on first write. */
export const awsSmSink: Sink = {
  async apply(op, value, ctx) {
    const target = op.target as AwsSmTarget;
    const client = ctx.aws.secretsManager(target);
    const secretId = `${target.prefix}${op.name}`;
    try {
      const out = (await client.send(
        new PutSecretValueCommand({ SecretId: secretId, SecretString: value.reveal() }),
      )) as { VersionId?: string };
      return out.VersionId ? { version: out.VersionId } : {};
    } catch (error) {
      if ((error as AwsErrorShape)?.name !== "ResourceNotFoundException") throw toSinkError(error);
    }
    try {
      const out = (await client.send(
        new CreateSecretCommand({ Name: secretId, SecretString: value.reveal(), KmsKeyId: target.kmsKeyId }),
      )) as { VersionId?: string };
      return out.VersionId ? { version: out.VersionId } : {};
    } catch (error) {
      throw toSinkError(error);
    }
  },

  /** DescribeSecret (never GetSecretValue): LastChangedDate; ResourceNotFoundException is missing. */
  async lastModified(op, ctx) {
    const target = op.target as AwsSmTarget;
    let out: { LastChangedDate?: unknown };
    try {
      out = (await ctx.aws.secretsManager(target).send(new DescribeSecretCommand({ SecretId: `${target.prefix}${op.name}` }))) as typeof out;
    } catch (error) {
      if ((error as AwsErrorShape)?.name === "ResourceNotFoundException") return { status: "missing" };
      throw toSinkError(error);
    }
    const time = providerTime(out.LastChangedDate);
    return time === null ? { status: "unsupported", reason: "AWS returned no LastChangedDate" } : { status: "found", time };
  },
};
