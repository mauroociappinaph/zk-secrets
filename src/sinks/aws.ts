import { CreateSecretCommand, PutSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { PutParameterCommand } from "@aws-sdk/client-ssm";
import type { AwsSmTarget, AwsSsmTarget } from "../policy/types.ts";
import { safeCode } from "./http.ts";
import { SinkError, type Sink } from "./types.ts";

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
};
