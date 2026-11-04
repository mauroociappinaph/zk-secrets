import { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { SSMClient } from "@aws-sdk/client-ssm";
import { fromNodeProviderChain, fromTemporaryCredentials } from "@aws-sdk/credential-providers";
import type { AwsSmTarget, AwsSsmTarget, AwsTargetBase } from "../policy/types.ts";
import type { AwsClientFactory } from "./types.ts";

const SESSION_SECONDS = 900;

/**
 * Session policy attached to AssumeRole: the effective permissions are the intersection of the
 * role and this document, so a zks session can only write under the target prefix.
 */
export function sessionPolicyFor(target: AwsSsmTarget | AwsSmTarget): string {
  const writeStatement =
    target.provider === "aws-ssm"
      ? {
          Effect: "Allow",
          Action: ["ssm:PutParameter", "ssm:AddTagsToResource"],
          Resource: `arn:aws:ssm:${target.region}:*:parameter${target.prefix}*`,
        }
      : {
          Effect: "Allow",
          Action: ["secretsmanager:PutSecretValue", "secretsmanager:CreateSecret", "secretsmanager:DescribeSecret"],
          Resource: `arn:aws:secretsmanager:${target.region}:*:secret:${target.prefix}*`,
        };
  return JSON.stringify({
    Version: "2012-10-17",
    Statement: [writeStatement, { Effect: "Allow", Action: ["kms:Encrypt", "kms:GenerateDataKey"], Resource: "*" }],
  });
}

function credentialsFor(target: AwsSsmTarget | AwsSmTarget) {
  const base = fromNodeProviderChain(target.profile ? { profile: target.profile } : {});
  if (!target.roleArn) return base;
  return fromTemporaryCredentials({
    params: {
      RoleArn: target.roleArn,
      RoleSessionName: "zks",
      DurationSeconds: SESSION_SECONDS,
      Policy: sessionPolicyFor(target),
    },
    masterCredentials: base,
    clientConfig: { region: target.region, ignoreConfiguredEndpointUrls: true },
  });
}

/**
 * Uses the credentials already on the machine (SSO, profile, env) - zks never stores AWS keys.
 * `endpoint_url` in ~/.aws/config is ignored, so a same-user edit cannot redirect a write.
 */
export function createAwsClientFactory(): AwsClientFactory {
  const config = (target: AwsTargetBase & (AwsSsmTarget | AwsSmTarget)) => ({
    region: target.region,
    credentials: credentialsFor(target),
    maxAttempts: 3,
    ignoreConfiguredEndpointUrls: true,
  });
  return {
    ssm: (target) => new SSMClient(config(target)),
    secretsManager: (target) => new SecretsManagerClient(config(target)),
  };
}
