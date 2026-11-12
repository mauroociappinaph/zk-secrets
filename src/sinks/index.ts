import type { Provider } from "../policy/types.ts";
import { awsSmSink, awsSsmSink } from "./aws.ts";
import { composeSink } from "./compose.ts";
import { dockerSwarmSink } from "./docker.ts";
import { dotenvSink } from "./dotenv.ts";
import { githubSink } from "./github.ts";
import { netlifySink } from "./netlify.ts";
import { railwaySink } from "./railway.ts";
import { supabaseSink } from "./supabase.ts";
import type { Sink } from "./types.ts";
import { vercelSink } from "./vercel.ts";

export function createSinks(): Record<Provider, Sink> {
  return {
    vercel: vercelSink,
    "aws-ssm": awsSsmSink,
    "aws-sm": awsSmSink,
    github: githubSink,
    railway: railwaySink,
    supabase: supabaseSink,
    netlify: netlifySink,
    "docker-swarm": dockerSwarmSink,
    compose: composeSink,
    dotenv: dotenvSink,
  };
}
