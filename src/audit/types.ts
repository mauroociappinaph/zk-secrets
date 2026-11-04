import type { Provider, SourceKind } from "../policy/types.ts";

export type AuditResult = "applied" | "denied" | "failed";

/** Metadata only. There is deliberately no field that could hold a value or a hash of one. */
export interface AuditEntryInput {
  ts: string;
  actorHuman: string;
  actorAgent: string;
  project: string;
  provider: Provider;
  target: string;
  environment: string;
  variableName: string;
  action: "set";
  sensitive: boolean;
  sourceKind: SourceKind;
  result: AuditResult;
  providerVersion: string;
  errorCode: string;
}

export interface AuditRecord extends AuditEntryInput {
  auditId: string;
  prevHash: string;
  hash: string;
  mirroredAt: string;
}

export interface AuditVerification {
  ok: boolean;
  count: number;
  brokenAt?: string;
}

export interface AuditStore {
  append(entry: AuditEntryInput): AuditRecord;
  list(options?: { limit?: number; project?: string }): AuditRecord[];
  verify(): AuditVerification;
  pendingMirror(limit: number): AuditRecord[];
  markMirrored(auditIds: string[], ts: string): void;
  close(): void;
}

export interface MirrorResult {
  configured: boolean;
  pushed: number;
  pending: number;
  error?: string;
}

export interface Mirror {
  /** Pushes pending records to the remote mirror. Never throws. */
  sync(store: AuditStore): Promise<MirrorResult>;
}
