import type { Provider, SourceKind } from "../policy/types.ts";

export type AuditResult = "applied" | "denied" | "failed";

/** How a write was approved: in the dialog, or without one because every destination was trusted. */
export type ApprovalMode = "dialog" | "trusted";

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
  approval?: ApprovalMode;
}

export interface AuditRecord extends Omit<AuditEntryInput, "approval"> {
  /** "" for records written before approval modes existed. */
  approval: ApprovalMode | "";
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

/** Record count and last hash, kept outside the database so a deleted tail is detected. */
export interface AuditAnchor {
  count: number;
  hash: string;
}

export interface AuditStore {
  append(entry: AuditEntryInput): AuditRecord;
  list(options?: { limit?: number; project?: string }): AuditRecord[];
  head(): AuditAnchor;
  /** With an anchor, also fails with brokenAt "truncated" when records up to the anchor are missing. */
  verify(anchor?: AuditAnchor): AuditVerification;
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
