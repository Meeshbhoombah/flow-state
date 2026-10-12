import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "node:crypto";
import { appendFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { getResponseSchema } from "./response_gaurd.js";

export const TOOL_ID = "security-assessment-mcp-2";
export const TOOL_ACTION = "analyze_contract";
export const POLICY_VERSION = 1;
export const POLICY_ALGORITHM = "Ed25519" as const;

const TRUST_PATH = join("config", "tool-trust.json");
const POLICY_DIRECTORY = join("config", "signed-policies");
const AUDIT_PATH = "tool-policy-audit.jsonl";

type JsonObject = Record<string, unknown>;

export type ToolPolicyPayload = {
  toolId: string;
  mcp: string;
  action: string;
  contractHash: string;
  policyVersion: number;
  keyId: string;
  algorithm: typeof POLICY_ALGORITHM;
  issuedAt: string;
  expiresAt: string;
};

export type SignedToolPolicy = {
  payload: ToolPolicyPayload;
  signature: string;
};

type TrustedKey = {
  keyId: string;
  algorithm: typeof POLICY_ALGORITHM;
  publicKeyPem: string;
};

type TrustRegistry = {
  tools: Record<string, TrustedKey>;
};

type PolicyAuditRecord = {
  timestamp: string;
  status: "accepted" | "rejected";
  toolId: string;
  mcp: string;
  action: string;
  policyVersion?: number;
  contractHash?: string;
  signatureHash?: string;
  reason?: string;
};

export function canonicalize(value: unknown): string {
  function sort(input: unknown): unknown {
    if (Array.isArray(input)) {
      return input.map(sort);
    }

    if (input !== null && typeof input === "object") {
      const object = input as JsonObject;

      return Object.fromEntries(
        Object.keys(object)
          .sort()
          .map((key) => [key, sort(object[key])]),
      );
    }

    return input;
  }

  return JSON.stringify(sort(value));
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function getContractHash(mcp: string, action: string): string {
  return sha256(canonicalize(getResponseSchema(mcp, action)));
}

export function getPolicyPath(mcp: string, action: string): string {
  return join(POLICY_DIRECTORY, `${mcp}.${action}.json`);
}

export function createSignedToolPolicy(
  privateKeyPem: string,
  keyId: string,
  now = new Date(),
): SignedToolPolicy {
  const issuedAt = now.toISOString();
  const expiresAt = new Date(
    now.getTime() + 365 * 24 * 60 * 60 * 1000,
  ).toISOString();

  const payload: ToolPolicyPayload = {
    toolId: TOOL_ID,
    mcp: TOOL_ID,
    action: TOOL_ACTION,
    contractHash: getContractHash(TOOL_ID, TOOL_ACTION),
    policyVersion: POLICY_VERSION,
    keyId,
    algorithm: POLICY_ALGORITHM,
    issuedAt,
    expiresAt,
  };

  const signature = ed25519Sign(
    null,
    Buffer.from(canonicalize(payload), "utf8"),
    createPrivateKey(privateKeyPem),
  ).toString("base64url");

  return { payload, signature };
}

export function verifySignedToolPolicy(
  envelope: SignedToolPolicy,
  trustedKey: TrustedKey,
  expected: {
    toolId: string;
    mcp: string;
    action: string;
    contractHash: string;
  },
  now = new Date(),
): void {
  if (
    envelope === null ||
    typeof envelope !== "object" ||
    envelope.payload === null ||
    typeof envelope.payload !== "object" ||
    typeof envelope.signature !== "string" ||
    envelope.signature.length === 0
  ) {
    throw new Error("Missing or malformed signed tool policy.");
  }

  const payload = envelope.payload;

  if (payload.algorithm !== POLICY_ALGORITHM) {
    throw new Error("Unsupported tool-policy signature algorithm.");
  }

  if (
    trustedKey.algorithm !== POLICY_ALGORITHM ||
    payload.keyId !== trustedKey.keyId
  ) {
    throw new Error("Tool-policy signing key is not trusted.");
  }

  if (
    payload.toolId !== expected.toolId ||
    payload.mcp !== expected.mcp ||
    payload.action !== expected.action
  ) {
    throw new Error("Signed policy does not authorize this MCP action.");
  }

  if (payload.contractHash !== expected.contractHash) {
    throw new Error("Signed policy response-contract hash mismatch.");
  }

  if (
    payload.policyVersion !== POLICY_VERSION ||
    !Number.isInteger(payload.policyVersion)
  ) {
    throw new Error("Unsupported tool-policy version.");
  }

  const issuedAt = Date.parse(payload.issuedAt);
  const expiresAt = Date.parse(payload.expiresAt);

  if (
    !Number.isFinite(issuedAt) ||
    !Number.isFinite(expiresAt) ||
    issuedAt > now.getTime() ||
    expiresAt <= now.getTime() ||
    expiresAt <= issuedAt
  ) {
    throw new Error("Tool policy is not currently valid.");
  }

  let signature: Buffer;

  try {
    signature = Buffer.from(envelope.signature, "base64url");
  } catch {
    throw new Error("Malformed tool-policy signature.");
  }

  if (
    signature.length !== 64 ||
    signature.toString("base64url") !== envelope.signature
  ) {
    throw new Error("Malformed Ed25519 tool-policy signature.");
  }

  const valid = ed25519Verify(
    null,
    Buffer.from(canonicalize(payload), "utf8"),
    createPublicKey(trustedKey.publicKeyPem),
    signature,
  );

  if (!valid) {
    throw new Error("Invalid tool-policy signature.");
  }
}

async function appendAudit(record: PolicyAuditRecord): Promise<void> {
  await appendFile(AUDIT_PATH, `${JSON.stringify(record)}\n`, "utf8");
}

/**
 * This is the fail-closed enforcement gate called by the MCP handler.
 * It logs the decision before allowing the handler to perform work.
 */
export async function enforceSignedToolPolicy(
  mcp: string,
  action: string,
): Promise<void> {
  let payload: ToolPolicyPayload | undefined;
  let signatureHash: string | undefined;

  try {
    const [trustText, policyText] = await Promise.all([
      readFile(TRUST_PATH, "utf8"),
      readFile(getPolicyPath(mcp, action), "utf8"),
    ]);

    const trust = JSON.parse(trustText) as TrustRegistry;
    const envelope = JSON.parse(policyText) as SignedToolPolicy;
    payload = envelope?.payload;

    if (
      !trust ||
      !trust.tools ||
      typeof trust.tools !== "object"
    ) {
      throw new Error("Malformed tool trust registry.");
    }

    signatureHash =
      typeof envelope?.signature === "string"
        ? sha256(envelope.signature)
        : undefined;

    const trustedKey = trust.tools[TOOL_ID];

    if (!trustedKey) {
      throw new Error(`No trusted public key registered for ${TOOL_ID}.`);
    }

    verifySignedToolPolicy(
      envelope,
      trustedKey,
      {
        toolId: TOOL_ID,
        mcp,
        action,
        contractHash: getContractHash(mcp, action),
      },
    );

    await appendAudit({
      timestamp: new Date().toISOString(),
      status: "accepted",
      toolId: TOOL_ID,
      mcp,
      action,
      policyVersion: payload.policyVersion,
      contractHash: payload.contractHash,
      signatureHash,
    });
  } catch (error) {
    const reason =
      error instanceof Error ? error.message : String(error);

    // Failure to record a rejection must not allow the tool to execute.
    await appendAudit({
      timestamp: new Date().toISOString(),
      status: "rejected",
      toolId: TOOL_ID,
      mcp,
      action,
      policyVersion: payload?.policyVersion,
      contractHash: payload?.contractHash,
      signatureHash,
      reason,
    });

    throw new Error(`Tool policy rejected: ${reason}`);
  }
}

