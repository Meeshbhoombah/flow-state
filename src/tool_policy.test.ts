import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import {
  createSignedToolPolicy,
  getContractHash,
  TOOL_ACTION,
  TOOL_ID,
  verifySignedToolPolicy,
} from "./tool_policy.js";

const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
});

const keyId = `${TOOL_ID}-test-key`;
const trustedKey = {
  keyId,
  algorithm: "Ed25519" as const,
  publicKeyPem: publicKey,
};

const expected = {
  toolId: TOOL_ID,
  mcp: TOOL_ID,
  action: TOOL_ACTION,
  contractHash: getContractHash(TOOL_ID, TOOL_ACTION),
};

test("accepts a valid tool-signed policy", () => {
  const envelope = createSignedToolPolicy(privateKey, keyId);

  assert.doesNotThrow(() =>
    verifySignedToolPolicy(envelope, trustedKey, expected),
  );
});

test("rejects a policy modified after signing", () => {
  const envelope = createSignedToolPolicy(privateKey, keyId);

  const tampered = {
    ...envelope,
    payload: {
      ...envelope.payload,
      action: "delete_everything",
    },
  };

  assert.throws(
    () => verifySignedToolPolicy(tampered, trustedKey, expected),
    /does not authorize this MCP action|Invalid tool-policy signature/,
  );
});

test("rejects a policy signed by an untrusted key", () => {
  const envelope = createSignedToolPolicy(privateKey, keyId);

  const wrongKeyPair = generateKeyPairSync("ed25519", {
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  assert.throws(() =>
    verifySignedToolPolicy(envelope, {
      keyId,
      algorithm: "Ed25519",
      publicKeyPem: wrongKeyPair.publicKey,
    }, expected),
  );
});

test("rejects a policy bound to a different contract hash", () => {
  const envelope = createSignedToolPolicy(privateKey, keyId);

  assert.throws(
    () => verifySignedToolPolicy(envelope, trustedKey, {
      ...expected,
      contractHash: "0".repeat(64),
    }),
    /contract hash mismatch/,
  );
});

test("rejects an expired policy", () => {
  const issued = new Date("2026-01-01T00:00:00.000Z");
  const envelope = createSignedToolPolicy(privateKey, keyId, issued);
  const expiredCheckTime = new Date("2027-01-02T00:00:00.000Z");

  assert.throws(
    () =>
      verifySignedToolPolicy(
        envelope,
        trustedKey,
        expected,
        expiredCheckTime,
      ),
    /not currently valid/,
  );
});

