import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
} from "node:crypto";
import {
  access,
  mkdir,
  readFile,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import {
  createSignedToolPolicy,
  getPolicyPath,
  TOOL_ID,
} from "./tool_policy.js";

const PRIVATE_KEY_PATH = join("keys", `${TOOL_ID}.private.pem`);
const TRUST_PATH = join("config", "tool-trust.json");

type TrustedKey = {
  keyId: string;
  algorithm: "Ed25519";
  publicKeyPem: string;
};

type TrustRegistry = {
  tools: Record<string, TrustedKey>;
};

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function generateIdentity(): Promise<void> {
  await mkdir("keys", { recursive: true });
  await mkdir("config", { recursive: true });

  if (await exists(PRIVATE_KEY_PATH)) {
    throw new Error(
      `Refusing to overwrite ${PRIVATE_KEY_PATH}. Back up or rotate the key deliberately.`,
    );
  }

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

  await writeFile(PRIVATE_KEY_PATH, privateKey, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });

  let registry: TrustRegistry = { tools: {} };

  if (await exists(TRUST_PATH)) {
    registry = JSON.parse(
      await readFile(TRUST_PATH, "utf8"),
    ) as TrustRegistry;
  }

  registry.tools ??= {};

  if (registry.tools[TOOL_ID]) {
    throw new Error(
      `A trusted key already exists for ${TOOL_ID}. Refusing to replace it.`,
    );
  }

  registry.tools[TOOL_ID] = {
    keyId: `${TOOL_ID}-ed25519-v1`,
    algorithm: "Ed25519",
    publicKeyPem: publicKey,
  };

  await writeFile(
    TRUST_PATH,
    `${JSON.stringify(registry, null, 2)}\n`,
    "utf8",
  );

  console.log(`Generated tool identity: ${TOOL_ID}`);
  console.log(`Private key: ${PRIVATE_KEY_PATH}`);
  console.log(`Trusted public key: ${TRUST_PATH}`);
  console.log("Keep the private key secret and out of version control.");
}

async function signPolicy(): Promise<void> {
  const privateKeyPem = await readFile(PRIVATE_KEY_PATH, "utf8");
  const registry = JSON.parse(
    await readFile(TRUST_PATH, "utf8"),
  ) as TrustRegistry;

  const trustedKey = registry.tools?.[TOOL_ID];

  if (!trustedKey) {
    throw new Error(`No trusted key configured for ${TOOL_ID}.`);
  }

  // Ensure the private key corresponds to the public key in the trust registry.
  const derivedPublicKey = createPublicKey(
    createPrivateKey(privateKeyPem),
  ).export({ type: "spki", format: "pem" }).toString();

  const registeredPublicKey = createPublicKey(
    trustedKey.publicKeyPem,
  ).export({ type: "spki", format: "pem" }).toString();

  if (derivedPublicKey !== registeredPublicKey) {
    throw new Error(
      "Private key does not match the registered trusted public key.",
    );
  }

  const envelope = createSignedToolPolicy(
    privateKeyPem,
    trustedKey.keyId,
  );

  const outputPath = getPolicyPath(
    envelope.payload.mcp,
    envelope.payload.action,
  );

  await mkdir("config/signed-policies", { recursive: true });
  await writeFile(
    outputPath,
    `${JSON.stringify(envelope, null, 2)}\n`,
    "utf8",
  );

  console.log(`Signed policy written to ${outputPath}`);
  console.log(`Tool: ${envelope.payload.toolId}`);
  console.log(`Action: ${envelope.payload.action}`);
  console.log(`Contract SHA-256: ${envelope.payload.contractHash}`);
  console.log(`Expires: ${envelope.payload.expiresAt}`);
}

async function main(): Promise<void> {
  const command = process.argv[2];

  if (command === "keygen") {
    await generateIdentity();
    return;
  }

  if (command === "sign") {
    await signPolicy();
    return;
  }

  throw new Error(
    "Usage: npm run policy -- keygen | sign",
  );
}

main().catch((error: unknown) => {
  console.error(
    error instanceof Error ? error.message : error,
  );
  process.exitCode = 1;
});


