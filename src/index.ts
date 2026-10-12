import { ArmorIQClient } from "@armoriq/sdk";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";

import {
  getResponseSchema,
  validateToolResponse,
  type JsonSchema,
} from "./response_gaurd.js";

type JsonObject = Record<string, unknown>;

type ActionRequest = {
  mcp: string;
  action: string;
  description: string;
  expectedResponse: string;
  params: JsonObject;
};

function canonicalize(value: unknown): string {
  function sort(value: unknown): unknown {
    if (Array.isArray(value)) {
      return value.map(sort);
    }

    if (value !== null && typeof value === "object") {
      const object = value as Record<string, unknown>;

      return Object.fromEntries(
        Object.keys(object)
          .sort()
          .map((key) => [key, sort(object[key])]),
      );
    }

    return value;
  }

  return JSON.stringify(sort(value));
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function assertSupportedSchema(schema: JsonSchema): void {
  const allowedKeys = new Set([
    "type",
    "description",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
  ]);

  const allowedTypes = new Set([
    "object",
    "array",
    "string",
    "integer",
    "number",
    "boolean",
    "null",
  ]);

  function inspect(node: unknown, path: string): void {
    if (
      node === null ||
      typeof node !== "object" ||
      Array.isArray(node)
    ) {
      throw new Error(`Invalid schema node at ${path}`);
    }

    const value = node as Record<string, unknown>;

    for (const key of Object.keys(value)) {
      if (!allowedKeys.has(key)) {
        throw new Error(
          `Unsupported schema keyword at ${path}: ${key}`,
        );
      }
    }

    if (
      typeof value.type !== "string" ||
      !allowedTypes.has(value.type)
    ) {
      throw new Error(`Unsupported schema type at ${path}`);
    }

    if (value.type === "object") {
      if (
        value.additionalProperties !== false ||
        value.properties === null ||
        typeof value.properties !== "object" ||
        Array.isArray(value.properties) ||
        !Array.isArray(value.required)
      ) {
        throw new Error(
          `Object must declare properties, required, and additionalProperties:false at ${path}`,
        );
      }

      const properties = value.properties as Record<string, unknown>;
      const required = value.required as unknown[];

      if (
        required.length !== Object.keys(properties).length ||
        !Object.keys(properties).every((key) =>
          required.includes(key),
        )
      ) {
        throw new Error(
          `Every declared property must be required at ${path}`,
        );
      }

      for (const [key, child] of Object.entries(properties)) {
        inspect(child, `${path}.properties.${key}`);
      }
    }

    if (value.type === "array") {
      if (value.items === undefined) {
        throw new Error(`Array must define items at ${path}`);
      }

      inspect(value.items, `${path}.items`);
    }

    if (
      value.enum !== undefined &&
      !Array.isArray(value.enum)
    ) {
      throw new Error(`enum must be an array at ${path}`);
    }
  }

  if (schema.type !== "object") {
    throw new Error("Response contract must have a root object.");
  }

  inspect(schema, "$");
}

async function approveContract(hash: string): Promise<void> {
  if (process.argv.includes("--yes")) {
    return;
  }

  console.log(`\nResponse contract SHA-256: ${hash}`);

  const rl = createInterface({
    input: stdin,
    output: stdout,
  });

  try {
    const answer = await rl.question(
      "\nApprove this contract before executing the action? [y/N] ",
    );

    if (answer.trim().toLowerCase() !== "y") {
      throw new Error(
        "Contract not approved. Action not executed.",
      );
    }
  } finally {
    rl.close();
  }
}

async function executeGatedAction(
  request: ActionRequest,
): Promise<unknown> {
  const schema = getResponseSchema(
    request.mcp,
    request.action,
  );

  assertSupportedSchema(schema);

  const contractHash = sha256(canonicalize(schema));

  await approveContract(contractHash);

  const goal =
    `Execute ${request.mcp}.${request.action}. ` +
    `Expected response contract SHA-256: ${contractHash}`;

  const prompt = [
    request.description,
    `Expected response: ${request.expectedResponse}`,
    `Response contract SHA-256: ${contractHash}`,
    "Execute only the action specified in the plan.",
  ].join("\n");

  const plan = {
    goal,
    steps: [
      {
        action: request.action,
        mcp: request.mcp,
        params: request.params,
      },
    ],
  };

  const armor = new ArmorIQClient({
    apiKey: process.env.ARMORIQ_API_KEY!,
    userId: process.env.ARMORIQ_USER_ID!,
    agentId: process.env.ARMORIQ_AGENT_ID!,
  });

  const planHash = sha256(canonicalize(plan));

  const captured = armor.capturePlan(
    "gpt-4o-mini",
    prompt,
    plan,
  );

  console.log("\n--- ArmorIQ captured plan ---");
  console.dir(captured, { depth: 4 });

  const token = await armor.getIntentToken(captured, {
    validitySeconds: 300,
  });

  const result = await armor.invokeWithPolicy(
    request.mcp,
    request.action,
    token,
    request.params,
    {
      userEmail: process.env.USER_EMAIL!,
    },
  );

  return validateToolResponse(
    request.mcp,
    request.action,
    result,
    {
      planHash,
      contractHash,
    },
  );
}

async function main(): Promise<void> {
  const configPath = process.argv.find(
    (arg) => arg.endsWith(".json"),
  );

  if (!configPath) {
    throw new Error(
      "Usage: npm start -- request.json [--yes]",
    );
  }

  const request = JSON.parse(
    await readFile(configPath, "utf8"),
  ) as ActionRequest;

  const result = await executeGatedAction(request);

  console.log(JSON.stringify(result, null, 2));
}

main().catch((error: unknown) => {
  console.error(
    "ACTION RESULT REJECTED:",
    error instanceof Error ? error.message : error,
  );

  process.exitCode = 1;
});

