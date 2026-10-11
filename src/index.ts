import { ArmorIQClient } from "@armoriq/sdk";
import Ajv, { type AnySchema } from "ajv";

import { createHash } from "node:crypto";
import { appendFile, readFile } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";

type JsonObject = Record<string, unknown>;

type ActionRequest = {
  mcp: string;
  action: string;
  description: string;
  expectedResponse: string;
  params: JsonObject;
};

type JsonSchema = {
  type: string;
  [key: string]: unknown;
};

const ajv = new Ajv({ allErrors: true, strict: true });

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

/**
 * Ask OpenAI to propose a response contract.
 *
 * The tool's actual input parameters and source code are not sent
 * to OpenAI by this function. Only the action description and
 * expected response description are supplied.
 */

/*
async function generateResponseSchema(
  request: ActionRequest,
): Promise<JsonSchema> {
  const response = await openai.responses.create({
    model: "gpt-4o-mini",
    input: [
      {
        role: "system",
        content: [
          "You design strict JSON Schema response contracts.",
          "Return only a JSON Schema serialized as a string in schema_json.",
          "The schema must describe the expected response, not the input.",
          "Use a root object.",
          "Use only object, array, string, integer, number, boolean, null.",
          "Use properties, required, items, enum, minimum, maximum,",
          "minLength, maxLength, minItems, maxItems, description,",
          "and additionalProperties.",
          "Set additionalProperties to false for every object.",
          "Require every declared property.",
          "Do not use $ref, definitions, remote references, or patterns.",
          "Do not invent fields unsupported by the response description.",
        ].join(" "),
      },
      {
        role: "user",
        content: [
          `MCP: ${request.mcp}`,
          `Action: ${request.action}`,
          `Action description: ${request.description}`,
          `Expected response: ${request.expectedResponse}`,
          "Generate the response contract.",
        ].join("\n"),
      },
    ],
    text: {
      format: {
        type: "json_schema",
        name: "response_contract_proposal",
        strict: true,
        schema: {
          type: "object",
          properties: {
            schema_json: {
              type: "string",
            },
            rationale: {
              type: "string",
            },
          },
          required: ["schema_json", "rationale"],
          additionalProperties: false,
        },
      },
    },
  });

  if (!response.output_text) {
    throw new Error("OpenAI returned no response contract.");
  }

  const proposal = JSON.parse(response.output_text) as {
    schema_json: string;
    rationale: string;
  };

  const schema = JSON.parse(proposal.schema_json) as JsonSchema;

  assertSupportedSchema(schema);

  // Compile before execution so invalid schemas fail closed.
  ajv.compile(schema as AnySchema);

  console.log("\nProposed response contract:");
  console.log(JSON.stringify(schema, null, 2));
  console.log("\nRationale:", proposal.rationale);

  return schema;
}
*/


const SECURITY_ANALYSIS_SCHEMA: JsonSchema = {
  type: "object",
  properties: {
    status: {
      type: "string",
    },
    filename: {
      type: "string",
      minLength: 1,
    },
    source_sha256: {
      type: "string",
      minLength: 64,
      maxLength: 64,
    },
    summary: {
      type: "string",
    },
    findings: {
      type: "array",
      items: {
        type: "object",
        properties: {
          id: {
            type: "string",
            minLength: 1,
          },
          severity: {
            type: "string",
            enum: ["low", "medium", "high", "critical"],
          },
          title: {
            type: "string",
            minLength: 1,
          },
          file: {
            type: "string",
            minLength: 1,
          },
          line: {
            type: "integer",
            minimum: 1,
          },
          evidence: {
            type: "string",
            minLength: 1,
          },
        },
        required: [
          "id",
          "severity",
          "title",
          "file",
          "line",
          "evidence",
        ],
        additionalProperties: false,
      },
    },
  },
  required: [
    "status",
    "filename",
    "source_sha256",
    "summary",
    "findings",
  ],
  additionalProperties: false,
};

function getResponseSchema(request: ActionRequest): JsonSchema {
  if (
    request.mcp === "security-assessment-mcp-2" &&
    request.action === "analyze_contract"
  ) {
    return SECURITY_ANALYSIS_SCHEMA;
  }

  throw new Error(
      `No predefined response contract for ${request.mcp}.${request.action}`,
    );
  }


  /**
   * Restrict generated contracts to a small, predictable subset
   * of JSON Schema. This avoids arbitrary schema features and
   * remote reference resolution.
   */
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
      if (node === null || typeof node !== "object" || Array.isArray(node)) {
        throw new Error(`Invalid schema node at ${path}`);
      }

      const value = node as Record<string, unknown>;

      for (const key of Object.keys(value)) {
        if (!allowedKeys.has(key)) {
          throw new Error(`Unsupported schema keyword at ${path}: ${key}`);
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
          throw new Error(`Object must declare properties, required, and additionalProperties:false at ${path}`);
        }

        const properties = value.properties as Record<string, unknown>;
        const required = value.required as unknown[];

        if (
          required.length !== Object.keys(properties).length ||
          !Object.keys(properties).every((key) => required.includes(key))
        ) {
          throw new Error(`Every declared property must be required at ${path}`);
        }

        for (const [key, child] of Object.entries(properties)) {
          inspect(child, `${path}.properties.${key}`);
        }
      }

      if (value.type === "array") {
        if (!value.items) {
          throw new Error(`Array must define items at ${path}`);
        }

        inspect(value.items, `${path}.items`);
      }

      if (value.enum !== undefined && !Array.isArray(value.enum)) {
        throw new Error(`enum must be an array at ${path}`);
      }
    }

    if (schema.type !== "object") {
      throw new Error("Response contract must have a root object.");
    }

    inspect(schema, "$");
  }

  async function approveContract(
    schema: JsonSchema,
    hash: string,
  ): Promise<void> {
    if (process.argv.includes("--yes")) {
      return;
    }

    console.log(`\nResponse contract SHA-256: ${hash}`);

    const rl = createInterface({ input: stdin, output: stdout });

    try {
      const answer = await rl.question(
        "\nApprove this contract before executing the action? [y/N] ",
      );

      if (answer.trim().toLowerCase() !== "y") {
        throw new Error("Contract not approved. Action not executed.");
      }
    } finally {
      rl.close();
    }
  }

  function parseResponse(data: unknown): unknown {
    if (typeof data !== "string") {
      return data;
    }

    try {
      return JSON.parse(data);
    } catch {
      throw new Error("Tool returned a string that is not valid JSON.");
    }
  }

  async function writeAudit(record: JsonObject): Promise<void> {
    await appendFile(
      "contract-gate-audit.jsonl",
      `${JSON.stringify(record)}\n`,
      { mode: 0o600 },
    );
  }

  async function executeGatedAction(
    request: ActionRequest,
  ): Promise<unknown> {
    const schema = getResponseSchema(request);

    assertSupportedSchema(schema);
    ajv.compile(schema as AnySchema);

    const schemaText = canonicalize(schema);
    const contractHash = sha256(schemaText);

    await approveContract(schema, contractHash);

    /*
     * Use one action per plan. Embedding the contract hash in the
     * signed plan goal binds this action to the proposed contract
     * without altering the MCP tool's actual input parameters.
     */
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

  let planHash = "";
  let responseHash = "";

  try {
    const captured = armor.capturePlan(
      "gpt-4o-mini",
      prompt,
      plan,
    );

    console.log("\n--- ArmorIQ captured plan ---");
    console.dir(captured, { depth: 4 });

    planHash = sha256(canonicalize(plan));

    const token = await armor.getIntentToken(captured, {
      validitySeconds: 300,
    });

    // The parameters must match the captured plan exactly.
    const result = await armor.invokeWithPolicy(
      request.mcp,
      request.action,
      token,
      request.params,
      {
        userEmail: process.env.USER_EMAIL!,
      },
    );

    console.log("\n--- ArmorIQ invocation result ---");
    console.dir(result, { depth: 4 });

    if (
      result === null ||
      typeof result !== "object" ||
      !("result" in result)
    ) {
      throw new Error(
        `Unexpected ArmorIQ invocation result shape. Keys: ${
          result !== null && typeof result === "object"
            ? Object.keys(result).join(", ")
            : typeof result
        }`,
      );
    }

    const invocationResult = result.result;

    if (
      invocationResult === null ||
      typeof invocationResult !== "object"
    ) {
      throw new Error("ArmorIQ returned an invalid tool result.");
    }

    const toolResult = invocationResult as {
      structuredContent?: unknown;
      content?: Array<{ type?: string; text?: string }>;
    };

    // Prefer structuredContent; fall back to parsing the text content.
    const data =
      toolResult.structuredContent ??
      parseResponse(
        toolResult.content?.find(
          (item) => item.type === "text" && typeof item.text === "string",
        )?.text,
      );

    responseHash = sha256(canonicalize(data));

    const validate = ajv.compile(schema as AnySchema);
    const valid = validate(data);

    if (!valid) {
      const errors = validate.errors ?? [];

      await writeAudit({
        timestamp: new Date().toISOString(),
        status: "rejected",
        mcp: request.mcp,
        action: request.action,
        planHash,
        contractHash,
        responseHash,
        errors,
      });

      throw new Error(
        `Response rejected: ${JSON.stringify(errors)}`,
      );
    }

    await writeAudit({
      timestamp: new Date().toISOString(),
      status: "accepted",
      mcp: request.mcp,
      action: request.action,
      planHash,
      contractHash,
      responseHash,
    });

    return data;
  } catch (error) {
    // Don't expose an unvalidated response to the caller.
    throw error;
  }
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

  // This is the first point at which the accepted response
  // is returned to the caller.
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error: unknown) => {
  console.error(
    "ACTION RESULT REJECTED:",
    error instanceof Error ? error.message : error,
  );
  process.exitCode = 1;
});
