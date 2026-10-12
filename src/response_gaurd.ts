import Ajv, { type AnySchema } from "ajv";
import { createHash } from "node:crypto";
import { appendFile } from "node:fs/promises";

export type JsonSchema = {
  type: string;
  [key: string]: unknown;
};

type JsonObject = Record<string, unknown>;

type AuditContext = {
  planHash: string;
  contractHash: string;
};

type AuditRecord = {
  timestamp: string;
  status: "accepted" | "rejected";
  mcp: string;
  action: string;
  planHash: string;
  contractHash: string;
  responseHash: string | null;
  errors?: unknown;
};

const ajv = new Ajv({
  allErrors: true,
  strict: true,
});

const AUDIT_LOG_PATH = "contract-gate-audit.jsonl";

/**
 * The response contract for the Solidity security-analysis demo.
 * Register additional tool contracts in SCHEMA_REGISTRY.
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
          },
          severity: {
            type: "string",
            enum: ["low", "medium", "high", "critical"],
          },
          title: {
            type: "string",
          },
          file: {
            type: "string",
          },
          line: {
            type: "integer",
            minimum: 1,
          },
          evidence: {
            type: "string",
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

/**
 * Every registered tool must have an explicit response contract.
 * Unknown tools fail closed rather than receiving a permissive schema.
 */
const SCHEMA_REGISTRY = new Map<string, JsonSchema>([
  [
    "security-assessment-mcp-2.analyze_contract",
    SECURITY_ANALYSIS_SCHEMA,
  ],
]);

function canonicalize(value: unknown): string {
  function sort(input: unknown): unknown {
    if (Array.isArray(input)) {
      return input.map(sort);
    }

    if (input !== null && typeof input === "object") {
      const object = input as Record<string, unknown>;

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

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function getResponseSchema(
  mcp: string,
  action: string,
): JsonSchema {
  const key = `${mcp}.${action}`;
  const schema = SCHEMA_REGISTRY.get(key);

  if (!schema) {
    throw new Error(
      `No response contract is registered for ${key}. Action not executed.`,
    );
  }

  return schema;
}

async function writeAudit(record: AuditRecord): Promise<void> {
  await appendFile(
    AUDIT_LOG_PATH,
    `${JSON.stringify(record)}\n`,
    "utf8",
  );
}

function extractToolPayload(invocation: unknown): unknown {
  if (
    invocation === null ||
    typeof invocation !== "object" ||
    !("result" in invocation)
  ) {
    throw new Error(
      "Unexpected ArmorIQ invocation result shape.",
    );
  }

  const invocationResult = (
    invocation as { result: unknown }
  ).result;

  if (
    invocationResult === null ||
    typeof invocationResult !== "object"
  ) {
    throw new Error("ArmorIQ returned an invalid tool result.");
  }

  const toolResult = invocationResult as {
    structuredContent?: unknown;
    content?: Array<{
      type?: string;
      text?: string;
    }>;
  };

  if (toolResult.structuredContent !== undefined &&
      toolResult.structuredContent !== null) {
    return toolResult.structuredContent;
  }

  const textContent = toolResult.content?.find(
    (item) =>
      item.type === "text" &&
      typeof item.text === "string",
  )?.text;

  if (typeof textContent !== "string") {
    throw new Error(
      "Tool response contained neither structuredContent nor text content.",
    );
  }

  try {
    return JSON.parse(textContent) as unknown;
  } catch {
    throw new Error(
      "Tool response text was not valid JSON.",
    );
  }
}

/**
 * Extracts, validates, and audits the tool response.
 * The caller receives a payload only after schema validation
 * and successful acceptance auditing.
 */
export async function validateToolResponse(
  mcp: string,
  action: string,
  invocation: unknown,
  context: AuditContext,
): Promise<unknown> {
  let responseHash: string | null = null;

  try {
    const schema = getResponseSchema(mcp, action);
    const payload = extractToolPayload(invocation);

    responseHash = sha256(canonicalize(payload));

    const validate = ajv.compile(schema as AnySchema);
    const valid = validate(payload);

    if (!valid) {
      const errors = validate.errors ?? [];

      await writeAudit({
        timestamp: new Date().toISOString(),
        status: "rejected",
        mcp,
        action,
        ...context,
        responseHash,
        errors,
      });

      throw new Error(
        `Response rejected by schema for ${mcp}.${action}: ${JSON.stringify(errors)}`,
      );
    }

    await writeAudit({
      timestamp: new Date().toISOString(),
      status: "accepted",
      mcp,
      action,
      ...context,
      responseHash,
    });

    return payload;
  } catch (error) {
    /*
     * Schema-validation failures have already been audited above.
     * For extraction, registry, or other failures, record a rejection.
     */
    const alreadyAudited =
      error instanceof Error &&
      error.message.startsWith(
        `Response rejected by schema for ${mcp}.${action}:`,
      );

    if (!alreadyAudited) {
      await writeAudit({
        timestamp: new Date().toISOString(),
        status: "rejected",
        mcp,
        action,
        ...context,
        responseHash,
        errors: {
          message:
            error instanceof Error
              ? error.message
              : String(error),
        },
      });
    }

    throw error;
  }
}

