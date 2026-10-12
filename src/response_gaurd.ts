
import { createHash } from "node:crypto";
import { appendFile } from "node:fs/promises";

export type JsonSchema = {
  type: string;
  [key: string]: unknown;
};

type JsonObject = Record<string, unknown>;

const ajv = new Ajv({ allErrors: true, strict: true });

const SECURITY_ANALYSIS_SCHEMA: JsonSchema = {
  type: "object",
  properties: {
    status: { type: "string" },
    filename: { type: "string", minLength: 1 },
    source_sha256: {
      type: "string",
      minLength: 64,
      maxLength: 64,
    },
    summary: { type: "string" },
    findings: {
      type: "array",
      items: {
        type: "object",
        properties: {
          id: { type: "string", minLength: 1 },
          severity: {
            type: "string",
            enum: ["low", "medium", "high", "critical"],
          },
          title: { type: "string", minLength: 1 },
          file: { type: "string", minLength: 1 },
          line: { type: "integer", minimum: 1 },
          evidence: { type: "string", minLength: 1 },
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

const SCHEMA_REGISTRY = new Map<string, JsonSchema>([
  [
    "security-assessment-mcp-2.analyze_contract",
    SECURITY_ANALYSIS_SCHEMA,
  ],
]);

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

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

async function writeAudit(record: JsonObject): Promise<void> {
  await appendFile(
    "contract-gate-audit.jsonl",
    `${JSON.stringify(record)}\n`,
    { mode: 0o600 },
  );
}

export function getResponseSchema(
  mcp: string,
  action: string,
): JsonSchema {
  const key = `${mcp}.${action}`;
  const schema = SCHEMA_REGISTRY.get(key);

  if (!schema) {
    throw new Error(`No response schema registered for ${key}`);
  }

  return schema;
}

type AuditContext = {
  planHash: string;
  contractHash: string;
};

type ToolResult = {
  structuredContent?: unknown;
  content?: Array<{
    type?: string;
    text?: string;
  }>;
};

function extractPayload(invocation: unknown): unknown {
  if (
    invocation === null ||
    typeof invocation !== "object" ||
    !("result" in invocation)
  ) {
    throw new Error("Unexpected ArmorIQ invocation result shape.");
  }

  const toolResult = (invocation as { result: unknown }).result;

  if (toolResult === null || typeof toolResult !== "object") {
    throw new Error("ArmorIQ returned an invalid tool result.");
  }

  const result = toolResult as ToolResult;

  if (result.structuredContent !== undefined &&
      result.structuredContent !== null) {
    return result.structuredContent;
  }

  const textContent = result.content?.find(
    (item) => item.type === "text" && typeof item.text === "string",
  )?.text;

  if (typeof textContent !== "string") {
    throw new Error("Tool returned no structured or text response.");
  }

  try {
    return JSON.parse(textContent);
  } catch {
    throw new Error("Tool returned text that is not valid JSON.");
  }
}

/**
 * Extract, validate, and audit one ArmorIQ tool response.
 * Only returns a payload after it passes the registered schema.
 */
export async function validateToolResponse(
  mcp: string,
  action: string,
  invocation: unknown,
  context: AuditContext,
): Promise<unknown> {
  const key = `${mcp}.${action}`;
  let responseHash: string | null = null;

  try {
    const schema = getResponseSchema(mcp, action);
    const payload = extractPayload(invocation);

    responseHash = sha256(canonicalize(payload));

    const validate = ajv.compile(schema as AnySchema);

    if (!validate(payload)) {
      const errors = validate.errors ?? [];

      await writeAudit({
        timestamp: new Date().toISOString(),
        status: "rejected",
        mcp,
        action,
        schemaKey: key,
        ...context,
        responseHash,
        reason: "schema_validation_failed",
        errors,
      });

      throw new Error(
        `Response rejected by schema for ${key}: ${JSON.stringify(errors)}`,
      );
    }

    await writeAudit({
      timestamp: new Date().toISOString(),
      status: "accepted",
      mcp,
      action,
      schemaKey: key,
      ...context,
      responseHash,
    });

    return payload;
  } catch (error) {
    // Schema-invalid responses were already audited above.
    // Avoid writing a duplicate event for that same failure.
    if (
      error instanceof Error &&
      error.message.startsWith("Response rejected by schema for ")
    ) {
      throw error;
    }

    await writeAudit({
      timestamp: new Date().toISOString(),
      status: "rejected",
      mcp,
      action,
      schemaKey: key,
      ...context,
      responseHash,
      reason: "extraction_or_validation_error",
      error: error instanceof Error ? error.message : "Unknown error",
    });

    throw error;
  }
}

