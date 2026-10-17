import { ArmorIQClient } from "@armoriq/sdk";
import { appendFile } from "node:fs/promises";
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

type Authorization = "allow" | "block";

type Execution = "success" | "failed" | "not_executed";

type AuditEvent = "authorization" | "execution";

type DecisionAuditRecord = {
  timestamp: string;
  event: AuditEvent;
  planId: string | null;
  requestHash: string;
  contractHash: string | null;
  planHash: string | null;
  mcp: string;
  action: string;
  authorization: Authorization;
  execution: Execution;
  reason: string;
  matchedPolicy?: string;
  armorIQAction?: string;
};

const AUDIT_PATH = "kevlar-decision-audit.jsonl";

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

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function classifyFailure(error: unknown): string {
  const message = errorMessage(error);

  if (
    /response rejected by schema|response contract|schema validation/i.test(
      message,
    )
  ) {
    return "response_contract_mismatch";
  }

  if (
    /signature|signed request|tool policy rejected|invalid token|intent mismatch/i.test(
      message,
    )
  ) {
    return "mcp_signature_or_execution_policy_rejected";
  }

  if (/authorization blocked|policy denied|enforce-unavailable|enforce-rejected/i.test(message)) {
    return "authorization_denied";
  }

  return "execution_failed";
}

function assertActionRequest(value: unknown): ActionRequest {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Request must be a JSON object.");
  }

  const request = value as Record<string, unknown>;

  if (
    typeof request.mcp !== "string" ||
    request.mcp.length === 0 ||
    typeof request.action !== "string" ||
    request.action.length === 0 ||
    typeof request.description !== "string" ||
    typeof request.expectedResponse !== "string" ||
    request.params === null ||
    typeof request.params !== "object" ||
    Array.isArray(request.params)
  ) {
    throw new Error(
      "Invalid request. Expected mcp, action, description, " +
        "expectedResponse, and an object-valued params field.",
    );
  }

  return request as ActionRequest;
}

function requiredEnvironmentVariable(name: string): string {
  const value = process.env[name];

  if (!value || value.trim().length === 0) {
    throw new Error(`Required environment variable ${name} is missing.`);
  }

  return value;
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

async function writeDecisionAudit(
  record: DecisionAuditRecord,
): Promise<void> {
  await appendFile(
    AUDIT_PATH,
    `${JSON.stringify(record)}\n`,
    "utf8",
  );
}

async function executeGatedAction(
  request: ActionRequest,
): Promise<unknown> {
  const requestHash = sha256(
    canonicalize({
      mcp: request.mcp,
      action: request.action,
      params: request.params,
    }),
  );

  let contractHash: string | null = null;
  let planHash: string | null = null;
  let planId: string | null = null;

  let authorization: Authorization = "block";
  let execution: Execution = "not_executed";

  let authorizationRecorded = false;
  let executionStarted = false;
  let reportAttempted = false;

  let reason = "pre_execution_check_failed";
  let matchedPolicy: string | undefined;
  let armorIQAction: string | undefined;

  let session:
    | ReturnType<ArmorIQClient["startSession"]>
    | undefined;

  let token:
    | Awaited<ReturnType<NonNullable<typeof session>["startPlan"]>>
    | undefined;

  const armor = new ArmorIQClient({
    apiKey: requiredEnvironmentVariable("ARMORIQ_API_KEY"),
    userId: requiredEnvironmentVariable("ARMORIQ_USER_ID"),
    agentId: requiredEnvironmentVariable("ARMORIQ_AGENT_ID"),
  });

  const writeAuthorization = async (
    decision: Authorization,
    decisionReason: string,
  ): Promise<void> => {
    await writeDecisionAudit({
      timestamp: new Date().toISOString(),
      event: "authorization",
      planId,
      requestHash,
      contractHash,
      planHash,
      mcp: request.mcp,
      action: request.action,
      authorization: decision,
      execution: "not_executed",
      reason: decisionReason,
      matchedPolicy,
      armorIQAction,
    });

    authorization = decision;
    reason = decisionReason;
    authorizationRecorded = true;
  };

  const writeExecution = async (
    outcome: Execution,
    outcomeReason: string,
  ): Promise<void> => {
    await writeDecisionAudit({
      timestamp: new Date().toISOString(),
      event: "execution",
      planId,
      requestHash,
      contractHash,
      planHash,
      mcp: request.mcp,
      action: request.action,
      authorization,
      execution: outcome,
      reason: outcomeReason,
      matchedPolicy,
      armorIQAction,
    });

    execution = outcome;
    reason = outcomeReason;
  };

  try {
    const schema = getResponseSchema(
      request.mcp,
      request.action,
    );

    assertSupportedSchema(schema);

    contractHash = sha256(canonicalize(schema));

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

    planHash = sha256(canonicalize(plan));

    console.log("\n--- Kevlar plan ---");
    console.dir(plan, { depth: 4 });

    const userEmail = requiredEnvironmentVariable("USER_EMAIL");

    /*
     * SDK mode performs an explicit ArmorIQ policy check.
     * The MCP action must not execute unless check() explicitly allows it.
     */
    session = armor.startSession({
      mode: "sdk",
      defaultMcpName: request.mcp,
      llm: "gpt-4o-mini",
      validitySeconds: 300,
    });

    token = await session.startPlan(
      [
        {
          name: request.action,
          args: request.params,
        },
      ],
      goal,
    );

    if (!token.planId) {
      throw new Error(
        "ArmorIQ did not return a plan ID; cannot track plan status.",
      );
    }

    planId = token.planId;

    console.log("ArmorIQ plan started:", planId);
    console.log("Checking policy before MCP execution...");

    const decision = await session.check(
      request.action,
      request.params,
      userEmail,
    );

    matchedPolicy = decision.matchedPolicy;
    armorIQAction = decision.action;

    if (!decision.allowed) {
      const denialReason =
        decision.reason ?? `ArmorIQ policy action: ${decision.action}`;

      await writeAuthorization(
        "block",
        `armoriq_policy_denied: ${denialReason}`,
      );

      console.error("AUTHORIZATION BLOCKED:", {
        mcp: request.mcp,
        action: request.action,
        policyAction: decision.action,
        matchedPolicy,
        reason: denialReason,
      });

      throw new Error(`Authorization blocked: ${denialReason}`);
    }

    /*
     * Record the explicit allow before performing the external action.
     * If this local audit write fails, the MCP call is never attempted.
     */
    await writeAuthorization(
      "allow",
      "armoriq_policy_allowed",
    );

    console.log("AUTHORIZATION ALLOWED:", {
      mcp: request.mcp,
      action: request.action,
      matchedPolicy: matchedPolicy ?? "not reported by ArmorIQ",
    });

    const startedAt = Date.now();
    executionStarted = true;

    /*
     * Preserve the existing signed-token MCP invocation.
     * ArmorIQ's session check is an explicit policy gate; this invocation
     * still performs the actual MCP call using the issued intent token.
     */
    const invocation = await armor.invokeWithPolicy(
      request.mcp,
      request.action,
      token,
      request.params,
      { userEmail },
    );

    const validated = await validateToolResponse(
      request.mcp,
      request.action,
      invocation,
      {
        planHash,
        contractHash,
      },
    );

    await session.report(
      request.action,
      request.params,
      validated,
      {
        status: "success",
        durationMs: Date.now() - startedAt,
      },
    );

    reportAttempted = true;

    await writeExecution(
      "success",
      "response_contract_validated",
    );

    await armor.completePlan(planId);

    console.log("EXECUTION SUCCEEDED:", {
      planId,
      authorization,
      execution: "success",
    });

    return validated;
  } catch (error: unknown) {
    const message = errorMessage(error);
    const failureReason = classifyFailure(error);

    /*
     * If no explicit allow/block record was written, fail closed and
     * record a block. This covers contract approval, schema, setup,
     * and policy-check failures that occur before an allow is recorded.
     */
    if (!authorizationRecorded) {
      await writeAuthorization(
        "block",
        `pre_execution_block: ${failureReason}: ${message}`,
      );
    }

    /*
     * Report the failed step to ArmorIQ when a session and plan exist.
     * A post-authorization MCP or contract failure does not rewrite the
     * earlier authorization decision; it records a failed execution.
     */
    if (session && token && !reportAttempted) {
      try {
        await session.report(
          request.action,
          request.params,
          null,
          {
            status: "failed",
            errorMessage: message,
          },
        );

        reportAttempted = true;
      } catch (reportError: unknown) {
        console.error(
          "Could not report execution failure to ArmorIQ:",
          errorMessage(reportError),
        );
      }
    }

    const outcome: Execution = executionStarted
      ? "failed"
      : "not_executed";

    try {
      await writeExecution(outcome, `${failureReason}: ${message}`);
    } catch (auditError: unknown) {
      console.error(
        "CRITICAL: Could not write Kevlar execution audit:",
        errorMessage(auditError),
      );
    }

    if (planId) {
      await armor.updatePlanStatus(planId, "failed");
    }

    console.error("ACTION REJECTED:", {
      planId,
      authorization,
      execution: outcome,
      reason: failureReason,
      message,
    });

    throw error;
  } finally {
    if (session) {
      try {
        await session.flushObservability();
      } catch (error: unknown) {
        console.error(
          "ArmorIQ observability flush failed:",
          errorMessage(error),
        );
      }

      try {
        await session.close();
      } catch (error: unknown) {
        console.error(
          "ArmorIQ session close failed:",
          errorMessage(error),
        );
      }
    }
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

  const rawRequest = JSON.parse(
    await readFile(configPath, "utf8"),
  ) as unknown;

  const request = assertActionRequest(rawRequest);

  const result = await executeGatedAction(request);

  console.log(JSON.stringify(result, null, 2));
}

main().catch((error: unknown) => {
  console.error(
    "ACTION RESULT REJECTED:",
    errorMessage(error),
  );

  process.exitCode = 1;
});
