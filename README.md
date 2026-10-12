# Kevlar

Extends the cryptographic guarantees provided by ArmorIQ.

With its SHA-256-based Merkle DAG, ArmorIQ's Intents provide a foundation for stronger cryptographic guarantees across an agent's subsystems. Kevlar validates JSON responses from MCP tool calls against predefined schema contracts whose hashes are incorporated into the agent's execution plan.

Kevlar also introduces **tool-specific Ed25519-signed policies**. Each tool has a cryptographic identity, and its policy is signed using the corresponding private key. Before executing a protected MCP tool, the server verifies the policy's signature, trusted identity, permitted action, contract hash, and expiration. Invalid, untrusted, expired, or mismatched policies are rejected before the tool executes.

Together, these controls improve the integrity, accountability, and auditability of agent tool execution.

## Getting Started

### Installation

#### Prerequisites

Install the following software before setting up the project.

| Software | Requirement | Purpose |
|---|---|---|
| Git | Current stable version | Clone the repository |
| Node.js | 18 or newer | Run the TypeScript application |
| npm | Compatible with your Node.js installation | Install dependencies and run scripts |
| Python | 3.10 or newer | Install the ArmorIQ CLI |
| pipx or pip | Current supported version | Install the ArmorIQ CLI |
| ngrok | Current stable version | Expose the local MCP endpoint |
| ArmorIQ account | Verified account with an organization | Obtain credentials and register the MCP |
| Internet access | HTTPS outbound access | Reach ArmorIQ services and install dependencies |

The signing and verification implementation uses Node.js's built-in cryptography APIs. No additional cryptography package is required.

The project also requires an ArmorIQ API key, a user identity, an agent identity, and an email value for invocation context.

#### macOS

On a fresh macOS installation, install Apple's command-line tools:

```bash
xcode-select --install
```

Install Homebrew by following its official instructions:

https://brew.sh/

Install Git, Node.js, Python, pipx, and ngrok:

```bash
brew install git node python pipx
brew install ngrok/ngrok/ngrok
```

Verify the installations:

```bash
git --version
node --version
npm --version
python3 --version
pipx --version
ngrok version
```

#### Linux

On Ubuntu or Debian, install the basic development tools:

```bash
sudo apt update
sudo apt install -y git curl ca-certificates python3 python3-pip \
  python3-venv pipx
```

Install Node.js 18 or newer and npm using a maintained distribution method appropriate for your Linux distribution.

Verify the installations:

```bash
git --version
python3 --version
pipx --version
node --version
npm --version
```

Install ngrok using its official instructions:

https://ngrok.com/download

Ensure `node`, `npm`, `python3`, `pipx`, and `ngrok` are available on your shell's `PATH`. If necessary, run:

```bash
pipx ensurepath
```

Restart the terminal if your shell configuration requires it.

#### Windows

Install the following using their official installers:

- Git: https://git-scm.com/download/win
- Node.js: https://nodejs.org/
- Python: https://www.python.org/downloads/windows/
- ngrok: https://ngrok.com/download

Enable the options that add Git, Node.js, and Python to `PATH` when offered.

Open a new PowerShell terminal and verify:

```powershell
git --version
node --version
npm --version
py --version
py -m pip --version
```

Install pipx:

```powershell
py -m pip install --user pipx
py -m pipx ensurepath
```

Close and reopen PowerShell, then verify:

```powershell
pipx --version
ngrok version
```

#### Install the ArmorIQ CLI

Kevlar uses the ArmorIQ TypeScript SDK at runtime. The ArmorIQ CLI is used for account authentication and configuration registration.

Install it with pipx:

```bash
pipx install armoriq-sdk
```

Verify the installation:

```bash
armoriq --help
```

Authenticate with ArmorIQ:

```bash
armoriq login
armoriq whoami
armoriq orgs
```

Complete the browser authentication flow and confirm that your account belongs to the intended organization.

Official ArmorIQ documentation:

- Installation: https://docs.armoriq.ai/sdk/installation
- CLI: https://docs.armoriq.ai/cli
- Configuration: https://docs.armoriq.ai/platform/sdk-cli/armoriq-yaml

#### Clone the repository

```bash
git clone https://github.com/Meeshbhoombah/flow-state.git
cd flow-state
npm install
```

Check the available scripts:

```bash
npm run
```

The project includes scripts for running the request runner, starting the MCP server, typechecking, testing policy verification, and managing signed policies.

### Configure ArmorIQ

Open `armoriq.yaml` and confirm the MCP identifier, tool name, endpoint, identity, and policy.

The registered MCP identifier must match the identifier used by the request runner, MCP server, and response schema registry.

The demo configuration uses these values:

```yaml
identity:
  api_key: $ARMORIQ_API_KEY
  user_id: security-service
  agent_id: security-assessment-bot

proxy:
  url: https://proxy.armoriq.ai
  timeout: 30
  max_retries: 3

mcp_servers:
  - id: security-assessment-mcp-2
    url: https://YOUR-NGROK-HOST/mcp
    auth:
      type: none
    description: Local demo for testing the response contract

policy:
  allow:
    - security-assessment-mcp-2.analyze_contract
  deny: []
```

Keep any other required fields in the repository's existing configuration. This snippet illustrates the relevant settings; it is not intended to replace the complete working configuration blindly.

Keep the policy restricted to the tools required for the demo.

### Configure environment variables

The request runner expects these environment variables:

- `ARMORIQ_API_KEY`: your ArmorIQ API key.
- `ARMORIQ_USER_ID`: the service user identity.
- `ARMORIQ_AGENT_ID`: the agent identity.
- `USER_EMAIL`: the email identity used for invocation context.

For macOS and Linux, export the variables in the terminal that will run the application:

```bash
export ARMORIQ_API_KEY="YOUR_ARMORIQ_API_KEY"
export ARMORIQ_USER_ID="security-service"
export ARMORIQ_AGENT_ID="security-assessment-bot"
export USER_EMAIL="YOUR_EMAIL"
```

For Windows PowerShell:

```powershell
$env:ARMORIQ_API_KEY = "YOUR_ARMORIQ_API_KEY"
$env:ARMORIQ_USER_ID = "security-service"
$env:ARMORIQ_AGENT_ID = "security-assessment-bot"
$env:USER_EMAIL = "YOUR_EMAIL"
```

These variables apply to the current terminal session. Set them in every terminal that needs them, or use a local secret manager.

Never commit real credentials or a `.env` file to source control.

## Tool Identity and Signed Policies

Kevlar uses Ed25519 public-key cryptography to associate a trusted signing identity with each protected tool.

The signing workflow has two operations:

- **`keygen`** creates a tool's signing identity and registers its public key in the local trust registry.
- **`sign`** creates a signed policy binding the tool identity to a specific MCP server, action, response contract hash, policy version, and expiration.

At runtime, the MCP server loads the trusted public key and signed policy, verifies the signature and policy constraints, and rejects execution if verification fails.

### Generate a tool identity

For a new local development environment, generate the signing identity:

```bash
npm run policy -- keygen
```

This creates:

```text
keys/
  security-assessment-mcp-2.private.pem

config/
  tool-trust.json
```

The private key is used to sign policies. The trust registry associates the tool identifier with its trusted public key, key ID, and signature algorithm.

**Keep the private key secret. Never commit it, publish it, or include it in logs.**

The generated private key is local to the environment. Back it up securely if it is needed for future policy signing.

If a trust registry already contains the tool's identity, the key-generation command intentionally refuses to overwrite that identity. Do not generate a replacement key merely to resolve a signing or verification error.

### Sign the tool policy

After generating the tool identity, create the signed policy:

```bash
npm run policy -- sign
```

The command:

1. Loads the tool's private key.
2. Loads the public key registered in `config/tool-trust.json`.
3. Confirms that the private key corresponds to the registered public key.
4. Calculates the response contract hash.
5. Signs the policy using Ed25519.
6. Writes the signed policy artifact to the configured policy directory.

The default output is:

```text
config/
  tool-trust.json
  signed-policies/
    security-assessment-mcp-2.analyze_contract.json
```

The signed policy includes the tool identity, MCP identifier, action name, contract hash, policy version, key ID, algorithm, issuance time, expiration time, and digital signature.

The signing command prints the policy's contract hash and expiration time.

### Trust registry and Git

The trust registry contains public-key material, not private signing keys. For a controlled deployment, it should be provisioned and reviewed as part of the trusted configuration.

For the repository's development workflow:

- Commit `config/tool-trust.json` when its public key is intended to be the shared trusted identity.
- Commit signed policy artifacts when they are intended to be reviewed and versioned with the source.
- Never commit `keys/*.private.pem`.
- Keep runtime audit logs out of version control unless a specific audit-retention workflow requires otherwise.

A fresh clone of a repository containing a trust registry and signed policy can verify that policy using the committed public key. It does not need the private key merely to verify the signature. The private key is needed to issue a new signature.

**Security boundary:** a public key in Git is not independently protected against malicious changes to the repository. If an attacker can change both the trust registry and the policy, they may replace the trusted identity. Protect changes to trusted keys through code review and, in production, use a separately controlled trust-provisioning mechanism.

### Verify the signed-policy implementation

Run the TypeScript compiler:

```bash
npm run typecheck
```

Run the policy-signature tests:

```bash
npm test
```

The tests exercise these cases:

- A valid tool-signed policy is accepted.
- A policy modified after signing is rejected.
- A policy signed by an untrusted key is rejected.
- A policy bound to a different contract hash is rejected.
- An expired policy is rejected.

These tests validate the policy verification implementation. They do not, by themselves, demonstrate that ArmorIQ's proxy performs verification of Kevlar's custom tool signature.

## Register the MCP Endpoint

Start the local MCP server in a dedicated terminal:

```bash
npm run mcp:dev
```

The server listens on `127.0.0.1:3000`. Keep it running.

In a second terminal, start ngrok:

```bash
ngrok http 3000
```

Copy the HTTPS forwarding URL from ngrok. Append `/mcp` to form the MCP endpoint.

For example, if ngrok prints:

```text
https://example.ngrok-free.app
```

the MCP endpoint is:

```text
https://example.ngrok-free.app/mcp
```

The hostname is illustrative; use the URL generated by your own ngrok session.

Update the `url` field in `armoriq.yaml` to match the current tunnel URL. A new tunnel URL may require updating and re-registering the configuration.

Validate and register the configuration:

```bash
armoriq validate
armoriq register
armoriq status
```

If a command is unavailable in your installed CLI version, consult `armoriq --help` and the current ArmorIQ documentation.

## Usage

### 1. Start the MCP server

In Terminal 1:

```bash
cd flow-state
npm run mcp:dev
```

The server must remain running on port `3000`.

Before invoking a protected tool, the server verifies its signed policy. If verification fails, the server must reject the operation before the tool's analysis handler executes.

### 2. Start ngrok

In Terminal 2:

```bash
cd flow-state
ngrok http 3000
```

Confirm that the HTTPS forwarding URL matches the MCP endpoint registered in `armoriq.yaml`.

### 3. Run the request

In Terminal 3, configure the required environment variables and run:

```bash
cd flow-state
npm start -- request.json
```

The program will:

1. Load the request and response schema.
2. Compute and display the response contract hash.
3. Ask for approval before executing the action.
4. Capture an ArmorIQ plan and request an intent token.
5. Invoke `analyze_contract` through ArmorIQ.
6. Validate the returned payload against the JSON Schema.
7. Append an audit entry and print the accepted result.

Enter `y` when prompted to approve the contract. Any other response leaves the action unapproved.

### 4. Run without interactive contract approval

The request runner also supports a `--yes` flag:

```bash
npm start -- request.json --yes
```

This skips the interactive contract-approval prompt. Use it only when you intentionally want noninteractive execution.

The flag does not remove the need for response-schema validation or signed-policy verification.

### 5. Inspect the audit log

After an execution reaches the response-validation stage, inspect the most recent contract-gate audit entries:

```bash
tail -n 5 contract-gate-audit.jsonl
```

On Windows PowerShell:

```powershell
Get-Content contract-gate-audit.jsonl -Tail 5
```

Accepted entries include execution metadata such as the MCP identifier, action, plan hash, contract hash, and response hash. Rejected entries may include validation errors.

Search for rejected response-validation entries on macOS or Linux:

```bash
grep '"status":"rejected"' contract-gate-audit.jsonl
```

On PowerShell:

```powershell
Select-String '"status":"rejected"' contract-gate-audit.jsonl
```

The signed-policy enforcement also maintains a separate audit log:

```text
tool-policy-audit.jsonl
```

Inspect it with:

```bash
tail -n 5 tool-policy-audit.jsonl
```

The policy audit records accepted and rejected policy-verification decisions. A request rejected before reaching response validation may have a policy audit entry without a corresponding contract-gate audit entry.

Treat both logs as operational records, and protect them from unauthorized modification.

## Testing Policy Rejection

The following procedure tests that the MCP server rejects a policy whose signature has been modified.

First, stop the MCP server with `Ctrl+C`. Back up the valid signed policy:

```bash
cp config/signed-policies/security-assessment-mcp-2.analyze_contract.json \
  /tmp/flow-state-policy-valid.json
```

Modify the signature without changing the policy payload:

```bash
node -e '
const fs = require("node:fs");
const p = "config/signed-policies/security-assessment-mcp-2.analyze_contract.json";
const policy = JSON.parse(fs.readFileSync(p, "utf8"));
const sig = policy.signature;
policy.signature = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
fs.writeFileSync(p, JSON.stringify(policy, null, 2) + "\n");
'
```

Restart the MCP server:

```bash
npm run mcp:dev
```

In another terminal, submit the request:

```bash
npm start -- request.json --yes
```

The expected behavior is that the server rejects the modified signature and does not execute `analyze_contract`.

Stop the MCP server after the negative test. Restore the original policy:

```bash
cp /tmp/flow-state-policy-valid.json \
  config/signed-policies/security-assessment-mcp-2.analyze_contract.json
```

Restart the MCP server and submit the request again:

```bash
npm run mcp:dev
```

In another terminal:

```bash
npm start -- request.json --yes
```

The valid policy should pass verification again.

If ArmorIQ returns an error before the MCP server processes the request, inspect both the request runner's output and the MCP server's logs. An error in the request runner's response parser does not, by itself, establish whether policy verification failed.

## Troubleshooting

### ngrok returns `502 Bad Gateway` or `ERR_NGROK_8012`

The tunnel cannot reach the local server. Confirm that the MCP server is running and listening on port `3000`.

On macOS or Linux:

```bash
lsof -nP -iTCP:3000 -sTCP:LISTEN
curl -i http://127.0.0.1:3000/mcp
```

A basic GET request may not be a valid MCP protocol operation. The important point is that the connection reaches the server.

### ArmorIQ reports an authentication error

Check the API key, identity variables, organization, and login status:

```bash
armoriq whoami
armoriq status
```

Reauthenticate if necessary:

```bash
armoriq login
```

### The MCP tool is not found or ArmorIQ denies the invocation

Verify that the MCP identifier and action match in:

- `armoriq.yaml`
- The request plan in `request.json`
- The MCP server registration in `mcp/mcp-server.ts`
- The response schema registry in `src/response_gaurd.ts`
- The signed-policy configuration

Then validate and register the ArmorIQ configuration again if necessary.

### The signed policy is rejected

Check that the following files exist:

```text
config/tool-trust.json
config/signed-policies/security-assessment-mcp-2.analyze_contract.json
```

Then verify that:

- The public key in the trust registry matches the key that signed the policy.
- The key ID and algorithm match the trusted identity.
- The policy identifies the expected tool and MCP action.
- The policy contract hash matches the current response schema.
- The policy has not expired.
- The signature has not been altered.

If you still have the correct private key, regenerate the policy:

```bash
npm run policy -- sign
```

Do not generate a new keypair or replace the trust registry as a first troubleshooting step. Doing so may create a trust mismatch or invalidate the existing identity.

### The response is rejected

Inspect the validation errors and the latest entry in `contract-gate-audit.jsonl`.

Confirm that the tool response includes every required property, uses an allowed severity, has a positive integer line number, and contains no unexpected fields.

### The response text is not valid JSON

This message may indicate that an error payload was returned instead of the expected JSON response. Inspect the MCP server logs and the ArmorIQ invocation output to identify the original error.

If the MCP server rejects the signed policy, resolve the policy-verification failure before debugging response parsing.

### The audit log is not updated

The contract-gate audit is written only when execution reaches the response-validation logic. A network failure or policy rejection before a tool response reaches the validator may therefore produce no contract-gate audit entry.

Check `tool-policy-audit.jsonl` as well when investigating a signed-policy rejection.

## Security Considerations

- Never commit API keys, private signing keys, or other credentials.
- Keep the ArmorIQ policy restricted to the minimum required tools.
- Treat the public-key trust registry as security-sensitive configuration, even though it contains no private key.
- Protect trusted-key changes through code review or a separate deployment trust mechanism.
- Treat the demo analyzer's output as a candidate finding, not a complete security assessment.
- Do not expose the local MCP server directly to the public internet.
- Use a controlled tunnel and keep it running only while testing.
- Protect audit logs from unauthorized modification.
- The custom Ed25519 policy signature is verified by Kevlar's MCP server. It is not a claim that ArmorIQ's proxy natively verifies this custom signature.
- A valid tool signature proves that the policy was signed by the holder of the corresponding private key. It does not, by itself, prove that the policy was authorized by the user or by ArmorIQ.
- For production use, add separately controlled policy authorization, stronger audit-log integrity protections, comprehensive adversarial tests, key rotation and revocation procedures, and a real security-analysis engine.

