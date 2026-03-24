# OPENANT.md Template

This file provides manual security context for OpenAnt vulnerability analysis.
Place this file (named `OPENANT.md` or `OPENANT.json`) in your repository root.

## Supported Application Types

OpenAnt supports these four application types:

| Type | Description | Attack Model |
|------|-------------|--------------|
| `web_app` | Web applications and API servers | Remote attacker with browser/HTTP client |
| `cli_tool` | Command-line tools and utilities | Local user with shell access (already has filesystem access) |
| `library` | Reusable code packages and SDKs | No direct attack surface; security depends on caller |
| `agent_framework` | AI agent and LLM frameworks | Code execution is intentional; focus on sandbox escapes |

**Note:** Manual overrides can use any `application_type` value (validation is skipped for manual overrides). Use this to analyze unsupported application types by mapping them to the closest supported type.

**Override modes:** When this file is detected, the `generate-context` command prompts for how to handle it:
- `use` — Use this file as-is, skip LLM generation (default)
- `merge` — Feed this file into the LLM alongside other repo sources (README, etc.)
- `ignore` — Ignore this file and generate context from scratch

Use `--override-mode <mode>` to skip the prompt.

## Format

Include a JSON code block with the following structure:

```json
{
  "application_type": "web_app",
  "purpose": "Description of what this application does",
  "intended_behaviors": [
    "Behavior that is BY DESIGN, not a vulnerability",
    "Another intended behavior"
  ],
  "trust_boundaries": {
    "input_source": "untrusted|semi_trusted|trusted"
  },
  "security_model": "Description of security approach, or null",
  "not_a_vulnerability": [
    "Specific pattern that should NOT be flagged"
  ],
  "requires_remote_trigger": true,
  "confidence": 1.0,
  "evidence": ["Manual configuration by repository maintainers"]
}
```

## Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `application_type` | string | One of: `web_app`, `cli_tool`, `library`, `agent_framework` |
| `purpose` | string | 1-2 sentence description of what the application does |
| `intended_behaviors` | string[] | Behaviors that are BY DESIGN, not vulnerabilities |
| `trust_boundaries` | object | Maps input sources to trust levels: `untrusted`, `semi_trusted`, `trusted` |
| `security_model` | string\|null | Description of documented security approach |
| `not_a_vulnerability` | string[] | Specific patterns that should NOT be flagged |
| `requires_remote_trigger` | boolean | `true` for web_app, `false` for cli_tool/library/agent_framework |
| `confidence` | number | 0.0-1.0, set to 1.0 for manual config |
| `evidence` | string[] | What led to these conclusions |

## Examples by Application Type

### Web Application (`web_app`)

```json
{
  "application_type": "web_app",
  "purpose": "E-commerce platform with user accounts and payment processing",
  "intended_behaviors": [
    "Accepts file uploads from authenticated users",
    "Sends emails to user-provided addresses",
    "Stores user data in database"
  ],
  "trust_boundaries": {
    "http_request_body": "untrusted",
    "http_headers": "untrusted",
    "query_parameters": "untrusted",
    "session_data": "semi_trusted",
    "database_content": "semi_trusted",
    "config_files": "trusted"
  },
  "security_model": "JWT authentication, input validation, parameterized queries",
  "not_a_vulnerability": [
    "Email sending to user-provided addresses - intended feature with rate limiting"
  ],
  "requires_remote_trigger": true,
  "confidence": 1.0,
  "evidence": ["Manual configuration"]
}
```

### CLI Tool (`cli_tool`)

```json
{
  "application_type": "cli_tool",
  "purpose": "Command-line tool for managing cloud infrastructure",
  "intended_behaviors": [
    "Reads and writes local configuration files",
    "Makes API calls to cloud providers",
    "Executes shell commands for deployment"
  ],
  "trust_boundaries": {
    "cli_arguments": "trusted",
    "config_files": "trusted",
    "environment_variables": "trusted",
    "api_responses": "semi_trusted"
  },
  "security_model": "API keys stored in environment variables, no web interface",
  "not_a_vulnerability": [
    "Path traversal in file operations - user has filesystem access",
    "Command execution - user can already run commands",
    "Reading arbitrary files - user has filesystem access"
  ],
  "requires_remote_trigger": false,
  "confidence": 1.0,
  "evidence": ["Manual configuration"]
}
```

### Library (`library`)

```json
{
  "application_type": "library",
  "purpose": "HTTP client library for making API requests",
  "intended_behaviors": [
    "Makes HTTP requests to developer-specified URLs",
    "Follows redirects",
    "Handles authentication headers"
  ],
  "trust_boundaries": {
    "function_parameters": "depends on caller",
    "config_objects": "trusted"
  },
  "security_model": "Library does not validate URLs - caller's responsibility",
  "not_a_vulnerability": [
    "SSRF via URL parameter - library function, caller controls input",
    "Following redirects - documented behavior"
  ],
  "requires_remote_trigger": false,
  "confidence": 1.0,
  "evidence": ["Manual configuration"]
}
```

### Agent Framework (`agent_framework`)

```json
{
  "application_type": "agent_framework",
  "purpose": "Framework for building AI agents that execute code and use tools",
  "intended_behaviors": [
    "Executes user-provided code in agent sandbox",
    "Spawns subprocesses to run agent tools",
    "Clones git repositories from user-specified URLs",
    "Makes HTTP requests to user-configured endpoints"
  ],
  "trust_boundaries": {
    "cli_arguments": "trusted",
    "http_requests": "untrusted",
    "hub_content": "semi_trusted",
    "agent_code": "untrusted"
  },
  "security_model": "Allowlist-based deserialization, optional Docker sandboxing for agent execution",
  "not_a_vulnerability": [
    "Subprocess execution in agent tools - this is the core feature",
    "Path traversal in CLI commands - user has filesystem access",
    "Dynamic imports in agent middleware - intentional for extensibility",
    "SSRF in developer-configured base_url - not user-controlled"
  ],
  "requires_remote_trigger": false,
  "confidence": 1.0,
  "evidence": ["Manual configuration by repository maintainers"]
}
```

## Unsupported Application Types

If your application doesn't fit the supported types (e.g., desktop app, mobile app, game), you can still use OpenAnt by:

1. Creating a `OPENANT.md` with the closest matching type
2. Adding detailed `not_a_vulnerability` entries for patterns specific to your application
3. Setting appropriate `trust_boundaries` for your application's input sources

Example for a desktop application (mapped to `cli_tool`):

```json
{
  "application_type": "cli_tool",
  "purpose": "Desktop application for video editing (mapped from desktop_app)",
  "intended_behaviors": [
    "Reads and writes local video files",
    "Uses GPU for rendering",
    "Saves project files to user-specified paths"
  ],
  "trust_boundaries": {
    "user_interface_input": "semi_trusted",
    "project_files": "semi_trusted",
    "local_files": "trusted"
  },
  "security_model": "Local-only application, no network features",
  "not_a_vulnerability": [
    "Path traversal - user selects files via file picker",
    "File writes - user controls save location",
    "DLL/library loading - local application"
  ],
  "requires_remote_trigger": false,
  "confidence": 1.0,
  "evidence": ["Manual configuration - desktop app mapped to cli_tool"]
}
```
