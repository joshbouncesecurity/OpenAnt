# Running OpenAnt with Local Claude Code

Use the local Claude Code session for authentication instead of an API key.

## Prerequisites

- Claude Code CLI (`claude`) on PATH
- An authenticated Claude Code session (run `claude` once to log in)

## Setup

```powershell
cd libs\openant-core

# Create and activate a venv
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install Python dependencies
pip install -r requirements.txt

# Install JS parser dependencies (needed for JavaScript/TypeScript repos)
cd parsers\javascript
npm install
cd ..\..

# Configure environment (add to .env file)
Add-Content .env "OPENANT_LOCAL_CLAUDE=true"

# Point to your Claude Code config directory
Add-Content .env "CLAUDE_CONFIG_DIR=C:\Users\YourUser\.claude-k"
```

## Running a scan

```powershell
cd libs\openant-core

# Basic scan
python -m openant scan C:\path\to\repo

# Specify language
python -m openant scan C:\path\to\repo -l javascript

# With Stage 2 attacker simulation
python -m openant scan C:\path\to\repo --verify

# Use sonnet (cheaper) instead of opus
python -m openant scan C:\path\to\repo --model sonnet

# Limit number of units analyzed
python -m openant scan C:\path\to\repo --limit 10

# Output to a specific directory
python -m openant scan C:\path\to\repo -o .\results
```

## Individual pipeline steps

```powershell
# Parse only
python -m openant parse C:\path\to\repo -o .\output

# Enhance a parsed dataset
python -m openant enhance dataset.json --repo-path C:\path\to\repo

# Analyze a dataset
python -m openant analyze dataset.json

# Analyze with verification
python -m openant analyze dataset.json --verify
```

## Environment variables

| Variable | Description |
|---|---|
| `OPENANT_LOCAL_CLAUDE` | Set to `true` to use local Claude Code session (no API key needed) |
| `CLAUDE_CONFIG_DIR` | Path to your Claude Code config directory (e.g. `C:\Users\You\.claude-k`) |
| `ANTHROPIC_API_KEY` | Required only when `OPENANT_LOCAL_CLAUDE` is not `true` |

## How it works

When `OPENANT_LOCAL_CLAUDE=true`, OpenAnt calls `claude -p` (print mode) as a
subprocess instead of using the Anthropic API directly. This uses the local
Claude Code session's authentication, so no API key is needed. The
`CLAUDE_CONFIG_DIR` env var tells the CLI which config/session to use.
