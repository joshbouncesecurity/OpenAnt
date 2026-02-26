# OpenAnt Two-Stage Vulnerability Analysis

**Created**: December 26, 2024
**Status**: IMPLEMENTED WITH ATTACKER SIMULATION (January 14, 2026)

---

## Overview

OpenAnt uses a two-stage approach for vulnerability analysis. Stage 1 detects potential issues with simple, direct prompts. Stage 2 verifies each finding using Opus with tool access to explore the codebase.

---

## Key Insight: Simple Prompts Work Better

The original implementation had complex, multi-step instructions. Testing revealed that **simple, direct prompts produce better results**:

- Ask direct questions: "What does this code do?" and "What is the security risk?"
- Trust the model's capabilities
- Use nuanced categories instead of binary VULNERABLE/SAFE

---

## Finding Categories

Five categories capture the spectrum of security states:

| Category | Meaning | Action |
|----------|---------|--------|
| `vulnerable` | Exploitable vulnerability, no protection | Immediate fix required |
| `bypassable` | Security controls exist but can be circumvented | Review and strengthen |
| `inconclusive` | Security posture cannot be determined | Manual review needed |
| `protected` | Handles dangerous operations with effective controls | Monitor |
| `safe` | No security-sensitive operations | None |

---

## Stage 1: Vulnerability Detection

**Prompt:** Simple and direct

```
Assess this code for security.

## Context
Route: {route}
Files: {files}
Pre-analysis hint: {security_classification}

## Code
```{language}
{code}
```

## Response
1. What does this code do?
2. What is the security risk?

Provide your assessment as JSON:
{
    "finding": "safe" | "protected" | "bypassable" | "vulnerable" | "inconclusive",
    "attack_vector": "How this could be exploited, or null if safe/protected",
    "reasoning": "...",
    "confidence": 0.0-1.0
}
```

**Implementation:** `prompts/vulnerability_analysis.py`

---

## Stage 2: Finding Verification (Attacker Simulation)

Stage 2 verifies **all findings** using Opus with tool access and **attacker simulation**.

**Key Breakthrough (Jan 14, 2026):** Changed from "code analysis mode" to "attacker simulation mode". The model role-plays as an attacker with only a browser, attempting to exploit the vulnerability step-by-step. This naturally surfaces roadblocks that make theoretical vulnerabilities unexploitable.

**System Prompt:**
```
You are a penetration tester. You only report vulnerabilities you can actually exploit.
```

**User Prompt:**
```
Stage 1 claims this function is **{finding}**.
Their reasoning: {reasoning}

>>> TARGET FUNCTION <<<
{primary_code}

Context:
{context_code}

---

You are an attacker on the internet. You have a browser and nothing else.
No server access, no admin credentials, no ability to modify files on the server.

Try to exploit this code using MULTIPLE different approaches. Think about:
- What different inputs can you control?
- What different properties/fields can you manipulate?
- What different endpoints or entry points exist?

For EACH approach, trace through step by step until you succeed or hit a blocker.

IMPORTANT:
- Only conclude PROTECTED or SAFE if ALL approaches fail. If ANY approach succeeds, conclude VULNERABLE.
- A vulnerability must harm someone OTHER than the attacker.
```

**Why it works:**

1. **Attacker Simulation:** The model has the knowledge to identify false positives, but only applies it when forced to **simulate being an attacker** rather than **analyze code**. When simulating an attack, the model naturally hits roadblocks:
   - "I can't create symlinks on the server because I don't have filesystem access"
   - "I can only SELECT from admin-configured endpoints, not provide arbitrary URLs"

2. **Multi-Approach Requirement:** Single-path exploration missed vulnerabilities where one property was protected but another wasn't (e.g., `workspaceId` protected but `id` injectable for mass assignment). Requiring MULTIPLE approaches ensures exhaustive testing.

**Results:** 0 false positives on object-browser (25 units)

### Available Tools

| Tool | Purpose |
|------|---------|
| `search_usages` | Find where a function is called |
| `search_definitions` | Find where a function is defined |
| `read_function` | Get full function code by ID |
| `list_functions` | List all functions in a file |
| `finish` | Complete verification with verdict |

**Implementation:**
- `utilities/finding_verifier.py` - Main verification logic
- `prompts/verification_prompts.py` - Attacker simulation prompts (moved from utilities/ Jan 14)

---

## Architecture

```
experiment.py
     │
     ▼
┌─────────────────┐
│  STAGE 1        │
│  ───────────────│
│  Simple prompt  │
│  Direct questions│
│  5 categories   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  STAGE 2        │
│  ───────────────│
│  Opus + Tools   │
│  Validate ALL   │
│  Agree/Disagree │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  PRODUCTS       │
│  ───────────────│
│  CSV export     │
│  HTML report    │
└─────────────────┘
```

---

## Test Results

### Object-Browser (25 units - Attacker Simulation)

| Metric | Value |
|--------|-------|
| Units analyzed | 25 |
| Final VULNERABLE | **0** |
| Final SAFE | 23 |
| Final PROTECTED | 2 |
| False positive rate | **0%** |

**Prompt evolution:** 10 → 5 → 3 → 2 → 0 vulnerabilities over 7 iterations

**False positive categories eliminated:**
1. Admin-controlled input treated as attack vector (CLI args, config files)
2. Standard security patterns misidentified (OAuth/STS URL parameters)
3. Platform security boundaries ignored (S3 ACLs, admin-configured endpoints)
4. Context confusion/hallucination (model attributed concerns from context to target)

### Flowise (13 units)

| Stage 2 Outcome | Count |
|-----------------|-------|
| Agreed with Stage 1 | 11 |
| Corrected Stage 1 | 2 |

**Corrections made:**
- Playwright: protected → vulnerable (symlink bypass)
- Puppeteer: protected → vulnerable (symlink bypass)

**Final distribution:**

| Category | Count |
|----------|-------|
| vulnerable | 5 |
| bypassable | 7 |
| protected | 1 |

---

## Usage

```bash
# Stage 1 only
python experiment.py --dataset flowise

# Stage 1 + Stage 2 verification
python experiment.py --dataset flowise --verify --verify-verbose
```

**Output:** `experiment_{name}_{timestamp}.json`

---

## Product Export

### CSV Export

```bash
python export_csv.py experiment.json dataset.json output.csv
```

Columns: file, unit_id, unit_description, unit_code, stage2_verdict, stage2_justification, stage1_verdict, stage1_justification, stage1_confidence, agentic_classification

### HTML Report

```bash
python generate_report.py experiment.json dataset.json report.html
```

Features:
- Stats overview cards
- Interactive pie charts with labels/percentages
- Category explanation table
- LLM-generated remediation guidance
- Findings table sorted by severity

---

## Cost Analysis

| Stage | Model | Cost per Unit | Notes |
|-------|-------|---------------|-------|
| Stage 1 | Opus | ~$0.20 | Single call |
| Stage 2 | Opus | ~$1.05 | Agentic (10-20 iterations) |
| Report | Sonnet | ~$0.05 | Remediation guidance |

**Total per unit:** ~$1.25 for full two-stage analysis

---

## Files

### Core
```
experiment.py              - Main experiment runner
export_csv.py              - CSV export
generate_report.py         - HTML report with LLM remediation
```

### Prompts
```
prompts/
  vulnerability_analysis.py        - Unified Stage 1 prompt (language-agnostic)
  verification_prompts.py          - Stage 2 attacker simulation prompt
  prompt_selector.py               - Routes to vulnerability_analysis prompt
```

### Verification
```
utilities/
  finding_verifier.py      - Stage 2 verification with Opus + tools
  verification_prompts.py  - Stage 2 prompts
```

---

## Key Design Decisions

1. **Attacker simulation > Code analysis**: Force the model to role-play as an attacker, not analyze code
2. **No rules needed**: The constraint "you have a browser and nothing else" replaces complex rules
3. **Simple prompts**: Direct questions work better than complex instructions
4. **Nuanced categories**: 5-level spectrum captures security reality
5. **Verify all findings**: Stage 2 checks everything, not just vulnerabilities
6. **Target function marking**: Clear `>>> TARGET FUNCTION <<<` markers prevent context confusion

---

## Completed Tasks

- [x] Create `utilities/finding_verifier.py`
- [x] Create `prompts/verification_prompts.py`
- [x] Modify `experiment.py` with Stage 2 loop
- [x] Add CLI flags (`--verify`, `--verify-verbose`)
- [x] Test on Flowise 13 units
- [x] Simplify Stage 1 prompt (Dec 28)
- [x] Simplify Stage 2 prompt (Dec 28)
- [x] Add 5-category finding system (Dec 28)
- [x] Create CSV export (Dec 28)
- [x] Create HTML report with charts (Dec 28)
- [x] Move verification_prompts.py to prompts/ directory (Jan 14, 2026)
- [x] Implement attacker simulation prompt (Jan 14, 2026)
- [x] Add target function marking to prevent context confusion (Jan 14, 2026)
- [x] Achieve 0% false positive rate on object-browser (Jan 14, 2026)
- [x] Add multi-approach requirement to prevent premature PROTECTED conclusions (Jan 19, 2026)
- [x] Add victim requirement - vulnerability must harm someone other than the attacker (Jan 19, 2026)

---

## Related Documentation

- `CURRENT_IMPLEMENTATION.md` - Overall project status
- `parsers/javascript/PARSER_PIPELINE.md` - Parser pipeline
- `datasets/flowise/FLOWISE_JAVASCRIPT_REPOSITORY_COST_ESTIMATES.md` - Cost estimates
