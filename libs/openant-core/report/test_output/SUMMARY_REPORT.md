# paperless-ngx Security Analysis

**Repository:** https://github.com/paperless-ngx/paperless-ngx
**Analysis Date:** 2026-01-26
**Application Type:** web_app

## Results

| Verdict | Count |
|---------|-------|
| Vulnerable | 5 |
| Safe | 16 |
| Protected | 3 |
| Inconclusive | 0 |
| Error | 0 |

## Pipeline Statistics

- Parsed: 944 functions from 83 files
- After reachability filter: 81 units
- After CodeQL filter: 24 units
- Analyzed in Stage 1: 24 units
- Verified in Stage 2: 10 findings

## Confirmed Vulnerabilities

| # | Vulnerability | Location | CWE | Verified |
|---|--------------|----------|-----|----------|
| 1 | Credential Theft | src/paperless_mail/views.py:MailAccountViewSet.test | CWE-639 | dynamic |
| 2 | IDOR Notes Deletion | src/documents/views.py:DocumentViewSet.notes | CWE-639 | dynamic |
| 3 | Email Abuse | src/documents/views.py:DocumentViewSet.email_documents | CWE-284 | dynamic |
| 4 | Bulk Download DoS | src/documents/views.py:BulkDownloadView.post | CWE-400 | dynamic |
| 5 | Mail Parser DoS | src/paperless_mail/parsers.py:MailDocumentParser.parse_file_to_message | CWE-400 | static |

## False Positives Eliminated

| Finding | Stage 1 | Stage 2 | Reason |
|---------|---------|---------|--------|
| Trash Restore Bypass | vulnerable | protected | global_objects includes deleted documents; permission check works correctly |
| ConsumerPlugin._write | path_traversal | protected | Paths are system-generated with sanitization |
| Command.handle (export) | zip_slip | safe | CLI command, not web-accessible |
| BulkEditObjectsView.post | toctou | protected | Race condition not practically exploitable |

## Methodology

Two-stage analysis:
1. Stage 1: LLM-based vulnerability detection on filtered code units
2. Stage 2: Attacker simulation to verify exploitability

Attacker model: Remote attacker with browser access, no server-side access, no admin credentials.
