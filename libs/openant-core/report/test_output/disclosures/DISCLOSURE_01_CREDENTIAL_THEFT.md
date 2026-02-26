# Security Disclosure: Mail Account Credential Theft

**Product:** paperless-ngx
**Type:** CWE-639 (Authorization Bypass Through User-Controlled Key)
**Affected:** All versions with mail account functionality

## Summary

Mail account test endpoint fetches stored credentials when user submits asterisks as password. No ownership verification before fetching, allowing any authenticated user to steal another user's email credentials.

## Vulnerable Code

`src/paperless_mail/views.py`:

```python
if (
    len(serializer.validated_data.get("password").replace("*", "")) == 0
    and request.data["id"] is not None
):
    # No ownership check
    existing_account = MailAccount.objects.get(pk=request.data["id"])
    serializer.validated_data["password"] = existing_account.password
```

Asterisk pattern is a legitimate UX feature. The bug is missing authorization before fetching credentials.

## Steps to Reproduce

**Prerequisites:**
- Paperless-ngx instance with two user accounts
- Victim has configured a mail account
- Attacker has any authenticated account

**Step 1:** Set up a credential capture server (simple IMAP mock that logs LOGIN commands)

**Step 2:** As admin, create a victim user and configure their mail account with a secret password

**Step 3:** As attacker, obtain an authentication token via POST /api/token/

**Step 4:** As attacker, send POST /api/mail_accounts/test/ with victim's account ID, password="**********", and imap_server pointing to attacker's capture server

**Step 5:** Observe the capture server receives the victim's plaintext password

**Tested:** Docker (ghcr.io/paperless-ngx/paperless-ngx:latest), 2026-01-26.

## Impact

- Any authenticated user can steal any other user's mail credentials
- Credentials include passwords, OAuth tokens, and refresh tokens
- Mail account IDs are sequential integers (easy to enumerate)
- Compromised credentials enable access to victim's email inbox

## Suggested Fix

Add ownership verification:

```python
if (
    len(serializer.validated_data.get("password").replace("*", "")) == 0
    and request.data["id"] is not None
):
    existing_account = MailAccount.objects.get(pk=request.data["id"])

    # Add ownership check
    if existing_account.owner != request.user and not request.user.is_superuser:
        raise PermissionDenied("Not authorized")

    serializer.validated_data["password"] = existing_account.password
```

---

Discovered via static analysis. Confirmed via dynamic testing.
