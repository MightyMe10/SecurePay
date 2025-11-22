# Secure Pay

Secure Pay is a hardened Flask application that delivers MFA-protected account access, internal fund transfers, and an auditable transaction history. The app is designed for instructional use and showcases layered defenses such as Argon2 password hashing, encrypted TOTP seeds, RBAC, CSRF protection, and strict security headers.

## Operational Readiness Notice

Secure Pay is an instructional reference implementation showcasing layered security patterns (MFA, RBAC, session governance, hardened headers). While care has been taken to apply industry best practices, it has not undergone formal penetration testing, third‑party code audit, or compliance validation. Treat this codebase as a learning and demo asset.

Before any production deployment you must:
- Perform a full security review (threat modeling, dependency audit, dynamic/penetration testing).
- Replace SQLite with a hardened, encrypted production database.
- Centralize secrets (no .env files) and enable monitored secret rotation.
- Enforce TLS everywhere and add monitoring/alerting for auth events.
- Apply continuous patch management (Dependabot / CodeQL / SBOM scanning).

Using the repository “as is” for real financial transactions is not advised until these steps are completed. This notice does not reflect negatively on the quality of the implementation; it clarifies scope and encourages responsible adoption.

## Features

- User onboarding with password-policy enforcement and automatic account provisioning.
- MFA login flow that validates passwords and 6-digit TOTP codes before establishing a session.
- Account dashboard with balance summary plus recent activity snapshot.
- Internal fund transfer workflow secured with CSRF tokens and server-side validation.
- Beneficiary (contact) management so users can store frequently used recipients.
- Device management center that lists active sessions and lets users log out suspicious devices.
- Admin-only console with freeze/unfreeze and forced password reset actions per user.
- MFA-protected in-portal password reset flow for end users.
- Transaction history viewer and admin-only panel that lists all users/accounts.

## Security Controls

| Control                       | Implementation                                                                                       | Threat Mitigated                                |
| ----------------------------- | ---------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| Strong password policy        | WTForms validators + `security.validate_password_strength` enforce 12+ chars, mixed classes          | Weak/stolen passwords                           |
| Argon2id hashing              | `argon2-cffi` hashes stored via `security.hash_password` with optional rehash                        | Credential cracking & broken authentication     |
| Encrypted TOTP seeds          | Secrets encrypted with Fernet before persisting; decrypted only when validating codes                | Sensitive data exposure, MFA bypass via DB leak |
| TOTP-based MFA                | `pyotp` verifies 6-digit codes with ±1 window                                                        | Account takeover even with leaked password      |
| RBAC                          | `decorators.role_required` restricts `/admin` routes to admins                                       | Privilege escalation                            |
| Session hardening             | HttpOnly/SameSite cookies, optional Secure flag, 30-minute lifetime, Flask-Login "strong" protection | Session hijacking & fixation                    |
| Account lockout               | Failed-login counter compared to `MAX_LOGIN_ATTEMPTS`                                                | Brute-force attacks                             |
| CSRF mitigation               | Flask-WTF global `CSRFProtect`, `form.hidden_tag()` on all state-changing forms                      | CSRF                                            |
| CSP + headers                 | `register_security_headers` sets CSP, X-Frame-Options, Referrer-Policy, etc.                         | XSS, clickjacking                               |
| Parameterized DB access       | SQLAlchemy ORM and helper methods prevent string-concatenated SQL                                    | SQL injection                                   |
| Input validation/sanitization | WTForms validators (email/account regex, numeric enforcement) + Jinja auto-escaping                  | XSS & data integrity                            |
| Device/session monitoring     | `ActiveSession` records tied to browser fingerprint + `/devices` termination UI                      | Session hijacking detection & response          |
| Admin account governance      | `/admin` console enforces RBAC, freeze/unfreeze, and temporary password resets                       | Unauthorized access persistence                 |
| MFA password resets           | `/settings/password` demands current password + valid TOTP before applying Argon2 hashing            | Compromised session abuse                       |

### Additional Recommendations

- Run behind TLS (`https://`) in production so Secure/HSTS cookies are honored.
- Keep environment secrets (`SECRET_KEY`, `SECURITY_PASSWORD_SALT`, `TOTP_ENCRYPTION_KEY`) in a vault or OS-level secret store.

## Getting Started

```powershell
# 1. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment (example)
$env:FLASK_ENV = "development"
$env:SECRET_KEY = "replace-me"
$env:SECURITY_PASSWORD_SALT = "another-random-string"
# Optional but recommended 32-byte urlsafe base64 key
$env:TOTP_ENCRYPTION_KEY = "b64encodedfernetkey=="

# 4. Initialize the SQLite database
flask --app app init-db

# 5. (Optional) Create an admin user with MFA seed output
flask --app app create-admin

# 6. Run the dev server with reloader
flask --app app run --debug
```

The CLI prompts for secure inputs via `getpass` and prints the generated MFA seed once so that it can be registered in any authenticator app.

## Configuration Reference

| Variable                     | Default                   | Notes                                                                 |
| ---------------------------- | ------------------------- | --------------------------------------------------------------------- |
| `FLASK_ENV`                  | `production`              | Use `development` for verbose errors / insecure cookies.              |
| `SECRET_KEY`                 | `dev-change-me`           | Required for session + CSRF signing; set to 32+ random bytes in prod. |
| `DATABASE_URL`               | `sqlite:///secure_pay.db` | Point to PostgreSQL/MySQL URI for production.                         |
| `SECURITY_PASSWORD_SALT`     | `set-a-random-salt`       | Used for potential future token signing.                              |
| `TOTP_ENCRYPTION_KEY`        | derived from `SECRET_KEY` | Provide your own 32-byte base64 key to isolate MFA secret encryption. |
| `MAX_LOGIN_ATTEMPTS`         | `5`                       | Lockout threshold for failed logins.                                  |
| `PERMANENT_SESSION_LIFETIME` | 30 minutes                | Controls the Flask session lifetime.                                  |

## Project Structure

```
secure_pay/
├── __init__.py          # Factory, extensions, CLI helpers, security headers
├── config.py            # Environment-specific configuration
├── decorators.py        # RBAC helpers
├── extensions.py        # SQLAlchemy, LoginManager, CSRFProtect instances
├── forms.py             # WTForms for auth, transfers, admin controls, beneficiaries
├── models.py            # Users, Accounts, Transactions, Beneficiaries, ActiveSessions
├── routes.py            # Auth + portal blueprints (transfers, devices, admin, settings)
├── security.py          # Password policy, Argon2 hashing, encrypted TOTP helpers
├── templates/           # Jinja2 templates
└── static/css/          # Minimal styling
```

## Testing the Build Task

A VS Code task named **"Compile Secure Pay"** runs `python -m compileall secure_pay` using the workspace virtual environment. You can re-run it via **Terminal → Run Task** to ensure all modules are syntactically sound before deployment.

## Next Steps

- Integrate an outbound email/SMS service if out-of-band alerts are required.
- Replace SQLite with a managed relational database for production workloads.
