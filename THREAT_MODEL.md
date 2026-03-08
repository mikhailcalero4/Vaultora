# 🛡️ Vaultora Threat Model

**Version:** 1.0
**Date:** March 2026
**Framework:** STRIDE
**Standard:** NIST SP 800-30, OWASP Top 10

---

## 1. System Overview

Vaultora is a secure file storage and transfer web application. Users authenticate
via username/password + TOTP MFA, then upload files which are AES-256 encrypted
before being stored on disk. Every download is integrity-verified against a stored
SHA-256 hash. All actions are audit logged.

---

## 2. Assets

| Asset | Description | Sensitivity |
|---|---|---|
| Uploaded files | Encrypted `.enc` files on disk | Critical |
| AES-256 encryption key | Stored in environment variable | Critical |
| User credentials | PBKDF2-SHA256 hashed passwords in DB | High |
| TOTP secrets | Per-user TOTP seeds in DB | High |
| Session tokens | Flask signed cookies | High |
| Audit logs | Action log with IP and timestamp | Medium |
| Database (`vaultora.db`) | All models: User, File, AuditLog, Metric | High |
| Share links | Password-protected one-use tokens | Medium |

---

## 3. Adversaries

| Adversary | Capability | Goal |
|---|---|---|
| External attacker | Network access, automated tools | Steal files or credentials |
| Malicious insider | Authenticated user account | Escalate privileges, exfiltrate data |
| Script kiddie | Public exploit tools | Deface, DoS, or unauthorized access |
| Malware | Uploaded via file upload | Execute code, spread, exfiltrate |
| Nation-state | Advanced persistent threat | Long-term data exfiltration |

---

## 4. Attack Surface

| Surface | Exposure | Notes |
|---|---|---|
| `/login` POST | Public | Username/password input — brute force target |
| `/two_factor` POST | Semi-public | TOTP input — requires valid credentials first |
| `/upload` POST | Authenticated | File input — malware upload vector |
| `/download/<file>` GET | Authenticated | File retrieval — IDOR risk if not owner-checked |
| `/admin/*` routes | Admin only | Privilege escalation target |
| `/share/<token>` GET | Public | Unauthenticated — token must be unguessable |
| SQLite database file | Local filesystem | Direct file access if server is compromised |
| AES key | Environment variable | Exposed if server environment is compromised |
| Session cookie | Browser | XSS/CSRF/hijacking target |

---

## 5. STRIDE Analysis

### S — Spoofing

| Threat | Attack Vector | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| Credential brute force | Automated POST to `/login` | High | High | Rate limiting (10/min), account lockout via 429 |
| Session hijacking | Stolen cookie via XSS or network sniff | Medium | Critical | Secure/HttpOnly cookies, HSTS, 2hr session expiry |
| TOTP bypass | Replay attack on 6-digit code | Low | High | pyotp enforces 30-second window — replay blocked |
| Fake admin account | Register with admin role | Low | Critical | Role assigned server-side only, never from input |

---

### T — Tampering

| Threat | Attack Vector | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| File tampering at rest | Direct modification of `.enc` file on disk | Low | Critical | AES-256 EAX authenticated encryption — tag verification fails on tamper |
| Hash collision / integrity bypass | Replace file + update DB hash | Very Low | Critical | SHA-256 stored at upload; recomputed and compared on every download |
| Malicious file upload | Upload `.exe`, `.sh`, or malware | Medium | High | ClamAV scan before save, file extension allowlist |
| CSRF form submission | Forged POST from malicious site | Medium | High | flask-wtf CSRF tokens on every form |
| Database tampering | Direct SQLite file modification | Low | High | Audit log append pattern; admin-only access to log view |

---

### R — Repudiation

| Threat | Attack Vector | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| User denies file upload | Claims they never uploaded a file | Medium | Medium | AuditLog records username, filename, IP, timestamp on every upload |
| Admin denies key rotation | Claims rotation never happened | Low | Medium | Key rotation logged as `AuditLog(action="key_rotation")` |
| Attacker covers tracks | Deletes audit log entries | Low | High | Audit log is DB-only, admin-read-only — no delete route exists |

---

### I — Information Disclosure

| Threat | Attack Vector | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| AES key exposure | Key stored in plaintext file | Medium | Critical | Key loaded from env var (`AES_KEY_B64`), never written to disk in production |
| Password exposure | DB breach exposes passwords | Low | Critical | PBKDF2-SHA256 hashing via Werkzeug — no plaintext passwords stored |
| Session token theft | Network interception | Low | High | HSTS enforced via flask-talisman; Secure cookie flag set |
| File path traversal | `../` in filename parameter | Medium | High | `werkzeug.utils.secure_filename()` on every file input |
| Error message leakage | Stack traces in 500 responses | Low | Medium | `FLASK_DEBUG=false` in production; custom error pages |
| TOTP secret exposure | DB breach exposes TOTP seeds | Low | High | Secrets stored in DB — recommend encrypting column in future |

---

### D — Denial of Service

| Threat | Attack Vector | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| Login flood | Automated POST to `/login` | High | Medium | Rate limited to 10 requests/minute per IP — returns 429 |
| Upload flood | Large file spam | Medium | High | 50MB `MAX_CONTENT_LENGTH` limit enforced by Flask |
| Storage exhaustion | Upload many files | Low | Medium | File retention/expiry via APScheduler nightly cleanup |
| ClamAV timeout | Oversized file scan | Low | Low | File size cap prevents oversized scans |

---

### E — Elevation of Privilege

| Threat | Attack Vector | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| IDOR on download | Guess another user's filename | Medium | High | `File.query.filter_by(owner=session["user"])` — only owner can download |
| Role escalation | Modify session cookie | Low | Critical | Session signed with `FLASK_SECRET_KEY` — tampering invalidates signature |
| Admin route access | Regular user hits `/admin/*` | Medium | High | `@role_required("admin")` decorator enforced on all admin routes — returns 403 |
| Insecure direct object reference on delete | POST `/delete/<filename>` for another user's file | Medium | High | Owner check before delete — returns 404 if not owner |

---

## 6. Risk Matrix

```
          │ Low Impact │ Medium Impact │ High Impact │ Critical Impact
──────────┼────────────┼───────────────┼─────────────┼────────────────
High      │            │ Login flood   │ Malware     │
Likelihood│            │               │ upload      │
──────────┼────────────┼───────────────┼─────────────┼────────────────
Medium    │            │ Repudiation   │ IDOR        │ Session
Likelihood│            │               │ Path trav.  │ hijacking
──────────┼────────────┼───────────────┼─────────────┼────────────────
Low       │            │ Error leakage │ DB breach   │ Key exposure
Likelihood│            │               │             │ Role escalation
```

---

## 7. Controls Mapped to NIST SP 800-53

| NIST Control | Control Name | Vaultora Implementation |
|---|---|---|
| AC-2 | Account Management | User model with roles, admin seeding |
| AC-3 | Access Enforcement | `@login_required`, `@role_required` decorators |
| AC-17 | Remote Access | Session-based auth with TOTP MFA |
| AU-2 | Audit Events | AuditLog on every upload, download, delete, login |
| AU-9 | Protection of Audit Info | Admin-only audit log view, no delete route |
| IA-2 | Identification & Authentication | Username + PBKDF2 password + TOTP |
| IA-5 | Authenticator Management | pyotp TOTP, per-user secrets |
| SC-8 | Transmission Confidentiality | HSTS via flask-talisman |
| SC-28 | Protection of Info at Rest | AES-256 EAX encryption on all files |
| SI-3 | Malicious Code Protection | ClamAV malware scanning on upload |
| SI-7 | Software & Info Integrity | SHA-256 integrity check on every download |
| SI-10 | Info Input Validation | `secure_filename`, file type allowlist |

---

## 8. Controls Mapped to OWASP Top 10 (2021)

| OWASP Risk | Vaultora Mitigation |
|---|---|
| A01 Broken Access Control | RBAC with owner-check on all file operations |
| A02 Cryptographic Failures | AES-256 EAX, PBKDF2-SHA256, env-var key storage |
| A03 Injection | SQLAlchemy ORM (parameterized queries), secure_filename |
| A04 Insecure Design | Threat model, defense-in-depth architecture |
| A05 Security Misconfiguration | flask-talisman headers, FLASK_DEBUG=false |
| A06 Vulnerable Components | requirements.txt pinned, pip audit recommended |
| A07 Auth Failures | Rate limiting, TOTP MFA, session expiry |
| A08 Software Integrity Failures | SHA-256 on every download, AES authenticated mode |
| A09 Logging Failures | Full AuditLog + Metric logging on all actions |
| A10 SSRF | No outbound requests from user input; ipapi.co call is server-side only |

---

## 9. Residual Risks & Future Mitigations

| Residual Risk | Priority | Recommended Fix |
|---|---|---|
| TOTP secret stored unencrypted in DB | High | Encrypt `totp_secret` column with AES before storing |
| SQLite not suitable for multi-user production | Medium | Migrate to PostgreSQL for concurrent write safety |
| No account lockout after failed logins | Medium | Add `failed_attempts` counter to User model |
| ClamAV may not be installed on all systems | Medium | Add graceful fallback with warning if pyclamd unavailable |
| Share link tokens stored as plaintext | Low | Hash tokens in DB, compare on lookup |
| No 2FA recovery codes | Low | Generate and store hashed backup codes at registration |