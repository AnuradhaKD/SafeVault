## SafeVault Activity 3 — Summary

### Vulnerabilities identified
1) SQL Injection risk
- Any query built using string concatenation with user input can be exploited.
- Risk areas: user lookups, search/filter queries, ORDER BY clauses built from request values.

2) XSS (Cross-Site Scripting) risk
- Any user-generated content rendered into HTML without encoding can execute scripts.
- Risk areas: profile pages, dashboards, comment displays, admin tools.

### Fixes applied
1) SQL Injection fixes
- Implemented repositories using parameterized queries only (@username, @email, etc.).
- For dynamic sorting, used an allowlist mapping (never inject raw column names).
- Added tests ensuring attacker input is not present in SQL command text.

2) XSS fixes
- Kept strict input validation for username/email.
- Added output encoding before embedding user values into HTML (HtmlEncoder).
- Added tests that submit XSS payloads and verify HTML output is escaped (&lt; ... &gt;).

3) Added Security Headers (defense-in-depth)
- Content-Security-Policy (CSP)
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Referrer-Policy

### How Copilot assisted (for your report)
- Flagged vulnerable patterns (string concatenation SQL, raw HTML rendering).
- Suggested secure replacements (parameterized queries, encoding helpers, allowlist strategy).
- Generated realistic attack tests (SQLi: ' OR '1'='1, XSS: <script>... ).
- Helped iterate quickly by producing code + tests and refining until tests passed.
