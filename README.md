# SafeVault (Activity 3) — Debug & Fix SQLi + XSS + Tests + Summary

This final activity hardens SafeVault by:
- eliminating SQL injection risks (no string concatenation; parameterized queries)
- reducing XSS risk (strict input validation + output encoding in HTML responses)
- adding security headers (CSP, X-Content-Type-Options, etc.)
- adding tests that simulate SQLi/XSS attacks and verify the fixes

## Run
- dotnet test
- dotnet run --project SafeVault.Api

## Endpoints (demo)
- POST /auth/register
- POST /auth/login
- GET  /me (JWT required)
- GET  /admin/dashboard (Admin role required)
- POST /comments (JWT required)
- GET  /profile (JWT required) — returns HTML safely encoded
