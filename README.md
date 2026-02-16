# SafeVault (Activity 1) — Secure Input + Parameterized Queries + Tests

This sample uses **ASP.NET Core Minimal API** + **MySqlConnector** + **NUnit**.

## What’s included
- Server-side input validation (allowlist + length checks)
- Output encoding to reduce XSS risk
- Parameterized queries to prevent SQL injection
- NUnit tests that simulate SQLi / XSS-style inputs and verify they’re blocked

## Run
1. Install .NET 8 SDK
2. From repo root:
   - `dotnet test`
   - `dotnet run --project SafeVault.Api`

## Notes
- Client-side validation is helpful UX, but **server-side validation is the real protection**.
- For real apps, also add:
  - CSP + security headers
  - CSRF protection for form posts
  - Authentication/authorization

# SafeVault (Activity 2) — Authentication + RBAC + Tests

This extends Activity 1 with:

- Secure password hashing (**bcrypt**)
- Login that returns a **JWT**
- Role-Based Access Control (RBAC) using ASP.NET Core authorization policies
- Integration tests for:
  - invalid login attempts
  - unauthorized/forbidden access to admin routes
  - successful admin access

## Quick start
1) Install .NET 8 SDK
2) From repo root:
   - `dotnet test`
   - `dotnet run --project SafeVault.Api`

The API uses an **in-memory repository by default** (so you can run/tests without MySQL).
You can swap to MySQL later by implementing `IUserRepository` with parameterized queries.

## Endpoints
- `POST /auth/register`  (creates user with role User/Admin)
- `POST /auth/login`     (returns JWT)
- `GET  /me`             (authenticated)
- `GET  /admin/dashboard` (Admin role only)



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
