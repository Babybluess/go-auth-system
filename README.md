# authapi

A JWT-authenticated REST API in Go backed by PostgreSQL, with refresh-token rotation, per-IP rate limiting, input validation, and role-based access control.

## Features

- **JWT access tokens** — 15-minute lifetime, signed with HS256
- **Refresh token rotation** — SHA-256-hashed tokens stored in a `sessions` table; each use issues a new token and invalidates the old one
- **Input validation** — `go-playground/validator` with custom `password_strength` rule (requires uppercase, lowercase, and digit)
- **Rate limiting** — `/login` and `/refresh` are limited to 5 requests burst then 1 per 10 seconds per IP
- **Role-based access** — `role` column on users; `RequireRole` middleware for protected routes
- **Integration tests** — `testcontainers-go` spins up a real Postgres instance; `httptest.NewRecorder()` drives every handler

## Setup

### Prerequisites

- Go 1.21+
- PostgreSQL
- Docker (for running tests)

### 1. Create the database and apply migrations

```bash
createdb authapi
psql -d authapi -f migrations/001_create_users.sql
psql -d authapi -f migrations/002_add_role_to_users.sql
psql -d authapi -f migrations/003_create_sessions.sql
```

### 2. Configure environment

Copy or create a `.env` file in the project root:

```env
DATABASE_URL=postgres://postgres:postgres@localhost:5432/authapi?sslmode=disable
JWT_SECRET=change-me-to-a-long-random-string
```

### 3. Run

```bash
go run main.go
# Listening on :8080
```

## API

### `POST /register`

```bash
curl -X POST localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"Secret1"}'
```

```json
{"access_token":"eyJ...","refresh_token":"..."}
```

Password must be at least 8 characters and contain at least one uppercase letter, one lowercase letter, and one digit.

---

### `POST /login`

```bash
curl -X POST localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"Secret1"}'
```

```json
{"access_token":"eyJ...","refresh_token":"..."}
```

Rate-limited: 5 requests burst, then 1 per 10 seconds per IP. Returns `429` with a `Retry-After: 10` header when exceeded.

---

### `POST /refresh`

Exchanges a refresh token for a new access token and a rotated refresh token. The submitted token is immediately invalidated.

```bash
curl -X POST localhost:8080/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"..."}'
```

```json
{"access_token":"eyJ...","refresh_token":"..."}
```

---

### `GET /me` *(requires Bearer token)*

```bash
curl localhost:8080/me \
  -H "Authorization: Bearer eyJ..."
```

```json
{"id":1,"email":"alice@example.com","role":"user","created_at":"2026-06-17T10:00:00Z"}
```

## Testing

Tests use `testcontainers-go` to spin up a real `postgres:16-alpine` container — no mocks, no manual DB setup required. Docker must be running.

```bash
go test ./internal/handlers/ -v
```

The test suite covers:

| Test | What it checks |
|---|---|
| `TestRegister_Success` | 201 + access & refresh tokens returned |
| `TestRegister_InvalidJSON` | 400 on malformed body |
| `TestRegister_WeakPassword` | 400 on validation failure |
| `TestRegister_DuplicateEmail` | 409 on second registration with same email |
| `TestLogin_Success` | 200 + tokens after valid credentials |
| `TestLogin_WrongPassword` | 401 on incorrect password |
| `TestLogin_UnknownEmail` | 401 on unknown email |
| `TestRefresh_Success` | 200 + new token pair |
| `TestRefresh_InvalidToken` | 401 on bogus token |
| `TestRefresh_Rotation` | 401 when the same refresh token is reused |
| `TestMe_Success` | 200 + correct user data, no `password_hash` leak |
| `TestMe_UserNotFound` | 404 for non-existent user ID |
| `TestFullAuthFlow` | register → login → refresh → /me end-to-end |

## Project layout

```
authapi/
├── main.go                          entrypoint, router, middleware wiring
├── .env                             environment config (not committed)
├── migrations/
│   ├── 001_create_users.sql
│   ├── 002_add_role_to_users.sql
│   └── 003_create_sessions.sql
└── internal/
    ├── config/config.go             env-based config struct
    ├── db/db.go                     database connection helper
    ├── models/user.go               User struct
    ├── auth/
    │   ├── jwt.go                   token generation & parsing
    │   ├── middleware.go            Logger, RequireAuth, RequireRole
    │   ├── ratelimit.go             per-IP rate limiter for /login & /refresh
    │   └── token.go                refresh token generation & hashing
    └── handlers/
        ├── auth.go                  POST /register, /login, /refresh
        ├── users.go                 GET /me
        ├── setup_test.go            TestMain — Postgres container + schema
        ├── auth_test.go             handler tests for auth endpoints
        └── users_test.go            handler tests for /me
```
