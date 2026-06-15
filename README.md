# authapi

A minimal JWT-authenticated REST API in Go, backed by PostgreSQL.

## Setup

1. Create a database and apply the migration:

   ```bash
   createdb authapi
   psql -d authapi -f migrations/001_create_users.sql
   ```

2. Install dependencies:

   ```bash
   go mod tidy
   ```

3. (Optional) set your database URL:

   ```bash
   export DATABASE_URL="postgres://postgres:postgres@localhost:5432/authapi?sslmode=disable"
   ```

4. Run the server:

   ```bash
   go run main.go
   ```

## Try it

```bash
# create an account
curl -X POST localhost:8080/register \
  -d '{"email":"a@b.com","password":"hunter2"}'
# -> {"token":"eyJ..."}

# access a protected route
curl localhost:8080/me \
  -H "Authorization: Bearer eyJ..."
# -> {"id":1,"email":"a@b.com","created_at":"..."}
```

## Project layout

```
authapi/
├── main.go                      entrypoint, router, middleware wiring
├── internal/
│   ├── db/db.go                 database connection
│   ├── auth/jwt.go               token generation & parsing
│   ├── auth/middleware.go       Logger and RequireAuth middleware
│   ├── models/user.go            User struct
│   └── handlers/
│       ├── auth.go               /register, /login
│       └── users.go              /me (protected)
└── migrations/001_create_users.sql
```

## Next steps

- Add refresh tokens + a sessions table
- Move config (JWT secret, DSN, port) into env-based config struct
- Add input validation (e.g. go-playground/validator)
- Rate-limit /login
- Add role-based access control
- Write handler tests with httptest + testcontainers-go
