package handlers_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var testDB *sql.DB

// schema consolidates all migrations so the test container starts from scratch each run.
const schema = `
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';
CREATE TABLE IF NOT EXISTS sessions (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_token_hash_idx ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx    ON sessions(user_id);
`

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

// run wraps the actual test execution so deferred container cleanup fires before os.Exit.
func run(m *testing.M) int {
	ctx := context.Background()

	ctr, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		// Wait until Postgres logs its ready message twice: once for template DB init,
		// once for actual readiness. Without this the schema exec races the server startup.
		tc.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start postgres container: %v\n", err)
		return 1
	}
	defer func() {
		if err := ctr.Terminate(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "terminate postgres container: %v\n", err)
		}
	}()

	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection string: %v\n", err)
		return 1
	}

	testDB, err = sql.Open("postgres", connStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open db: %v\n", err)
		return 1
	}
	defer testDB.Close()

	if _, err = testDB.ExecContext(ctx, schema); err != nil {
		fmt.Fprintf(os.Stderr, "run schema: %v\n", err)
		return 1
	}

	return m.Run()
}

// truncateTables resets all data between tests so each test starts with a clean state.
func truncateTables(t *testing.T) {
	t.Helper()
	if _, err := testDB.Exec(`TRUNCATE TABLE sessions, users RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate tables: %v", err)
	}
}
