package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"authapi/internal/handlers"
)

func TestRegister_Success(t *testing.T) {
	truncateTables(t)
	h := newAuthHandler()

	w := doRequest(h.Register, http.MethodPost, `{"email":"user@example.com","password":"Password1"}`)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	tokens := decodeTokens(t, w)
	if tokens["access_token"] == "" || tokens["refresh_token"] == "" {
		t.Error("expected non-empty tokens")
	}
}

func TestRegister_InvalidJSON(t *testing.T) {
	truncateTables(t)
	h := newAuthHandler()

	w := doRequest(h.Register, http.MethodPost, `{bad json`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestRegister_WeakPassword(t *testing.T) {
	truncateTables(t)
	h := newAuthHandler()

	w := doRequest(h.Register, http.MethodPost, `{"email":"user@example.com","password":"weak"}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	truncateTables(t)
	h := newAuthHandler()

	body := `{"email":"dup@example.com","password":"Password1"}`

	w1 := doRequest(h.Register, http.MethodPost, body)
	if w1.Code != http.StatusCreated {
		t.Fatalf("first register: expected 201, got %d", w1.Code)
	}

	w2 := doRequest(h.Register, http.MethodPost, body)
	if w2.Code != http.StatusConflict {
		t.Fatalf("second register: expected 409, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestLogin_Success(t *testing.T) {
	truncateTables(t)
	h := newAuthHandler()

	doRequest(h.Register, http.MethodPost, `{"email":"login@example.com","password":"Password1"}`)

	w := doRequest(h.Login, http.MethodPost, `{"email":"login@example.com","password":"Password1"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	tokens := decodeTokens(t, w)
	if tokens["access_token"] == "" || tokens["refresh_token"] == "" {
		t.Error("expected non-empty tokens")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	truncateTables(t)
	h := newAuthHandler()

	doRequest(h.Register, http.MethodPost, `{"email":"pw@example.com","password":"Password1"}`)

	w := doRequest(h.Login, http.MethodPost, `{"email":"pw@example.com","password":"WrongPass1"}`)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestLogin_UnknownEmail(t *testing.T) {
	truncateTables(t)
	h := newAuthHandler()

	w := doRequest(h.Login, http.MethodPost, `{"email":"nobody@example.com","password":"Password1"}`)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRefresh_Success(t *testing.T) {
	truncateTables(t)
	h := newAuthHandler()

	regW := doRequest(h.Register, http.MethodPost, `{"email":"ref@example.com","password":"Password1"}`)
	tokens := decodeTokens(t, regW)

	refreshBody, _ := json.Marshal(map[string]string{"refresh_token": tokens["refresh_token"]})
	req := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewBuffer(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Refresh(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	newTokens := decodeTokens(t, w)
	if newTokens["access_token"] == "" || newTokens["refresh_token"] == "" {
		t.Error("expected new tokens in response")
	}
}

func TestRefresh_InvalidToken(t *testing.T) {
	truncateTables(t)
	h := newAuthHandler()

	w := doRequest(h.Refresh, http.MethodPost, `{"refresh_token":"notavalidtoken"}`)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRefresh_Rotation(t *testing.T) {
	truncateTables(t)
	h := newAuthHandler()

	regW := doRequest(h.Register, http.MethodPost, `{"email":"rot@example.com","password":"Password1"}`)
	tokens := decodeTokens(t, regW)
	refreshBody, _ := json.Marshal(map[string]string{"refresh_token": tokens["refresh_token"]})

	// First use — must succeed.
	req1 := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewBuffer(refreshBody))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	h.Refresh(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first refresh: expected 200, got %d", w1.Code)
	}

	// Reuse of the consumed token must be rejected (rotation).
	req2 := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewBuffer(refreshBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	h.Refresh(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("reused token: expected 401, got %d", w2.Code)
	}
}

// newAuthHandler returns an AuthHandler wired to the shared test database.
func newAuthHandler() *handlers.AuthHandler {
	return &handlers.AuthHandler{DB: testDB}
}

// doRequest fires a handler with a JSON body and returns the recorded response.
func doRequest(handler http.HandlerFunc, method, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

// decodeTokens unmarshals an access/refresh token pair from the response body.
func decodeTokens(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var m map[string]string
	if err := json.NewDecoder(w.Body).Decode(&m); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return m
}
