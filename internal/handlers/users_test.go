package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"authapi/internal/auth"
	"authapi/internal/handlers"
)

func TestMe_Success(t *testing.T) {
	truncateTables(t)

	authH := &handlers.AuthHandler{DB: testDB}
	userH := &handlers.UserHandler{DB: testDB}

	regW := doRequest(authH.Register, http.MethodPost, `{"email":"me@example.com","password":"Password1"}`)
	if regW.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d: %s", regW.Code, regW.Body.String())
	}

	var tokens map[string]string
	json.NewDecoder(regW.Body).Decode(&tokens)

	claims, err := auth.ParseToken(tokens["access_token"])
	if err != nil {
		t.Fatalf("parse access token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	ctx := context.WithValue(req.Context(), auth.UserIDKey, claims.UserID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	userH.Me(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var user map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&user); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if user["email"] != "me@example.com" {
		t.Errorf("expected email me@example.com, got %v", user["email"])
	}
	if _, ok := user["password_hash"]; ok {
		t.Error("password_hash must not appear in response")
	}
}

func TestMe_UserNotFound(t *testing.T) {
	truncateTables(t)

	userH := &handlers.UserHandler{DB: testDB}

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	ctx := context.WithValue(req.Context(), auth.UserIDKey, 99999)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	userH.Me(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// Register a user, log in, get /me — full happy path across all handlers.
func TestFullAuthFlow(t *testing.T) {
	truncateTables(t)

	authH := &handlers.AuthHandler{DB: testDB}
	userH := &handlers.UserHandler{DB: testDB}

	// Register
	regW := doRequest(authH.Register, http.MethodPost, `{"email":"flow@example.com","password":"Password1"}`)
	if regW.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", regW.Code)
	}

	// Login with fresh recorder (body already read above)
	loginW := doRequest(authH.Login, http.MethodPost, `{"email":"flow@example.com","password":"Password1"}`)
	if loginW.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d", loginW.Code)
	}

	var tokens map[string]string
	json.NewDecoder(loginW.Body).Decode(&tokens)

	// Refresh
	refreshBody, _ := json.Marshal(map[string]string{"refresh_token": tokens["refresh_token"]})
	req := httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewBuffer(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	refreshW := httptest.NewRecorder()
	authH.Refresh(refreshW, req)
	if refreshW.Code != http.StatusOK {
		t.Fatalf("refresh: expected 200, got %d", refreshW.Code)
	}

	var newTokens map[string]string
	json.NewDecoder(refreshW.Body).Decode(&newTokens)

	// /me with new access token
	claims, err := auth.ParseToken(newTokens["access_token"])
	if err != nil {
		t.Fatalf("parse refreshed token: %v", err)
	}
	meReq := httptest.NewRequest(http.MethodGet, "/me", nil)
	meCtx := context.WithValue(meReq.Context(), auth.UserIDKey, claims.UserID)
	meReq = meReq.WithContext(meCtx)
	meW := httptest.NewRecorder()
	userH.Me(meW, meReq)

	if meW.Code != http.StatusOK {
		t.Fatalf("/me: expected 200, got %d", meW.Code)
	}
}
