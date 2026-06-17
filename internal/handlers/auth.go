package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unicode"

	"authapi/internal/auth"

	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

var validate *validator.Validate

func init() {
	validate = validator.New(validator.WithRequiredStructEnabled())
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name, _, _ := strings.Cut(fld.Tag.Get("json"), ",")
		if name == "-" {
			return ""
		}
		return name
	})
	validate.RegisterValidation("password_strength", func(fl validator.FieldLevel) bool {
		var hasUpper, hasLower, hasDigit bool
		for _, c := range fl.Field().String() {
			switch {
			case unicode.IsUpper(c):
				hasUpper = true
			case unicode.IsLower(c):
				hasLower = true
			case unicode.IsDigit(c):
				hasDigit = true
			}
		}
		return hasUpper && hasLower && hasDigit
	})
}

type AuthHandler struct {
	DB *sql.DB
}

type registerRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,password_strength"`
}

type loginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type fieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type errorResponse struct {
	Errors []fieldError `json:"errors"`
}

func validationMessage(e validator.FieldError) string {
	switch e.Tag() {
	case "required":
		return e.Field() + " is required"
	case "email":
		return "invalid email format"
	case "min":
		return "must be at least " + e.Param() + " characters"
	case "password_strength":
		return "password must contain at least one uppercase letter, one lowercase letter, and one digit"
	default:
		return "invalid value"
	}
}

func respondValidationErrors(w http.ResponseWriter, errs validator.ValidationErrors) {
	fields := make([]fieldError, 0, len(errs))
	for _, e := range errs {
		fields = append(fields, fieldError{Field: e.Field(), Message: validationMessage(e)})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(errorResponse{Errors: fields})
}

func respondError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// createSession inserts a new refresh-token session for userID and returns the
// raw token to send to the client (only the SHA-256 hash is persisted).
func (h *AuthHandler) createSession(userID int) (string, error) {
	raw, hash, err := auth.NewRefreshToken()
	if err != nil {
		return "", err
	}
	_, err = h.DB.Exec(
		`INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
		userID, hash, time.Now().Add(7*24*time.Hour),
	)
	return raw, err
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := validate.Struct(req); err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			respondValidationErrors(w, ve)
			return
		}
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	var userID int
	var role string
	err = h.DB.QueryRow(
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, role`,
		req.Email, string(hash),
	).Scan(&userID, &role)
	if err != nil {
		respondError(w, http.StatusConflict, "email already registered")
		return
	}

	accessToken, err := auth.GenerateToken(userID, role)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	refreshToken, err := h.createSession(userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tokenResponse{AccessToken: accessToken, RefreshToken: refreshToken})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := validate.Struct(req); err != nil {
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			respondValidationErrors(w, ve)
			return
		}
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}

	var userID int
	var hash, role string
	err := h.DB.QueryRow(
		`SELECT id, password_hash, role FROM users WHERE email = $1`, req.Email,
	).Scan(&userID, &hash, &role)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		respondError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	accessToken, err := auth.GenerateToken(userID, role)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	refreshToken, err := h.createSession(userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResponse{AccessToken: accessToken, RefreshToken: refreshToken})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validate.Struct(req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	tokenHash := auth.HashRefreshToken(req.RefreshToken)

	var userID int
	var role string
	err := h.DB.QueryRow(`
		SELECT s.user_id, u.role
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > now()
	`, tokenHash).Scan(&userID, &role)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	// Rotate: delete the consumed session before issuing a new one.
	if _, err = h.DB.Exec(`DELETE FROM sessions WHERE token_hash = $1`, tokenHash); err != nil {
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	accessToken, err := auth.GenerateToken(userID, role)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	newRefresh, err := h.createSession(userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResponse{AccessToken: accessToken, RefreshToken: newRefresh})
}
