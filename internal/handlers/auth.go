package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
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
	err = h.DB.QueryRow(
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`,
		req.Email, string(hash),
	).Scan(&userID)
	if err != nil {
		respondError(w, http.StatusConflict, "email already registered")
		return
	}

	token, err := auth.GenerateToken(userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
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
	var hash string
	err := h.DB.QueryRow(
		`SELECT id, password_hash FROM users WHERE email = $1`, req.Email,
	).Scan(&userID, &hash)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		respondError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	token, err := auth.GenerateToken(userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}
