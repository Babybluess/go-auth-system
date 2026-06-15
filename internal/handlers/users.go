package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"authapi/internal/auth"
	"authapi/internal/models"
)

type UserHandler struct {
	DB *sql.DB
}

// Me returns the profile of the currently authenticated user.
func (h *UserHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(auth.UserIDKey).(int)

	var u models.User
	err := h.DB.QueryRow(
		`SELECT id, email, created_at FROM users WHERE id = $1`, userID,
	).Scan(&u.ID, &u.Email, &u.CreatedAt)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(u)
}
