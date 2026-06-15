package models

import "time"

type User struct {
	ID           int       `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"` // never serialize this
	CreatedAt    time.Time `json:"created_at"`
}
