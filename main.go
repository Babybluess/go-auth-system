package main

import (
	"log"
	"net/http"
	"os"

	"authapi/internal/auth"
	"authapi/internal/db"
	"authapi/internal/handlers"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	dsn := os.Getenv("DATABASE_URL")

	conn, err := db.Connect(dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	authHandler := &handlers.AuthHandler{DB: conn}
	userHandler := &handlers.UserHandler{DB: conn}

	r := chi.NewRouter()
	r.Use(auth.Logger)

	// Public routes - no token required
	r.Post("/register", authHandler.Register)
	r.Post("/login", authHandler.Login)

	// Protected routes - JWT middleware required
	r.Group(func(r chi.Router) {
		r.Use(auth.RequireAuth)
		r.Get("/me", userHandler.Me)
	})

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
