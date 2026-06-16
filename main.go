package main

import (
	"log"
	"net/http"

	"authapi/internal/auth"
	"authapi/internal/config"
	"authapi/internal/db"
	"authapi/internal/handlers"

	"github.com/go-chi/chi/v5"
)

func main() {
	config, err := config.GetConfig()

	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	if config.DB_URL == "" {
		log.Fatal("DATABASE_URL is empty")
	}
	conn, err := db.Connect(config.DB_URL)
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
