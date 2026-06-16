package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DB_URL     string
	JWT_SECRET string
}

func GetConfig() (Config, error) {
	if err := godotenv.Load(); err != nil {
		return Config{}, err
	}

	return Config{
		DB_URL:     os.Getenv("DATABASE_URL"),
		JWT_SECRET: os.Getenv("JWT_SECRET"),
	}, nil
}
