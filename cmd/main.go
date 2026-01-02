package main

import (
	"log"
	"todomanager/internal/handlers"
	"todomanager/internal/repositories"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Загружаем .env

	err := godotenv.Load("./configs/.env")
	if err != nil {
		log.Fatal("Failed to load .env:", err)
	}

	// Запуск SQLite и закрытие базы после завершения функции main

	db := repositories.OpenSQLite()
	defer db.Close()

	// HTTP-маршрутизатор gin, его хендлеры и запуск на порте :8080

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.POST("/register", handlers.Register)
	r.POST("/login", handlers.Login)
	r.POST("/test", handlers.Test)
	r.POST("/logout", handlers.Logout)

	log.Println("Сервер запущен на порте :8080")
	r.Run(":8080")
}
