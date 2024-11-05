// main.go
package main

import (
	"fmt"
	"log"
	"os"
	"univoting-backend/models"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB

// Connects to PostgreSQL using GORM
func connectDatabase() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	// Load DB config from environment variables
	dbHost := os.Getenv("DB_HOST")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbPort := os.Getenv("DB_PORT")

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		dbHost, dbUser, dbPassword, dbName, dbPort)

	var errDB error
	db, errDB = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if errDB != nil {
		log.Fatalf("Error connecting to database: %v", errDB)
	}

	log.Println("Database connected successfully")

	// Run migrations for Voter model
	db.AutoMigrate(&models.Voter{})
	log.Println("Database migrated successfully")
}

func main() {
	router := gin.Default()

	// Connect to the database
	connectDatabase()

	// Define a basic route to test the server
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Welcome to the E-Voting Backend!",
		})
	})

	log.Println("Starting server on http://localhost:8080")
	router.Run(":8080")
}
