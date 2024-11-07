package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// DB is the global database instance
var DB *gorm.DB
var JWTSecret []byte
var EncryptionKey [32]byte

func LoadConfig(){
	// Load .env file
    err := godotenv.Load(".env")
    if err != nil {
        log.Fatalf("Error loading .env file")
    }

    // Set JWT secret key from environment variable
    JWTSecret = []byte(os.Getenv("JWT_SECRET"))
    if len(JWTSecret) == 0 {
        log.Fatalf("JWT secret key not set in .env file")
    }

     // Load encryption key from environment variable
    key := os.Getenv("ENCRYPTION_KEY")
    if len(key) < 32 {
        log.Fatalf("Encryption key must be 32 bytes")
    }

    // Copy the key into the encryptionKey array
    copy(EncryptionKey[:], []byte(key))
}

func ConnectDatabase(){
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
	DB, errDB = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if errDB != nil {
		log.Fatalf("Error connecting to database: %v", errDB)
	}

	log.Println("Database connected successfully")
}