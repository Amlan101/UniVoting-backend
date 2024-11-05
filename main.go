// main.go
package main

import (
	"fmt"
	"log"
	"os"
	"time"
	"net/http"
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v4"
	"univoting-backend/models"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB

// Secret key used for signing JWTs 
var jwtSecret []byte

func init() {
    // Load .env file
    err := godotenv.Load(".env")
    if err != nil {
        log.Fatalf("Error loading .env file")
    }

    // Set JWT secret key from environment variable
    jwtSecret = []byte(os.Getenv("JWT_SECRET"))
    if len(jwtSecret) == 0 {
        log.Fatalf("JWT secret key not set in .env file")
    }
}

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

// RegisterVoterHandler handles user registration requests
func registerVoter(c *gin.Context) {
    var input struct {
        Name     string `json:"name" binding:"required"`
        Email    string `json:"email" binding:"required,email"`
        Password string `json:"password" binding:"required"`
    }

    // Bind input JSON to struct
    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Hash the password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
        return
    }

    // Create a new Voter instance
    voter := models.Voter{
        Name:     input.Name,
        Email:    input.Email,
        Password: string(hashedPassword),
    }

    // Save the voter to the database
    if err := db.Create(&voter).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create voter"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Voter registered successfully"})
}

// LoginVoterHandler handles login requests
func loginVoter(c *gin.Context) {
    var input struct {
        Email    string `json:"email" binding:"required,email"`
        Password string `json:"password" binding:"required"`
    }

    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Find voter by email
    var voter models.Voter
    if err := db.Where("email = ?", input.Email).First(&voter).Error; err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
        return
    }

    // Check password
    if err := bcrypt.CompareHashAndPassword([]byte(voter.Password), []byte(input.Password)); err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
        return
    }

    // Generate JWT token
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "voter_id": voter.ID,
        "exp":      time.Now().Add(time.Hour * 1).Unix(),
    })

    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func main() {
	router := gin.Default()

	// Connect to the database
	connectDatabase()

	// Routes
	router.POST("/register", registerVoter)
	router.POST("/login", loginVoter)

	// Define a basic route to test the server
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Welcome to the E-Voting Backend!",
		})
	})

	log.Println("Starting server on http://localhost:8080")
	router.Run(":8080")
}
