package main

import (
	"fmt"
	"log"
	"os"
	"time"
	"net/http"
    "crypto/rand"
    "encoding/base64"
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v4"
    "golang.org/x/crypto/nacl/secretbox"
	"univoting-backend/models"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB

// Secret key used for signing JWTs 
var jwtSecret []byte

// Replace this with a secure 32-byte key (e.g., from environment variable)
var encryptionKey [32]byte

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

     // Load encryption key from environment variable
    key := os.Getenv("ENCRYPTION_KEY")
    if len(key) < 32 {
        log.Fatalf("Encryption key must be 32 bytes")
    }

    // Copy the key into the encryptionKey array
    copy(encryptionKey[:], []byte(key))
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
	db.AutoMigrate(&models.Voter{}, &models.Vote{})
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

// CastVoteHandler handles vote casting requests
func castVote(c *gin.Context) {
    // Get the voter ID from JWT token
    token := c.Request.Header.Get("Authorization")
    voterID, err := validateTokenAndGetVoterID(token)
    if(err != nil){
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }

    // Check if the voter has already voted
    var voter models.Voter
    if err := db.First(&voter, voterID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Voter not found"})
        return
    }

    if voter.HasVoted {
        c.JSON(http.StatusForbidden, gin.H{"error": "Voter has already voted"})
        return
    }

    // Bind and validate vote data from request body
    var input struct {
        VoteData string `json:"vote_data" binding:"required"`
    }
    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

     // Encrypt the vote data
     var nonce [24]byte
     if _, err := rand.Read(nonce[:]); err != nil {
         c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate nonce"})
         return
     }
     encryptedVote := secretbox.Seal(nonce[:], []byte(input.VoteData), &nonce, &encryptionKey)
     encryptedVoteString := base64.StdEncoding.EncodeToString(encryptedVote)
 
     // Create and save the vote
     vote := models.Vote{
         VoterID:      voter.ID,
         EncryptedVote: encryptedVoteString,
     }
     if err := db.Create(&vote).Error; err != nil {
         c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to record vote"})
         return
     }

    // Mark voter as having voted
    voter.HasVoted = true
    db.Save(&voter)

    c.JSON(http.StatusOK, gin.H{"message": "Vote cast successfully"})
}

// Helper function to validate JWT token and get voter ID
func validateTokenAndGetVoterID(tokenString string) (uint, error) {
    // Parse and validate JWT token
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return jwtSecret, nil
    })

    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        voterID := uint(claims["voter_id"].(float64))
        return voterID, nil
    }
    return 0, err
}


func main() {
	router := gin.Default()

	// Connect to the database
	connectDatabase()

	// Routes
	router.POST("/register", registerVoter)
	router.POST("/login", loginVoter)
    router.POST("/vote", castVote)

	// Define a basic route to test the server
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Welcome to the E-Voting Backend!",
		})
	})

	log.Println("Starting server on http://localhost:8080")
	router.Run(":8080")
}
