package controllers

import (
	"univoting-backend/config"
	"univoting-backend/models"
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/nacl/secretbox"
)

// CastVote handles the casting of votes for a specific poll option
func CastVote(c *gin.Context) {
	// Get the voter ID from the context (set by JWT middleware)
	voterID, exists := c.Get("voter_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Check if the voter has already voted
	var voter models.Voter
	if err := config.DB.First(&voter, voterID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Voter not found"})
		return
	}
	if voter.HasVoted {
		c.JSON(http.StatusForbidden, gin.H{"error": "Voter has already voted"})
		return
	}

	// Bind and validate vote data from request body
	var input struct {
		OptionID uint `json:"option_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Encrypt the vote data (OptionID)
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate nonce"})
		return
	}
	encryptedVote := secretbox.Seal(nonce[:], []byte(string(input.OptionID)), &nonce, &config.EncryptionKey)
	encryptedVoteString := base64.StdEncoding.EncodeToString(encryptedVote)

	// Create and save the vote
	vote := models.Vote{
		VoterID:      voter.ID,
		EncryptedVote: encryptedVoteString,
	}
	if err := config.DB.Create(&vote).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to record vote"})
		return
	}

	// Mark voter as having voted
	voter.HasVoted = true
	config.DB.Save(&voter)

	c.JSON(http.StatusOK, gin.H{"message": "Vote cast successfully"})
}
