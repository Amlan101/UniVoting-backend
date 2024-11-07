package controllers

import (
	"univoting-backend/config"
	"univoting-backend/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

// CreatePoll handles poll creation by an admin
func CreatePoll(c *gin.Context) {
	// Get the voter ID from the context (set by JWT middleware)
	voterID, exists := c.Get("voter_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Check if the user is an admin
	var voter models.Voter
	if err := config.DB.First(&voter, voterID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Voter not found"})
		return
	}
	if !voter.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only admins can create polls"})
		return
	}

	// Parse poll data from request body
	var input struct {
		Question string   `json:"question" binding:"required"`
		Options  []string `json:"options" binding:"required,min=2"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create poll and options
	poll := models.Poll{Question: input.Question, IsActive: true}
	if err := config.DB.Create(&poll).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create poll"})
		return
	}

	// Create options and associate them with the poll
	for _, optionText := range input.Options {
		option := models.Option{PollID: poll.ID, Text: optionText}
		if err := config.DB.Create(&option).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create poll option"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Poll created successfully"})
}
