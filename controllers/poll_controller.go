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

// GetActivePolls retrieves all active polls and their options
func GetActivePolls(c *gin.Context) {
    var polls []models.Poll

    // Fetch all active polls with their options
    if err := config.DB.Preload("Options").Where("is_active = ?", true).Find(&polls).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve polls"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"polls": polls})
}

// DeactivatePoll sets a poll's IsActive field to false, preventing further votes
func DeactivatePoll(c *gin.Context) {
    // Verify admin status from JWT token 
    voterID, exists := c.Get("voter_id")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }

    // Check if user is admin
    var voter models.Voter
    if err := config.DB.First(&voter, voterID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Voter not found"})
        return
    }
    if !voter.IsAdmin {
        c.JSON(http.StatusForbidden, gin.H{"error": "Only admins can deactivate polls"})
        return
    }

    // Get poll ID from URL
    pollID := c.Param("poll_id")

    // Find and update the poll
    var poll models.Poll
    if err := config.DB.First(&poll, pollID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Poll not found"})
        return
    }

    poll.IsActive = false
    config.DB.Save(&poll)

    c.JSON(http.StatusOK, gin.H{"message": "Poll deactivated successfully"})
}

// DeletePoll removes a poll and its associated options from the database
func DeletePoll(c *gin.Context) {
    // Verify admin status from JWT token 
    voterID, exists := c.Get("voter_id")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }

    // Check if user is admin
    var voter models.Voter
    if err := config.DB.First(&voter, voterID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Voter not found"})
        return
    }
    if !voter.IsAdmin {
        c.JSON(http.StatusForbidden, gin.H{"error": "Only admins can delete polls"})
        return
    }

    // Get poll ID from URL
    pollID := c.Param("poll_id")

    // Delete the poll and its options
    if err := config.DB.Where("poll_id = ?", pollID).Delete(&models.Option{}).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete poll options"})
        return
    }
    if err := config.DB.Delete(&models.Poll{}, pollID).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete poll"})
        return
    }


    c.JSON(http.StatusOK, gin.H{"message": "Poll deleted successfully"})
}

// GetPollResults retrieves the aggregated results of a specific poll
func GetPollResults(c *gin.Context) {
    // Verify admin status from JWT token (set by JWTAuthMiddleware)
    voterID, exists := c.Get("voter_id")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }

    // Check if user is admin
    var voter models.Voter
    if err := config.DB.First(&voter, voterID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Voter not found"})
        return
    }
    if !voter.IsAdmin {
        c.JSON(http.StatusForbidden, gin.H{"error": "Only admins can retrieve poll results"})
        return
    }

    // Get poll ID from URL
    pollID := c.Param("poll_id")

    // Find the poll and preload options with vote counts
    var poll models.Poll
    if err := config.DB.Preload("Options").First(&poll, pollID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Poll not found"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "poll": gin.H{
            "question": poll.Question,
            "options":  poll.Options,
        },
    })
}