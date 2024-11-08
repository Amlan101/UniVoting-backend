package controllers

import (
	"encoding/base64"
	"net/http"
	"univoting-backend/config"
	"univoting-backend/models"

	"github.com/codahale/sss"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/nacl/secretbox"
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

// TallyVotes reconstructs and tallies votes for a specific poll
func TallyVotes(c *gin.Context) {
    pollID := c.Param("poll_id")
    var poll models.Poll

    // Check if poll exists
    if err := config.DB.Preload("Options").First(&poll, pollID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Poll not found"})
        return
    }

    // Retrieve all vote shares from each table
    var voteShares1 []models.VoteShare1
    var voteShares2 []models.VoteShare2
    var voteShares3 []models.VoteShare3
    var voteShares4 []models.VoteShare4
    var voteShares5 []models.VoteShare5

    config.DB.Find(&voteShares1)
    config.DB.Find(&voteShares2)
    config.DB.Find(&voteShares3)
    config.DB.Find(&voteShares4)
    config.DB.Find(&voteShares5)

    // Group shares by voter
    sharesByVoter := map[uint][][]byte{}
    for _, share := range voteShares1 {
        decodedShare, _ := base64.StdEncoding.DecodeString(share.ShareData)
        sharesByVoter[share.VoterID] = append(sharesByVoter[share.VoterID], decodedShare)
    }
    for _, share := range voteShares2 {
        decodedShare, _ := base64.StdEncoding.DecodeString(share.ShareData)
        sharesByVoter[share.VoterID] = append(sharesByVoter[share.VoterID], decodedShare)
    }
    for _, share := range voteShares3 {
        decodedShare, _ := base64.StdEncoding.DecodeString(share.ShareData)
        sharesByVoter[share.VoterID] = append(sharesByVoter[share.VoterID], decodedShare)
    }
    for _, share := range voteShares4 {
        decodedShare, _ := base64.StdEncoding.DecodeString(share.ShareData)
        sharesByVoter[share.VoterID] = append(sharesByVoter[share.VoterID], decodedShare)
    }
    for _, share := range voteShares5 {
        decodedShare, _ := base64.StdEncoding.DecodeString(share.ShareData)
        sharesByVoter[share.VoterID] = append(sharesByVoter[share.VoterID], decodedShare)
    }

    // Reconstruct votes
    voteCounts := map[uint]int{} // OptionID -> Vote Count
    for _, shares := range sharesByVoter {
        if len(shares) >= 3 { // Only reconstruct if we have the threshold number of shares
            shareMap := make(map[byte][]byte)
            for i, share := range shares {
                shareMap[byte(i)] = share
            }

            encryptedVote := sss.Combine(shareMap)
            if encryptedVote == nil {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reconstruct vote"})
                return
            }

            // Decrypt the reconstructed vote
            var nonce [24]byte
            copy(nonce[:], encryptedVote[:24])
            decrypted, ok := secretbox.Open(nil, encryptedVote[24:], &nonce, &config.EncryptionKey)
            if !ok {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt vote"})
                return
            }

            optionID := uint(decrypted[0]) // Assuming the option ID is stored as a single byte
            voteCounts[optionID]++
        }
    }

    c.JSON(http.StatusOK, gin.H{"results": voteCounts})
}
