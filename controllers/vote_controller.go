package controllers

import (
	"univoting-backend/config"
	"univoting-backend/models"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"github.com/codahale/sss"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/nacl/secretbox"
)

// CastVote handles the casting of votes for a specific poll option
func CastVote(c *gin.Context) {
    voterID, exists := c.Get("voter_id")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }

    var input struct {
        OptionID uint `json:"option_id" binding:"required"`
    }
    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    var nonce [24]byte
    if _, err := rand.Read(nonce[:]); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate nonce"})
        return
    }

    // Encrypt the vote data (OptionID)
    encryptedVote := secretbox.Seal(nonce[:], []byte{byte(input.OptionID)}, &nonce, &config.EncryptionKey)

    // Split the encrypted vote into shares using Shamir's Secret Sharing
    shares, err := sss.Split(3, 5, encryptedVote) // Example: threshold of 3, total of 5 shares
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to split encrypted vote"})
        return
    }

    // Distribute shares across tables
    for i, share := range shares {
        shareData := base64.StdEncoding.EncodeToString(share)
        switch i {
        case 0:
            voteShare := models.VoteShare1{VoterID: voterID.(uint), ShareIndex: int(i), ShareData: shareData}
            config.DB.Create(&voteShare)
        case 1:
            voteShare := models.VoteShare2{VoterID: voterID.(uint), ShareIndex: int(i), ShareData: shareData}
            config.DB.Create(&voteShare)
        case 2:
            voteShare := models.VoteShare3{VoterID: voterID.(uint), ShareIndex: int(i), ShareData: shareData}
            config.DB.Create(&voteShare)
        case 3:
            voteShare := models.VoteShare4{VoterID: voterID.(uint), ShareIndex: int(i), ShareData: shareData}
            config.DB.Create(&voteShare)
        case 4:
            voteShare := models.VoteShare5{VoterID: voterID.(uint), ShareIndex: int(i), ShareData: shareData}
            config.DB.Create(&voteShare)
                default:
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Unexpected number of shares"})
            return
        }
    }

    // Mark the voter as having voted
    var voter models.Voter
    config.DB.First(&voter, voterID)
    voter.HasVoted = true
    config.DB.Save(&voter)

    c.JSON(http.StatusOK, gin.H{"message": "Vote cast successfully with secret sharing"})
}

