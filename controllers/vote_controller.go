package controllers

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "net/http"
    "github.com/codahale/sss"
    "github.com/gin-gonic/gin"
    "golang.org/x/crypto/nacl/secretbox"
    "univoting-backend/config"
    "univoting-backend/models"
)

func CastVote(c *gin.Context) {
    voterID, exists := c.Get("voter_id")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }

    var input struct {
        PollID   uint `json:"poll_id" binding:"required"`
        OptionID uint `json:"option_id" binding:"required"`
    }
    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Validate that the option belongs to the specified poll
    var option models.Option
    if err := config.DB.Where("id = ? AND poll_id = ?", input.OptionID, input.PollID).First(&option).Error; err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid poll or option ID"})
        return
    }

    // Check if voter has already voted
    var voter models.Voter
    if err := config.DB.First(&voter, voterID).Error; err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid voter"})
        return
    }
    if voter.HasVoted {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Voter has already cast a vote"})
        return
    }

    var nonce [24]byte
    if _, err := rand.Read(nonce[:]); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate nonce"})
        return
    }

    // Convert OptionID to bytes, ensuring proper size
    optionBytes := make([]byte, 8) // uint64 size
    optionBytes[0] = byte(input.OptionID)

    // Encrypt the vote data
    encryptedVote := secretbox.Seal(nonce[:], optionBytes, &nonce, &config.EncryptionKey)

    // Create a SHA-256 hash of the encrypted vote
    hashedVote := sha256.Sum256(encryptedVote)
    hashedVoteSlice := hashedVote[:]

    // Define the number of shares we want as bytes
    var totalShares byte = 5
    var threshold byte = 2

    // Split the encrypted vote into shares using Shamir's Secret Sharing
    shares, err := sss.Split(totalShares, threshold, hashedVoteSlice)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "Failed to split encrypted vote",
            "details": err.Error(),
        })
        return
    }

    // Verify we got the expected number of shares
    if len(shares) != int(totalShares) {
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "Invalid number of shares generated",
            "expected": totalShares,
            "got": len(shares),
        })
        return
    }

    // Begin transaction for share distribution
    tx := config.DB.Begin()

    // Create and store shares
    for shareIndex := byte(0); shareIndex < totalShares; shareIndex++ {
        shareData := base64.StdEncoding.EncodeToString(shares[shareIndex])
        var voteShare interface{}

        // Create the appropriate share model based on index
        switch shareIndex {
        case 0:
            voteShare = &models.VoteShare1{VoterID: voterID.(uint), ShareIndex: int(shareIndex), ShareData: shareData}
        case 1:
            voteShare = &models.VoteShare2{VoterID: voterID.(uint), ShareIndex: int(shareIndex), ShareData: shareData}
        case 2:
            voteShare = &models.VoteShare3{VoterID: voterID.(uint), ShareIndex: int(shareIndex), ShareData: shareData}
        case 3:
            voteShare = &models.VoteShare4{VoterID: voterID.(uint), ShareIndex: int(shareIndex), ShareData: shareData}
        case 4:
            voteShare = &models.VoteShare5{VoterID: voterID.(uint), ShareIndex: int(shareIndex), ShareData: shareData}
        default:
            tx.Rollback()
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid share index"})
            return
        }

        if err := tx.Create(voteShare).Error; err != nil {
            tx.Rollback()
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save vote share"})
            return
        }
    }

    // Mark the voter as having voted
    voter.HasVoted = true
    if err := tx.Save(&voter).Error; err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update voter status"})
        return
    }

    // Commit transaction
    if err := tx.Commit().Error; err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Vote cast successfully with secret sharing"})
}