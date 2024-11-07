package models

import "gorm.io/gorm"

type Vote struct {
	gorm.Model
	VoterID   uint  `json:"voter_id"`
	EncryptedVote string  `json:"encrypted_vote"`
}