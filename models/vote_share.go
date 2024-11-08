package models

import "gorm.io/gorm"

type VoteShare struct {
    gorm.Model
    VoterID    uint   `json:"voter_id"`
    ShareIndex int    `json:"share_index"`
    ShareData  string `json:"share_data"`
}
