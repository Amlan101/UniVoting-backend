package models

import "gorm.io/gorm"

type VoteShare1 struct {
    gorm.Model
    VoterID    uint   `json:"voter_id"`
    ShareIndex int    `json:"share_index"`
    ShareData  string `json:"share_data"`
}

type VoteShare2 struct {
    gorm.Model
    VoterID    uint   `json:"voter_id"`
    ShareIndex int    `json:"share_index"`
    ShareData  string `json:"share_data"`
}

type VoteShare3 struct {
    gorm.Model
    VoterID    uint   `json:"voter_id"`
    ShareIndex int    `json:"share_index"`
    ShareData  string `json:"share_data"`
}

type VoteShare4 struct {
    gorm.Model
    VoterID    uint   `json:"voter_id"`
    ShareIndex int    `json:"share_index"`
    ShareData  string `json:"share_data"`
}

type VoteShare5 struct {
    gorm.Model
    VoterID    uint   `json:"voter_id"`
    ShareIndex int    `json:"share_index"`
    ShareData  string `json:"share_data"`
}