package models

import "gorm.io/gorm"

type Poll struct {
    gorm.Model
    Question string   `json:"question"`
    Options  []Option `json:"options" gorm:"foreignKey:PollID"`
    IsActive bool     `json:"is_active"` 
}

// Option struct to represent each option in a poll
type Option struct {
    gorm.Model
    PollID uint   `json:"poll_id"`
    Text   string `json:"text"`
    Votes  uint   `json:"votes"` // Count of votes per option
}
