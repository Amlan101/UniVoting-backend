// Description: Defines the Voter model and its fields.
package models

import "gorm.io/gorm"

type Voter struct {
    gorm.Model          // Adds fields ID, CreatedAt, UpdatedAt, DeletedAt
    Name       string    `json:"name"`
    Email      string    `json:"email" gorm:"unique"`
    Password   string    `json:"-"`
    HasVoted   bool      `json:"has_voted"`
    IsAdmin    bool      `json:"is_admin"`
}
