package models

import "time"

const (
	UserStatusActive   = "active"
	UserStatusInactive = "inactive"
)

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"-"`
	IsAdmin   bool      `json:"is_admin"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
