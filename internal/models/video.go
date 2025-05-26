package models

import "time"

type Video struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	FileName    string    `json:"file_name"`
	UploadedBy  string    `json:"uploaded_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// NewVideo creates a new Video instance with zero values
func NewVideo() *Video {
	return &Video{
		ID:          "",
		Title:       "",
		Description: "",
		FileName:    "",
		UploadedBy:  "",
		CreatedAt:   time.Time{},
		UpdatedAt:   time.Time{},
	}
}

