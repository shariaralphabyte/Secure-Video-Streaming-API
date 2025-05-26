package handlers

import (
	"net/http"
	"time"

	"secure-video-api/internal/models"
	"secure-video-api/internal/database"

	"github.com/gin-gonic/gin"
)

// ListUsers lists all users (admin only)
func ListUsers(c *gin.Context) {
	rows, err := database.DB.Query(`
		SELECT 
			u.id, 
			u.email, 
			u.is_admin,
			u.status,
			u.created_at, 
			u.updated_at
		FROM users u 
		ORDER BY u.created_at DESC
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.IsAdmin,
			&user.Status,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			continue
		}
		users = append(users, user)
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"count": len(users),
	})
}

// DeactivateUser deactivates a user's token (admin only)
func DeactivateUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Get current user status
	var user models.User
	var createdAt, updatedAt string
	err := database.DB.QueryRow(`
		SELECT 
			id, 
			email, 
			is_admin,
			status,
			created_at, 
			updated_at 
		FROM users 
		WHERE id = ?
	`, userID).Scan(
		&user.ID,
		&user.Email,
		&user.IsAdmin,
		&user.Status,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Don't deactivate admin users
	if user.IsAdmin {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot deactivate admin user"})
		return
	}

	// Update status to inactive
	currentTime := time.Now().Format(time.RFC3339)
	_, err = database.DB.Exec(`
		UPDATE users 
		SET status = ?, updated_at = ?
		WHERE id = ?
	`, models.UserStatusInactive, currentTime, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deactivate user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User deactivated successfully",
		"user_id": userID,
	})
}

// ReactivateUser reactivates a user's token (admin only)
func ReactivateUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Get current user status
	var user models.User
	var createdAt, updatedAt string
	err := database.DB.QueryRow(`
		SELECT 
			id, 
			email, 
			is_admin,
			status,
			created_at, 
			updated_at 
		FROM users 
		WHERE id = ?
	`, userID).Scan(
		&user.ID,
		&user.Email,
		&user.IsAdmin,
		&user.Status,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Don't reactivate admin users
	if user.IsAdmin {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot reactivate admin user"})
		return
	}

	// Update status to active
	currentTime := time.Now().Format(time.RFC3339)
	_, err = database.DB.Exec(`
		UPDATE users 
		SET status = ?, updated_at = ?
		WHERE id = ?
	`, models.UserStatusActive, currentTime, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reactivate user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User reactivated successfully",
		"user_id": userID,
	})
}
