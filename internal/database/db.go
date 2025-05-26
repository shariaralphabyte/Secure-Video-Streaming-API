package database

import (
	"database/sql"
	"log"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

func InitDB() error {
	dbPath := os.Getenv("SQLITE_DB_PATH")
	var err error
	DB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}

	// Create users table
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			is_admin BOOLEAN DEFAULT FALSE,
			status TEXT DEFAULT 'active',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// Create videos table
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS videos (
			id TEXT PRIMARY KEY,
			title TEXT NOT NULL,
			description TEXT,
			file_name TEXT NOT NULL,
			uploaded_by TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (uploaded_by) REFERENCES users(id)
		)
	`)
	if err != nil {
		return err
	}

	return nil
}

func CreateDefaultAdmin() error {
	email := os.Getenv("ADMIN_EMAIL")
	password := os.Getenv("ADMIN_PASSWORD")

	// Check if admin already exists
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", email).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		log.Println("Admin user already exists")
		return nil
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Create admin user
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	_, err = DB.Exec(`
		INSERT INTO users (id, email, password, is_admin, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, generateUUID(), email, string(hashedPassword), true, "active", currentTime, currentTime)

	return err
}

func generateUUID() string {
	return "admin-" + os.Getenv("ADMIN_EMAIL") // This is a simplified version, you should use proper UUID generation
}
