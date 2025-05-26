package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	database "secure-video-api/internal/database"
	handlers "secure-video-api/internal/handlers"
	middleware "secure-video-api/internal/middleware"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}
}

func main() {
	// Set up signal handling for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Initialize database
	if err := database.InitDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	// Create default admin user
	if err := database.CreateDefaultAdmin(); err != nil {
		log.Printf("Error creating default admin: %v", err)
	}

	// Initialize router with debug mode
	gin.SetMode(gin.DebugMode)
	router := gin.New()

	// Add middlewares
	router.Use(gin.Recovery())
	router.Use(middleware.LoggingMiddleware())
	router.Use(middleware.ErrorHandlingMiddleware())
	router.SetTrustedProxies(nil)

	// Set maximum file upload size (100MB)
	router.MaxMultipartMemory = 100 << 20 // 100 MB

	// Get working directory
	workDir, err := os.Getwd()
	if err != nil {
		log.Fatal("Failed to get working directory:", err)
	}

	// Create storage directories if they don't exist
	storagePath := filepath.Join(workDir, "storage", "videos")
	encryptedPath := filepath.Join(workDir, "storage", "encrypted")

	// Override environment variables with absolute paths
	os.Setenv("STORAGE_PATH", storagePath)
	os.Setenv("ENCRYPTED_PATH", encryptedPath)

	log.Printf("Creating storage directories: %s and %s", storagePath, encryptedPath)

	// Ensure directories exist with proper macOS permissions
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		log.Fatal("Failed to create storage directory:", err)
	}
	if err := os.MkdirAll(encryptedPath, 0755); err != nil {
		log.Fatal("Failed to create encrypted directory:", err)
	}

	// Set proper permissions for macOS
	if err := os.Chmod(storagePath, 0755); err != nil {
		log.Fatal("Failed to set storage directory permissions:", err)
	}
	if err := os.Chmod(encryptedPath, 0755); err != nil {
		log.Fatal("Failed to set encrypted directory permissions:", err)
	}

	// API routes
	api := router.Group("/api")
	{
		// Public routes
		auth := api.Group("/auth")
		{
			auth.POST("/register", handlers.Register)
			auth.POST("/login", handlers.Login)
		}

		// Protected routes
		protected := api.Group("")
		protected.Use(middleware.AuthMiddleware())
		{
			// Video routes accessible to all authenticated users
			videos := protected.Group("/videos")
			{
				videos.GET("", handlers.ListVideos)
				videos.GET("/:id/stream", handlers.StreamVideo)
			}

			// Admin-only routes
			admin := protected.Group("/admin")
			admin.Use(middleware.AdminMiddleware())
			{
				// Video management
				admin.POST("/videos", handlers.UploadVideo)
				admin.PUT("/videos/:id", handlers.UpdateVideo)
				admin.DELETE("/videos/:id", handlers.DeleteVideo)

				// User management
				admin.GET("/users", handlers.ListUsers)
				admin.POST("/users/:id/deactivate", handlers.DeactivateUser)
				admin.POST("/users/:id/reactivate", handlers.ReactivateUser)
			}
		}
	}

	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	log.Printf("Admin credentials - Email: %s, Password: %s", os.Getenv("ADMIN_EMAIL"), os.Getenv("ADMIN_PASSWORD"))

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	<-quit
	log.Println("Server is shutting down...")

	// Give outstanding operations 5 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server stopped gracefully")
}
