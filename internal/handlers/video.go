package handlers

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"secure-video-api/internal/database"
	"secure-video-api/internal/models"
	"secure-video-api/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type VideoRequest struct {
	Title       string `form:"title" binding:"required"`
	Description string `form:"description"`
}

func UploadVideo(c *gin.Context) {
	log.Println("Starting video upload process...")

	var req VideoRequest
	if err := c.ShouldBind(&req); err != nil {
		log.Printf("Error binding request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	file, err := c.FormFile("video")
	if err != nil {
		log.Printf("Error getting video file: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Video file is required"})
		return
	}

	log.Printf("[Upload] Received video upload request - Title: %s, File: %s, Size: %d bytes",
		req.Title, file.Filename, file.Size)

	// Validate file extension
	ext := strings.ToLower(filepath.Ext(file.Filename))
	allowedExts := map[string]bool{".mp4": true, ".mov": true, ".avi": true, ".mkv": true}
	if !allowedExts[ext] {
		log.Printf("[Upload] Invalid file extension: %s", ext)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":              "Invalid file type",
			"details":            "Only video files (.mp4, .mov, .avi, .mkv) are allowed",
			"received_extension": ext,
		})
		return
	}

	// Generate unique filename and ensure directories exist
	videoID := uuid.New().String()
	filename := videoID + ext

	// Get absolute paths from environment
	workDir, err := os.Getwd()
	if err != nil {
		log.Printf("[Upload] Error getting working directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get working directory"})
		return
	}

	storagePath := os.Getenv("STORAGE_PATH")
	encryptedPath := os.Getenv("ENCRYPTED_PATH")

	// Convert to absolute paths if they're relative
	if !filepath.IsAbs(storagePath) {
		storagePath = filepath.Join(workDir, storagePath)
	}
	if !filepath.IsAbs(encryptedPath) {
		encryptedPath = filepath.Join(workDir, encryptedPath)
	}

	log.Printf("[Upload] Using storage path: %s", storagePath)
	log.Printf("[Upload] Using encrypted path: %s", encryptedPath)

	// Ensure storage directories exist with proper permissions
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		log.Printf("[Upload] Failed to create storage directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create storage directory",
			"details": err.Error(),
			"path":    storagePath,
		})
		return
	}
	if err := os.MkdirAll(encryptedPath, 0755); err != nil {
		log.Printf("[Upload] Failed to create encrypted directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create encrypted directory",
			"details": err.Error(),
			"path":    encryptedPath,
		})
		return
	}

	uploadPath := filepath.Join(storagePath, filename)
	encryptedPath = filepath.Join(encryptedPath, filename+".enc")

	// Open uploaded file
	src, err := file.Open()
	if err != nil {
		log.Printf("Error opening uploaded file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to open uploaded file: %v", err)})
		return
	}
	defer src.Close()

	// Create destination file
	if err := os.MkdirAll(filepath.Dir(uploadPath), 0755); err != nil {
		log.Printf("Error creating directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create directory: %v", err)})
		return
	}

	dst, err := os.Create(uploadPath)
	if err != nil {
		log.Printf("Error creating destination file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create destination file: %v", err)})
		return
	}
	defer dst.Close()

	// Copy file in chunks
	if _, err = io.Copy(dst, src); err != nil {
		os.Remove(uploadPath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save video: %v", err)})
		return
	}
	dst.Close() // Close before encryption

	// Encrypt the video
	key := []byte(os.Getenv("ENCRYPTION_KEY"))
	log.Printf("[Encryption] Starting encryption process")
	log.Printf("[Encryption] Key length: %d bytes", len(key))
	log.Printf("[Encryption] Upload path: %s", uploadPath)
	log.Printf("[Encryption] Encrypted path: %s", encryptedPath)
	log.Printf("[Encryption] Upload file exists: %v", fileExists(uploadPath))

	if fileInfo, err := os.Stat(uploadPath); err != nil {
		log.Printf("[Encryption] Error checking upload file: %v", err)
	} else {
		log.Printf("[Encryption] Upload file size: %d bytes", fileInfo.Size())
		log.Printf("[Encryption] Upload file permissions: %v", fileInfo.Mode())
	}

	if len(key) != 32 {
		os.Remove(uploadPath)
		errMsg := fmt.Sprintf("Invalid key length: %d bytes (expected 32)", len(key))
		log.Printf("[Encryption] Error: %s", errMsg)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":      "Encryption key error",
			"details":    errMsg,
			"key_length": len(key),
		})
		return
	}

	if err := utils.EncryptFile(uploadPath, encryptedPath, key); err != nil {
		log.Printf("[Encryption] Failed: %v", err)
		// Check encryption directory
		if encDir := filepath.Dir(encryptedPath); true {
			if info, err := os.Stat(encDir); err != nil {
				log.Printf("[Encryption] Error accessing encrypted dir: %v", err)
			} else {
				log.Printf("[Encryption] Encrypted dir permissions: %v", info.Mode())
			}
		}
		os.Remove(uploadPath)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":          "Encryption failed",
			"details":        err.Error(),
			"upload_path":    uploadPath,
			"encrypted_path": encryptedPath,
			"file_exists":    fileExists(uploadPath),
			"enc_dir_exists": fileExists(filepath.Dir(encryptedPath)),
		})
		return
	}

	log.Printf("[Encryption] Successfully encrypted video to %s", encryptedPath)

	// Remove the original file
	os.Remove(uploadPath)

	// Save video metadata to database
	userID, _ := c.Get("user_id")
	currentTime := time.Now().Format(time.RFC3339)

	_, err = database.DB.Exec(`
		INSERT INTO videos (
			id, 
			title, 
			description, 
			file_name, 
			uploaded_by, 
			created_at, 
			updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		videoID,
		req.Title,
		req.Description,
		filename,
		userID,
		currentTime,
		currentTime,
	)
	if err != nil {
		log.Printf("Error saving video metadata: %v", err)
		os.Remove(encryptedPath)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to save video metadata",
			"details": err.Error(),
			"video_id": videoID,
			"file_name": filename,
		})
		return
	}

	// Log success
	log.Printf("Successfully uploaded video: ID=%s, Title=%s, FileName=%s", videoID, req.Title, filename)

	c.JSON(http.StatusCreated, gin.H{
		"id":          videoID,
		"message":     "Video uploaded successfully",
		"file_name":   filename,
		"uploaded_by": userID,
	})
}

func StreamVideo(c *gin.Context) {
	videoID := c.Param("id")

	// Get video metadata
	var video models.Video
	err := database.DB.QueryRow(
		"SELECT file_name FROM videos WHERE id = ?",
		videoID,
	).Scan(&video.FileName)
	if err != nil {
		log.Printf("Error fetching video metadata: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Video not found"})
		return
	}

	encryptedPath := filepath.Join(os.Getenv("ENCRYPTED_PATH"), video.FileName+".enc")
	tempPath := filepath.Join(os.TempDir(), uuid.New().String()+filepath.Ext(video.FileName))
	defer os.Remove(tempPath)

	// Check if encrypted file exists
	if !fileExists(encryptedPath) {
		log.Printf("Encrypted file not found: %s", encryptedPath)
		c.JSON(http.StatusNotFound, gin.H{"error": "Video file not found"})
		return
	}

	// Create temporary directory with proper permissions
	tempDir := filepath.Join(os.TempDir(), "secure-video")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		log.Printf("Error creating temp directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create temp directory",
			"details": err.Error(),
			"temp_dir": tempDir,
		})
		return
	}

	// Create temporary file path in our custom temp directory
	tempPath = filepath.Join(tempDir, uuid.New().String()+filepath.Ext(video.FileName))
	defer os.Remove(tempPath)

	// Decrypt video to temp file
	key := []byte(os.Getenv("ENCRYPTION_KEY"))
	if len(key) != 32 {
		log.Printf("Invalid encryption key length: %d", len(key))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid encryption key"})
		return
	}

	// Create temp file with proper permissions
	tempFile, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Error creating temp file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create temp file",
			"details": err.Error(),
			"temp_path": tempPath,
		})
		return
	}
	tempFile.Close()

	if err := utils.DecryptFile(encryptedPath, tempPath, key); err != nil {
		log.Printf("Error decrypting video: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to decrypt video",
			"details": err.Error(),
			"encrypted_path": encryptedPath,
			"temp_path": tempPath,
		})
		return
	}

	// Stream the video
	videoFile, err := os.Open(tempPath)
	if err != nil {
		log.Printf("Error opening decrypted video: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open video"})
		return
	}
	defer videoFile.Close()

	fileInfo, err := videoFile.Stat()
	if err != nil {
		log.Printf("Error getting video info: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get video info"})
		return
	}

	// Handle range requests for video streaming
	rangeHeader := c.GetHeader("Range")
	if rangeHeader != "" {
		ranges, err := parseRange(rangeHeader, fileInfo.Size())
		if err != nil {
			log.Printf("Invalid range request: %v", err)
			c.JSON(http.StatusRequestedRangeNotSatisfiable, gin.H{"error": "Invalid range"})
			return
		}

		length := ranges[1] - ranges[0] + 1
		c.Status(http.StatusPartialContent)
		c.Header("Content-Range", fmt.Sprintf("bytes %d-%d/%d", ranges[0], ranges[1], fileInfo.Size()))
		c.Header("Content-Length", fmt.Sprintf("%d", length))
		c.Header("Accept-Ranges", "bytes")
		c.Header("Content-Type", "video/mp4")

		videoFile.Seek(ranges[0], 0)
		io.CopyN(c.Writer, videoFile, length)
		return
	}

	// Stream entire video if no range is specified
	c.Header("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	c.Header("Content-Type", "video/mp4")
	io.Copy(c.Writer, videoFile)
	io.Copy(c.Writer, videoFile)
}

func parseRange(rangeHeader string, size int64) ([]int64, error) {
	var start, end int64
	fmt.Sscanf(rangeHeader, "bytes=%d-%d", &start, &end)
	if end == 0 {
		end = size - 1
	}
	if start > end || start < 0 || end >= size {
		return nil, fmt.Errorf("invalid range")
	}
	return []int64{start, end}, nil
}

func ListVideos(c *gin.Context) {
	log.Println("Starting to fetch videos...")

	// Get all videos from database
	rows, err := database.DB.Query(`
		SELECT 
			v.id, 
			v.title, 
			v.description, 
			v.file_name, 
			v.uploaded_by, 
			v.created_at, 
			v.updated_at 
		FROM videos v 
		ORDER BY v.created_at DESC
	`)
	if err != nil {
		log.Printf("Error fetching videos: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch videos"})
		return
	}
	defer rows.Close()

	// Create slice to hold video data
	var videos []models.Video
	for rows.Next() {
		var video models.Video
		var createdAt, updatedAt string
		err := rows.Scan(
			&video.ID,
			&video.Title,
			&video.Description,
			&video.FileName,
			&video.UploadedBy,
			&createdAt,
			&updatedAt,
		)
		if err != nil {
			log.Printf("Error scanning video row: %v", err)
			continue
		}

		// Convert string timestamps to time.Time
		video.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
		if err != nil {
			log.Printf("Error parsing created_at: %v", err)
			continue
		}
		video.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt)
		if err != nil {
			log.Printf("Error parsing updated_at: %v", err)
			continue
		}

		// Log video details
		log.Printf("Scanned video: ID=%s, Title=%s, FileName=%s, UploadedBy=%s, CreatedAt=%v, UpdatedAt=%v",
			video.ID, video.Title, video.FileName, video.UploadedBy, video.CreatedAt, video.UpdatedAt)

		// Add to videos slice
		videos = append(videos, video)
	}

	// Check for any errors after scanning
	if err = rows.Err(); err != nil {
		log.Printf("Error after scanning rows: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading videos"})
		return
	}

	// Log total number of videos
	log.Printf("Successfully fetched %d videos", len(videos))

	// Return the videos as JSON
	c.JSON(http.StatusOK, gin.H{
		"videos": videos,
		"count":  len(videos),
	})
}


func UpdateVideo(c *gin.Context) {
	videoID := c.Param("id")
	var req VideoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := database.DB.Exec(
		"UPDATE videos SET title = ?, description = ? WHERE id = ?",
		req.Title, req.Description, videoID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update video"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Video not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Video updated successfully"})
}

func DeleteVideo(c *gin.Context) {
	videoID := c.Param("id")

	// Get video filename
	var filename string
	err := database.DB.QueryRow("SELECT file_name FROM videos WHERE id = ?", videoID).Scan(&filename)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Video not found"})
		return
	}

	// Delete encrypted file
	encryptedPath := filepath.Join(os.Getenv("ENCRYPTED_PATH"), filename+".enc")
	os.Remove(encryptedPath)

	// Delete from database
	result, err := database.DB.Exec("DELETE FROM videos WHERE id = ?", videoID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete video"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Video not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Video deleted successfully"})
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
