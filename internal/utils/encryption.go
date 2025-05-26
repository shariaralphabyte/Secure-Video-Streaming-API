package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// FileCleanup handles proper cleanup of files on macOS
type FileCleanup struct {
	paths []string
	mu    sync.Mutex
}

func NewFileCleanup() *FileCleanup {
	return &FileCleanup{
		paths: make([]string, 0),
	}
}

func (fc *FileCleanup) Add(path string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.paths = append(fc.paths, path)
}

func (fc *FileCleanup) Cleanup() {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	for _, path := range fc.paths {
		if err := os.Remove(path); err != nil {
			if !os.IsNotExist(err) {
				log.Printf("Error cleaning up file %s: %v", path, err)
			}
		}
	}
	fc.paths = fc.paths[:0]
}

func (fc *FileCleanup) CleanupExcept(path string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	var remainingPaths []string
	for _, p := range fc.paths {
		if p != path {
			if err := os.Remove(p); err != nil {
				if !os.IsNotExist(err) {
					log.Printf("[Cleanup] Error removing file %s: %v", p, err)
				}
			}
		} else {
			remainingPaths = append(remainingPaths, p)
		}
	}
	fc.paths = remainingPaths
}

// cleanupOnError handles cleanup when an error occurs during encryption/decryption
func cleanupOnError(cleanup *FileCleanup, tempFiles []string, err error) error {
	for _, file := range tempFiles {
		if err := os.Remove(file); err != nil {
			if !os.IsNotExist(err) {
				log.Printf("[Cleanup] Error removing temporary file %s: %v", file, err)
			}
		}
	}
	cleanup.Cleanup()
	return err
}

// createTempFile creates a temporary file with proper permissions for macOS
func createTempFile(prefix string) (string, error) {
	tmpDir := os.TempDir()
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return "", fmt.Errorf("failed to ensure temp directory exists: %v", err)
	}

	tmpFile, err := os.CreateTemp(tmpDir, prefix)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %v", err)
	}

	tmpPath := tmpFile.Name()
	tmpFile.Close()

	// Set proper permissions for macOS
	if err := os.Chmod(tmpPath, 0644); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to set temp file permissions: %v", err)
	}

	return tmpPath, nil
}

func EncryptFile(inputPath, outputPath string, key []byte) error {
	cleanup := NewFileCleanup()
	defer cleanup.Cleanup()

	// Validate paths are absolute
	if !filepath.IsAbs(inputPath) {
		return fmt.Errorf("input path must be absolute: %s", inputPath)
	}
	if !filepath.IsAbs(outputPath) {
		return fmt.Errorf("output path must be absolute: %s", outputPath)
	}

	// Create temporary file for atomic operation
	tempOutput, err := createTempFile("encrypt-")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %v", err)
	}
	cleanup.Add(tempOutput)

	// Log operation details
	log.Printf("[EncryptFile] Starting encryption")
	log.Printf("[EncryptFile] Input path: %s", inputPath)
	log.Printf("[EncryptFile] Output path: %s", outputPath)
	log.Printf("[EncryptFile] Temp path: %s", tempOutput)

	// Validate key length
	if len(key) != 32 {
		return fmt.Errorf("invalid key length: got %d bytes, want 32 bytes", len(key))
	}

	// Ensure input file exists and validate permissions
	if err := validateFileAndPermissions(inputPath, false); err != nil {
		return fmt.Errorf("input validation error: %v", err)
	}

	// Validate output path and directory permissions
	if err := validateFileAndPermissions(outputPath, true); err != nil {
		return fmt.Errorf("output validation error: %v", err)
	}

	// Open input file with macOS-compatible permissions
	inFile, err := os.OpenFile(inputPath, os.O_RDONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open input file %s: %v (permissions: %s)", inputPath, err, getFilePermissions(inputPath))
	}
	defer inFile.Close()

	// Ensure output directory exists with proper permissions
	outDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for %s: %v", outDir, err)
	}

	// Create output file with explicit permissions
	outFile, err := os.OpenFile(tempOutput, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %v (dir permissions: %s)",
			tempOutput, err, getFilePermissions(outDir))
	}
	defer outFile.Close()

	// Ensure file permissions are set correctly
	if err := os.Chmod(tempOutput, 0644); err != nil {
		return fmt.Errorf("failed to set permissions on output file: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}

	// Create the GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %v", err)
	}

	// Create and write nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to create nonce: %v", err)
	}
	if _, err := outFile.Write(nonce); err != nil {
		return fmt.Errorf("failed to write nonce: %v", err)
	}

	// Create a buffer for reading chunks
	const chunkSize = 64 * 1024 // 64KB chunks
	buf := make([]byte, chunkSize)

	// Read and encrypt file in chunks
	for {
		n, err := inFile.Read(buf)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read input file: %v", err)
		}
		if n == 0 {
			break
		}

		// Encrypt chunk
		ciphertext := gcm.Seal(nil, nonce, buf[:n], nil)

		// Write encrypted chunk
		if _, err := outFile.Write(ciphertext); err != nil {
			return fmt.Errorf("failed to write encrypted data: %v", err)
		}
	}

	// Use atomic rename for final move
	if err := os.Rename(tempOutput, outputPath); err != nil {
		return fmt.Errorf("failed to move encrypted file to final location: %v", err)
	}

	// Remove temp file from cleanup list since it was successfully moved
	cleanup.mu.Lock()
	for i, path := range cleanup.paths {
		if path == tempOutput {
			cleanup.paths = append(cleanup.paths[:i], cleanup.paths[i+1:]...)
			break
		}
	}
	cleanup.mu.Unlock()

	return nil
}

func DecryptFile(inputPath, outputPath string, key []byte) error {
	cleanup := NewFileCleanup()
	defer cleanup.Cleanup()

	// Create temporary file for atomic operation
	tempOutput, err := createTempFile("decrypt-")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %v", err)
	}
	cleanup.Add(tempOutput)

	// Validate key length
	if len(key) != 32 {
		return fmt.Errorf("invalid key length: got %d bytes, want 32 bytes", len(key))
	}

	// Validate input file and permissions
	if err := validateFileAndPermissions(inputPath, false); err != nil {
		return fmt.Errorf("input validation error: %v", err)
	}

	// Validate output path and directory permissions
	if err := validateFileAndPermissions(outputPath, true); err != nil {
		return fmt.Errorf("output validation error: %v", err)
	}

	// Open input file with explicit permissions
	inFile, err := os.OpenFile(inputPath, os.O_RDONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open encrypted file %s: %v (permissions: %s)",
			inputPath, err, getFilePermissions(inputPath))
	}
	defer inFile.Close()

	// Create output file with explicit permissions
	outFile, err := os.OpenFile(tempOutput, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %v (dir permissions: %s)",
			tempOutput, err, getFilePermissions(filepath.Dir(tempOutput)))
	}
	defer outFile.Close()

	// Ensure file permissions are set correctly
	if err := os.Chmod(tempOutput, 0644); err != nil {
		return fmt.Errorf("failed to set permissions on output file: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	nonce := make([]byte, nonceSize)

	// Read the nonce
	if _, err := io.ReadFull(inFile, nonce); err != nil {
		return fmt.Errorf("failed to read nonce: %v", err)
	}

	// Create a buffer for reading chunks
	const chunkSize = 64 * 1024 // 64KB chunks
	buf := make([]byte, chunkSize+gcm.Overhead())

	// Read and decrypt file in chunks
	for {
		n, err := inFile.Read(buf)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read encrypted file: %v", err)
		}
		if n == 0 {
			break
		}

		// Decrypt chunk
		plaintext, err := gcm.Open(nil, nonce, buf[:n], nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt data: %v", err)
		}

		// Write decrypted chunk
		if _, err := outFile.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write decrypted data: %v", err)
		}
	}

	// Use atomic rename for final move
	if err := os.Rename(tempOutput, outputPath); err != nil {
		return fmt.Errorf("failed to move decrypted file to final location: %v", err)
	}

	// Remove temp file from cleanup list since it was successfully moved
	cleanup.mu.Lock()
	for i, path := range cleanup.paths {
		if path == tempOutput {
			cleanup.paths = append(cleanup.paths[:i], cleanup.paths[i+1:]...)
			break
		}
	}
	cleanup.mu.Unlock()

	return nil
}

func getFilePermissions(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Sprintf("error getting permissions: %v", err)
	}
	mode := info.Mode()
	return fmt.Sprintf("%04o", mode.Perm())
}

func validateFileAndPermissions(path string, isOutput bool) error {
	dir := filepath.Dir(path)

	// Ensure directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	// Check directory permissions
	dirInfo, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("failed to check directory %s: %v", dir, err)
	}

	dirPerm := dirInfo.Mode().Perm()
	if dirPerm&0755 != 0755 {
		// Try to fix directory permissions
		if err := os.Chmod(dir, 0755); err != nil {
			return fmt.Errorf("insufficient directory permissions %04o and unable to fix: %v", dirPerm, err)
		}
	}

	if !isOutput {
		// For input files, check if file exists and is readable
		fileInfo, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("failed to check input file: %v", err)
		}

		if !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("not a regular file: %s", path)
		}

		// Check file permissions
		filePerm := fileInfo.Mode().Perm()
		if filePerm&0444 != 0444 {
			// Try to fix file permissions
			if err := os.Chmod(path, 0644); err != nil {
				return fmt.Errorf("insufficient file permissions %04o and unable to fix: %v", filePerm, err)
			}
		}
	}

	return nil
}

func checkFileAccess(path string) error {
	// Check if file exists
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", path)
		}
		return fmt.Errorf("error checking file status: %v", err)
	}

	// Check if it's a regular file
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", path)
	}

	// Try to open the file for reading
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("cannot access file %s: %v (permissions: %s)",
			path, err, getFilePermissions(path))
	}
	file.Close()

	// Check if directory is accessible
	dir := filepath.Dir(path)
	dirInfo, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("error accessing directory %s: %v", dir, err)
	}
	if !dirInfo.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}

	// Check directory permissions
	if dirPerm := dirInfo.Mode().Perm(); dirPerm&0700 != 0700 {
		return fmt.Errorf("insufficient directory permissions: %04o", dirPerm)
	}

	return nil
}
