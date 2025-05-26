# Secure Video Streaming API

A secure video streaming service built with Go that provides encrypted video storage and streaming capabilities.

## Features

- User authentication with JWT
- Role-based access control (Admin/User)
- Secure video upload with AES-256 encryption
- Video streaming with range request support
- CRUD operations for video management (Admin only)
- SQLite database for data persistence
- User management using revolk token

## Prerequisites

- Go 1.18 or higher
- SQLite3
- ffmpeg (optional, for video processing)

## Installation

1. Clone the repository:
```bash
git clone [<repository-url>](https://github.com/shariaralphabyte/Secure-Video-Streaming-API.git)
cd secure-video-api
```

2. Install dependencies:
```bash
go mod download
```

3. Create a .env file (already provided) with the following configuration:
```env
SERVER_PORT=8080
JWT_SECRET=your-super-secret-key-change-in-production
ENCRYPTION_KEY=32-byte-key-for-video-encryption12
SQLITE_DB_PATH=./database.db
STORAGE_PATH=./storage/videos
ENCRYPTED_PATH=./storage/encrypted
ADMIN_EMAIL=shariar99@gmail.com
ADMIN_PASSWORD=Alpha1234
```

4. Create required directories:
```bash
mkdir -p storage/videos storage/encrypted
```

## Running the Application

1. Build and run the application:
```bash
go run cmd/api/main.go
```

The server will start on http://localhost:8080

## Default Admin Account

Email: shariar99@gmail.com
Password: Alpha1234

## API Endpoints

### Authentication
- POST /api/auth/register - Register a new user
- POST /api/auth/login - Login user

### Videos (Protected Routes)
- GET /api/videos - List all videos
- GET /api/videos/:id/stream - Stream a video

### Admin Routes (Protected + Admin Only)
- POST /api/admin/videos - Upload a new video
- PUT /api/admin/videos/:id - Update video details
- DELETE /api/admin/videos/:id - Delete a video

## Testing with Postman

1. Import the provided Postman collection (`secure-video-api.postman_collection.json`).
2. Set up the environment variable `base_url` to `http://localhost:8080`.
3. Login with the admin credentials to get a JWT token.
4. Set the received token in the `token` environment variable.
5. Use the collection to test all endpoints.

## Security Features

- AES-256 encryption for stored videos
- JWT-based authentication
- Password hashing with bcrypt
- Role-based access control
- Secure video streaming with range request support
- No direct access to video files
- OTP print in console for additional security

## Project Structure

```
.
├── cmd/
│   └── api/
│       └── main.go
├── config/
├── internal/
│   ├── auth/
│   ├── database/
│   ├── handlers/
│   ├── middleware/
│   ├── models/
│   ├── storage/
│   └── utils/
├── storage/
│   ├── encrypted/
│   └── videos/
├── go.mod
├── go.sum
└── .env
```


