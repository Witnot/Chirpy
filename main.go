package main
import (
	"encoding/json"
	"fmt"
	_ "github.com/lib/pq"
	"net/http"
	"sync/atomic"
	"regexp"
	"database/sql"
	"log"
	"os"
    "github.com/google/uuid"	
    "github.com/Witnot/Chirpy/internal/database"
	"github.com/joho/godotenv"
	"errors"	
	"time"
	"github.com/Witnot/Chirpy/internal/auth"
	"strings"
	"sort"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	jwtSecret string
    polkaKey       string
}


// Middleware to count hits for /app/
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// Admin metrics handler (GET only, HTML response)
func (cfg *apiConfig) handleAdminMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	hits := cfg.fileserverHits.Load()
	html := fmt.Sprintf(`
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, hits)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// Admin reset handler (POST only)
func (cfg *apiConfig) handleAdminReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Only allow in dev environment
	if cfg.platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Forbidden: Not in dev environment"))
		return
	}

	// Reset metrics counter
	cfg.fileserverHits.Store(0)

	// Delete all users
	if err := cfg.db.DeleteAllUsers(r.Context()); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to delete users"})
		return
	}


	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits counter reset and all users deleted"))
}

func handleValidateChirp(w http.ResponseWriter, r *http.Request) {
    type chirpRequest struct {
        Body string `json:"body"`
    }
    type chirpResponse struct {
        CleanedBody string `json:"cleaned_body"`
    }

    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }

    var req chirpRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Something went wrong"})
        return
    }

    if len(req.Body) > 140 {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Chirp is too long"})
        return
    }

    // Profanity filter
    profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
    cleaned := req.Body
    for _, word := range profaneWords {
        re := regexp.MustCompile(`(?i)\b` + word + `\b`)
        cleaned = re.ReplaceAllString(cleaned, "****")
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(chirpResponse{CleanedBody: cleaned})
}
type createUserRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}
type createUserResponse struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Email     string `json:"email"`
	IsChirpyRed  bool   `json:"is_chirpy_red"`
}

func (cfg *apiConfig) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	// Hash the password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to hash password"})
		return
	}

	// Create user in DB
	user, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:          req.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Could not create user"})
		return
	}

	// Wrap SQLC user in response struct (exclude password)
	resp := createUserResponse{
		ID:        user.ID.String(),
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
		UpdatedAt: user.UpdatedAt.Format(time.RFC3339),
		Email:     user.Email,
		IsChirpyRed:  user.IsChirpyRed,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}


type createChirpResponse struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Body      string `json:"body"`
	UserID    string `json:"user_id"`
}

type createChirpRequest struct {
    Body string `json:"body"`
}
func (cfg *apiConfig) handleCreateChirp(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }

    // Get JWT from Authorization header
    tokenString, err := auth.GetBearerToken(r.Header)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Missing or invalid token"})
        return
    }

    // Validate JWT
    userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid or expired token"})
        return
    }

    // Decode request body
    var req createChirpRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
        return
    }

    // Validate chirp length
    if len(req.Body) > 140 {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Chirp is too long"})
        return
    }

    // Profanity filter
    profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
    cleaned := req.Body
    for _, word := range profaneWords {
        re := regexp.MustCompile(`(?i)\b` + word + `\b`)
        cleaned = re.ReplaceAllString(cleaned, "****")
    }

    // Create chirp in DB
    params := database.CreateChirpParams{
        Body:   cleaned,
        UserID: userID,
    }

    chirp, err := cfg.db.CreateChirp(r.Context(), params)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create chirp"})
        return
    }

    // Return JSON response
    resp := createChirpResponse{
        ID:        chirp.ID.String(),
        CreatedAt: chirp.CreatedAt.Format("2006-01-02T15:04:05Z"),
        UpdatedAt: chirp.UpdatedAt.Format("2006-01-02T15:04:05Z"),
        Body:      chirp.Body,
        UserID:    chirp.UserID.String(),
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(resp)
}

func (cfg *apiConfig) handleGetChirps(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }

    // Optional query parameters
    authorIDStr := r.URL.Query().Get("author_id")
    sortOrder := r.URL.Query().Get("sort") // "asc" or "desc"

    var chirps []database.Chirp
    var err error

    if authorIDStr != "" {
        // Parse author_id as UUID
        authorUUID, parseErr := uuid.Parse(authorIDStr)
        if parseErr != nil {
            http.Error(w, "invalid author_id", http.StatusBadRequest)
            return
        }

        // Fetch chirps for this author
        chirps, err = cfg.db.GetChirpsByUserID(r.Context(), authorUUID)
    } else {
        // Fetch all chirps
        chirps, err = cfg.db.GetChirps(r.Context())
    }

    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to fetch chirps"})
        return
    }

    // Sort chirps in-memory
    if sortOrder != "desc" {
        sort.Slice(chirps, func(i, j int) bool {
            return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
        })
    } else {
        sort.Slice(chirps, func(i, j int) bool {
            return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
        })
    }

    // Transform DB rows into API response objects
    resp := make([]map[string]interface{}, len(chirps))
    for i, c := range chirps {
        resp[i] = map[string]interface{}{
            "id":         c.ID,
            "created_at": c.CreatedAt,
            "updated_at": c.UpdatedAt,
            "body":       c.Body,
            "user_id":    c.UserID,
        }
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(resp)
}

func (cfg *apiConfig) handleGetChirpByID(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }

    // Extract chirpID from URL path
    parts := strings.Split(r.URL.Path, "/")
    if len(parts) < 4 || parts[3] == "" {
        http.Error(w, "chirp ID missing", http.StatusBadRequest)
        return
    }
    chirpIDStr := parts[3]

    chirpUUID, err := uuid.Parse(chirpIDStr)
    if err != nil {
        http.Error(w, "invalid chirp ID", http.StatusBadRequest)
        return
    }

    chirp, err := cfg.db.GetChirpByID(r.Context(), chirpUUID)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            http.Error(w, "chirp not found", http.StatusNotFound)
        } else {
            http.Error(w, "failed to fetch chirp", http.StatusInternalServerError)
        }
        return
    }

    resp := createChirpResponse{
        ID:        chirp.ID.String(),
        CreatedAt: chirp.CreatedAt.Format(time.RFC3339),
        UpdatedAt: chirp.UpdatedAt.Format(time.RFC3339),
        Body:      chirp.Body,
        UserID:    chirp.UserID.String(),
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(resp)
}

type loginRequest struct {
    Email           string `json:"email"`
    Password        string `json:"password"`
    ExpiresInSeconds *int   `json:"expires_in_seconds,omitempty"`
}
func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }

    var req loginRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
        return
    }

    // Look up user by email
    user, err := cfg.db.GetUserByEmail(r.Context(), req.Email)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Incorrect email or password"})
        return
    }

    // Compare password with stored hash
    if err := auth.CheckPasswordHash(req.Password, user.HashedPassword); err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Incorrect email or password"})
        return
    }

    // Generate access token (JWT) - 1 hour
    accessToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Hour)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create access token"})
        return
    }

    // Generate refresh token (random 256-bit string)
    refreshToken, err := auth.MakeRefreshToken()
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create refresh token"})
        return
    }

    // Save refresh token in DB (expires in 60 days)
    expiresAt := time.Now().Add(60 * 24 * time.Hour) // 60 days
    _, err = cfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
        Token:     refreshToken,
        UserID:    user.ID,
        ExpiresAt: expiresAt,
    })
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to save refresh token"})
        return
    }

    // Return user info + tokens
    resp := map[string]interface{}{
        "id":            user.ID.String(),
        "created_at":    user.CreatedAt.Format(time.RFC3339),
        "updated_at":    user.UpdatedAt.Format(time.RFC3339),
        "email":         user.Email,
		"is_chirpy_red": user.IsChirpyRed,
        "token":         accessToken,
        "refresh_token": refreshToken,
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(resp)
}

func (cfg *apiConfig) handleRefresh(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }

    // Extract token from Authorization header
    refreshToken, err := auth.GetBearerToken(r.Header)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Missing or invalid Authorization header"})
        return
    }

    // Look up token in DB
    tokenRow, err := cfg.db.GetRefreshToken(r.Context(), refreshToken)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid refresh token"})
        return
    }

    // Check if token is expired or revoked
    if tokenRow.ExpiresAt.Before(time.Now().UTC()) || (tokenRow.RevokedAt.Valid && !tokenRow.RevokedAt.Time.IsZero()) {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(map[string]string{"error": "Refresh token expired or revoked"})
        return
    }

    // Generate new access token (JWT) for the user
    accessToken, err := auth.MakeJWT(tokenRow.UserID, cfg.jwtSecret, time.Hour)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create access token"})
        return
    }

    // Return the new access token
    resp := map[string]string{
        "token": accessToken,
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(resp)
}
func (cfg *apiConfig) handleRevoke(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }

    // Extract the refresh token from Authorization header
    refreshToken, err := auth.GetBearerToken(r.Header)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }

    // Revoke the token in the database
    err = cfg.db.RevokeRefreshToken(r.Context(), refreshToken)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    // Successful revoke, return 204 No Content
    w.WriteHeader(http.StatusNoContent)
}
type updateUserRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

func (cfg *apiConfig) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPut {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }

    // Extract the access token from the Authorization header
    tokenString, err := auth.GetBearerToken(r.Header)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }

    // Validate JWT and get the user ID
    userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }

    // Decode request body
    var req updateUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
        return
    }

    // Hash the new password
    hashedPassword, err := auth.HashPassword(req.Password)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to hash password"})
        return
    }

    // Update the user in the database
    updatedUser, err := cfg.db.UpdateUser(r.Context(), database.UpdateUserParams{
        ID:             userID,
        Email:          req.Email,
        HashedPassword: hashedPassword,
    })
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update user"})
        return
    }

    // Return updated user (without password)
    resp := map[string]interface{}{
        "id":         updatedUser.ID.String(),
        "created_at": updatedUser.CreatedAt.Format(time.RFC3339),
        "updated_at": updatedUser.UpdatedAt.Format(time.RFC3339),
        "email":      updatedUser.Email,
		"is_chirpy_red": updatedUser.IsChirpyRed, // include Chirpy Red status
	}

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(resp)
}

func (cfg *apiConfig) handleDeleteChirp(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodDelete {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }

    // Extract chirpID from URL path
    parts := strings.Split(r.URL.Path, "/")
    if len(parts) < 4 || parts[3] == "" {
        http.Error(w, "chirp ID missing", http.StatusBadRequest)
        return
    }
    chirpIDStr := parts[3]

    chirpUUID, err := uuid.Parse(chirpIDStr)
    if err != nil {
        http.Error(w, "invalid chirp ID", http.StatusBadRequest)
        return
    }

    // Authenticate user from JWT
    tokenStr, err := auth.GetBearerToken(r.Header)
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    userID, err := auth.ValidateJWT(tokenStr, cfg.jwtSecret)
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    // Fetch the chirp to check ownership
    chirp, err := cfg.db.GetChirpByID(r.Context(), chirpUUID)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            http.Error(w, "chirp not found", http.StatusNotFound)
        } else {
            http.Error(w, "failed to fetch chirp", http.StatusInternalServerError)
        }
        return
    }

    if chirp.UserID != userID {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }

    // Delete the chirp
    if err := cfg.db.DeleteChirp(r.Context(), chirpUUID); err != nil {
        http.Error(w, "failed to delete chirp", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

type polkaWebhookRequest struct {
	Event string `json:"event"`
	Data  struct {
		UserID string `json:"user_id"`
	} `json:"data"`
}

func (cfg *apiConfig) handlePolkaWebhook(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }

    apiKey, err := auth.GetAPIKey(r.Header)
    if err != nil || apiKey != cfg.polkaKey {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }

    // Decode the webhook body
    var req struct {
        Event string `json:"event"`
        Data  struct {
            UserID string `json:"user_id"`
        } `json:"data"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    if req.Event != "user.upgraded" {
        w.WriteHeader(http.StatusNoContent)
        return
    }

    userUUID, err := uuid.Parse(req.Data.UserID)
    if err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    // Upgrade user in DB
	err = cfg.db.UpgradeUserToChirpyRed(r.Context(), userUUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

    w.WriteHeader(http.StatusNoContent)
}






func main() {
	// Load env vars
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found (falling back to system env)")
	}

	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("DB_URL not set in environment")
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET not set in environment")
	}
	platform := os.Getenv("PLATFORM")
	polkaKey := os.Getenv("POLKA_KEY")
	if polkaKey == "" {
		log.Fatal("POLKA_KEY not set in environment")
	}
	// Open DB connection
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Cannot open DB connection:", err)
	}
	defer db.Close()

	// Initialize SQLC Queries
	dbQueries := database.New(db)

	// Inject into apiConfig
	apiCfg := &apiConfig{
		db:             dbQueries,
		fileserverHits: atomic.Int32{},
		platform:       platform,
		jwtSecret: jwtSecret, // add this field to apiConfig
		polkaKey:       polkaKey, // <-- add this field to apiConfig
	}

	// --- ROUTES ---
	mux := http.NewServeMux()

	// /api/healthz handler (GET only)
	mux.HandleFunc("/api/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Serve static files under /app/ with metrics middleware
	fileServer := http.FileServer(http.Dir("."))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", fileServer)))

	// Serve assets under /assets/
	assetsServer := http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets")))
	mux.Handle("/assets/", assetsServer)

	// Admin endpoints
	mux.HandleFunc("/admin/metrics", apiCfg.handleAdminMetrics)
	mux.HandleFunc("/admin/reset", apiCfg.handleAdminReset)

	// API endpoints

	// Validation
	mux.HandleFunc("POST /api/validate_chirp", handleValidateChirp)

	// Users
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			apiCfg.handleCreateUser(w, r)
		case http.MethodPut:
			apiCfg.handleUpdateUser(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/login", apiCfg.handleLogin)
	// Chirps
	mux.HandleFunc("POST /api/chirps", apiCfg.handleCreateChirp)
	mux.HandleFunc("GET /api/chirps", apiCfg.handleGetChirps)
	mux.HandleFunc("/api/polka/webhooks", apiCfg.handlePolkaWebhook)


	mux.HandleFunc("/api/refresh", apiCfg.handleRefresh)
	mux.HandleFunc("/api/revoke", apiCfg.handleRevoke)
	mux.HandleFunc("/api/chirps/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			apiCfg.handleGetChirpByID(w, r)
		case http.MethodDelete:
			apiCfg.handleDeleteChirp(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})





	// --- START SERVER ---
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	log.Println("Server listening on :8080")
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
