package auth

import (
	"golang.org/x/crypto/bcrypt"
    "time"
    "errors"
    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
	"net/http"
	"strings"
	"crypto/rand"
	"encoding/hex"
	"fmt"		
)

// HashPassword takes a plain-text password and returns a bcrypt hash.
func HashPassword(password string) (string, error) {
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashBytes), nil
}

// CheckPasswordHash compares a plain-text password with a bcrypt hashed password.
// Returns nil if they match, or an error otherwise.
func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// MakeJWT creates a signed JWT token for the given user ID, using HS256 and RegisteredClaims.
func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
    now := time.Now().UTC()

    claims := jwt.RegisteredClaims{
        Issuer:    "chirpy",
        IssuedAt:  jwt.NewNumericDate(now),
        ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
        Subject:   userID.String(),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

    signedToken, err := token.SignedString([]byte(tokenSecret))
    if err != nil {
        return "", err
    }

    return signedToken, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
    // Parse the token with RegisteredClaims
    token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
        // Make sure the signing method is HS256
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("unexpected signing method")
        }
        return []byte(tokenSecret), nil
    })

    if err != nil {
        return uuid.Nil, err
    }

    // Extract claims
    claims, ok := token.Claims.(*jwt.RegisteredClaims)
    if !ok || !token.Valid {
        return uuid.Nil, errors.New("invalid token")
    }

    // Convert Subject to uuid.UUID
    userID, err := uuid.Parse(claims.Subject)
    if err != nil {
        return uuid.Nil, err
    }

    return userID, nil
}
func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header not found")
	}

	parts := strings.Fields(authHeader)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", errors.New("invalid authorization header format")
	}

	return parts[1], nil
}



// MakeRefreshToken generates a random 256-bit (32-byte) hex-encoded string.
func MakeRefreshToken() (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return hex.EncodeToString(b), nil
}
func GetAPIKey(headers http.Header) (string, error) {
    authHeader := headers.Get("Authorization")
    if authHeader == "" {
        return "", errors.New("Authorization header missing")
    }

    const prefix = "ApiKey "
    if !strings.HasPrefix(authHeader, prefix) {
        return "", errors.New("Invalid Authorization header format")
    }

    return strings.TrimSpace(authHeader[len(prefix):]), nil
}