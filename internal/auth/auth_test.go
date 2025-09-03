package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	secret := "mysecretkey"
	expires := time.Minute * 5

	// Create JWT
	token, err := MakeJWT(userID, secret, expires)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	// Validate JWT
	parsedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateJWT returned error: %v", err)
	}

	if parsedID != userID {
		t.Fatalf("Expected userID %v, got %v", userID, parsedID)
	}
}

func TestExpiredJWT(t *testing.T) {
	userID := uuid.New()
	secret := "mysecretkey"
	// Set token to expire in the past
	token, err := MakeJWT(userID, secret, -time.Minute)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Fatalf("Expected error for expired token, got nil")
	}
}

func TestJWTWrongSecret(t *testing.T) {
	userID := uuid.New()
	secret := "mysecretkey"
	wrongSecret := "wrongsecret"
	expires := time.Minute * 5

	token, err := MakeJWT(userID, secret, expires)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	_, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Fatalf("Expected error for wrong secret, got nil")
	}
}

func TestJWTTamperedToken(t *testing.T) {
	userID := uuid.New()
	secret := "mysecretkey"
	expires := time.Minute * 5

	token, err := MakeJWT(userID, secret, expires)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	// Tamper with the token by appending a character
	tamperedToken := token + "x"

	_, err = ValidateJWT(tamperedToken, secret)
	if err == nil {
		t.Fatalf("Expected error for tampered token, got nil")
	}
}
