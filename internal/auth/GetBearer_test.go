package auth

import (
	"net/http"
	"testing"
)

func TestGetBearerToken(t *testing.T) {
	token := "abc123"
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)

	got, err := GetBearerToken(headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != token {
		t.Fatalf("expected %s, got %s", token, got)
	}

	// Test missing header
	headers = http.Header{}
	_, err = GetBearerToken(headers)
	if err == nil {
		t.Fatal("expected error for missing header")
	}

	// Test invalid format
	headers.Set("Authorization", "InvalidTokenFormat")
	_, err = GetBearerToken(headers)
	if err == nil {
		t.Fatal("expected error for invalid header format")
	}
}
