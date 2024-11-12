package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Define test cases
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			expectedKey:   "abc123",
			expectedError: nil,
		},
		{
			name:          "Missing Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Header - No ApiKey Prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Header - Empty Value",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Header - Only Prefix",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	// Run test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check error
			if tt.expectedError != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.expectedError)
					return
				}
				if err.Error() != tt.expectedError.Error() {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
					return
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
				return
			}

			// Check key value
			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}
