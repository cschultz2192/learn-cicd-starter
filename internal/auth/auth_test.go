package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestAuth(t *testing.T) {
	type test struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}

	tests := []test{
		{
			name:        "Valid api Key",
			headers:     http.Header{"Authorization": []string{"ApiKey my-api-key"}},
			expectedKey: "my-api-key",
			expectedErr: nil,
		},
		{
			name:        "missing authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "wrong scheme (Bearer instead of ApiKey)",
			headers:     http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "header with no value after scheme",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "completely malformed header",
			headers:     http.Header{"Authorization": []string{"notvalid"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tc := range tests {
		got, err := GetAPIKey(tc.headers)
		if got != tc.expectedKey {
			t.Fatalf("\nname: %v\nexpected: %v, got: %v", tc.name, tc.expectedKey, got)
		}
		if tc.expectedErr == nil && err != nil {
			t.Fatalf("\nname: %v\nexpectedErr: nil, gotErr: %v", tc.name, err)
		}
		if tc.expectedErr != nil && err == nil {
			t.Fatalf("\nname: %v\nexpectedErr: %v, gotErr: nil", tc.name, tc.expectedErr)
		}
		if tc.expectedErr != nil && err != nil && err.Error() != tc.expectedErr.Error() {
			t.Fatalf("\nname: %v\nexpectedErr: %v, gotErr: %v", tc.name, tc.expectedErr, err)
		}
	}
}
