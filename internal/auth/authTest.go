package auth

import (
	"errors"
	"net/http"
	"reflect"
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
		if !reflect.DeepEqual(got, tc.expectedErr) {
			t.Fatalf("expected: %v, got: %v", tc.expectedKey, got)
		}
		if err == tc.expectedErr {
			t.Fatalf("expectedErr: %v, gotErr: %v", tc.expectedErr, err)
		}
	}

}
