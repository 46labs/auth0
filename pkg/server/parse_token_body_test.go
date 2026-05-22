package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseTokenBody(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		wantForm    map[string]string
		wantErr     bool
	}{
		{
			name:        "form-encoded",
			contentType: "application/x-www-form-urlencoded",
			body:        "grant_type=authorization_code&code=abc&client_id=pl8txt-ios",
			wantForm: map[string]string{
				"grant_type": "authorization_code",
				"code":       "abc",
				"client_id":  "pl8txt-ios",
			},
		},
		{
			name:        "json",
			contentType: "application/json",
			body:        `{"grant_type":"authorization_code","code":"abc","client_id":"pl8txt-ios"}`,
			wantForm: map[string]string{
				"grant_type": "authorization_code",
				"code":       "abc",
				"client_id":  "pl8txt-ios",
			},
		},
		{
			name:        "json with charset",
			contentType: "application/json; charset=utf-8",
			body:        `{"grant_type":"refresh_token","refresh_token":"r1"}`,
			wantForm: map[string]string{
				"grant_type":    "refresh_token",
				"refresh_token": "r1",
			},
		},
		{
			name:        "json with bool and number coerced",
			contentType: "application/json",
			body:        `{"grant_type":"x","retry":true,"expires_in":3600}`,
			wantForm: map[string]string{
				"grant_type": "x",
				"retry":      "true",
				"expires_in": "3600",
			},
		},
		{
			name:        "json empty body",
			contentType: "application/json",
			body:        "",
			wantForm:    map[string]string{},
		},
		{
			name:        "json malformed",
			contentType: "application/json",
			body:        `{"grant_type":`,
			wantErr:     true,
		},
		{
			name:        "form-encoded malformed is still nil error (stdlib parses lenient)",
			contentType: "application/x-www-form-urlencoded",
			body:        "this is not valid form data but parses anyway",
			wantForm:    map[string]string{"this is not valid form data but parses anyway": ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(tt.body))
			r.Header.Set("Content-Type", tt.contentType)

			err := parseTokenBody(r)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for k, want := range tt.wantForm {
				if got := r.FormValue(k); got != want {
					t.Errorf("FormValue(%q) = %q, want %q", k, got, want)
				}
			}
			for k := range r.Form {
				if _, ok := tt.wantForm[k]; !ok {
					t.Errorf("unexpected form key %q = %q", k, r.FormValue(k))
				}
			}
		})
	}
}
