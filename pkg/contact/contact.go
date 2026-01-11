package contact

import (
	"fmt"
	"regexp"
	"strings"
)

var digitRegex = regexp.MustCompile(`[^\d]`)
var letterRegex = regexp.MustCompile(`[a-zA-Z]`)

// IsEmail checks if the identifier is likely an email address
// Returns true if contains @ or has letters
func IsEmail(identifier string) bool {
	return strings.Contains(identifier, "@") || letterRegex.MatchString(identifier)
}

// NormalizePhoneToE164 normalizes a phone number to E.164 format
// Defaults to US (+1) country code for 10-digit numbers
// Returns normalized number or error if invalid
func NormalizePhoneToE164(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("phone number cannot be empty")
	}

	// Remove all non-digit characters
	digitsOnly := digitRegex.ReplaceAllString(input, "")

	if digitsOnly == "" {
		return "", fmt.Errorf("phone number must contain digits")
	}

	// Handle different cases
	switch len(digitsOnly) {
	case 10:
		// US number without country code: 5551234567
		return "+1" + digitsOnly, nil
	case 11:
		// Number with country code (assume 1 prefix is US)
		if strings.HasPrefix(digitsOnly, "1") {
			return "+" + digitsOnly, nil
		}
		// Non-US 11-digit number
		return "+" + digitsOnly, nil
	default:
		// International numbers (12-15 digits)
		if len(digitsOnly) > 11 && len(digitsOnly) <= 15 {
			return "+" + digitsOnly, nil
		}
		return "", fmt.Errorf("invalid phone number length: %d digits", len(digitsOnly))
	}
}

// IsValidE164 checks if a phone number is in valid E.164 format
func IsValidE164(phone string) bool {
	if !strings.HasPrefix(phone, "+") {
		return false
	}

	digitsOnly := digitRegex.ReplaceAllString(phone, "")
	length := len(digitsOnly)

	// E.164 allows 10-15 digits (including country code)
	return length >= 10 && length <= 15
}
