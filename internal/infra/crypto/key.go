package crypto

import (
	"strings"
)

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func calculateChecksum(data string, length int) string {
	sum := 0
	for i, char := range data {
		val := strings.IndexRune(alphabet, char)
		if i%2 == 0 {
			val *= 2
		}
		sum += val
	}

	var checksum strings.Builder
	for i := 0; i < length; i++ {
		idx := (sum + i*31) % len(alphabet)
		checksum.WriteByte(alphabet[idx])
	}
	return checksum.String()
}

func ValidateKey(key string, luhnLen int) bool {
	dataPart := key[:len(key)-luhnLen]
	providedLuhn := key[len(key)-luhnLen:]

	expectedLuhn := calculateChecksum(dataPart, luhnLen)
	return providedLuhn == expectedLuhn
}

// SanitizeKey uppercases, strips separators, and folds the ambiguous
// characters O/I/L to their native-alphabet look-alikes 0/1/1. This is a
// human-typo correction specific to the native key alphabet (which
// deliberately excludes O/I/L) — use it only where the value is expected
// to be a native-format key. Use NormalizeKey for anything else.
func SanitizeKey(input string) string {
	s := strings.ToUpper(input)
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")

	s = strings.ReplaceAll(s, "O", "0")
	s = strings.ReplaceAll(s, "I", "1")
	s = strings.ReplaceAll(s, "L", "1")

	return s
}

// NormalizeKey uppercases and strips separators, with no other
// transformation. Unlike SanitizeKey, it never assumes the input is in the
// native key alphabet, so it's safe to use on any license key string
// regardless of which system minted it.
func NormalizeKey(input string) string {
	s := strings.ToUpper(input)
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}
