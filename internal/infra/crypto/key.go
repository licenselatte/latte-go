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

func SanitizeKey(input string) string {
	s := strings.ToUpper(input)
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")

	s = strings.ReplaceAll(s, "O", "0")
	s = strings.ReplaceAll(s, "I", "1")
	s = strings.ReplaceAll(s, "L", "1")

	return s
}
