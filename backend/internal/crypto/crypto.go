// Package crypto provides server-side AES-256-GCM encryption and
// Argon2id password hashing used to protect clip content at rest.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ---- AES-256-GCM cipher ----

// Cipher wraps an AES-256-GCM block cipher.
// The wire format is: base64( nonce[12] || ciphertext ).
type Cipher struct {
	key []byte
}

// NewCipher creates a Cipher from a 64-character lowercase hex key (32 bytes).
func NewCipher(keyHex string) (*Cipher, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("ENCRYPTION_KEY is not valid hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("ENCRYPTION_KEY must decode to 32 bytes (got %d)", len(key))
	}
	return &Cipher{key: key}, nil
}

// Encrypt encrypts plaintext and returns a base64-encoded ciphertext string.
// The 12-byte random nonce is prepended to the ciphertext before encoding.
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt decodes and decrypts a ciphertext produced by Encrypt.
func (c *Cipher) Decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cipher.NewGCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("gcm.Open: %w", err) // authentication failure or corruption
	}
	return string(plaintext), nil
}

// ---- Argon2id password hashing ----

// Argon2id parameters tuned for interactive login workloads.
// Adjust m (memory KiB) and t (iterations) upward for stricter security if hardware allows.
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

// HashPassword hashes a plaintext password using Argon2id and returns a
// PHC-style encoded string.
//
// Format: $argon2id$v=19$m=<m>,t=<t>,p=<p>$<salt_b64>$<hash_b64>
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	encoded := fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory,
		argonTime,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return encoded, nil
}

// VerifyPassword checks a plaintext password against a stored Argon2id hash.
// Returns (true, nil) on match, (false, nil) on mismatch, or an error if the
// hash string is malformed.
func VerifyPassword(password, encodedHash string) (bool, error) {
	m, t, p, salt, storedHash, err := parseArgon2Hash(encodedHash)
	if err != nil {
		return false, fmt.Errorf("parsing stored hash: %w", err)
	}

	computedHash := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(storedHash)))

	// Constant-time comparison prevents timing-based oracle attacks.
	if subtle.ConstantTimeCompare(computedHash, storedHash) == 1 {
		return true, nil
	}
	return false, nil
}

// parseArgon2Hash decodes a PHC-formatted Argon2id string.
func parseArgon2Hash(encoded string) (memory uint32, time uint32, threads uint8, salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	// expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
	if len(parts) != 6 {
		err = fmt.Errorf("invalid hash format: expected 6 segments, got %d", len(parts))
		return
	}
	if parts[1] != "argon2id" {
		err = fmt.Errorf("unsupported algorithm %q", parts[1])
		return
	}

	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		err = fmt.Errorf("invalid parameter segment %q", parts[3])
		return
	}
	for _, param := range params {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			err = fmt.Errorf("invalid param %q", param)
			return
		}
		val, parseErr := strconv.ParseUint(kv[1], 10, 64)
		if parseErr != nil {
			err = fmt.Errorf("parsing param %q: %w", param, parseErr)
			return
		}
		switch kv[0] {
		case "m":
			memory = uint32(val)
		case "t":
			time = uint32(val)
		case "p":
			threads = uint8(val)
		}
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		err = fmt.Errorf("decoding salt: %w", err)
		return
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		err = fmt.Errorf("decoding hash: %w", err)
	}
	return
}
