package endecryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/fachrioktavian/paychef/pkg/formatter"
)

func (a *Aes) Encrypt(input formatter.Input, keyHex string) error {
	// Decode hex-encoded key
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return errors.New("key must be 32 bytes (64 hex characters)")
	}

	input.SetAesKey(key)

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("failed to generate IV: %w", err)
	}

	input.SetIv(iv)

	// Get shellcode from input
	shellcode, err := input.GetShellcode()
	if err != nil {
		return fmt.Errorf("failed to get shellcode: %w", err)
	}

	// Apply PKCS#7 padding at the end
	padLen := aes.BlockSize - (len(shellcode) % aes.BlockSize)
	if padLen == 0 {
		padLen = aes.BlockSize
	}

	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	plaintext := append(shellcode, padding...)

	// Encrypt in CBC mode
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)

	input.SetEncryptedShellcode(ciphertext)

	// Return ciphertext, IV, and original key bytes
	return nil

}

func (a *Aes) EncryptBak(buf []byte, keyHex string) ([]byte, []byte, []byte, error) {
	// Decode hex-encoded key
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return nil, nil, nil, errors.New("key must be 32 bytes (64 hex characters)")
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Apply PKCS#7 padding at the end
	padLen := aes.BlockSize - (len(buf) % aes.BlockSize)
	if padLen == 0 {
		padLen = aes.BlockSize
	}
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	plaintext := append(buf, padding...)

	// Encrypt in CBC mode
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)

	// Return ciphertext, IV, and original key bytes
	return ciphertext, iv, key, nil
}
