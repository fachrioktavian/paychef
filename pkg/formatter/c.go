package formatter

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func (s *Stager) SetAesKey(key []byte) {
	s.AesKey = key
}

func (s *Stager) SetIv(iv []byte) {
	s.IV = iv
}

func (s *Stager) SetEncryptedShellcode(encryptedShellcode []byte) {
	s.EncryptedShellcode = encryptedShellcode
}

func (s *Stager) SetXorKey(key byte) {
	s.XorKey = key
}

func (s *Stager) SetEncodedShellcode(encodedShellcode []byte) {
	s.EncodedShellcode = encodedShellcode
}

func (s *Stager) GetShellcode() ([]byte, error) {
	if len(s.Shellcode) == 0 {
		return nil, fmt.Errorf("shellcode is not set, please call SetShellcode() first")
	}
	return s.Shellcode, nil
}

func (s *Stager) SetRawContent() error {
	content, err := os.ReadFile(s.Path)
	if err != nil {
		return fmt.Errorf("failed to read shellcode file: %w", err)
	}
	s.RawContent = content
	return nil
}

func (s *Stager) SetShellcode() error {
	err := s.SetShellcodeFormat()
	if err != nil {
		return fmt.Errorf("failed to detect shellcode format: %w", err)
	}

	if err := s.ParseShellcode(s.Format); err != nil {
		return fmt.Errorf("failed to read shellcode: %w", err)
	}

	return nil
}

func (s *Stager) SetShellcodeFormat() error {
	if len(s.RawContent) == 0 {
		return fmt.Errorf("raw content is empty, please read the file first")
	}

	if strings.Contains(string(s.RawContent), "\\x") {
		s.Format = C_FORMAT // C-style shellcode
		return nil
	} else if strings.Contains(string(s.RawContent), "[Byte[]] $buf") {
		s.Format = PS1_FORMAT // PowerShell-style shellcode
		return nil
	}

	return fmt.Errorf("unknown shellcode format")
}

func (s *Stager) ParseShellcode(format string) error {
	var re *regexp.Regexp

	if format == C_FORMAT {
		re = regexp.MustCompile(`\\x([0-9A-Fa-f]{2})`)
	} else if format == PS1_FORMAT {
		re = regexp.MustCompile(`0x([0-9A-Fa-f]{1,2})`)
	} else {
		return fmt.Errorf("unsupported shellcode format: %s", format)
	}

	matches := re.FindAllStringSubmatch(string(s.RawContent), -1)
	if matches == nil {
		return fmt.Errorf("no shellcode found in C format")
	}
	buf := make([]byte, len(matches))
	for i, m := range matches {
		val, err := strconv.ParseUint(m[1], 16, 8)
		if err != nil {
			return err
		}
		buf[i] = byte(val)
	}
	s.Shellcode = buf
	return nil
}

func (s *Stager) PrintResult() error {
	var sb strings.Builder
	if s.Format == C_FORMAT {
		if s.Mode == ENCODE_XOR_MODE {
			sb.WriteString(fmt.Sprintf("unsigned char buf[%d] =\n", len(s.EncodedShellcode)))
			buildCBuffer(&sb, s.EncodedShellcode, 16)
			sb.WriteString(fmt.Sprintf("unsigned char key = '\\x%02x';\n", s.XorKey))
		} else if s.Mode == ENCRYPT_AES_MODE {
			sb.WriteString(fmt.Sprintf("unsigned char buf[%d] =\n", len(s.EncryptedShellcode)))
			buildCBuffer(&sb, s.EncryptedShellcode, 16)
			if len(s.IV) > 0 {
				sb.WriteString(fmt.Sprintf("unsigned char iv[%d] =\n", len(s.IV)))
				buildCBuffer(&sb, s.IV, 16)
			}
			if len(s.AesKey) > 0 {
				sb.WriteString(fmt.Sprintf("unsigned char key[%d] =\n", len(s.AesKey)))
				buildCBuffer(&sb, s.AesKey, 16)
			}
		}
	}

	if s.Format == PS1_FORMAT {
		if s.Mode == ENCODE_XOR_MODE {
			sb.WriteString("[Byte[]] $buf = ")
			buildPS1Buffer(&sb, s.EncodedShellcode)
			sb.WriteString(fmt.Sprintf("[Byte] $key = 0x%02x\n", s.XorKey))
		} else if s.Mode == ENCRYPT_AES_MODE {
			sb.WriteString("[Byte[]] $buf = ")
			buildPS1Buffer(&sb, s.EncryptedShellcode)
			if len(s.IV) > 0 {
				sb.WriteString("[Byte[]] $iv = ")
				buildPS1Buffer(&sb, s.IV)
			}
			if len(s.AesKey) > 0 {
				sb.WriteString("[Byte[]] $key = ")
				buildPS1Buffer(&sb, s.AesKey)
			}
		}

	}

	fmt.Println(sb.String())
	return nil
}

func buildCBuffer(psb *strings.Builder, buf []byte, lineLen int) {
	semicolon := false
	for i := 0; i < len(buf); i += lineLen {
		end := i + lineLen
		if end >= len(buf) {
			end = len(buf)
			semicolon = true
		}
		psb.WriteString("\"")
		for _, b := range buf[i:end] {
			psb.WriteString(fmt.Sprintf("\\x%02x", b))
		}
		if !semicolon {
			psb.WriteString("\"\n")
		} else {
			psb.WriteString("\";\n")
		}
	}
}

func buildPS1Buffer(psb *strings.Builder, buf []byte) {
	for i, b := range buf {
		if i > 0 {
			psb.WriteString(",")
		}
		psb.WriteString(fmt.Sprintf("0x%02x", b))
	}
	psb.WriteString("\n")
}

func (s *Stager) WriteResult() error {
	if err := os.WriteFile(ENCRYPTED_SHELLCODE_FILE, s.EncryptedShellcode, 0644); err != nil {
		return fmt.Errorf("failed to write encrypted shellcode to file: %w", err)
	}
	if len(s.IV) > 0 {
		if err := os.WriteFile(IV_FILE, s.IV, 0644); err != nil {
			return fmt.Errorf("failed to write IV to file: %w", err)
		}
	}
	if len(s.AesKey) > 0 {
		if err := os.WriteFile(KEY_FILE, s.AesKey, 0644); err != nil {
			return fmt.Errorf("failed to write key to file: %w", err)
		}
	}
	return nil
}

// func (s *Stager) PrintFormattedShellcode(format string) {
// 	var sb strings.Builder
// }

func (r *Reader) ReadCShellcode(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Regex to find all \xHH escapes
	re := regexp.MustCompile(`\\x([0-9A-Fa-f]{2})`)
	matches := re.FindAllStringSubmatch(string(content), -1)

	buf := make([]byte, len(matches))
	for i, m := range matches {
		val, err := strconv.ParseUint(m[1], 16, 8)
		if err != nil {
			return nil, err
		}
		buf[i] = byte(val)
	}
	return buf, nil
}

func (o *Output) FormatCShellcode(buf []byte, iv []byte, key []byte) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("unsigned char buf[%d] =\n", len(buf)))
	lineLen := 16
	semicolon := false
	for i := 0; i < len(buf); i += lineLen {
		end := i + lineLen
		if end >= len(buf) {
			end = len(buf)
			semicolon = true
		}
		sb.WriteString("\"")
		for _, b := range buf[i:end] {
			sb.WriteString(fmt.Sprintf("\\x%02x", b))
		}
		if !semicolon {
			sb.WriteString("\"\n")
		} else {
			sb.WriteString("\";\n")
		}
	}

	if len(iv) > 0 {
		semicolon = false
		sb.WriteString(fmt.Sprintf("unsigned char iv[%d] =\n", len(iv)))
		for i := 0; i < len(iv); i += lineLen {
			end := i + lineLen
			if end >= len(iv) {
				end = len(iv)
				semicolon = true
			}
			sb.WriteString("\"")
			for _, b := range iv[i:end] {
				sb.WriteString(fmt.Sprintf("\\x%02x", b))
			}
			if !semicolon {
				sb.WriteString("\"\n")
			} else {
				sb.WriteString("\";\n")
			}
		}
	}

	if len(key) > 0 {
		semicolon = false
		sb.WriteString(fmt.Sprintf("unsigned char key[%d] =\n", len(key)))
		for i := 0; i < len(key); i += lineLen {
			end := i + lineLen
			if end >= len(key) {
				end = len(key)
				semicolon = true
			}
			sb.WriteString("\"")
			for _, b := range key[i:end] {
				sb.WriteString(fmt.Sprintf("\\x%02x", b))
			}
			if !semicolon {
				sb.WriteString("\"\n")
			} else {
				sb.WriteString("\";\n")
			}
		}
	}

	return sb.String()
}
