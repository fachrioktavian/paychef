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
	s.XoredShellcode = encodedShellcode
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

func (s *Stager) SetArchitecture(architecture string) error {
	if architecture != AMD64_ARCH && architecture != X86_ARCH {
		return fmt.Errorf("unsupported architecture: %s, supported are: %s, %s", architecture, AMD64_ARCH, X86_ARCH)
	}
	s.Architecture = architecture
	return nil
}

func (s *Stager) SetOutput(output string) error {
	s.Output = output
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
	} else if strings.Contains(string(s.RawContent), "Array(") {
		s.Format = VBA_FORMAT // VBA-style shellcode
		return nil
	}

	return fmt.Errorf("unknown shellcode format")
}

func (s *Stager) ParseShellcode(format string) error {
    raw := string(s.RawContent)

    switch format {
    case C_FORMAT:
        return s.parseHexBytes(`\\x([0-9A-Fa-f]{2})`, raw)
    case PS1_FORMAT:
        return s.parseHexBytes(`0x([0-9A-Fa-f]{1,2})`, raw)
    case VBA_FORMAT:
        // 1) Remove VBA line-continuations
        raw = strings.ReplaceAll(raw, "_", "")
        // 2) Pull out what's inside Array(...)
        arrayRe := regexp.MustCompile(`(?i)Array\(([^)]*)\)`)
        sub := arrayRe.FindStringSubmatch(raw)
        if len(sub) < 2 {
            return fmt.Errorf("no shellcode found in VBA format")
        }
        // 3) Find all the decimal numbers in that substring
        numRe := regexp.MustCompile(`\b\d{1,3}\b`)
        nums := numRe.FindAllString(sub[1], -1)
        if len(nums) == 0 {
            return fmt.Errorf("no numeric bytes found in VBA shellcode")
        }
        buf := make([]byte, len(nums))
        for i, ns := range nums {
            v, err := strconv.Atoi(ns)
            if err != nil {
                return err
            }
            if v < 0 || v > 255 {
                return fmt.Errorf("byte value out of range: %d", v)
            }
            buf[i] = byte(v)
        }
        s.Shellcode = buf
        return nil
    default:
        return fmt.Errorf("unsupported shellcode format: %s", format)
    }
}

// helper to reduce duplication for hex-based formats
func (s *Stager) parseHexBytes(pattern, raw string) error {
    re := regexp.MustCompile(pattern)
    matches := re.FindAllStringSubmatch(raw, -1)
    if len(matches) == 0 {
        return fmt.Errorf("no shellcode found in hex format")
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

    switch s.Format {
    case C_FORMAT:
        if s.Mode == ENCODE_XOR_MODE {
            sb.WriteString(fmt.Sprintf("unsigned char buf[%d] =\n", len(s.XoredShellcode)))
            buildCBuffer(&sb, s.XoredShellcode, 16)
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

    case PS1_FORMAT:
        if s.Mode == ENCODE_XOR_MODE {
            sb.WriteString("[Byte[]] $buf = ")
            buildPS1Buffer(&sb, s.XoredShellcode)
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

    case VBA_FORMAT:
        const elemsPerLine = 50  // change this to break sooner or later

        if s.Mode == ENCODE_XOR_MODE {
            sb.WriteString("buf = Array(")
            buildVBABuffer(&sb, s.XoredShellcode, elemsPerLine)
            sb.WriteString(")\n")
            sb.WriteString(fmt.Sprintf("key = %d\n", s.XorKey))
        } else if s.Mode == ENCRYPT_AES_MODE {
            sb.WriteString("buf = Array(")
            buildVBABuffer(&sb, s.EncryptedShellcode, elemsPerLine)
            sb.WriteString(")\n")
            if len(s.IV) > 0 {
                sb.WriteString("iv  = Array(")
                buildVBABuffer(&sb, s.IV, elemsPerLine)
                sb.WriteString(")\n")
            }
            if len(s.AesKey) > 0 {
                sb.WriteString("key = Array(")
                buildVBABuffer(&sb, s.AesKey, elemsPerLine)
                sb.WriteString(")\n")
            }
        }

    default:
        return fmt.Errorf("unsupported format: %s", s.Format)
    }

	s.SetOutput(sb.String())
	fmt.Println(s.Output)
	
    return nil
}

func buildVBABuffer(sb *strings.Builder, buf []byte, elemsPerLine int) {
    total := len(buf)
	startofLine := false
    for i, b := range buf {
        // write the number
        if i > 0 && !startofLine {
            sb.WriteString(",")
        }
        sb.WriteString(strconv.Itoa(int(b)))
		startofLine = false

        // if we've hit the limit AND we're not at the very end, break line
        if (i+1)%elemsPerLine == 0 && i != total-1 {
            sb.WriteString(", _\n")
			startofLine = true
        }
    }
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
	if len(s.EncryptedShellcode) > 0 {
		fileName := fmt.Sprintf(ENCRYPTED_SHELLCODE_FILE, s.Architecture)
		if err := os.WriteFile(fileName, s.EncryptedShellcode, 0644); err != nil {
			return fmt.Errorf("failed to write encrypted shellcode to file: %w", err)
		}
	}
	if len(s.IV) > 0 {
		fileName := fmt.Sprintf(IV_FILE, s.Architecture)
		if err := os.WriteFile(fileName, s.IV, 0644); err != nil {
			return fmt.Errorf("failed to write IV to file: %w", err)
		}
	}
	if len(s.AesKey) > 0 {
		fileName := fmt.Sprintf(KEY_FILE, s.Architecture)
		if err := os.WriteFile(fileName, s.AesKey, 0644); err != nil {
			return fmt.Errorf("failed to write key to file: %w", err)
		}
	}

	if len (s.XoredShellcode) > 0 {
		fileName := fmt.Sprintf(XORED_SHELLCODE_FILE, s.Architecture)
		if err := os.WriteFile(fileName, s.XoredShellcode, 0644); err != nil {
			return fmt.Errorf("failed to write xored shellcode to file: %w", err)
		}
	}
	if s.XorKey != 0 {
		fileName := fmt.Sprintf(XOR_KEY_FILE, s.Architecture)
		if err := os.WriteFile(fileName, []byte{byte(s.XorKey)}, 0644); err != nil {
			return fmt.Errorf("failed to write xor key to file: %w", err)
		}
	}

	outputFileName := fmt.Sprintf(OUTPUT_FILE, s.Architecture, s.Mode, s.Format)
	if err := os.WriteFile(outputFileName, []byte(s.Output), 0644); err != nil {
		return fmt.Errorf("failed to write output to file: %w", err)
	} 

	return nil
}

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
