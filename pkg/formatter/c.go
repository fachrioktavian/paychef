package formatter

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"fmt"
)

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