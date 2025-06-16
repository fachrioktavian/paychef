package endecoder

import (
	"github.com/fachrioktavian/paychef/pkg/formatter"
)

func (x *Xor) Encode(input formatter.Input, key byte) error {
	input.SetXorKey(key)
	// Get the shellcode from the input
	shellcode, err := input.GetShellcode()
	if err != nil {
		return err
	}

	// Encode the shellcode using XOR
	encodedShellcode := make([]byte, len(shellcode))
	for i, b := range shellcode {
		encodedShellcode[i] = b ^ key
	}

	input.SetEncodedShellcode(encodedShellcode)
	return nil
}

func (x *Xor) EncodeBak(buf []byte, key byte) []byte {
	out := make([]byte, len(buf))
	for i, b := range buf {
		out[i] = b ^ key
	}
	return out
}
