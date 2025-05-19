package endecoder

func (x *Xor) Encode(buf []byte, key byte) []byte {
	out := make([]byte, len(buf))
	for i, b := range buf {
		out[i] = b ^ key
	}
	return out
}