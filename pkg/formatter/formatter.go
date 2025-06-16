package formatter

type Reader struct {
}

func NewReader() *Reader {
	return &Reader{}
}

type Output struct {
}

func NewOutput() *Output {
	return &Output{}
}

type Input interface {
	SetRawContent() error
	SetShellcode() error
	SetAesKey(key []byte)
	SetIv(iv []byte)
	SetEncryptedShellcode(encryptedShellcode []byte)
	SetShellcodeFormat() error
	SetXorKey(key byte)
	SetEncodedShellcode(encodedShellcode []byte)

	ParseShellcode(format string) error

	GetShellcode() ([]byte, error)
	WriteResult() error
	PrintResult() error
}

type Stager struct {
	Path               string
	Format             string
	Mode               string
	RawContent         []byte
	Shellcode          []byte
	EncryptedShellcode []byte
	IV                 []byte
	AesKey             []byte
	EncodedShellcode   []byte
	XorKey             byte
}

func NewStager(path string, mode string) *Stager {
	return &Stager{
		Path:               path,
		Mode:               mode,
		Format:             "",
		RawContent:         nil,
		Shellcode:          nil,
		EncryptedShellcode: nil,
		IV:                 nil,
		AesKey:             nil,
		EncodedShellcode:   nil,
		XorKey:             0,
	}
}

const (
	C_FORMAT         = "c"
	PS1_FORMAT       = "ps1"
	ENCRYPT_AES_MODE = "encrypt-aes"
	ENCODE_XOR_MODE  = "encode-xor"

	ENCRYPTED_SHELLCODE_FILE = "assets/encrypted_shellcode.bin"
	IV_FILE                  = "assets/iv.bin"
	KEY_FILE                 = "assets/key.bin"
)
