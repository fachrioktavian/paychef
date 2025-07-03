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
	SetArchitecture(architecture string) error
	SetAesKey(key []byte)
	SetIv(iv []byte)
	SetEncryptedShellcode(encryptedShellcode []byte)
	SetShellcodeFormat() error
	SetXorKey(key byte)
	SetEncodedShellcode(encodedShellcode []byte)
	SetOutput(output string) error

	ParseShellcode(format string) error

	GetShellcode() ([]byte, error)
	WriteResult() error
	PrintResult() error
}

type Stager struct {
	Path               string
	Format             string
	Mode               string
	Architecture	   string 
	RawContent         []byte
	Shellcode          []byte
	EncryptedShellcode []byte
	IV                 []byte
	AesKey             []byte
	XoredShellcode     []byte
	XorKey             byte
	Output 		   	   string
	OutputFilePath     string
}

func NewStager(path string, mode string) *Stager {
	return &Stager{
		Path:               path,
		Mode:               mode,
		Format:             "",
		Architecture:       "",
		RawContent:         nil,
		Shellcode:          nil,
		EncryptedShellcode: nil,
		IV:                 nil,
		AesKey:             nil,
		XoredShellcode:     nil,
		XorKey:             0,
		Output:             "",
		OutputFilePath:     "",
	}
}

const (
	C_FORMAT         = "c"
	PS1_FORMAT       = "ps1"
	VBA_FORMAT	     = "vba"
	ENCRYPT_AES_MODE = "encrypt-aes"
	ENCODE_XOR_MODE  = "encode-xor"
	AMD64_ARCH     = "amd64"
	X86_ARCH       = "x86"

	ENCRYPTED_SHELLCODE_FILE = "assets/encrypted_shellcode-%s.bin"
	IV_FILE                  = "assets/iv-%s.bin"
	KEY_FILE                 = "assets/key-%s.bin"
	XORED_SHELLCODE_FILE 	 = "assets/xored_shellcode-%s.bin"
	XOR_KEY_FILE             = "assets/xor_key-%s.bin"
	OUTPUT_FILE			     = "assets/output-%s-%s-%s.txt" // Output file path format: assets/output-{architecture}-{mode}-{format}.txt
)
