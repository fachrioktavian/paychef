package main

import (
	"fmt"
	"strconv"

	"github.com/fachrioktavian/paychef/pkg/endecoder"
	"github.com/fachrioktavian/paychef/pkg/endecryptor"
	"github.com/fachrioktavian/paychef/pkg/formatter"
	"github.com/fachrioktavian/paychef/pkg/logger"

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
			encodedShellcode, iv, key, err := aes.Encrypt(shellcode, aesKey)
			if err != nil {
				inAppLogger.Error("Error encrypting shellcode", "error", err)
				return
			}
			formattedShellcode := o.FormatCShellcode(encodedShellcode, iv, key)
			fmt.Println(formattedShellcode)
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

	rootCmd.AddCommand(
		obfuscateXorCmd,
		obfuscateAesCmd,
	)

	rootCmd.Execute()
}