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

## FTP 

### Brute Force

<code>hydra -V -f -L [USER_LIST] -P [PASSWORDS_LIST] ftp://[IP] -u -vV</code>

### Download

<code>ftp [IP]</code>

<code>PASSIVE</code>

<code>BINARY</code>

<code>get [FILE]</code>

### Upload

<code>ftp [IP]</code>

<code>PASSIVE</code>

<code>BINARY</code>

<code>put [FILE]</code>


## Exploitation




