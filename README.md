# OSCP-Cheat-Sheet

## Enumeration

### NMAP

#### TCP 

<code>nmap -v -sS -sC -sV -T4 -Pn -oA nmap/[filename.tcp] -p- [IP]</code>

#### UDP

<code>nmap -sU -v -sS -sC -sV -T4 -Pn -oA nmap/[filename.udp] [IP]</code>

#### SMB

<code>nmap -p 139,445 -Pn -script=smb-vuln* [IP]</code>

<code>smbclient -L //[IP]/</code>

<code>enum4linux [IP] -a</code>




