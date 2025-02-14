---
title: DeRPnStiNK Writeup - Vulnhub
date: 2025-02-13
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, DeRPnStiNK, OSCP Prep]
image:
  path: /assets/img/commons/vulnhub/DeRPnStiNK/portada.png
---

Anterior [**OSCP Lab 6**](https://lvs3c.github.io/posts/OSCP-w1r3s/)

¡Saludos!

`OSCP Lab 7`

En este writeup, realizaremos la máquina [**DeRPnStiNK**](https://www.vulnhub.com/entry/derpnstink-1,221/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **B**
- **C**
- **D**
- Y por último, tenemos permisos full del usuario, con lo cual podemos convirtirnos en root y obtener las flags del CTF.

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
10.11.12.19     00:0c:29:3a:b3:df       VMware, Inc.
10.11.12.200    00:50:56:ef:e9:97       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.694 seconds (95.03 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.19
PING 10.11.12.19 (10.11.12.19) 56(84) bytes of data.
64 bytes from 10.11.12.19: icmp_seq=1 ttl=64 time=0.763 ms

--- 10.11.12.19 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.763/0.763/0.763/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.19 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-13 20:47 -03
Nmap scan report for 10.11.12.19
Host is up (0.00040s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:3A:B3:DF (VMware)

Nmap done: 1 IP address (1 host up) scanned in 6.46 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ nmap -p21,22,80 -sCV 10.11.12.19 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-13 20:48 -03
Nmap scan report for 10.11.12.19
Host is up (0.00064s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 12:4e:f8:6e:7b:6c:c6:d8:7c:d8:29:77:d1:0b:eb:72 (DSA)
|   2048 72:c5:1c:5f:81:7b:dd:1a:fb:2e:59:67:fe:a6:91:2f (RSA)
|   256 06:77:0f:4b:96:0a:3a:2c:3b:f0:8c:2b:57:b5:97:bc (ECDSA)
|_  256 28:e8:ed:7c:60:7f:19:6c:e3:24:79:31:ca:ab:5d:2d (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-robots.txt: 2 disallowed entries
|_/php/ /temporary/
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: DeRPnStiNK
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.02 seconds
```

El informe de `Nmap` nos revela:
- Puerto `21` servidor `vsftpd 3.0.2`.
- Puerto `22` servidor `OpenSSH 6.6.1p1`.
- Puerto `80` servidor `Apache httpd 2.4.7`.


### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.19/
http://10.11.12.19/ [200 OK] Apache[2.4.7], Country[RESERVED][ZZ], Google-API[ajax/libs/jquery/1.7.1/jquery.min.js], HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[10.11.12.19], JQuery[1.7.1], Script[text/info,text/javascript], Title[DeRPnStiNK]
```

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ nmap -p80 --script http-enum 10.11.12.19 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-13 20:51 -03
Nmap scan report for 10.11.12.19
Host is up (0.00075s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /robots.txt: Robots file
|_  /weblog/wp-login.php: Wordpress login page.

Nmap done: 1 IP address (1 host up) scanned in 1.31 seconds
```

![wordpress](/assets/img/commons/vulnhub/DriftingBlues5/wordpress.png){: .center-image }

## Explotación

---



## Escalación de privilegios

---

Listamos la Flag 1.

```bash

```

Listamos la Flag 2.

```bash

```

Hope it helps!