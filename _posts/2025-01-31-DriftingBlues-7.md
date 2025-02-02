---
title: DriftingBlues 7 Writeup - Vulnhub
date: 2025-01-31
categories: [Writeups, Vulnhub]
tags: [Linux, Vulnhub, CTF, Easy, HTTP, DriftingBlues, Wordpress, wpscan, cewl, Hydra, wpscan]
image:
  path: /assets/img/commons/vulnhub/vulnhub.jpg
---

Resolución máquina anterior: [**DriftingBlues6**](https://lvs3c.github.io/posts/DriftingBlues-6/)

¡Saludos!

En este writeup, nos adentraremos en la primer máquina [**DriftingBlues7**](https://www.vulnhub.com/entry/driftingblues-7,680/), la cual tiene un nivel de dificultad **fácil** según la plataforma. Se trata de una máquina **Linux** en la cual veremos **enumeración de servicios**, **cewl** para generar un diccionario y realizar fuerza bruta sobre **Wordpress** con **wpscan**, **Hydra** para fuerta bruta del servicio `SSH`{: .filepath} para luego conectarnos a la máquina víctima y utilizaremos **linPEAS** y **Pspy** para validar el sitema y procesos logrando así elevar nuestros privilegios como usuario **root**, obteniendo las flags del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ arp-scan -I ens32 --localnet --ignoredups
Interface: ens32, type: EN10MB, MAC: 00:0c:29:c4:47:79, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.37     00:0c:29:f2:2e:3b       VMware, Inc.
10.11.12.254    00:50:56:f6:71:b0       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.385 seconds (107.34 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.37
PING 10.11.12.37 (10.11.12.37) 56(84) bytes of data.
64 bytes from 10.11.12.37: icmp_seq=1 ttl=64 time=0.454 ms

--- 10.11.12.37 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.454/0.454/0.454/0.000 ms

```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.37 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-31 20:16 -03
Nmap scan report for 10.11.12.37
Host is up (0.0021s latency).
Not shown: 65527 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
66/tcp   open  sqlnet
80/tcp   open  http
111/tcp  open  rpcbind
443/tcp  open  https
2403/tcp open  taskmaster2000
3306/tcp open  mysql
8086/tcp open  d-s-n
MAC Address: 00:0C:29:F2:2E:3B (VMware)

Nmap done: 1 IP address (1 host up) scanned in 5.79 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ nmap -p22,66,80,111,443,2403,3306,8086 -sCV 10.11.12.37 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-31 20:25 -03
Nmap scan report for 10.11.12.37
Host is up (0.00020s latency).

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 c4:fa:e5:5f:88:c1:a1:f0:51:8b:ae:e3:fb:c1:27:72 (RSA)
|   256 01:97:8b:bf:ad:ba:5c:78:a7:45:90:a1:0a:63:fc:21 (ECDSA)
|_  256 45:28:39:e0:1b:a8:85:e0:c0:b0:fa:1f:00:8c:5e:d1 (ED25519)
66/tcp   open  http            SimpleHTTPServer 0.6 (Python 2.7.5)
|_http-server-header: SimpleHTTP/0.6 Python/2.7.5
|_http-title: Scalable Cost Effective Cloud Storage for Developers
80/tcp   open  http            Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3)
|_http-title: Did not follow redirect to https://10.11.12.37/
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3
111/tcp  open  rpcbind         2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
443/tcp  open  ssl/http        Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3)
|_ssl-date: TLS randomness does not represent time
| http-title: EyesOfNetwork
|_Requested resource was /login.php##
| ssl-cert: Subject: commonName=localhost/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2021-04-03T14:37:22
|_Not valid after:  2022-04-03T14:37:22
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3
2403/tcp open  taskmaster2000?
3306/tcp open  mysql           MariaDB (unauthorized)
8086/tcp open  http            InfluxDB http admin 1.7.9
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
MAC Address: 00:0C:29:F2:2E:3B (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 145.64 seconds
```

El informe de `Nmap` nos revela:
- Puerto `22` servidor `OpenSSH 7.4`
- Puerto `66` servidor `Apache 2.4.38`.
- Puerto `80` servidor `Apache 2.4.38`.
- Puerto `111` servidor `Apache 2.4.38`.
- Puerto `443` servidor `Apache 2.4.38`.
- Puerto `2403` servidor `Apache 2.4.38`.
- Puerto `3306` servidor `Apache 2.4.38`.
- Puerto `8086` servidor `Apache 2.4.38`.


### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.35/
```

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ nmap -p80 --script http-enum 10.11.12.35 -oN nmap_webscan

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
