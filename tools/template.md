---
title: DriftingBlues 5 Writeup - Vulnhub
date: 2025-01-25
categories: [Writeups, Vulnhub]
tags: [Linux, Vulnhub, CTF, Easy, HTTP, DriftingBlues, Wordpress, wpscan, cewl, Hydra, wpscan]
image:
  path: /assets/img/commons/vulnhub/vulnhub.jpg
  #/assets/img/commons/vulnhub/DarkHole2/portada.png
---

Resolución máquina anterior: [**DriftingBlues5**](https://lvs3c.github.io/posts/DriftingBlues-5/)

¡Saludos!

En este writeup, nos adentraremos en la primer máquina [**DriftingBlues5**](https://www.vulnhub.com/entry/driftingblues-5,662/), la cual tiene un nivel de dificultad **fácil** según la plataforma. Se trata de una máquina **Linux** en la cual veremos:
- **enumeración de servicios**.
- **GIT-Dumper** para obtener los datos de un repositorio desde la web, obteniendo datos de acceso al panel de login.
- **SQLinjection** explicada de manera manual y automatizada con **sqlmap**, obteniendo de la base de datos información de usuario para conectarnos por SSH.
- **User pivoting** mediante un servicio interno, lanzando una reverse shell.
- Y por último, dos formas de elevar nuestros privilegios.
    - Ejecutar **python** con permisos de root, logrando así elevar nuestros privilegios como usuario **root**, obteniendo las flags del CTF.
    - Explotar la vulnerabilidad `CVE-2021-4034` sobre el binario `pkexec` con permiso `SUID`{: .filepath}, convirtiéndonos en root y obtener las flags del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ arp-scan -I ens32 --localnet --ignoredups
```

```bash
❯ ping -c 1 10.11.12.35
```

## Escaneo

---

A continuación, realizamos un escaneo con `Nmap` para identificar los puertos abiertos en el sistema objetivo.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.11.12.35 -oG nmap_ports
```

## Enumeración

---

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados a los puertos abiertos. Además, ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

```bash
❯ nmap -p22,80 -sCV 10.11.12.35 -oN nmap_services

```

El informe de `Nmap` nos revela:
- Puerto `22` servidor `OpenSSH 7.9p1`.
- Puerto `80` servidor `Apache 2.4.38`.


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