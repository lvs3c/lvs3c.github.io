---
title: Lazysysadmin Writeup - Vulnhub
date: 2025-02-12
categories: [Writeups, Vulnhub OSCP Prep]
tags: [Linux, Vulnhub, CTF, Lazysysadmin, OSCP Prep, smbmap, Wordpress]
image:
  path: /assets/img/commons/vulnhub/lazysysadmin/portada.png
  #/assets/img/commons/vulnhub/DarkHole2/portada.png
---

Anterior [*OSCP Lab 18*](https://lvs3c.github.io/posts/OSCP-SickOs1.1/)

¡Saludos!

**`OSCP Lab 19`**

En este writeup, realizaremos la máquina [**Lazysysadmin**](https://www.vulnhub.com/entry/lazysysadmin-1,205/). 

Se trata de una máquina **Linux** en la cual veremos:
- **Enumeración de servicios**.
- **Fuzzing de archivos y directorios**.
- **B**
- **C**
- **D**
- Y por último, tenemos permisos full del usuario, con lo cual podemos convertirnos en root y obtener las flags del CTF.

¡Empecemos!

## Reconocimiento activo

---

Necesitamos encontrar la ip correspondiente a la máquina, lo hacemos mediante la herramienta `arp-scan` y posteriormente el comando `ping` para verificar si la máquina objetivo está activa.

```bash
❯ sudo arp-scan -I ens37 --localnet --ignoredups
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

Seguidamente, efectuamos una enumeración de las versiones de los servicios asociados y ejecutamos un conjunto de scripts predeterminados de `Nmap` para realizar pruebas complementarias sobre los puertos y servicios identificados.

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

Lanzamoos `gobuster` para obtener más información sobre archivos o directorios.

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

> The posts' _layout_ has been set to `post` by default, so there is no need to add the variable _layout_ in the Front Matter block.
{: .prompt-tip }
{: .prompt-info }
{: .prompt-warning }