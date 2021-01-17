# [NMAP Room](https://tryhackme.com/room/furthernmap)

## Task 1 Deploy

ip= 10.10.4.145

## Task 2 Inroduction

When it comes to hacking, knowledge is power. The more knowledge you have about a target system or network, the more options you have available. This makes it imperative that proper enumeration is carried out before any exploitation attempts are made.

Say we have been given an IP (or multiple IP addresses) to perform a security audit on. Before we do anything else, we need to get an idea of the “landscape” we are attacking. What this means is that we need to establish which services are running on the targets. For example, perhaps one of them is running a webserver, and another is acting as a Windows Active Directory Domain Controller. The first stage in establishing this “map” of the landscape is something called port scanning. When a computer runs a network service, it opens a networking construct called a “port” to receive the connection.  Ports are necessary for making multiple network requests or having multiple services available. For example, when you load several webpages at once in a web browser, the program must have some way of determining which tab is loading which web page. This is done by establishing connections to the remote webservers using different ports on your local machine. Equally, if you want a server to be able to run more than one service (for example, perhaps you want your webserver to run both HTTP and HTTPS versions of the site), then you need some way to direct the traffic to the appropriate service. Once again, ports are the solution to this. Network connections are made between two ports – an open port listening on the server and a randomly selected port on your own computer. For example, when you connect to a web page, your computer may open port 49534 to connect to the server’s port 443.

![example](./3XAfRpI.png)

As in the previous example, the diagram shows what happens when you connect to numerous websites at the same time. Your computer opens up a different, high-numbered port (at random), which it uses for all its communications with the remote server.

Every computer has a total of 65535 available ports; however, many of these are registered as standard ports. For example, a HTTP Webservice can nearly always be found on port 80 of the server. A HTTPS Webservice can be found on port 443. Windows NETBIOS can be found on port 139 and SMB can be found on port 445. It is important to note; however, that especially in a CTF setting, it is not unheard of for even these standard ports to be altered, making it even more imperative that we perform appropriate enumeration on the target.

If we do not know which of these ports a server has open, then we do not have a hope of successfully attacking the target; thus, it is crucial that we begin any attack with a port scan. This can be accomplished in a variety of ways – usually using a tool called nmap, which is the focus of this room. Nmap can be used to perform many different kinds of port scan – the most common of these will be introduced in upcoming tasks; however, the basic theory is this: nmap will connect to each port of the target in turn. Depending on how the port responds, it can be determined as being open, closed, or filtered (usually by a firewall). Once we know which ports are open, we can then look at enumerating which services are running on each port – either manually, or more commonly using nmap.

So, why nmap? The short answer is that it's currently the industry standard for a reason: no other port scanning tool comes close to matching its functionality (although some newcomers are now matching it for speed). It is an extremely powerful tool – made even more powerful by its scripting engine which can be used to scan for vulnerabilities, and in some cases even perform the exploit directly! Once again, this will be covered more in upcoming tasks.

For now, it is important that you understand: what port scanning is; why it is necessary; and that nmap is the tool of choice for any kind of initial enumeration.

Q: What networking constructs are used to direct traffic to the right application on a server?

A: ports

Q: How many of these are available on any network-enabled computer?

A: 65535

Q: [Research] How many of these are considered "well-known"? (These are the "standard" numbers mentioned in the task)

A: 1024

## Task 3 Nmap Switches

Like most pentesting tools, nmap is run from the terminal. There are versions available for both Windows and Linux. For this room we will assume that you are using Linux; however, the switches should be identical. Nmap is installed by default in both Kali Linux and the TryHackMe Attack Box.

Nmap can be accessed by typing nmap into the terminal command line, followed by some of the "switches" (command arguments which tell a program to do different things) we will be covering below.

All you'll need for this is the help menu for nmap (accessed with nmap -h) and/or the nmap man page (access with man nmap). For each answer, include all parts of the switch unless otherwise specified. This includes the hyphen at the start (-).

Q: What is the first switch listed in the help menu for a 'Syn Scan' (more on this later!)?

A: -sS

Q: Which switch would you use for a "UDP scan"?

A: -Su

Q: If you wanted to detect which operating system the target is running on, which switch would you use?

A: -O

Q: Nmap provides a switch to detect the version of the services running on the target. What is this switch?

A: -sV

Q: The default output provided by nmap often does not provide enough information for a pentester. How would you increase the verbosity?

A: -v

Q: Verbosity level one is good, but verbosity level two is better! How would you set the verbosity level to two?
(Note: it's highly advisable to always use at least this option)

A: -vv

Q: We should always save the output of our scans -- this means that we only need to run the scan once (reducing network traffic and thus chance of detection), and gives us a reference to use when writing reports for clients.

What switch would you use to save the nmap results in three major formats?

A: -oA

Q: What switch would you use to save the nmap results in a "normal" format?

A: -oN

Q: A very useful output format: how would you save results in a "grepable" format?

A: -oG

Q: Sometimes the results we're getting just aren't enough. If we don't care about how loud we are, we can enable "aggressive" mode. This is a shorthand switch that activates service detection, operating system detection, a traceroute and common script scanning.

How would you activate this setting?

A: -A

Q: Nmap offers five levels of "timing" template. These are essentially used to increase the speed your scan runs at. Be careful though: higher speeds are noisier, and can incur errors!

How would you set the timing template to level 5?

A: -T5

We can also choose which port(s) to scan.

Q: How would you tell nmap to only scan port 80?

A: -p 80

Q: How would you tell nmap to scan ports 1000-1500?

A: -p 1000-1500

A very useful option that should not be ignored:

Q: How would you tell nmap to scan all ports?

A: -p-

Q: How would you activate a script from the nmap scripting library (lots more on this later!)?

A: --script

Q: How would you activate all of the scripts in the "vuln" category?

A: --script=vuln

## Task 4 Scan Types Overview

When port scanning with Nmap, there are three basic scan types. These are:

* TCP Connect Scans (-sT)
* SYN "Half-open" Scans (-sS)
* UDP Scans (-sU)

Additionally there are several less common port scan types, some of which we will also cover (albeit in less detail). These are:

* TCP Null Scans (-sN)
* TCP FIN Scans (-sF)
* TCP Xmas Scans (-sX)

Most of these (with the exception of UDP scans) are used for very similar purposes, however, the way that they work differs between each scan. This means that, whilst one of the first three scans are likely to be your go-to in most situations, it's worth bearing in mind that other scan types exist.

In terms of network scanning, we will also look briefly at ICMP (or "ping") scanning.

## Task 5 Scan Types TCP Connect Scans

For example, if a port is closed, RFC 793 states that:

"... If the connection does not exist (CLOSED) then a reset is sent in response to any incoming segment except another reset.  In particular, SYNs addressed to a non-existent connection are rejected by this means."

In other words, if Nmap sends a TCP request with the SYN flag set to a closed port, the target server will respond with a TCP packet with the RST (Reset) flag set. By this response, Nmap can establish that the port is closed.

If, however, the request is sent to an open port, the target will respond with a TCP packet with the SYN/ACK flags set. Nmap then marks this port as being open (and completes the handshake by sending back a TCP packet with ACK set).

This is all well and good, however, there is a third possibility.

What if the port is open, but hidden behind a firewall?

Many firewalls are configured to simply drop incoming packets. Nmap sends a TCP SYN request, and receives nothing back. This indicates that the port is being protected by a firewall and thus the port is considered to be filtered.

That said, it is very easy to configure a firewall to respond with a RST TCP packet. For example, in IPtables for Linux, a simple version of the command would be as follows:

```iptables -I INPUT -p tcp --dport <port> -j REJECT --reject-with tcp-reset```

This can make it extremely difficult (if not impossible) to get an accurate reading of the target(s).

Q: Which RFC defines the appropriate behaviour for the TCP protocol?

A: RFC 793

Q: If a port is closed, which flag should the server send back to indicate this?

A: RST

## Task 6 Scan Types SYN Scans

As with TCP scans, SYN scans (-sS) are used to scan the TCP port-range of a target or targets; however, the two scan types work slightly differently. SYN scans are sometimes referred to as "Half-open" scans, or "Stealth" scans.

Where TCP scans perform a full three-way handshake with the target, SYN scans sends back a RST TCP packet after receiving a SYN/ACK from the server (this prevents the server from repeatedly trying to make the request). In other words, the sequence for scanning an open port looks like this:

This has a variety of advantages for us as hackers:

* It can be used to bypass older Intrusion Detection systems as they are looking out for a full three way handshake. This is often no longer the case with modern IDS solutions; it is for this reason that SYN scans are still frequently referred to as "stealth" scans.
* SYN scans are often not logged by applications listening on open ports, as standard practice is to log a connection once it's been fully established. Again, this plays into the idea of SYN scans being stealthy.
* Without having to bother about completing (and disconnecting from) a three-way handshake for every port, SYN scans are significantly faster than a standard TCP Connect scan.
  
All in all, the pros outweigh the cons.

For this reason, SYN scans are the default scans used by Nmap if run with sudo permissions. If run without sudo permissions, Nmap defaults to the TCP Connect scan we saw in the previous task.

Q: There are two other names for a SYN scan, what are they?

A: Half-open,Stealth

Q: Can Nmap use a SYN scan without Sudo permissions (Y/N)?

A: N

## Task 7 Scan Types UDP Scans

Due to this difficulty in identifying whether a UDP port is actually open, UDP scans tend to be incredibly slow in comparison to the various TCP scans (in the region of 20 minutes to scan the first 1000 ports, with a good connection). For this reason it's usually good practice to run an Nmap scan with --top-ports <number> enabled. For example, scanning with  nmap -sU --top-ports 20 <target>. Will scan the top 20 most commonly used UDP ports, resulting in a much more acceptable scan time.

Q: If a UDP port doesn't respond to an Nmap scan, what will it be marked as?

A: open|filtered

Q: When a UDP port is closed, by convention the target should send back a "port unreachable" message. Which protocol would it use to do so?

A: ICMP

## Task 8 Scan Types NULL, FIN and Xmas

Q: Which of the three shown scan types uses the URG flag?

A: XMAS

Q: Why are NULL, FIN and Xmas scans generally used?

A: firewall evasion

Q: Which common OS may respond to a NULL, FIN or Xmas scan with a RST for every port?

A: Microsoft Windows

## Task 9 Scan Types ICMP Network Scanning

Q: How would you perform a ping sweep on the 172.16.x.x network (Netmask: 255.255.0.0) using Nmap? (CIDR notation)

A: nmap -sn 172.16.0.0/16

## Task 10 NSE Scripts Overview

The Nmap Scripting Engine (NSE) is an incredibly powerful addition to Nmap, extending its functionality quite considerably. NSE Scripts are written in the Lua programming language, and can be used to do a variety of things: from scanning for vulnerabilities, to automating exploits for them. The NSE is particularly useful for reconnaisance, however, it is well worth bearing in mind how extensive the script library is.

There are many categories available. Some useful categories include:

    safe:- Won't affect the target
    intrusive:- Not safe: likely to affect the target
    vuln:- Scan for vulnerabilities
    exploit:- Attempt to exploit a vulnerability
    auth:- Attempt to bypass authentication for running services (e.g. Log into an FTP server anonymously)
    brute:- Attempt to bruteforce credentials for running services
    discovery:- Attempt to query running services for further information about the network (e.g. query an SNMP server).

A more exhaustive list can be found [here](https://nmap.org/book/nse-usage.html).

Q: What language are NSE scripts written in?

A: lua

Q: Which category of scripts would be a very bad idea to run in a production environment?

A: intrusive

## Task 11 NSE Scripts Working with the NSE

```sh
nmap --script-help ftp-anon.nse
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-17 17:24 CET

ftp-anon
Categories: default auth safe
https://nmap.org/nsedoc/scripts/ftp-anon.html
  Checks if an FTP server allows anonymous logins.

  If anonymous is allowed, gets a directory listing of the root directory
  and highlights writeable files.
```

Q: What optional argument can the ftp-anon.nse script take?

A: maxlist

## Task 12 NSE Scripts Searching for Scripts

Installing New Scripts

We mentioned previously that the Nmap website contains a list of scripts, so, what happens if one of these is missing in the scripts directory locally? A standard sudo apt update && sudo apt install nmap should fix this; however, it's also possible to install the scripts manually by downloading the script from Nmap (sudo wget -O /usr/share/nmap/scripts/<script-name>.nse https://svn.nmap.org/nmap/scripts/<script-name>.nse). This must then be followed up with nmap --script-updatedb, which updates the script.db file to contain the newly downloaded script.

It's worth noting that you would require the same "updatedb" command if you were to make your own NSE script and add it into Nmap -- a more than manageable task with some basic knowledge of Lua!

Search for "smb" scripts in the /usr/share/nmap/scripts/ directory using either of the demonstrated methods.

Q: What is the filename of the script which determines the underlying OS of the SMB server?

A: smb-os-discovery.nse

Q: Read through this script. What does it depend on?

```sh
grep depend /usr/share/nmap/scripts/smb-os-discovery.nse
The following fields may be included in the output, depending on the
dependencies = {"smb-brute"}
```

A: smb-brute

## Task 13 Firewall Evasion

We have already seen some techniques for bypassing firewalls (think stealth scans, along with NULL, FIN and Xmas scans); however, there is another very common firewall configuration which it's imperative we know how to bypass.

Your typical Windows host will, with its default firewall, block all ICMP packets. This presents a problem: not only do we often use ping to manually establish the activity of a target, Nmap does the same thing by default. This means that Nmap will register a host with this firewall configuration as dead and not bother scanning it at all.

So, we need a way to get around this configuration. Fortunately Nmap provides an option for this: -Pn, which tells Nmap to not bother pinging the host before scanning it. This means that Nmap will always treat the target host(s) as being alive, effectively bypassing the ICMP block; however, it comes at the price of potentially taking a very long time to complete the scan (if the host really is dead then Nmap will still be checking and double checking every specified port).

It's worth noting that if you're already directly on the local network, Nmap can also use ARP requests to determine host activity.

There are a variety of other switches which Nmap considers useful for firewall evasion. We will not go through these in detail, however, they can be found here.

The following switches are of particular note:

    -f:- Used to fragment the packets (i.e. split them into smaller pieces) making it less likely that the packets will be detected by a firewall or IDS.
    An alternative to -f, but providing more control over the size of the packets: --mtu <number>, accepts a maximum transmission unit size to use for the packets sent. This must be a multiple of 8.
    --scan-delay <time>ms:- used to add a delay between packets sent. This is very useful if the network is unstable, but also for evading any time-based firewall/IDS triggers which may be in place.
    --badsum:- this is used to generate in invalid checksum for packets. Any real TCP/IP stack would drop this packet, however, firewalls may potentially respond automatically, without bothering to check the checksum of the packet. As such, this switch can be used to determine the presence of a firewall/IDS.

Q:  Which simple (and frequently relied upon) protocol is often blocked, requiring the use of the -Pn switch?

A: ICMP

Q: [Research] Which Nmap switch allows you to append an arbitrary length of random data to the end of packets?

A: --data-length

## Task 14 Practical

Q: Does the target (10.10.4.145)respond to ICMP (ping) requests (Y/N)?

A: N

Q: Perform an Xmas scan on the first 999 ports of the target -- how many ports are shown to be open or filtered?

```sh
sudo nmap -vv -Pn -sX -p1-999 -oN nmap1.txt 10.10.4.145
Nmap scan report for 10.10.4.145
Host is up, received user-set.
All 999 scanned ports on 10.10.4.145 are open|filtered because of 999 no-responses
```

A: 999

Q: Note: The answer will be in your scan results. Think carefully about which switches to use -- and read the hint before asking for help!

A: no responses

Q: Perform a TCP SYN scan on the first 5000 ports of the target -- how many ports are shown to be open?

```sh
sudo nmap -vv -sS -p1-5000 10.10.4.145 -Pn -oN nmap2.txt
!!! Crashies the systemp
```

A: 5

Q: Open Wireshark (see Cryillic's Wireshark Room for instructions) and perform a TCP Connect scan against port 80 on the target, monitoring the results. Make sure you understand what's going on.

```sh
sudo nmap -vv -Pn -sT -p80 $ip -oN nmap3.txt
```

Q: Deploy the ftp-anon script against the box. Can Nmap login successfully to the FTP server on port 21? (Y/N)

```sh
sudo nmap -vv -Pn -p 21 --script=ftp-anon  10.10.214.126

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 127
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
```

A: Y
