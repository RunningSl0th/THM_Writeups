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



