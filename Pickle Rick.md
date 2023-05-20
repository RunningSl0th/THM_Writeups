# Pickle Rick
In the instruction of this lab it says that we simply can go to `https://<LAB IP>.p.thmlabs.com/`. No need to NMAP here.
So let's do that.

We see a nice page and it seems Rick forgot his password (and turned himself into a pickle again. Let's look for the password.

# HTML Source Code
Since we only have this page we can check the headers and url of the page to look for information. One simple thing to do is to check the HTML source.
Here we find an HTML note:

```html
...
</div>

  <!--

    Note to self, remember username!

    Username: R1ckRul3s

  -->

</body>
</html>
```

Here is the username we have to remember.

### robots.txt
Maybe here's something:
```html
Wubbalubbadubdub
```
Hmmm...not sure what this is. Maybe a password. Let's take note of it

# NMAP
After looking for information in with the tools in the browser I decided I might use NMAP and some other tools. So first start scanning all ports and
save the results (for our pentest report)
```sh
┌──(kali㉿kali)-[~/…/THM/Pickle Rick/recon/nmap]
└─$ nmap 10.10.141.252 -p- -oA allports
```
## NMAP Results
```sh
Nmap scan report for 10.10.141.252
Host is up (0.025s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Only two ports. Since this is a small CTF challenge I leave the scanning here..maybe I have to come back later on.

## Directory and page scanning with ffuf
So check for directories and pages.
--of = Format of the output, I like HTML so I can have a nice overview
```sh
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://10.10.141.252/FUZZ -of html -o dirs80.html     -e .txt,.php,.html -v
```

I the results it gives me the `/portal.php` which redirects to `/login.php`. 

Since we only have a username we have to look for the password. But first try username = password. You never know....
Okay now we know that that wasn't the case.

### clue.txt
Since ffuf was still running I noticed a `/clue.txt` file. Let's check it out:
```html
Look around the file system for the other ingredient.
```
This is the only thing found. Since we do not have access to a file system we have to park this clue.

## Login
Wait... maybe we can try the gibberish of the robotx.txt

Bingo!! We can login with the username and the password form the robots.txt file

