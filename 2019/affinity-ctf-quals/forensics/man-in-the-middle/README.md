# Man in the middle

**Category**: Forensics

**Points**: 100

#### Challenge description:
*This task had no description other than:*
`Note: put flag into AFFCTF{} format.`

*This is a forensics task and we are given a PCAP file.*

---

This challenge was the second hardest forensics challenge. We were given a pcap file and I opened it up. I quickly noticed some interesting FTP traffic:

![FTP](https://i.imgur.com/gzHA779.png)

vsFTPd 3.0.3 has been used. The user `m` logged in with the password `m`. The user then listed a directory and retrieved the file `strictly_confidential`.

We can see the output of those commands using the `ftp-data` filter.

![FTP-data](https://i.imgur.com/7kAfqCn.png)

By looking in the line-based text data of those two packets we get the output.

![LIST output](https://i.imgur.com/1uHkHto.png)

![RETR output](https://i.imgur.com/rtgYT6T.png)

I saved the `strictly_confidential` file to my computer and checked it out. The file does not have that much content, but we can clearly see a header followed by some binary data.

```
VimCrypt~03!�	�����Ў=E, ������f9[J�82L�rk\O��C�*M�f�Vh��C��
```

VimCrypt sounds familiar! Vim actually comes packaged with a default encryption mechanism called VimCrypt. Whenever you feel like encrypting a file you have been working on, you can just type `:X` and type a password to encrypt your file. When you open the file again using Vim, it asks for a password.
VimCrypt currently supports three encryption methods: zip (01), blowfish (02) and blowfish2 (03). By looking at the header (03), we can see that this file is encrypted using blowfish2.

It is harder to break blowfish2 than the two other encryption methods, so we need to find a password! I opened up the pcap file again looking for interesting stuff.
The SMTP traffic looked promising to take a closer look at. I found a mail sent from m@affinity.com to k@affinity.com with the text

```
the password is Horse Battery Staple Correct
```

![SMTP](https://i.imgur.com/j1dEXg2.png)


After opening the file in Vim using the password I found, I got the flag!

![Password](https://i.imgur.com/gGfmyAA.png)

![Flag](https://i.imgur.com/wljoWhJ.png)

```
AFFCTF{I_Should_Have_Used_Safer_Connection_..}
```
