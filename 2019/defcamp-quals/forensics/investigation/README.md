# Investigation

**Category**: Forensics

**Points**: 356

#### Challenge description:
During a criminal investigation a suspect was raided and all his electronic devices were seized. 
Unfortunately, the investigators haven't found the information they were looking for because the 
suspect backed up his data to the cloud and formatted his computer. The only information that we 
have at hand is the attached pcap.

---

No one else had solved this task when I started looking at it. So I was hoping for "first blood" for extra points :) However, one guy/girl managed to solve it right before I did. I am still happy with "second blood" though!

This is a forensics task and we have been given a PCAP file. In the task description it was mentioned that the person backed up the computer to the cloud.

Here is the summary of protocols used in the pcap file. Most of the traffic is TLS:

![summary](https://i.imgur.com/2EaerEQ.png)

I first started looking at the PCAP file for dns traffic related to the cloud, and I quickly spot alot of requests to amazonaws.com and a specific s3 bucket: `hand-soap`

![dns](https://i.imgur.com/QjU88v5.png)

I can also see a lot of traffic from the local IP to the server hosting the bucket I just found. 

Now I feel like just visiting the website to check if I have anonymous read access to the S3 bucket.

![s3 bucket](https://i.imgur.com/ym1Finb.png)
![s3backer](https://i.imgur.com/ncazZnL.png)

I can get a list of all the files in the bucket. The file names just look like numbers, except the last file in the bucket named `s3backer-mounted`.
The first thing I try is to fire up the AWS CLI tool and download all of the files. Most of the files are empty, and some of the files look like EXT4 files systems. I also find a password protected zip file. Inside of the zip file is a file called `secret`.


Now I want to check what **s3backer** really is. I find the Github page for the tool at [https://github.com/archiecobbs/s3backer](https://github.com/archiecobbs/s3backer) :
> **s3backer** is a filesystem that contains a single file backed by the Amazon Simple Storage Service (Amazon S3). As a filesystem, it is very simple: it provides a single normal file having a fixed size. Underneath, the file is divided up into blocks, and the content of each block is stored in a unique Amazon S3 object. In other words, what s3backer provides is really more like an S3-backed virtual hard disk device, rather than a filesystem.

It makes sense now that I know each S3 object is a block. That is why many of the files were empty, and they had the block numbers as file names. The `s3backer-mounted` file is there to tell s3backer that someone has already mounted the bucket.


Using s3backer, I try mounting the bucket in a folder:

```bash
$ s3backer --readOnly hand-soap --region="eu-central-1" --force s3b.mnt
s3backer: auto-detecting block size and total file size...
s3backer: auto-detected block size=128k and total size=1t
s3backer: warning: filesystem appears already mounted but you said `--force'
 so I'll proceed anyway even though your data may get corrupted.
```

According the s3backer wiki page, the next step is to mount `s3b.mnt/file` to a chosen folder.

```bash
$ sudo mount -o ro,loop s3b.mnt/file files.mnt

$ find files.mnt -ls
        2      4 drwxr-xr-x   3 root     root         4096 mars 30 15:02 files.mnt
       12      4 -rw-r--r--   1 root     root          255 sep.  5 10:21 files.mnt/docs.zip
       11     16 drwx------   2 root     root        16384 mars 30 14:57 files.mnt/lost+found
find: ‘files.mnt/lost+found’: Permission denied
```

This looks like the same zip file I found earlier, but this time I actually know it's called `docs.zip`. I need to find the password for unzipping `secret`, 
but after looking through the PCAP file once more I can't find anything more that will help me. The next thing I try is using the bucket name as password
for the zipfile:

```bash
$ unzip docs.zip 
Archive:  docs.zip
[docs.zip] secret password: hand-soap # Password shown for clarity
  inflating: secret                  

$ cat secret
DCTF{307b336479aed7b642d63fe1a807606a103acf5b10b9ecacfaf85a04519bef54}
```

Alright, I guess that worked! :D
