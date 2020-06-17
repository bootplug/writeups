# Zh3r0 CTF Writeup by team bootplug

##  void

```bash
$ file output.wav
output.wav: RIFF (little-endian) data, WAVE audio, mono 48000 Hz
```

Google `wav "mono 48000 Hz" "ctf"` and we find http://g4ngli0s.logdown.com/posts/1422073-bsidessfctf-for-latlong. The spectrum analysis on that page looks exactly like the one we see in Audacity. Copy the commands they used, adapted to the file names used in this challenge.

```bash
$ sox -t wav output.wav -esigned-integer -b16 -r 22050 -t raw output.raw
$ ./multimon-ng -t raw -a AFSK1200 output.raw
```
Or do everything in one command:
```bash
$ cat output.wav |
    sox -t raw -esigned-integer -b 16 -r 48000 - -esigned-integer -b 16 -r 22050 -t raw - |
    multimon-ng -t raw -a AFSK1200 -f alpha -

multimon-ng 1.1.8
  (C) 1996/1997 by Tom Sailer HB9JNX/AE4WA
  (C) 2012-2019 by Elias Oenal
Available demodulators: POCSAG512 POCSAG1200 POCSAG2400 FLEX EAS UFSK1200 CLIPFSK FMSFSK AFSK1200 AFSK2400 AFSK2400_2 AFSK2400_3 HAPN4800 FSK9600 DTMF ZVEI1 ZVEI2 ZVEI3 DZVEI PZVEI EEA EIA CCIR MORSE_CW DUMPCSV X10 SCOPE
Enabled demodulators: AFSK1200
AFSK1200: fm WDPX01-0 to APRS-0 UI  pid=F0
!/;E'q/Sz'O   /A=000000zh3r0{ax25_is_c00l__dm_me_the_solution}
```

yielding the flag `zh3r0{ax25_is_c00l__dm_me_the_solution}`

##  Tears
We - after brainstorming hundreds of different ways to understand the text - understood that we should use Tor. (Onions make us cry).

One teammate posted a wiki/index containing .onion URLs and a description of the site.

http://dirnxxdraygbifgc.onion/

From that site we found the forum by trying to find something like `galaxy` or `universe` that was mentioned in task description: 
http://galaxy3bhpzxecbywoa2j4tg43muepnhfalars4cce3fcx46qlc6t3id.onion/

And then this one by looking for the obvious username from the task description `un1v3rsek1ng`:
http://galaxy3bhpzxecbywoa2j4tg43muepnhfalars4cce3fcx46qlc6t3id.onion/profile/un1v3rsek1ng

Found loads of fake pictures because someone sabotaged us :'(, but eventually found the right picture. 

Then figured the pieces of text on the picture was base85, put the pieces together, decoded it and got the flag.

Base85 of `H>#*T0RGKkBeXFG?Xe%1DJ*<n1LG5[1idYE0P4[%Ed<'` is

`zh3r0{0ni0ns_br1ng_m3_t34rs_0f_cry}`


##  fsociety 

Always check robots.txt
http://web.zh3r0.ml:6565/robots.txt
```
# F-Society
User-agent: *
Disallow: /elliot.html
```

visit elliot.html, see large gif, check source
http://web.zh3r0.ml:6565/elliot.html
```html
<img src="elliot.gif" alt="check my js " id="selector">
```

Seems like we should check out the js on the page.
```html
<script src="myscript.js">
```

http://web.zh3r0.ml:6565/myscript.js
```js
(![]+[])[+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(+[![]]+[+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]+[+!+[]]+[+[]]+[+[]]+[+[]])])[+!+[]+[+[]]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]
```
is JSFuck and decodes into `fsocietyislit`, interesting let's take note of that and keep searching.

After more dirbusting we found /code and subsequently flag.php.
We're met with:

`Elliot need to submit hash here to get the flag.`

Guessed that the parameter was code and submitted md5 of the string we found earlier.

```bash
curl "http://web.zh3r0.ml:6565/code/flag.php" --data "code=46a07f610bdab202d6b83d78a5d72914"

zh3r0{ell1ot_y0u_4r3_1n}
```

##  armpw

QEMU stack is executeable

1. leak stack addr
2. leak stack cookie
3. return to shellcode on the stack

## Knock
Port scan, find list of ports. Hint on port 3389, a "main" webserver at port 80 and different webservers at the following ports, all returning a static website. Combining the hint, and sorting the port numbers (sans 80 and 3339), we get the flag with the script below. All the ports were within ASCII range.

```python
port_sort = [48, 49, 51, 52, 89, 95, 100, 101, 104, 105, 108, 110, 111, 114, 116, 117, 122, 123, 125]

# From the hint
order = [(0, 4), (1, 16), (2, 2), (3, 11), (4, 6), (5, 9), (6, 15), (7, 14), (8, 1), (9, 12), (10, 13), (11, 10), (12, 7), (13, 3), (14, 17), (15, 8), (16, 0), (17, 5), (18, 18)]

flag = [0]*19
for flag_ix, index in order:
    print(flag_ix, index)
    flag[index] = chr(port_sort[flag_ix])
print(''.join(flag))
```

Flag `zh3r0{You_n4iled1t}`
