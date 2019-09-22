# rerere

**Category**: Reverse Engineering

**Points**: 240

#### Challenge description:
> re rere rerere. Find the magic key, and encapsulate in SECT{...} to get the flag

---

Decompiling the code reveals just a single function, that outputs "YN" or "N". Giving random inputs to the binary produces "N", so we probably want it to print "YN" instead.

```
  gets(flag, argv, a3);
  v5 = 0;
  for ( i = 0; i <= 0xC; ++i )
  {
    v8 = 0.0;
    for ( j = 0; j <= 0xC; ++j )
      v8 = (i - 6) * v8 + dbl_201020[j];
    if ( v8 <= 0.0 )
      v3 = (v8 - 0.5);
    else
      v3 = (v8 + 0.5);
    v5 += flag[i] - v3;
  }
  if ( v5 )
    puts(L"N");
  else
    puts(L"YN");
```

Basically, it reads in the flag as an argument, then does some fancy math in a loop over 0xC bytes. This gives the information that the flag is 0xC long. After each round, the difference between `flag[i]` (unmodified) and `v3` (calculated independently of the flag) is added to `v5`. We want `v5` to stay at 0 to get to the "YN" output. That means that for each loop, `flag[i]` must be equal to `v3`.

We then fire up GDB, set a random flag of the correct length, and put a breakpoint at the place where they subtract v3 from flag[i]. Keep running this, and jot down the values of EAX for each round, and you get the flag.

``` 
set args 1234567890123
b *0x55555555494b
```
