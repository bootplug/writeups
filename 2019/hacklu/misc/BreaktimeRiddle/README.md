# <a name="breaktime"></a> Breaktime Riddle (249p)

Description:

```
While waiting for one of the speeches to start, a buddy of mine opened his laptop and typed in some lines of python.

'This is for you', he said. Turns out he likes to keep his code concise. I wonder what he will do when re-visiting the code in a couple of months or so. He did not even explain what this mess is all about and refuses to tell me anything further.

To mock me even more, my buddy put up the script on a server. I would like to impress him with a solution to this. It is a bit trickier than I thought, though. Can you give me a hand with this?

Download challenge files

nc breaktime-riddle.forfuture.fluxfingers.net 1337
```

We are given [riddle.py](riddle.py), which does the following for 50 rounds:

1. Creates a random permutation of the list `[0,1,2]`, which corresponds to the functions that return its input unmodified ("Always speaks truth"), inverts the input ("Always lies") or randomly inverts the input or not. This permutation is referenced as `(A,B,C)`.
2. Picks one out of 2 functions, that either always inverts or returns the input unmodified. This value is referenced as `X`.
3. For 3 iterations, reads in input and `eval()` the second part of it. You can only pick inputs from the set `['==','(',')','A','B','C','X','0','1','2']`, so no code execution. Instead, you are essentially allowed to ask boolean questions about the different values. The first parameter to the question, is an integer that decides which of A, B or C to ask the question, and this decides if you get a truthful answer, a lie, or a random response. After processing your question, the final answer will also potentially be inverted based on the value of `X`.
4. Ask which values `(A,B,C)` correspond to, based on the three questions you asked. You have to answer correctly all 50 times, and guessing randomly gives you a 1:6 chance of guessing correctly.

If you manage to guess correctly all 50 rounds, the flag is printed.

This problem corresponds to "[The Hardest Logic Puzzle Ever](https://en.wikipedia.org/wiki/The_Hardest_Logic_Puzzle_Ever)", just in code form. A, B, C corresponds to the three gods, and the X corresponds to whether "da" means "yes". The Wikipedia article is lengthy enough, but the gist of it is that you need to:

1. Figure out one of A, B or C that are guaranteed to **not** be random. Direct future questions to this entity.
2. Ask 2 boolean questions that each reveal a new fact about the remaining values.
3. With 3 unique facts, you have enough information to find the current permutation of `[0,1,2]` that corresponds to A, B and C.

A solution can be found in [solve.py](solve.py). 