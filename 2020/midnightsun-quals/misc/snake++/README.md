# Snake++

Snake Oil Co. has invented a special programming language to play their new and improved version of Snake. Beat the game to get the flag.

`nc snakeplusplus-01.play.midnightsunctf.se 55555`

---

When connecting to the server we get two options; play the game in human mode or computer mode.
The goal of this challenge is to win a game of snake. However there is a twist!

In human mode you play a game of snake, but there are one more feature! There are good apples that increase your length,
and bad apples that decrease it. Instead of picking up bad apples, you can shoot them. To control the snake you have to
send in "L" for turning left, "R" for turning right, " " for shooting and "" for going straight. The goal is to reach 42
in score. The board is 30x20 (also counting the walls of the board).

Playing human mode will not give us the flag, instead we get the following message

```
Score: 42
+----------------------------+
|                            |
|                            |
|                            |
|                            |
|                            |
|                            |
|                            |
|                            |
|    v<<<<<<<<        ^      |
|    v       ^        ^      |
|    v       ^        ^      |
|    v       ^<       ^      |
|    v                ^      |
|    v                ^      |
|    >>>>>>>>>>>>>>>>>^      |
|                            |
|        B                   |
|                            |
+----------------------------+
Congratulations! You win!!
Now use Snake++ to automate it.
```

In computer mode you have to use a custom programming language (Esoteric language) that uses registers, ROM, RAM,
if-else-statements and much more. Here is the documentation of Snake++

```
Snake++ Programming Language
============================

Using the Snake++ programming language, you can analyze the snake's environment
and calculate its next move, just like in the regular game.

Registers and memory
--------------------

Snake++ operates on 8 registers and 3 memory areas.  We distinguish between
text and numbers. 

There are 4 registers than can hold text, named: apple, banana, cherry and
date.  There are 4 registers that can hold numbers, named: red, green, blue and
yellow.

All 3 memory areas are 30 by 20 cells in size (just like the map of the world).
There is one RW memory area for text (TEXTRAM), and one for numbers (NUMRAM).
There is also one readonly memory area for text (TEXTROM).

Comments
--------

Any line starting with the '#' character is ignored.

Loading, storing and assigning
------------------------------

The following operators allow loading from and storing into memory:

Loading from RAM: <register> ~<8~~~ <x> <y>;
Storing into RAM: <register> ~~~8>~ <x> <y>;
Loading from ROM: <register> ~<8=== <x> <y>;

Note that there is no operator to store into ROM.  The memory area is
automatically selected based on the register and the operator.  For instance,
to load a number from NUMRAM row 7, column 5 into the blue register:

	blue ~<8~~~ 5 7;

Likewise, to store a text from the apple register into TEXTRAM row 0, column
12:

	apple ~~~8>~ 12 0;

Finally, since there is only ROM for text data:

	banana ~<8=== 5 6;

Values can also be assigned to registers using the := operator:

	blue := 5;
	cherry := "abc";

Arithmetic
----------

The following arithmetic operations are defined on numbers: + - / *
And for text, only + is defined.
Formulas can be enclosed in parentheses.

e.g.:
	blue ~<8~~~ (red+6) (green/2);
	red := blue + green * 2;
	banana := cherry + "x" + date;

Statements
----------

A program in Snake++ consists of a sequence of statements, each ending with a
semicolon.  Each of the load, store and assignment operations described above
are statements.  There are also statements for logging numbers and text (log
and logText respectively), returning a value to the game, if-then-else
branching and sliding to a label.

Logging Statements
------------------

to log the value of the blue register + 3:

	log blue+3;

to log the banana text register:

	logText banana;

Return Statement
----------------

Returning a text value will end the Snake++ program and hand control back to
the Snake game in progress.  The returned value can be used to control the
snake, and should be "", " ", "L" or "R". (See game instructions).  Only text
values can be returned.

example:
	return "R";


If-Then-Else Statement
----------------------

Works as you'd expect:

if <condition> then <sequence of statements> fi;
if <condition> then <sequence of statements> else <sequence of statements> fi;

Of note is the condition. It is possible to compare numbers to numbers, or text
to text.

For numbers, the operators are: ==, <>, >, >=, <, <=
For text, the operators are: == and <>
In each case, <> means "does not equal".

Example:

	if blue < yellow-3 then 
		logText "Looking good"; 
	else 
		logText "This is not good";
		blue := yellow - 3;
	fi;


Labels and Slide Statement
--------------------------

It is possible to label a statement by placing a label in front of it.
Labels are sequences of characters enclosed with curly braces.
For instance, the following statement is labeled {example}:
	{example} blue := 5;

During execution, it is possible to slide over from the current statement to
another labeled statement.

Example:

	green := 0;
	{loop}
		green := green + 1;
		if green < 10 then
			log green;
			slide {loop};
		fi;

Caution: it is only possible to slide to a labeled statement in the same or the
encompassing codeblock.

Program execution
-----------------

The execution environment for your Snake++ program is kept alive during the
entire game.  Before the game moves the snake, it will execute your (entire)
Snake++ program to determine what to do.  You should use the return statement
to return one of "", " ", "R" or "L".

For each execution of your program, only the TEXTROM and registers will be
altered.  TEXTROM will contain the worldmap, as also seen when playing the game
as a human.  All registers are wiped. The coordinates of the head of the snake
are placed in the blue (X-coordinate) and yellow (Y-coordinate) registers.
```


The easiest way to solve this in my opinion is to make the snake move in the following pattern:

```
 0. +----------------------------+
 1. |>v>v>v>v>v>v>v>v>v>v>v>v>v>v|
 2. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
 3. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
 4. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
 5. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
 6. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
 7. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
 8. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
 9. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
10. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
11. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
12. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
13. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
14. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
15. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
16. |^v^v^v^v^v^v^v^v^v^v^v^v^v^v|
17. |^>^>^>^>^>^>^>^>^>^>^>^>^>^v|
18. |^<<<<<<<<<<<<<<<<<<<<<<<<<<<|
19. +----------------------------+
```
1. Only in the beginning, turn the snake to make it go upwards
2. Make the snake go upwards until it reaches the top
3. Right before the top is reached, turn to the right two times and go down
4. Before reaching line 17. turn left until facing upwards and then continue up.
5. Follow this pattern until reaching the end of the right side.
6. Go all the way left using line 18, and continue the same pattern.
7. When going up or down, check the next position snake is going, if that position contains a bad apple, shoot it!

Here is the code I wrote to solve the challenge. One might have to run it a few times, as it does not take account of
bad apples while turning, and the snake needs to go upwards on an oddly number column for the pattern to work correctly.

```bash
logText "POS:";
logText "X:";
log blue;

logText "Y:";
log yellow;

#logText "DIR:";

banana ~<8=== blue yellow;
logText banana;

# Load initial start variable
green ~<8~~~ 2 0;
#log green;

# Load pending turns
apple ~<8~~~ 8 0;
#logText apple;

# Load left or right direction variable
cherry ~<8~~~ 12 0;

# We are on our way left, need one more turn
if apple == "turnleft" then
    apple := "";
    apple ~~~8>~ 8 0;
    return "L";
fi;

# We are on our way right, need one more turn
if apple == "turnright" then
    if yellow == 18 then
        if blue > 2 then
            return "";
        fi;
    fi;
    apple := "";
    apple ~~~8>~ 8 0;
    return "R";
fi;

# All the way right, lets go left
if blue == 28 then
    cherry := "left";
    cherry ~~~8>~ 12 0;
fi;

# All the way left, lets go right
if blue == 1 then
    cherry := "right";
    cherry ~~~8>~ 12 0;
fi;

# Initialize direction
if green == 0 then
    if banana == "<" then
        logText "Going left, lets go up";
        return "R";
    else
        if banana == ">" then
            logText "Going right, lets go up";
            return "L";
        else
            if banana == "^" then
                logText "Going up, keep going";
            else
                if banana == "v" then
                    logText "Going down, lets go up";
                    return "R";
                fi;
            fi;
        fi;
    fi;
fi;

green := 1;
green ~~~8>~ 2 0;

if banana == "^" then
    {loopup}
    if yellow > 2 then
	    date ~<8=== blue yellow-1;
        if date == "B" then
            logText "shooting up";
            return " ";
        fi;
        logText "going up";
        return "";
    fi;

    {godown}
    if cherry == "right" then
        logText "Turning right";
        apple := "turnright";
        apple ~~~8>~ 8 0;
        return "R";
    else
        logText "Turning left";
        apple := "turnleft";
        apple ~~~8>~ 8 0;
        return "L";
    fi;
fi;

if banana == "v" then
    {loopdown}
    if yellow < 16 then
	    date ~<8=== blue yellow+1;
        if date == "B" then
            logText "shooting down";
            return " ";
        fi;
        logText "going down";
        return "";
    fi;
    if yellow == 16 then
        if blue == 28 then
            return "";
        fi;
    fi;

    {goup}
    if cherry == "right" then
        logText "Turning left";
        apple := "turnleft";
        apple ~~~8>~ 8 0;
        return "L";
    else
        logText "Turning right";
        apple := "turnright";
        apple ~~~8>~ 8 0;
        return "R";
    fi;
fi;


logText "THE END!";
.
```
