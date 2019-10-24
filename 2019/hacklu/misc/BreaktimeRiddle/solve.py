from socket import socket

s = socket()
s.connect(("breaktime-riddle.forfuture.fluxfingers.net", 1337))


for _ in range(50):
    A, B, C = -1, -1, -1

    print(s.recv(1024))
    # Figure who is not random by asking A
    s.sendall(b"0 ( ( A == 0 ) == ( B == 2 ) ) == ( X == 1 )\n")
    if b"True" in s.recv(1024):
        # B is not random

        s.sendall(b"1 ( ( A == 2 ) == ( B == 0 ) ) == ( X == 1 )\n")
        if b"True" in s.recv(1024):
            # A is not random so C is random
            C = 2
        else:
            # A is random
            A = 2

        s.sendall(b"1 ( ( B == 1 ) ) == ( X == B )\n")
        if b"True" in s.recv(1024):
            # B is false
            B = 1
        else:
            B = 0

    else:
        # C is not random

        s.sendall(b"2 ( ( A == 2 ) == ( C == 0 ) ) == ( X == 1 )\n")
        if b"True" in s.recv(1024):
            # A is not random, so B is random
            B = 2
        else:
            # A is random
            A = 2

        s.sendall(b"2 ( ( C == 1 ) ) == ( X == C )\n")
        if b"True" in s.recv(1024):
            # C is false
            C = 1
        else:
            C = 0

    if (A == -1): A = list((set([0,1,2]) - set([B,C])))[0]
    if (B == -1): B = list((set([0,1,2]) - set([A,C])))[0]
    if (C == -1): C = list((set([0,1,2]) - set([A,B])))[0]

    print(b"%d %d %d\n" % (A,B,C))
    s.sendall(b"%d %d %d\n" % (A,B,C))

print(s.recv(1024))

# Good job, here is your flag: flag{Congr4ts_f0r_s0lving_The_Hardest_Logic_Puzzle_Ever}