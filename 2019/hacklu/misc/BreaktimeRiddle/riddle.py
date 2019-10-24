#!/usr/bin/env python3
from random import choice as c
from itertools import permutations as p
from secret import flag

v = ['==','(',')','A','B','C','X','0','1','2']
def calc(t1, t2, m1, X, i, expr):
    try:
        A, B, C = m1
        r = eval(expr)
    except Exception as e:
        print("Error...", e)
        exit(0)
    return t2[X](t1[m1[i]](r))

def do_round():
    t1 = (lambda r: r, lambda r: not r, lambda r: c((True, False)))
    t2 = (lambda r: r, lambda r: not r)
    m1 = c(list(p(range(len(t1)))))
    m2 = c(range(len(t2)))

    print(m1,m2)
    for _ in range(3):
        print("I?")
        ts = [t for t in input().split(" ") if t in v]
        print("R: {}".format(calc(t1, t2, m1, m2, int(ts[0]), "".join(ts[1:]))))

    print("A?")
    return m1 == tuple(map(int, input().split(" ")))

for i in range(50):
    if not do_round():
        print("Wrong...")
        exit(0)
    else:
        print("Correct!")

print("Good job, here is your flag: {}".format(flag))