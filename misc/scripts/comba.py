#!/usr/bin/python

import sys

def comba_indexes(N):

    indexes = []

    for i in xrange(0, 2*N):
        x = []

        for j in xrange(max(0, i-N+1), min(N, i+1)):
            x += [(j,i-j)]
        indexes += [sorted(x)]

    return indexes

def comba_sqr_indexes(N):

    indexes = []

    for i in xrange(0, 2*N):
        x = []

        for j in xrange(max(0, i-N+1), min(N, i+1)):
            if j < i-j:
                x += [(j,i-j)]
            else:
                x += [(i-j,j)]
        indexes += [sorted(x)]

    return indexes

def comba_multiply_code(N):
    indexes = comba_indexes(N)

    for (i,idx) in zip(range(0, len(indexes)), indexes):
        for pair in idx:
            print "word3_muladd(&w2, &w1, &w0, x[%2d], y[%2d]);" % (pair)
        print "z[%2d] = w0; w0 = w1; w1 = w2; w2 = 0;" % (i)

def comba_square_code(N):
    indexes = comba_sqr_indexes(N)

    for (rnd,idx) in zip(range(0, len(indexes)), indexes):
        for (i,pair) in zip(range(0, len(idx)), idx):
            if pair[0] == pair[1]:
                print "   word3_muladd(&w2, &w1, &w0, x[%2d], x[%2d]);" % (pair)
            elif i % 2 == 0:
                print "   word3_muladd_2(&w2, &w1, &w0, x[%2d], x[%2d]);" % (pair[0], pair[1])
        if rnd < len(idx)-2:
            print "   z[%2d] = w0; w0 = w1; w1 = w2; w2 = 0;\n" % (rnd)
        elif rnd == len(idx)-1:
            print "   z[%2d] = w0;\n" % (rnd)
        else:
            print "   z[%2d] = w1;\n" % (rnd)

def main(args = None):
    if args is None:
        args = sys.argv
    #comba_square_code(int(args[1]))
    comba_multiply_code(int(args[1]))

if __name__ == '__main__':
    sys.exit(main())
