#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import sys

fname = sys.argv[1]

def load_file():

        with open(fname) as f:
                content = [x.strip() for x in f.readlines()]
                for line in content:
                        if line and not re.match('^#.*', line):
                                word_rules(line)


def gen_numeric_seq():

        global numbers

        numbers         = []
        numbers_temp2   = []
        numbers_temp1   = map(str,range(9999))

        for n in numbers_temp1:
                numbers_temp2.append(n.zfill(4))

        numbers         = sorted(set(numbers_temp1 + numbers_temp2))
        numbers_temp1   = numbers_temp2 = []


def word_rules(word):
        print word
        print word + "@@"
        print word + "//"
        print word + ".."
        print word + ",,"
        print word + "@" + "0"
        print word + "@" + "1"
        print word + "@" + "12"
        print word + "@" + "123"
        print word + "@" + "1234"
        print word + "@" + "12345"
        print word + "@" + "123456"
        print word + "@" + "1234567"
        print word + "@" + "12345678"
        print word + "@" + "123456789"
        print word + "@" + "1234567890"
        print word + "@" + "0123456789"

        print word + "12345"
        print word + "123456"
        print word + "1234567"
        print word + "12345678"
        print word + "123456789"
        print word + "1234567890"
        print word + "0123456789"

        print "0" + "@" + word
        print "1" + "@" + word
        print "12" + "@" + word
        print "123" + "@" + word
        print "1234" + "@" + word
        print "12345" + "@" + word
        print "123456" + "@" + word
        print "1234567" + "@" + word
        print "12345678" + "@" + word
        print "123456789" + "@" + word
        print "1234567890" + "@" + word
        print "0123456789" + "@" + word

        print "12345" + word
        print "123456" + word
        print "1234567" + word
        print "12345678" + word
        print "123456789" + word
        print "1234567890" + word
        print "0123456789" + word

        print word + "@" + "admin"
        print "admin" + "@" + word

        for num in numbers:

                print "@" + num + word
                print num + "!" + word
                print num + "#" + word
                print num + "*" + word
                print num + "**" + word
                print num + "@" + word
                print num + "@" + word + "!"
                print num + word + "@"
                print num + word + "."
                print num + word + "$$"
                print num + word + "$$$"

                print "#" + word + "@" + num
                print "*" + word + num
                print "#" + word + num
                print "#" + word + "." + num
                print "#" + word + num + "$"
                print "@" + word + num
                print "@@" + word + num
                print "!@#" + word + num
                print word + "!" + num
                print word + "!" + num + "!!"
                print word + "!" + num + "@@"
                print word + "#" + num
                print word + "#" + num + "@"
                print word + "##" + num
                print word + "$" + num
                print word + "$" + num + "$"
                print word + "%" + num
                print word + "*" + num
                print word + "*" + num + "!"
                print word + "**" + num
                print word + "+" + num
                print word + "," + num
                print word + "-" + num
                print word + "." + num
                print word + "@" + num
                print word + "@" + num + "!!"
                print word + "@" + num + "#"
                print word + "@" + num + "##"
                print word + "@" + num + ")"
                print word + "@" + num + "*"
                print word + "@" + num + "**"
                print word + "@" + num + "*-"
                print word + "@" + num + "."
                print word + "@" + num + "/."
                print word + "@" + num + "@"
                print word + "@" + num + "@:"
                print word + "@" + num + "@;"
                print word + "@#" + num
                print word + "@!" + num
                print word + "@#$" + num
                print word + "@@" + num
                print word + "_" + num
                print word + num
                print word + num + "!"
                print word + num + "#"
                print word + num + "@"
                print word + num + "*"
                print word + num + "."
                print word + num + "**"
                print word + num + '$$'


def main():

        gen_numeric_seq()
        load_file()


if __name__ == '__main__':
        main()

