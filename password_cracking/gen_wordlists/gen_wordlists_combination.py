#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import glob

items       = []
item_temp   = []

files = sorted(glob.glob('*.dic'), key=os.path.getsize)
for f in files:

    # calculate the number of lines of each file
    fcontent = open(f)
    lines = 0
    buf_size = 1024 * 1024
    read_f = fcontent.read

    buf = read_f(buf_size)
    while buf:
        lines += buf.count('\n')
        buf = read_f(buf_size)

    fcontent.close()
    fsize = lines

    item_temp.append(f)
    item_temp.append(fsize)
    items.append(item_temp)
    item_temp   = []


final_items     = []
temp_f_items    = []

for i in items:
    for j in items:
        temp_t_size = i[1] * j[1]
        temp_f_items.append(temp_t_size)
        temp_f_items.append(i[0])
        temp_f_items.append(j[0])

        final_items.append(temp_f_items)

        temp_f_items = []

last_t_size = 0
for f_i in sorted(final_items):
    if last_t_size <> f_i[0]:
        print '\n'
    print 'hashcat --hwmon-temp-abort=100 -O --force --opencl-device-types 1,2 -w 3 -a 1 -m 1000 SAMFILE.SAM ' + str(f_i[1]) + ' ' + str(f_i[2]) + '\t\t# ' + str('{:1,}'.format(f_i[0]))
    last_t_size = f_i[0]

