#!/usr/bin/env python
# -*- coding: utf-8 -*-

from collections import Counter
import math
import sys
import re

filename = sys.argv[1]

# 12 characters
default_symbols_set = '''@\+\!\#\*$._%-,\&'''
prefix = 'hashcat --hwmon-temp-abort=100 -O --force --opencl-device-types 1,2 -w 4 -a 3 -m 1000 sample.sam -2 ' + default_symbols_set + ' -3 ?u?l?d?2'

'''
https://hashcat.net/wiki/doku.php?id=mask_attack
https://hashcat.net/wiki/doku.php?id=combination_count_formula

--------------------
masks
--------------------
?l ----> [a-z]                                      /  26 characters
?u ----> [A-Z]                                      /  26 characters
?d ----> [0-9]                                      /  10 characters
?s ----> «space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~    /  33 characters
--------------------
'''

# min and max threshold for masks
mask_len_max 	= 11
mask_len_min 	= 9

# total of each type of character
total_symbol 	= 12        #FIXME - later this value is gonna be dynamic according to the top symbols found
total_upper 	= 26
total_lower	= 26
total_num 	= 10

top_x_masks     = 300

with open(filename, 'rU') as file_content:

	all_masks = []
	top_symbols = []
	mask_vs_iterations = []
	for line in file_content:

		count_symbol 	= 0
		count_lower 	= 0
		count_upper 	= 0
		count_num 	= 0

		iteration_symbol	= 1
		iteration_upper	= 1
		iteration_lower	= 1
		iteration_num	= 1 

                # parsing only valid cracked hashes lines
		if re.match('^\s*$', line) or not re.match('.*:.*', line):
			continue

                # get the password field and split characters
		password = line.rsplit(':')[1]
		list_of_characters =  list(password)  # convert a string into a list of characters

		partial_mask = []
		for a in list_of_characters:
			if re.match('[0-9]', a): 
				count_num = count_num + 1
				x = '?d'
				partial_mask.append(x)
			elif re.match('[a-z]', a):
				count_lower = count_lower + 1
				x = '?l'
				partial_mask.append(x)
			elif re.match('[A-Z]', a):
				count_upper = count_upper + 1
				x = '?u'
				partial_mask.append(x)
			elif re.match('[^a-zA-Z0-9]', a):
				count_symbol = count_symbol + 1
				x = '?2'
				partial_mask.append(x)

				for each_symbol in list(a):
					top_symbols.append(each_symbol)

                # calculating the charsets and the number of iterations
		if count_symbol > 0:
			iteration_symbol = math.pow(total_symbol, count_symbol)
		if count_upper > 0:
			iteration_upper = math.pow(total_upper, count_upper)
		if count_lower > 0:
			iteration_lower = math.pow(total_lower, count_lower)
		if count_num > 0:
			iteration_num = math.pow(total_num, count_num)

		iteration_total = iteration_symbol * iteration_upper * iteration_lower * iteration_num

                # storing each mask found
		temp = ''.join(partial_mask)
		all_masks.append(temp)

		mask_vs_iteration = []
		mask_vs_iteration.append(temp)
		mask_vs_iteration.append(int(iteration_total))
		mask_vs_iterations.append(mask_vs_iteration)

        # converting the type of data
        mask_vs_iterations = [list(x) for x in set(tuple(x) for x in mask_vs_iterations)]

        # sort all_masks by the number of iterations
        # NOTE: we do not remove the duplicated records here in order to have the number of occurrences
	sorted_all_masks= sorted((Counter(all_masks)).items(), key=lambda a: a[1], reverse=True)

	## sorted the top_symbols by the number of occurrences
	sorted_top_symbols = sorted((Counter(top_symbols)).items(), key=lambda a: a[1], reverse=True)

	# generate the list of masks to be used, considering the threshold/range of mask length
        final_mask_list = []
	for i in sorted_all_masks:

            mask 	= i[0]				# '?l?d?l?l?l?l?l'	
            occurrence 	= i[1]				# 5
            mask_lenght = str(len(mask) /2)		# 7

            if int(mask_lenght) >= mask_len_min and int(mask_lenght) <= mask_len_max:
		for j in mask_vs_iterations:
			if mask in j:
				final_mask_list.append(j)

        # sort final_mask_list by number of iterations
        final_mask_list.sort(key=lambda x: x[1], reverse=False)

	# starting with a specific incremetal 8 characters long mask
	print prefix + ' -i ' + '?3?3?3?3?3?3?3?3'
        # picking the top_masks according to top_x_masks
        x = 1
        for mask in final_mask_list:
            if x <= top_x_masks:
                x = x+1
                print prefix + ' ' + mask[0] + '	# %s' % (mask[1])


print 'hashcat --hwmon-temp-abort=100 -i -O --force --opencl-device-types 1,2 -w 4 -a 3 -m 1000 sample.sam'

