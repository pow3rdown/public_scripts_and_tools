# ways to crack passwords by using hashcat:

+ bruteforce:
hashcat --hwmon-temp-abort=100 -i -O --force --opencl-device-types 1,2 -w 4 -a 3 -m 1000 sample.sam

+ mask:
hashcat --hwmon-temp-abort=100 -O --force --opencl-device-types 1,2 -w 4 -a 3 -m 1000 sample.sam -2 @\+\!\#\*$._%-,\& ?d?d?d?d?d?d?d?d?l

+ wordlist:
hashcat --hwmon-temp-abort=100 -O --force --opencl-device-types 1,2 -w 4 -a 0 -m 1000 sample.sam wordlist.dic -r all.rules

+ wordlist combination:
hashcat --hwmon-temp-abort=100 -O --force --opencl-device-types 1,2 -w 4 -a 1 -m 1000 sample.sam wordlist1.dic wordlist2.dic
