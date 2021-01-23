# ways to crack passwords by using hashcat:

* bruteforce:
```
hashcat --hwmon-temp-abort=100 -i -O --force --opencl-device-types 1,2 -w 4 -a 3 -m 1000 sample.sam
```
* mask:
```
hashcat --hwmon-temp-abort=100 -O --force --opencl-device-types 1,2 -w 4 -a 3 -m 1000 sample.sam -2 @\+\!\#\*$._%-,\& ?u?l?l?l?l?2?d?d?d?d
```
* wordlist:
```
hashcat --hwmon-temp-abort=100 -O --force --opencl-device-types 1,2 -w 4 -a 0 -m 1000 sample.sam wordlist.dic -r all.rules
```
* wordlist combination:
```
hashcat --hwmon-temp-abort=100 -O --force --opencl-device-types 1,2 -w 4 -a 1 -m 1000 sample.sam wordlist1.dic wordlist2.dic
```
* hashes:


| algorithm  |  id  |
| ------------------- | ------------------- |
|  md5 |  0 |
|  ntlm |  1000 |
|  lm |  3000 |
|  netntlmv1 |  5500 |
|  netntlmv2 |  5600 |
