# generate masks for cracking passwords according to patterns

once we have a partially cracked sam file, this script can analyze the pattern of passwords and generate hashcat commands for each mask.

```
hashcat -m 1000 --username --show sample.sam | awk -F: '{ print $1":"$3":000000:NO PASSWORD*********************:"$2":::"}' | sort -u > sample.cracked
./crack_sam_by_common_patterns.py sample.cracked > crack.sh
bash crack.sh
```
