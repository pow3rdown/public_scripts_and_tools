# generate masks for cracking passwords according to patterns

once we have a partially cracked sam file, this script can analyze the pattern of passwords and generate hashcat commands for each mask.

```
./crack_sam_by_patterns.py sample.cracked > crack.sh
bash crack.sh
```
