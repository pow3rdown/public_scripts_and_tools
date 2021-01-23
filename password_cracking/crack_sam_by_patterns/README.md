# generate masks for cracking passwords according to patterns

once we have a partially cracked sam file, this script can analyze the pattern of passwords already cracked and generate hashcat mask commands.

```
./crack_sam_by_patterns.py sample.cracked > crack.sh
bash crack.sh
```
