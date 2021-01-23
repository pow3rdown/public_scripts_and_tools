# some scripts to generate wordlists:

* **gen_wordlists_combination.py**:
generates hashcat commands based on the wordlists found at the current folder sorted by size.

* **gen_wordlist.py**:
generates a wordlist based on specific key words provided, such as : **company name**, **username**, **month**, **season**, **soccer teams** etc.
```
./gen_wordlist.py words.txt > wordlist.dic
```
