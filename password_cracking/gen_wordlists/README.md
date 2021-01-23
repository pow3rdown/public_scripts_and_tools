# some scripts to generate wordlists:

* **gen_wordlists_combination.py**:
the idea is to generate hashcat commands based on the wordlists found at the current folder sorted by size.

* **gen_wordlist.py**:
the idea is to generate a wordlist based on specific key words provided, such as : **foobar**, **company**, **user**, **month**, **season**, **soccer teams** etc.
```
./gen_wordlist.py words.txt > wordlist.dic
```
