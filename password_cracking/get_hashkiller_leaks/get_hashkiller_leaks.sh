#!/bin/bash
IFS='
'

rm -f *.txt
leaks=$( lynx --dump https://hashkiller.io/leaks | egrep -i "found_leaks" | awk '{ print $2 }' | sort -u )

for i in ${leaks}; do

        wget "$i"
done

cat *.txt | sed 's/^[0-9a-zA-Z]\{1,\}://g' >> all_leaks2.dic
sort -u all_leaks2.dic -o all_leaks.dic
rm -f all_leaks2.dic *.txt
