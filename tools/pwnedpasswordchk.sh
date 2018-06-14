#!/bin/bash
# Pwned password checker, 2018 by T. Castillo Girona
# Usage:
#	pwnedpasswordchk.sh -p password | -f file -d delay

API="https://api.pwnedpasswords.com/range/"
OSSL="/usr/bin/openssl"
CURL="/usr/bin/curl -s"
delay="5s"

passwd=""
passwdfile=""

while getopts "f:d:p:h" opt; do
	case "$opt" in
		f)
			passwdfile="$OPTARG"
			;;
		p)	
			passwd="$OPTARG"
			;;
		d)
			delay="${OPTARG}s"
			;;
		h)
			clear
			echo "Usage: $0 [-p PASSWORD] [-f FILE] [-d DELAY (in seconds)]"
			echo "  Example: $0 -p mariobros"
			echo "           $0 -f /usr/share/wordlists/rockyou.txt -d 10"
			exit 0
	esac
done

# Look for the given password:
if [ ! -z "$passwd" ]; then
	# Generate the sha1 hash:
	phash=`echo -n "$passwd"|openssl sha1|tr a-z A-Z|cut -d"=" -f2|tr -d " "`
	echo "$passwd = $phash"
	# Look for it:
	$CURL $API/${phash:0:5}|egrep --color=yes -E "^${phash:5:${#phash}-5}"
	test $? -eq 0 || echo "NOT PWNED (YET)"
	exit 0
fi

# Use a password file to look for pwned passwords:
if [ ! -z "$passwdfile" ]; then
	echo "Using passwords from: $passwdfile."
	if [ -r "$passwdfile" ]; then
		# Iterate over all its entries:
		tentries=`wc -l "$passwdfile"|cut -d" " -f1`
		echo "Total passwords: $tentries"; i=1
		while [ $i -le $tentries ]; do
			cpasswd=`head -$i "$passwdfile"|tail -1`
			phash=`echo -n "$cpasswd"|openssl sha1|tr a-z A-Z|cut -d"=" -f2|tr -d " "`
			echo "$cpasswd = $phash"
			$CURL $API/${phash:0:5}|egrep --color=yes -E "^${phash:5:${#phash}-5}"
			test $? -eq 0 || echo "NOT PWNED (YET)"
			i=`expr $i + 1`
			sleep $delay
		done
	else
		echo "Unable to read $passwdfile".
	fi
fi

exit 0
