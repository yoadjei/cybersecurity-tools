#/bin/bash

analyze_password_strength() {
	local pwd="$@"

	local len="$(echo -n "$pwd" | wc -c)"
	grep -q "[A-Z]" <<< "$pwd"
	local uppercase=$?
	grep -q "[a-z]" <<< "$pwd"
	local lowercase=$?
	grep -q "[0-9]" <<< "$pwd"
	local digit=$?
	grep -q "[[<>'!@#$%^&*(),.?"'"'":{}|<>/]" <<< "$pwd"
	local special_char=$?

	local score=0
	[ $len -gt 8 ] && score=$(($score + 1))
	[ $uppercase -eq 0 ] && score=$(($score + 1))
	[ $lowercase -eq 0 ] && score=$(($score + 1))
	[ $digit -eq 0 ] && score=$(($score + 1))
	[ $special_char -eq 0 ] && score=$(($score + 1))

	if [ $score -eq 5 ]; then echo "Strong"
	elif [ $score -ge 3 ]; then echo "Moderate"
	else echo "Weak"; fi

}

help() {
	echo "Usage: $0 <password>" >&2
	echo "Example: $0 some password_That-contains1!2@3#" >&2
	exit 1
}

[ $# -eq 0 ] && help

analyze_password_strength $@
