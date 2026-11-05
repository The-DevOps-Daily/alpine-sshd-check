#!/bin/sh
# List running Docker containers, find Alpine ones with an sshd process and
# run check.sh inside each (piped on stdin, nothing is copied in).
# Read-only. Exit: highest check.sh exit code seen (0 if none checked).
set -u
cd "$(dirname "$0")"
worst=0
printf '%-14s %-14s %-21s %-12s %-12s %-5s %s\n' CONTAINER IMAGE ALPINE INSTALLED FIXED EXIT RESULT
for id in $(docker ps -q); do
	name=$(docker inspect -f '{{.Name}}' "$id" | sed 's#^/##')
	image=$(docker inspect -f '{{.Config.Image}}' "$id")
	rel=$(docker exec "$id" cat /etc/alpine-release 2>/dev/null)
	if [ -z "$rel" ]; then
		printf '%-14s %-14s %-21s %-12s %-12s %-5s %s\n' "$name" "$image" - - - - "not Alpine, skipped"
		continue
	fi
	has_sshd=$(docker exec "$id" sh -c 'for d in /proc/[0-9]*; do c=$(cat $d/comm 2>/dev/null); case "$c" in sshd|sshd.pam|sshd.krb5) echo yes; exit;; esac; done')
	if [ "$has_sshd" != yes ]; then
		printf '%-14s %-14s %-21s %-12s %-12s %-5s %s\n' "$name" "$image" "$rel" - - - "no sshd running, not affected"
		continue
	fi
	out=$(docker exec -i -u 0 "$id" sh -s -- --json < check.sh 2>/dev/null)
	rc=$?
	field() { echo "$out" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }
	case $rc in
		0) res="not affected" ;; 1) res="AFFECTED" ;; 2) res="restart sshd" ;; *) res="cannot tell" ;;
	esac
	printf '%-14s %-14s %-21s %-12s %-12s %-5s %s\n' "$name" "$image" "$rel" "$(field installed_version)" "$(field fixed_version)" "$rc" "$res"
	[ "$rc" -gt "$worst" ] && worst=$rc
done
exit "$worst"
