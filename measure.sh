#!/bin/sh
# Record check.sh output on throwaway Alpine containers. This is the
# measurement harness, not the check: it creates, changes and removes its own
# containers and images (never anything else).
# Install phase: `apk add openssh-server` with network access (no sshd runs).
# Check phase: sshd runs with --network none (loopback only, no published
# port, nothing can connect to it). Nothing here attempts SSH authentication.
#
# Usage: sh measure.sh            (writes results/, removes its containers)
#        NET_INSTALL=host sh measure.sh   (if bridge networking fails)
set -u
cd "$(dirname "$0")"
NET_INSTALL=${NET_INSTALL:-bridge}
TAGS=${TAGS:-"3.21 3.22 3.23 3.24 edge"}
mkdir -p results
stamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
sum=$(sha256sum check.sh | cut -c1-12)
{ echo "recorded $stamp"; uname -m; docker version --format 'docker client {{.Client.Version}}, server {{.Server.Version}}'; } > results/environment.txt 2>&1

record() { # name container
	{
		echo "# $1, recorded $stamp, check.sh sha256 $sum"
		docker exec -i "$2" sh -s < check.sh; echo "exit=$?"
	} > "results/$1.txt" 2>&1
	docker exec -i "$2" sh -s -- --json < check.sh > "results/$1.json" 2>&1
	tail -1 "results/$1.txt"
}

for t in $TAGS; do
	docker rm -f "asc-build-$t" >/dev/null 2>&1
	docker run --name "asc-build-$t" --network "$NET_INSTALL" "alpine:$t" sh -c \
		'apk add -q --no-cache openssh-server && ssh-keygen -A >/dev/null && cat /etc/alpine-release && apk list -I openssh-server' \
		> "results/install-$t.txt" 2>&1
	docker commit "asc-build-$t" "asc-demo:$t" >/dev/null
	docker rm "asc-build-$t" >/dev/null
	docker run -d --name "asc-$t" --network none "asc-demo:$t" /usr/sbin/sshd -D -e >/dev/null || { echo "run failed for $t" >&2; exit 1; }
	sleep 1
	printf '%-28s ' "$t"; record "alpine-$t" "asc-$t"
done

# Variant: the workaround drop-in (PasswordAuthentication no).
docker run -d --name asc-pa-no --network none asc-demo:3.24 sh -c \
	"echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/00-no-passwords.conf && exec /usr/sbin/sshd -D -e" >/dev/null
sleep 1
printf '%-28s ' "3.24 PasswordAuthentication no"; record "alpine-3.24-password-auth-no" asc-pa-no

# Variant: a key-only user plus one user with a password (a random one,
# never printed). `adduser -D` writes "!" (locked, which also blocks key
# login), so the key-only user is then set to "*", the state the advisory
# describes for key-only users. All four conditions then hold; the installed
# package is the fixed one, so the version decides.
docker run -d --name asc-users --network none asc-demo:3.24 sh -c \
	'adduser -D deploy && adduser -D ops && echo "ops:$(head -c 18 /dev/urandom | base64)" | chpasswd >/dev/null 2>&1 && exec /usr/sbin/sshd -D -e' >/dev/null
sleep 1
docker exec asc-users awk -F: '$1 == "deploy" || $1 == "ops" {
	t = $2
	if (t != "*" && t != "!" && t != "") t = (t ~ /^\$[56]\$/) ? substr(t, 1, 3) " hash (not shown)" : "other (not shown)"
	print $1 ": " t }' /etc/shadow \
	> results/adduser-field-types.txt 2>&1
docker exec asc-users sed -i 's/^deploy:!:/deploy:*:/' /etc/shadow
docker exec asc-users awk -F: '$1 == "deploy" {print "after setting the key-only user: " $1 ": " $2}' /etc/shadow \
	>> results/adduser-field-types.txt 2>&1
printf '%-28s ' "3.24 key-only + password user"; record "alpine-3.24-users" asc-users

sh scan-containers.sh > results/scan-containers.txt 2>&1
echo "scan-containers exit=$?" >> results/scan-containers.txt

if [ "${KEEP:-0}" != 1 ]; then
	docker rm -f $(for t in $TAGS; do echo "asc-$t"; done) asc-pa-no asc-users >/dev/null
	docker rmi $(for t in $TAGS; do echo "asc-demo:$t"; done) >/dev/null
fi
