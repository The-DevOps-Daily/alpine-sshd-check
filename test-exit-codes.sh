#!/bin/sh
# Logic tests for check.sh exit codes 1, 2 and 3, in throwaway containers
# with --network none. No vulnerable package exists any more, so these are
# simulations and are labelled as such. Nothing here attempts SSH
# authentication. Needs the asc-demo:3.24 image (KEEP=1 sh measure.sh).
# T8 installs openssh-server from a tagged edge repository, so its build
# step needs network access (NET_INSTALL=host if bridge networking fails).
# Writes results/exit-code-tests.txt and removes its containers.
set -u
cd "$(dirname "$0")"
out=results/exit-code-tests.txt
img=asc-demo:3.24
tmp=$(mktemp -d)
NET_INSTALL=${NET_INSTALL:-bridge}
trap 'rm -rf "$tmp"; docker rm -f asc-t1 asc-t2 asc-t3 asc-t4 asc-t5 asc-t7 asc-t8 asc-t8-build >/dev/null 2>&1; docker rmi asc-demo:3.24-edge-openssh >/dev/null 2>&1' EXIT

run() { # label container [script]
	s=${3:-check.sh}
	r=$(docker exec -i "$2" sh -s < "$s" | tail -1)
	rc=$(docker exec -i "$2" sh -s < "$s" >/dev/null; echo $?)
	printf '%s\n  exit=%s  %s\n' "$1" "$rc" "$r"
}

{
echo "# recorded $(date -u +%Y-%m-%dT%H:%M:%SZ), check.sh sha256 $(sha256sum check.sh | cut -c1-12)"

docker run -d --name asc-t1 --network none "$img" sh -c \
	'adduser -D deploy && adduser -D ops && echo "ops:$(head -c 18 /dev/urandom | base64)" | chpasswd >/dev/null 2>&1 && sed -i "s/^deploy:!:/deploy:*:/" /etc/shadow && exec /usr/sbin/sshd -D -e' >/dev/null
sed 's/3.24) echo 10.3_p1-r2/3.24) echo 10.3_p1-r3/' check.sh > "$tmp/check-raised.sh"
sleep 1
run "T1 simulated exit 1: all four conditions true, fixed-version table raised to 10.3_p1-r3 in a temporary copy" asc-t1 "$tmp/check-raised.sh"
run "T1 control: same container, real check.sh" asc-t1

docker run -d --name asc-t2 --network none "$img" /usr/sbin/sshd -D -e >/dev/null
sleep 1
run "T2 before: sshd running, file untouched" asc-t2
docker exec asc-t2 sh -c 'cp -p /usr/sbin/sshd /usr/sbin/sshd.new && mv /usr/sbin/sshd.new /usr/sbin/sshd'
run "T2 simulated exit 2: same binary copied and renamed over /usr/sbin/sshd while sshd runs (what an upgrade does to the file)" asc-t2

docker run -d --name asc-t3 --network none "$img" sh -c 'cp /usr/sbin/sshd /tmp/sshd && exec /tmp/sshd -D -e -p 2222' >/dev/null
sleep 1
docker exec asc-t3 sh -c 'rm /tmp/sshd && printf "#!/bin/sh\ntouch /tmp/EXECUTED\n" > /tmp/sshd && chmod +x /tmp/sshd'
run "T3 exit 3: the running root sshd is /tmp/sshd, then replaced by a script that touches /tmp/EXECUTED" asc-t3
echo "  /tmp/EXECUTED exists: $(docker exec asc-t3 sh -c '[ -e /tmp/EXECUTED ] && echo yes || echo no')"

docker run -d --name asc-t4 --network none "$img" sh -c 'chmod o+w /usr/sbin/sshd && exec /usr/sbin/sshd -D -e' >/dev/null
sleep 1
run "T4 exit 3: /usr/sbin/sshd is world-writable" asc-t4

docker run -d --name asc-t5 --network none "$img" sh -c \
	'echo "@edge https://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories && exec /usr/sbin/sshd -D -e' >/dev/null
sleep 1
run "T5 a 3.24 host with an @edge repository line still uses the 3.24 fixed version" asc-t5
printf 'T6 not root\n  %s\n' "$(docker exec -i -u nobody asc-t5 sh -s < check.sh | tail -1)"

docker run -d --name asc-t7 --network none "$img" sh -c \
	'adduser -D deploy && adduser -D ops && echo "ops:$(head -c 18 /dev/urandom | base64)" | chpasswd >/dev/null 2>&1 && sed -i "s/^deploy:!:/deploy:*:/" /etc/shadow && echo "https://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories && exec /usr/sbin/sshd -D -e' >/dev/null
sleep 1
run "T7 a 3.24 host (all four conditions true, 3.24 fixed package) with an untagged edge repository line: compared against the edge fix, fails closed" asc-t7

docker run --name asc-t8-build --network "$NET_INSTALL" "$img" sh -c \
	'echo "@edge https://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories && apk add -q --no-cache openssh-server@edge && apk list -I openssh-server && grep openssh /etc/apk/world' > "$tmp/t8-build.txt" 2>&1
echo "T8 build: openssh-server@edge on 3.24 (exit $?):"; sed 's/^/  /' "$tmp/t8-build.txt"
docker commit asc-t8-build asc-demo:3.24-edge-openssh >/dev/null
docker run -d --name asc-t8 --network none asc-demo:3.24-edge-openssh /usr/sbin/sshd -D -e >/dev/null
sleep 1
run "T8 a 3.24 host with openssh-server pinned to @edge: compared against the edge fix" asc-t8
sed 's/edge) echo 10.6_p2-r0/edge) echo 10.6_p2-r1/' check.sh > "$tmp/check-edge-raised.sh"
docker exec asc-t8 sed -i 's/^openssh-server@edge/openssh-server/' /etc/apk/world
run "T9 simulated: T8 container with the @edge pin removed from /etc/apk/world and the edge fix raised to 10.6_p2-r1 in a temporary copy (an edge build newer than the 3.24 fix, source not visible)" asc-t8 "$tmp/check-edge-raised.sh"
} > "$out" 2>&1
cat "$out"
