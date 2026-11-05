# alpine-sshd-check

```bash
sudo sh check.sh            # on an Alpine host
sh check.sh --json          # machine-readable
docker exec -i <container> sh -s < check.sh    # inside a container, nothing is copied in
sh scan-containers.sh       # every running container on this Docker host
```

A read-only check for CVE-2026-123158, the Alpine Linux `openssh-server` password authentication bypass fixed on 2026-11-05 ([Alpine advisory](https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/), [OpenSSH 10.6p2 release notes](https://www.openssh.com/releasenotes.html#10.6p2), [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-123158)).

Write-up: https://devops-daily.com/posts/alpine-openssh-password-bypass

## What it reads

- `/etc/alpine-release` and `/etc/apk/repositories`, to find the branch, and `/etc/apk/world` for a repository pin, and the installed `openssh-server` (or `openssh-server-pam`) version from `apk list -I`.
- `sshd -T`, for `PasswordAuthentication`, `PermitRootLogin` and `UsePAM`.
- The TYPE of the password field in `/etc/shadow`: it counts fields that are exactly `*` and fields that start with `$5$` or `$6$` (a locked `!$6$...` field is counted too, to stay on the safe side). It never prints, stores or sends a hash or a user name.
- `/proc`, for the running sshd: its start time, and whether it is still the same file (device and inode) as the sshd binary on disk. An upgrade writes a new file, so a daemon that was not restarted shows up as a different file.

It changes nothing, does not connect to sshd and does not try to log in. It needs root to read `/etc/shadow` and to run `sshd -T`.

Because it runs as root, it sets a fixed `PATH` and executes only `/usr/sbin/sshd`, `/usr/sbin/sshd.pam` or `/usr/sbin/sshd.krb5`, and only if the file is owned by root and not group- or world-writable. It counts only sshd processes that run as uid 0. If the running sshd is any other binary, it reports "cannot tell" (exit 3) and does not execute it. An earlier draft ran the path it read from `/proc/<pid>/exe`; in a test container, a root process started as `/tmp/sshd` got that file executed. That is fixed.

## Mixed sources

A stable host can install openssh from edge. The check fails closed:

- An untagged, uncommented `/edge/` repository line: compared against the edge fixed version.
- openssh pinned to a tag (`openssh-server@edge` in `/etc/apk/world`): compared against the edge fix if that tag points to an edge repository, otherwise "cannot tell".
- An installed version newer than the branch fix but from another release series (and older than the edge fix): "cannot tell", never "not affected".
- A tagged `@edge` line with nothing pinned to it does not change the branch.

## The four conditions

A host is affected only if all four hold on a version older than the fixed one:

1. sshd is built without PAM (`openssh-server`), or it is `openssh-server-pam` with `UsePAM no`.
2. `PasswordAuthentication yes` (the default).
3. An account that can use a password login has `*` in the password field. Root counts only with `PermitRootLogin yes`. If `musl-nscd` is installed, directory users have no shadow entry and count too, so the script reports "unknown". `AllowUsers`, `DenyUsers` and `Match` blocks are not evaluated, so this errs on the side of "yes".
4. At least one local `$5$` or `$6$` hash exists.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Not affected (fixed version, or a condition is false) |
| 1 | Affected: vulnerable version and all four conditions hold |
| 2 | Fixed package installed, but the running sshd is not the file on disk: `rc-service sshd restart` |
| 3 | Cannot tell (not root, not Alpine, `sshd -T` failed, or a `Match` block may enable passwords) |

`scan-containers.sh` exits 1 if any container is affected, else 2 if any needs a restart, else 3 if any could not be checked, else 0. It runs each container's own `sh` with `docker exec`, as root inside that container, so only scan containers whose images you trust.

## Fixed versions (from the advisory)

| Branch | Fixed `openssh` |
| --- | --- |
| edge | 10.6_p2-r0 |
| 3.24 | 10.3_p1-r2 |
| 3.23 | 10.2_p1-r1 |
| 3.22 | 10.0_p1-r11 |
| 3.21 | 9.9_p2-r1 |
| 3.20 | 9.7_p1-r6 |
| 3.19 | 9.6_p1-r3 |
| 3.18 | 9.3_p2-r4 |
| 3.17 | 9.1_p1-r7 |
| 3.16 | 9.0_p1-r6 |

## Results

`measure.sh` records the check on throwaway containers: `alpine:3.21`, `3.22`, `3.23`, `3.24` and `edge` after `apk add openssh-server`, plus two 3.24 variants (`PasswordAuthentication no`, and a key-only user plus a user with a random password). The install step has network access; sshd then runs with `--network none`, so no port is published and nothing can connect to it. Output is in `results/`, recorded 2026-11-05 on Docker 29.9.3 (aarch64, see `results/environment.txt`). `measure.sh` is the measurement harness, not the check: it creates, changes and removes its own containers and images.

| Container | Installed | Exit | Notes |
| --- | --- | --- | --- |
| 3.21.10 | 9.9_p2-r1 | 0 | fixed |
| 3.22.8 | 10.0_p1-r11 | 0 | fixed |
| 3.23.8 | 10.2_p1-r1 | 0 | fixed |
| 3.24.4 | 10.3_p1-r2 | 0 | fixed |
| edge (3.25.0_alpha20260805) | 10.6_p2-r0 | 0 | fixed |
| 3.24.4, PasswordAuthentication no | 10.3_p1-r2 | 0 | condition 2 false |
| 3.24.4, key-only user + password user | 10.3_p1-r2 | 0 | all four conditions true, fixed version |

Two things the run found:

- `adduser -D` on 3.24 wrote `!` (locked), not `*`. A locked account is not affected, but it also cannot log in with a key. The key-only user was then set to `*`, the state the advisory describes for key-only users.
- OpenSSH 10.6 prints `sshd -T` keywords in mixed case (`PasswordAuthentication yes`), older versions in lower case. The first version of this script matched only lower case and reported "unknown" on edge. Match it case-insensitively (`grep -i`).

## Exit code tests

`test-exit-codes.sh` records `results/exit-code-tests.txt`. No vulnerable package exists any more, so exit 1 and 2 are simulations, labelled as such:

- Exit 1: all four conditions true, with a temporary copy of the script whose 3.24 fixed version is raised to 10.3_p1-r3.
- Exit 2: the same sshd binary copied and renamed over `/usr/sbin/sshd` while sshd runs, which is what an upgrade does to the file.
- Exit 3: a root process running `/tmp/sshd` (not executed by the check), a world-writable `/usr/sbin/sshd`, and a non-root run.
- Mixed sources: a tagged `@edge` line with nothing pinned (exit 0), an untagged edge line on 3.24 (exit 1, fails closed), a real `apk add openssh-server@edge` on 3.24 (10.6_p2-r0, exit 0), and the same container with the pin removed and the edge fix raised in a temporary copy (exit 3).

## Not tested

- No vulnerable package and no real upgrade: Alpine replaced the packages on every branch the same day, so every fresh install got the fixed version.
- `openssh-server-pam`, `musl-nscd` users, tiny-cloud images and branches 3.16 to 3.20 were not measured.

## License

MIT
