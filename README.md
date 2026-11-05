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

- `/etc/alpine-release` and `/etc/apk/repositories`, to find the branch, and the installed `openssh-server` (or `openssh-server-pam`) version from `apk list -I`.
- `sshd -T`, for `PasswordAuthentication`, `PermitRootLogin` and `UsePAM`.
- The TYPE of the password field in `/etc/shadow`: it counts fields that are exactly `*` and fields that start with `$5$` or `$6$` (a locked `!$6$...` field is counted too, to stay on the safe side). It never prints, stores or sends a hash or a user name.
- `/proc`, for the start time of the running sshd, compared with the ctime of the sshd binary (the time the package installed it).

It changes nothing, does not connect to sshd and does not try to log in. It needs root to read `/etc/shadow` and to run `sshd -T`.

## The four conditions

A host is affected only if all four hold on a version older than the fixed one:

1. sshd is built without PAM (`openssh-server`), or it is `openssh-server-pam` with `UsePAM no`.
2. `PasswordAuthentication yes` (the default).
3. An account that can use a password login has `*` in the password field. Root counts only with `PermitRootLogin yes`. Directory users through `musl-nscd` count, because they have no shadow entry.
4. At least one local `$5$` or `$6$` hash exists.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Not affected (fixed version, or a condition is false) |
| 1 | Affected: vulnerable version and all four conditions hold |
| 2 | Fixed package installed, but the running sshd started before it: `rc-service sshd restart` |
| 3 | Cannot tell (not root, not Alpine, `sshd -T` failed, or a `Match` block may enable passwords) |

`scan-containers.sh` exits with the highest code it saw.

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

`measure.sh` records the check on throwaway containers: `alpine:3.21`, `3.22`, `3.23`, `3.24` and `edge` after `apk add openssh-server`, plus two 3.24 variants (`PasswordAuthentication no`, and a key-only user plus a user with a random password). The install step has network access; sshd then runs with `--network none`, so no port is published and nothing can connect to it. Output is in `results/`, recorded 2026-11-05 on Docker 29.9.3 (aarch64).

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

## Not tested

- No vulnerable package: Alpine replaced the packages on every branch the same day, so every fresh install got the fixed version. Exit code 1 was tested only with a temporary copy of the script whose fixed-version table was raised by one release.
- No real "upgraded but not restarted" case, for the same reason. Exit code 2 was tested only by changing the ctime of the sshd binary with `chmod` in a running container, not with a real upgrade.
- `openssh-server-pam`, `musl-nscd` users and tiny-cloud images were not measured.

## License

MIT
