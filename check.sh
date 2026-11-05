#!/bin/sh
# Read-only check for CVE-2026-123158 (Alpine openssh-server password
# authentication bypass). It reads package versions, `sshd -T`, the TYPE of
# each /etc/shadow password field and sshd process start times. It never
# prints or stores password hashes, never connects to sshd and changes nothing.
#
# Exit codes: 0 not affected, 1 affected, 2 fixed but restart needed,
#             3 cannot tell
#
# Usage: sh check.sh [--json]
#        docker exec -i <container> sh -s -- --json < check.sh

JSON=0
case "${1:-}" in
	--json) JSON=1 ;;
	-h|--help) sed -n '2,12p' "$0" 2>/dev/null; exit 0 ;;
	"") ;;
	*) echo "unknown option: $1" >&2; exit 3 ;;
esac

notes=""
add_note() { notes="${notes:+$notes|}$1"; }

utc() { [ -n "$1" ] && date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null; }

fixed_for_branch() {
	case "$1" in
		edge) echo 10.6_p2-r0 ;;
		3.24) echo 10.3_p1-r2 ;;
		3.23) echo 10.2_p1-r1 ;;
		3.22) echo 10.0_p1-r11 ;;
		3.21) echo 9.9_p2-r1 ;;
		3.20) echo 9.7_p1-r6 ;;
		3.19) echo 9.6_p1-r3 ;;
		3.18) echo 9.3_p2-r4 ;;
		3.17) echo 9.1_p1-r7 ;;
		3.16) echo 9.0_p1-r6 ;;
		*) echo "" ;;
	esac
}

# Version of an installed package, or empty.
pkgver() {
	apk list -I "$1" 2>/dev/null | awk -v p="$1" '{
		n = $1; sub(/-[^-]+-r[0-9]+$/, "", n)
		if (n == p) { v = substr($1, length(p) + 2); print v; exit }
	}'
}

json_str() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }

release=""; branch=""; pkg=""; installed=""; fixed=""; version_fixed="unknown"
bin=""; c1="unknown"; c2="unknown"; c3="unknown"; c4="unknown"
star_total=0; star_login=0; root_star=0; sha_count=0; prl=""; usepam=""
running="no"; started=""; bin_ctime=""; exe_deleted="no"; restart="no"
verdict=""; code=3

finish() {
	if [ "$JSON" = 1 ]; then
		printf '{"cve":"CVE-2026-123158","alpine_release":%s,"branch":%s,' "$(json_str "$release")" "$(json_str "$branch")"
		printf '"package":%s,"installed_version":%s,"fixed_version":%s,"version_fixed":%s,' \
			"$(json_str "$pkg")" "$(json_str "$installed")" "$(json_str "$fixed")" "$(json_str "$version_fixed")"
		printf '"sshd_binary":%s,"conditions":{"non_pam_sshd":%s,"password_authentication":%s,' \
			"$(json_str "$bin")" "$(json_str "$c1")" "$(json_str "$c2")"
		printf '"no_password_account":%s,"local_sha_crypt_hash":%s},' "$(json_str "$c3")" "$(json_str "$c4")"
		printf '"star_accounts":%d,"star_accounts_password_login":%d,"root_is_star":%s,"sha_crypt_hashes":%d,' \
			"$star_total" "$star_login" "$( [ "$root_star" = 1 ] && echo true || echo false)" "$sha_count"
		printf '"permitrootlogin":%s,"sshd_running":%s,"sshd_started_utc":%s,"sshd_binary_installed_utc":%s,' \
			"$(json_str "$prl")" "$(json_str "$running")" "$(json_str "$(utc "$started")")" "$(json_str "$(utc "$bin_ctime")")"
		printf '"running_binary_deleted":%s,"restart_needed":%s,"verdict":%s,"exit_code":%d,"notes":[' \
			"$(json_str "$exe_deleted")" "$(json_str "$restart")" "$(json_str "$verdict")" "$code"
		first=1
		old_ifs=$IFS; IFS='|'
		for n in $notes; do
			[ "$first" = 1 ] || printf ','
			json_str "$n"; first=0
		done
		IFS=$old_ifs
		printf ']}\n'
	else
		echo "alpine-sshd-check: CVE-2026-123158"
		echo "Alpine release:     ${release:-none} (branch ${branch:-unknown})"
		echo "sshd binary:        ${bin:-none} (package ${pkg:-none})"
		echo "Installed openssh:  ${installed:-none}"
		echo "Fixed in:           ${fixed:-unknown} (installed is fixed: $version_fixed)"
		echo "[1] non-PAM sshd:                  $c1"
		echo "[2] PasswordAuthentication yes:    $c2"
		echo "[3] account with '*' that can use a password login: $c3 ($star_total '*' accounts, $star_login usable; root is '*': $([ "$root_star" = 1 ] && echo yes || echo no), PermitRootLogin ${prl:-unknown})"
		echo "[4] local \$5\$/\$6\$ hash:            $c4 ($sha_count found)"
		if [ "$running" = yes ]; then
			echo "sshd running:       yes, started $(utc "$started"), binary installed $(utc "$bin_ctime"), restart needed: $restart"
		else
			echo "sshd running:       no"
		fi
		old_ifs=$IFS; IFS='|'
		for n in $notes; do echo "note: $n"; done
		IFS=$old_ifs
		echo "Result:             $verdict (exit $code)"
	fi
	exit "$code"
}

if [ ! -r /etc/alpine-release ]; then
	verdict="CANNOT TELL: not Alpine Linux (no /etc/alpine-release)"; code=3; finish
fi
release=$(cat /etc/alpine-release)
case "$release" in
	*_alpha*|*_beta*|*_rc*) branch=edge ;;
	*) branch=$(echo "$release" | cut -d. -f1,2) ;;
esac
grep -q '/edge/' /etc/apk/repositories 2>/dev/null && branch=edge
fixed=$(fixed_for_branch "$branch")

if [ "$(id -u)" != 0 ]; then
	verdict="CANNOT TELL: run as root (needs /etc/shadow field types and sshd -T)"; code=3; finish
fi

# Find a running sshd listener (oldest sshd process).
clk=$(getconf CLK_TCK 2>/dev/null || echo 100)
btime=$(awk '/^btime/ {print $2}' /proc/stat)
oldest=""; run_pid=""
for d in /proc/[0-9]*; do
	comm=$(cat "$d/comm" 2>/dev/null) || continue
	case "$comm" in sshd|sshd.pam|sshd.krb5) ;; *) continue ;; esac
	st=$(sed 's/.*) //' "$d/stat" 2>/dev/null | awk '{print $20}')
	[ -n "$st" ] || continue
	if [ -z "$oldest" ] || [ "$st" -lt "$oldest" ]; then oldest=$st; run_pid=${d#/proc/}; fi
done
if [ -n "$run_pid" ]; then
	running=yes
	started=$((btime + oldest / clk))
	exe=$(readlink "/proc/$run_pid/exe" 2>/dev/null)
	case "$exe" in *" (deleted)") exe_deleted=yes; exe=${exe% (deleted)} ;; esac
	[ -n "$exe" ] && bin=$exe
fi

# Which sshd binary is (or would be) used.
if [ -z "$bin" ]; then
	if [ -x /usr/sbin/sshd.pam ] && grep -qiE '^[[:space:]]*UsePAM[[:space:]]+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
		bin=/usr/sbin/sshd.pam
	elif [ -x /usr/sbin/sshd ]; then
		bin=/usr/sbin/sshd
	fi
fi
case "$bin" in
	*/sshd.pam) pkg=openssh-server-pam ;;
	*/sshd.krb5) pkg=openssh-server-krb5 ;;
	*/sshd) pkg=openssh-server ;;
esac

if [ -z "$bin" ] || [ ! -e "$bin" ]; then
	verdict="NOT AFFECTED: no sshd installed"; code=0
	[ "$running" = yes ] && { verdict="CANNOT TELL: sshd running but its binary is missing"; code=3; }
	finish
fi

installed=$(pkgver "$pkg")
[ -z "$installed" ] && installed=$(pkgver openssh-server-common)
if [ -n "$installed" ] && [ -n "$fixed" ]; then
	case "$(apk version -t "$installed" "$fixed" 2>/dev/null)" in
		"<") version_fixed=no ;;
		"="|">") version_fixed=yes ;;
	esac
fi
[ -z "$fixed" ] && add_note "no fixed version known for branch '$branch' (advisory covers 3.16 to 3.24 and edge)"

# Restart check: running daemon older than the binary on disk.
bin_ctime=$(stat -c %Z "$bin" 2>/dev/null)
if [ "$running" = yes ]; then
	if [ "$exe_deleted" = yes ] || { [ -n "$bin_ctime" ] && [ "$started" -lt "$bin_ctime" ]; }; then
		restart=yes
	fi
fi

# sshd -T for the effective global config.
cfg=$("$bin" -T 2>/dev/null)
if [ -z "$cfg" ]; then
	add_note "sshd -T failed (no host keys or a config error); conditions 2 and 3 not known"
else
	pa=$(echo "$cfg" | awk 'tolower($1)=="passwordauthentication" {print tolower($2)}')
	prl=$(echo "$cfg" | awk 'tolower($1)=="permitrootlogin" {print tolower($2)}')
	usepam=$(echo "$cfg" | awk 'tolower($1)=="usepam" {print tolower($2)}')
	case "$pa" in
		yes) c2=yes ;;
		no)
			c2=no
			if grep -qiE '^[[:space:]]*PasswordAuthentication[[:space:]]+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
				c2=unknown; add_note "PasswordAuthentication is no globally, but a config line sets yes (Match block?)"
			fi ;;
	esac
fi

# Condition 1: built without PAM, or the PAM build with UsePAM no.
case "$pkg" in
	openssh-server) c1=yes ;;
	openssh-server-pam)
		case "$usepam" in yes) c1=no ;; no) c1=yes ;; esac ;;
esac

# Conditions 3 and 4: field TYPES only, never the values.
if [ ! -r /etc/shadow ]; then
	add_note "cannot read /etc/shadow"
else
	set -- $(awk -F: '
		$2 == "*" { star++; if ($1 == "root") root = 1; else nonroot++ }
		$2 ~ /^!*\$[56]\$/ { sha++ }
		END { printf "%d %d %d %d\n", star, nonroot, root, sha }' /etc/shadow)
	star_total=$1; star_login=$2; root_star=$3; sha_count=$4
	if [ "$root_star" = 1 ] && [ "$prl" = yes ]; then star_login=$((star_login + 1)); fi
	[ "$root_star" = 1 ] && [ "$prl" != yes ] && add_note "root is '*' but PermitRootLogin is '${prl:-unknown}'; root counts only with PermitRootLogin yes (an account that can doas to root still matters)"
	if [ "$star_login" -gt 0 ]; then c3=yes
	elif [ "$root_star" = 1 ] && [ -z "$prl" ]; then c3=unknown
	else c3=no; fi
	if apk info -e musl-nscd >/dev/null 2>&1; then
		c3=yes; add_note "musl-nscd installed: directory users have no shadow entry and count as accounts with no password"
	fi
	if [ "$sha_count" -gt 0 ]; then c4=yes; else c4=no; fi
fi

# Verdict.
all=yes; anyno=no
for c in "$c1" "$c2" "$c3" "$c4"; do
	case "$c" in no) anyno=yes; all=no ;; unknown) all=no ;; esac
done

if [ "$version_fixed" = yes ]; then
	if [ "$restart" = yes ]; then
		verdict="FIXED PACKAGE, BUT RESTART NEEDED: the running sshd started before the fixed package was installed (rc-service sshd restart)"; code=2
	else
		verdict="NOT AFFECTED: fixed openssh installed"; code=0
	fi
elif [ "$anyno" = yes ]; then
	verdict="NOT AFFECTED today: at least one condition is false. Upgrade anyway (apk upgrade -U -a)"; code=0
elif [ "$all" = yes ] && [ "$version_fixed" = no ]; then
	verdict="AFFECTED: all four conditions hold on a vulnerable version. Run apk upgrade -U -a, then rc-service sshd restart"; code=1
else
	verdict="CANNOT TELL: see the unknown items above"; code=3
fi
[ "$running" = no ] && [ "$code" = 1 ] && add_note "sshd is not running now; it is exposed once it starts"
finish
