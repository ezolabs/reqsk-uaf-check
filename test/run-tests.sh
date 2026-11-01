#!/usr/bin/env bash
# =============================================================================
# run-tests.sh -- exercise kernel-check.sh against real kernel bytes and
# controlled reachability fixtures.
#
# Nothing here touches a remote host, /proc, /sys or /boot: every input is a
# local file under .tmp/.  The reachability half is driven by fixture copies of
# `ss` and `bpftool` placed first on PATH.
#
# The important pair is:
#   vulnerable-image   real Ubuntu 7.0.0-28 vmlinuz -> VULNERABLE
#   patched            real 7.1.4 compiled bytes   -> PATCHED
# Both also contain the second `drop:`-label call that passes 1, which is the
# trap the script has to avoid.
# =============================================================================
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
DELIVERY=$(cd "$HERE/.." && pwd)
SCRIPT="$DELIVERY/kernel-check.sh"
FIX="$HERE/fixtures"
EVID="$HERE/evidence"

# The stub tools must be executable however this tree was copied here; a copy
# that drops the mode bit would otherwise fall through to the real ss/bpftool
# and silently test the host instead of the fixture.
chmod +x "$FIX"/bin/* 2>/dev/null || true

# Real kernel inputs.  These are local copies already present in this project.
BASE=$(cd "$DELIVERY/.." && pwd)
VMLINUX="$BASE/evidence/rce/ordering/ks/vmlinux.elf"
VMLINUZ="$BASE/evidence/rce/target/work/kernel/vmlinuz-7.0.0-28-generic"

mkdir -p "$EVID"
BIN="$EVID/bin"
rm -rf "$BIN"
mkdir -p "$BIN/exposed" "$BIN/disabled" "$BIN/bpf" "$BIN/nogroup" \
         "$BIN/ss-partial" "$BIN/ss-no-header" "$BIN/bpftool-fail"
ln -s "$FIX/bin/ss"            "$BIN/exposed/ss"
ln -s "$FIX/bin/bpftool-none"  "$BIN/exposed/bpftool"
ln -s "$FIX/bin/ss"            "$BIN/disabled/ss"
ln -s "$FIX/bin/bpftool-none"  "$BIN/disabled/bpftool"
ln -s "$FIX/bin/ss"            "$BIN/bpf/ss"
ln -s "$FIX/bin/bpftool"       "$BIN/bpf/bpftool"
ln -s "$FIX/bin/ss-no-group"   "$BIN/nogroup/ss"
ln -s "$FIX/bin/bpftool-none"  "$BIN/nogroup/bpftool"
# Stubs for the failure modes the old script mishandled.  These are written
# here rather than kept as fixture files so no copy of this tree can carry a
# stale or non-executable version of them.
ln -s "$FIX/bin/bpftool-none"  "$BIN/ss-partial/bpftool"
ln -s "$FIX/bin/bpftool-none"  "$BIN/ss-no-header/bpftool"
ln -s "$FIX/bin/ss"            "$BIN/bpftool-fail/ss"
cat > "$BIN/ss-partial/ss" <<'STUB'
#!/bin/sh
# ss that fails part-way: a plausible listing, then a non-zero exit.
cat <<'EOF'
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      4096   0.0.0.0:8080       0.0.0.0:*    users:(("nginx",pid=101,fd=6)) ino:111 sk:1
LISTEN 0      4096   0.0.0.0:8080       0.0.0.0:*    users:(("nginx",pid=102,fd=6)) ino:112 sk:2
EOF
echo "ss: netlink dump truncated" >&2
exit 1
STUB
cat > "$BIN/ss-no-header/ss" <<'STUB'
#!/bin/sh
# ss that exits 0 without the socket-table header: not a complete listing.
echo 'LISTEN 0      4096   0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=10,fd=3)) ino:11 sk:1'
exit 0
STUB
cat > "$BIN/bpftool-fail/bpftool" <<'STUB'
#!/bin/sh
# bpftool that fails (no CAP_BPF): empty output, non-zero exit.
echo "Error: can't get prog info: Operation not permitted" >&2
exit 1
STUB
chmod +x "$BIN/ss-partial/ss" "$BIN/ss-no-header/ss" "$BIN/bpftool-fail/bpftool"

# Composite fixtures built at run time: the privileged container's /proc is
# the kcore fixture plus a cgroup marker and the container's tcp_migrate_req.
FX="$EVID/fx"
rm -rf "$FX"
mkdir -p "$FX/proc-container-priv/1" "$FX/proc-container-priv/sys/net/ipv4"
cp "$FIX/proc-kcore-vuln/kcore"    "$FX/proc-container-priv/kcore"
cp "$FIX/proc-kcore-vuln/kallsyms" "$FX/proc-container-priv/kallsyms"
printf '0::/docker/abc123\n' > "$FX/proc-container-priv/1/cgroup"
printf '0\n'                 > "$FX/proc-container-priv/sys/net/ipv4/tcp_migrate_req"
# The same container, with its own group and migration enabled: the alarm
# must survive the scope change.
mkdir -p "$FX/proc-container-priv-mig/1" "$FX/proc-container-priv-mig/sys/net/ipv4"
cp "$FIX/proc-kcore-vuln/kcore"    "$FX/proc-container-priv-mig/kcore"
cp "$FIX/proc-kcore-vuln/kallsyms" "$FX/proc-container-priv-mig/kallsyms"
printf '0::/docker/abc123\n' > "$FX/proc-container-priv-mig/1/cgroup"
printf '1\n'                 > "$FX/proc-container-priv-mig/sys/net/ipv4/tcp_migrate_req"

# A /boot whose kernel image is present but unreadable (0600 root:root in
# production; mode 000 here so it is unreadable for any non-root uid).
mkdir -p "$FX/boot-unreadable"
: > "$FX/boot-unreadable/vmlinuz-$(uname -r)"
chmod 000 "$FX/boot-unreadable/vmlinuz-$(uname -r)"

PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); printf 'PASS  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL  %s  (%s)\n' "$1" "$2"; }
skip() { SKIP=$((SKIP + 1)); printf 'SKIP  %s  (%s)\n' "$1" "$2"; }

# check_text NAME REGEX
check_text() {
	if grep -Eq "$2" "$EVID/$1.txt"; then
		pass "$1 text /$2/"
	else
		fail "$1" "output does not match /$2/; see $EVID/$1.txt"
	fi
}

# check_absent NAME REGEX -- the pattern must NOT match
check_absent() {
	if grep -Eq "$2" "$EVID/$1.txt"; then
		fail "$1" "output matches /$2/ but must not; see $EVID/$1.txt"
	else
		pass "$1 text absent /$2/"
	fi
}

if [ ! -x "$SCRIPT" ]; then
	printf 'FAIL  kernel-check.sh is missing or not executable: %s\n' "$SCRIPT"
	exit 1
fi

printf 'kernel-check.sh self-test\n'
printf 'script: %s\n' "$SCRIPT"
printf 'evidence: %s\n\n' "$EVID"

# ---------------------------------------------------------------------------
# 0. usage
# ---------------------------------------------------------------------------
"$SCRIPT" --help > "$EVID/help.txt" 2>&1
if [ $? -eq 0 ] && grep -q 'WHY THE INSTRUCTION DECIDES' "$EVID/help.txt"; then
	pass "help"
else
	fail "help" "see $EVID/help.txt"
fi

# ---------------------------------------------------------------------------
# 0b. The default invocation on the machine running the test.  On this Mac
#     there is no Linux /boot or /proc, so it must fail closed with
#     UNDETERMINED; on a Linux node it inspects the running kernel.  Not
#     asserted, just captured as evidence.
# ---------------------------------------------------------------------------
"$SCRIPT" > "$EVID/default-host.txt" 2>&1
printf 'INFO  default-host exit %s (see %s)\n' "$?" "$EVID/default-host.txt"

# ---------------------------------------------------------------------------
# 1. VULNERABLE, end to end: real 7.0.0-28 vmlinuz -> decompress -> disassemble
#    -> EXPOSED with a SO_REUSEPORT group and tcp_migrate_req=1.
# ---------------------------------------------------------------------------
if [ -r "$VMLINUZ" ]; then
	CASE_PATH="$BIN/exposed"
	( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --image "$VMLINUZ" --symbols "$FIX/7.0.0-28.symbols" --proc-root "$FIX/proc-exposed" ) > "$EVID/vulnerable-image.txt" 2>&1
	_rc=$?
	[ "$_rc" = 0 ] && pass "vulnerable-image exit 0 (EXPOSED)" || fail "vulnerable-image" "exit $_rc, wanted 0"
	check_text "vulnerable-image" '^   VULNERABLE$'
	check_text "vulnerable-image" '^   EXPOSED -- '
	check_text "vulnerable-image" 'movl \$0x1,%edx'
	check_text "vulnerable-image" 'other call .* edx=1 .* not decisive'
else
	skip "vulnerable-image" "missing $VMLINUZ"
fi

# ---------------------------------------------------------------------------
# 2. Same kernel, migration disabled -> NOT EXPOSED.
# ---------------------------------------------------------------------------
if [ -r "$VMLINUX" ]; then
	CASE_PATH="$BIN/disabled"
	( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --vmlinux "$VMLINUX" --symbols "$FIX/7.0.0-28.symbols" --proc-root "$FIX/proc-disabled" ) > "$EVID/vulnerable-disabled.txt" 2>&1
	_rc=$?
	[ "$_rc" = 1 ] && pass "vulnerable-disabled exit 1 (NOT EXPOSED)" || fail "vulnerable-disabled" "exit $_rc, wanted 1"
	check_text "vulnerable-disabled" '^   VULNERABLE$'
	check_text "vulnerable-disabled" '^   NOT EXPOSED -- .*migration is disabled'
else
	skip "vulnerable-disabled" "missing $VMLINUX"
fi

# ---------------------------------------------------------------------------
# 3. Same kernel, a sk_reuseport BPF program is attached -> EXPOSED.
# ---------------------------------------------------------------------------
if [ -r "$VMLINUX" ]; then
	CASE_PATH="$BIN/bpf"
	( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --vmlinux "$VMLINUX" --symbols "$FIX/7.0.0-28.symbols" --proc-root "$FIX/proc-disabled" ) > "$EVID/vulnerable-bpf.txt" 2>&1
	_rc=$?
	[ "$_rc" = 0 ] && pass "vulnerable-bpf exit 0 (EXPOSED)" || fail "vulnerable-bpf" "exit $_rc, wanted 0"
	check_text "vulnerable-bpf" '^   EXPOSED -- .*BPF_PROG_TYPE_SK_REUSEPORT'
else
	skip "vulnerable-bpf" "missing $VMLINUX"
fi

# ---------------------------------------------------------------------------
# 4. Same kernel, no SO_REUSEPORT group -> NOT EXPOSED.
# ---------------------------------------------------------------------------
if [ -r "$VMLINUX" ]; then
	CASE_PATH="$BIN/nogroup"
	( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --vmlinux "$VMLINUX" --symbols "$FIX/7.0.0-28.symbols" --proc-root "$FIX/proc-disabled" ) > "$EVID/vulnerable-no-group.txt" 2>&1
	_rc=$?
	[ "$_rc" = 1 ] && pass "vulnerable-no-group exit 1 (NOT EXPOSED)" || fail "vulnerable-no-group" "exit $_rc, wanted 1"
	check_text "vulnerable-no-group" '^   NOT EXPOSED -- no SO_REUSEPORT group'
else
	skip "vulnerable-no-group" "missing $VMLINUX"
fi

# ---------------------------------------------------------------------------
# 5. PATCHED: the real 7.1.4 function bytes (extracted from /proc/kcore on a
#    live 7.1.4 VM), with the same reachability that exposed 7.0.0-28.
# ---------------------------------------------------------------------------
CASE_PATH="$BIN/exposed"
( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --vmlinux "$FIX/ns-7.1.4-reqsk-fn.elf" --symbols "$FIX/ns-7.1.4.symbols" --proc-root "$FIX/proc-exposed" ) > "$EVID/patched.txt" 2>&1
_rc=$?
[ "$_rc" = 1 ] && pass "patched exit 1 (NOT EXPOSED)" || fail "patched" "exit $_rc, wanted 1"
check_text "patched" '^   PATCHED$'
check_text "patched" '^   NOT EXPOSED -- the kernel carries the fix'
check_text "patched" 'xorl %edx,%edx'
check_text "patched" 'other call .* edx=1 .* not decisive'

# ---------------------------------------------------------------------------
# 6. The /proc/kcore fallback, with no /boot image at all.  These kcore files
#    are real function bytes wrapped in an ELF with one PT_LOAD, so the live
#    path (kallsyms + kcore program headers) is exercised without a Linux host.
# ---------------------------------------------------------------------------
CASE_PATH="$BIN/exposed"
( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --proc-root "$FIX/proc-kcore-vuln" --boot-root "$FIX/no-such-boot" ) > "$EVID/kcore-vulnerable.txt" 2>&1
_rc=$?
[ "$_rc" = 0 ] && pass "kcore-vulnerable exit 0 (EXPOSED)" || fail "kcore-vulnerable" "exit $_rc, wanted 0"
check_text "kcore-vulnerable" '^   VULNERABLE$'
check_text "kcore-vulnerable" '^   EXPOSED -- '
check_text "kcore-vulnerable" 'Method: decided from live .*kcore \(runtime text at 0xffffffff'

( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --proc-root "$FIX/proc-kcore-patched" --boot-root "$FIX/no-such-boot" ) > "$EVID/kcore-patched.txt" 2>&1
_rc=$?
[ "$_rc" = 1 ] && pass "kcore-patched exit 1 (NOT EXPOSED)" || fail "kcore-patched" "exit $_rc, wanted 1"
check_text "kcore-patched" '^   PATCHED$'
check_text "kcore-patched" '^   NOT EXPOSED -- the kernel carries the fix'
check_text "kcore-patched" 'Method: decided from live .*kcore \(runtime text at 0xffffffff'

# ---------------------------------------------------------------------------
# 7. A container with no /boot and no readable /proc/kcore: say so.
# ---------------------------------------------------------------------------
CASE_PATH="$BIN/exposed"
( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --proc-root "$FIX/proc-container" --boot-root "$FIX/no-such-boot" ) > "$EVID/container.txt" 2>&1
_rc=$?
[ "$_rc" = 2 ] && pass "container exit 2 (UNKNOWN)" || fail "container" "exit $_rc, wanted 2"
check_text "container" 'run this on the node, not in a pod'
check_text "container" '^   UNDETERMINED$'

# ---------------------------------------------------------------------------
# 8. Empty /proc and empty /boot: fail closed, never "safe by default".
# ---------------------------------------------------------------------------
mkdir -p "$FIX/proc-empty"
CASE_PATH="$BIN/exposed"
( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --proc-root "$FIX/proc-empty" --boot-root "$FIX/no-such-boot" ) > "$EVID/undetermined.txt" 2>&1
_rc=$?
[ "$_rc" = 2 ] && pass "undetermined exit 2 (UNKNOWN)" || fail "undetermined" "exit $_rc, wanted 2"
check_text "undetermined" '^   UNDETERMINED$'
check_text "undetermined" '^   UNKNOWN -- the kernel verdict is UNDETERMINED'

# ---------------------------------------------------------------------------
# 9. A mismatched symbol map must not produce a verdict.
# ---------------------------------------------------------------------------
( PATH="$BIN/exposed:$PATH"; "$SCRIPT" --vmlinux "$FIX/ns-7.1.4-reqsk-fn.elf" --symbols "$FIX/7.0.0-28.symbols" --proc-root "$FIX/proc-exposed" ) > "$EVID/mismatched-map.txt" 2>&1
_rc=$?
[ "$_rc" = 2 ] && pass "mismatched-map exit 2 (UNKNOWN)" || fail "mismatched-map" "exit $_rc, wanted 2"
check_text "mismatched-map" '^   UNDETERMINED$'
check_text "mismatched-map" 'does not match this image|no PT_LOAD'

# ---------------------------------------------------------------------------
# 10. Privileged container: /proc/kcore is readable, so the kernel verdict is
#     the host's, but ss and tcp_migrate_req are the container's network
#     namespace.  The container shows no group and tcp_migrate_req=0; the old
#     script answered a confident NOT EXPOSED about the node.  It must now be
#     UNKNOWN / exit 2.
# ---------------------------------------------------------------------------
CASE_PATH="$BIN/nogroup"
( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --proc-root "$FX/proc-container-priv" --boot-root "$FIX/no-such-boot" ) > "$EVID/container-privileged.txt" 2>&1
_rc=$?
[ "$_rc" = 2 ] && pass "container-privileged exit 2 (UNKNOWN)" || fail "container-privileged" "exit $_rc, wanted 2"
check_text "container-privileged" '^   VULNERABLE$'
check_text "container-privileged" 'Method: decided from live .*kcore'
check_text "container-privileged" '^   scope: these listeners and tcp_migrate_req are this container.s network namespace, not the node.s'
check_text "container-privileged" '^   SO_REUSEPORT group: no$'
check_text "container-privileged" '^   UNKNOWN -- .*this container.s network namespace, not the node.s'
check_text "container-privileged" 'run this on the node, not in a pod'
check_absent "container-privileged" '^   NOT EXPOSED -- '
check_absent "container-privileged" '^   EXPOSED -- '

# ---------------------------------------------------------------------------
# 11. The same fixture, with the caller asserting that it sees the host netns
#     (e.g. --net=host): the confident answer is allowed again.
# ---------------------------------------------------------------------------
( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --assume-host-netns --proc-root "$FX/proc-container-priv" --boot-root "$FIX/no-such-boot" ) > "$EVID/container-privileged-assumed.txt" 2>&1
_rc=$?
[ "$_rc" = 1 ] && pass "container-privileged-assumed exit 1 (NOT EXPOSED)" || fail "container-privileged-assumed" "exit $_rc, wanted 1"
check_text "container-privileged-assumed" '^   VULNERABLE$'
check_text "container-privileged-assumed" '^   scope: the host network namespace, asserted by --assume-host-netns'
check_text "container-privileged-assumed" '^   NOT EXPOSED -- no SO_REUSEPORT group'
check_text "container-privileged-assumed" 'run this on the node, not in a pod'

# ---------------------------------------------------------------------------
# 12. /boot/vmlinuz-* is present but unreadable: say exactly that, with the
#     mode and owner, instead of "no /boot kernel image".  Fail-closed either
#     way (UNDETERMINED, exit 2).
# ---------------------------------------------------------------------------
if [ ! -r "$FX/boot-unreadable/vmlinuz-$(uname -r)" ]; then
	( PATH="$BIN/exposed:$PATH"; "$SCRIPT" --proc-root "$FIX/proc-empty" --boot-root "$FX/boot-unreadable" ) > "$EVID/boot-unreadable.txt" 2>&1
	_rc=$?
	[ "$_rc" = 2 ] && pass "boot-unreadable exit 2 (UNKNOWN)" || fail "boot-unreadable" "exit $_rc, wanted 2"
	check_text "boot-unreadable" '^   UNDETERMINED$'
	check_text "boot-unreadable" 'present but not readable as uid [0-9]+ \(mode 0000 [^)]*\); re-run as root'
	check_absent "boot-unreadable" 'no /boot kernel image \(looked for'
else
	skip "boot-unreadable" "this uid can read a mode-000 file (running as root), so the fixture is not unreadable"
fi

# ---------------------------------------------------------------------------
# 12b. The System.map search has the same distinction.  This ELF carries no
#      symbol table, so the script falls through to the /boot System.map-*
#      candidates, which are present and unreadable.
# ---------------------------------------------------------------------------
mkdir -p "$FX/boot-unreadable-map"
: > "$FX/boot-unreadable-map/System.map-$(uname -r)"
chmod 000 "$FX/boot-unreadable-map/System.map-$(uname -r)"
if [ ! -r "$FX/boot-unreadable-map/System.map-$(uname -r)" ]; then
	( PATH="$BIN/exposed:$PATH"; "$SCRIPT" --vmlinux "$FIX/ns-7.1.4-reqsk-fn.elf" --proc-root "$FIX/proc-empty" --boot-root "$FX/boot-unreadable-map" ) > "$EVID/symbol-map-unreadable.txt" 2>&1
	_rc=$?
	[ "$_rc" = 2 ] && pass "symbol-map-unreadable exit 2 (UNKNOWN)" || fail "symbol-map-unreadable" "exit $_rc, wanted 2"
	check_text "symbol-map-unreadable" '^   UNDETERMINED$'
	check_text "symbol-map-unreadable" 'no readable symbol map for .*present but not readable as uid [0-9]+ \(mode 0000 [^)]*\); re-run as root'
	check_absent "symbol-map-unreadable" 'no symbol map for .*was found'
else
	skip "symbol-map-unreadable" "this uid can read a mode-000 file (running as root), so the fixture is not unreadable"
fi

# ---------------------------------------------------------------------------
# 13. ss exits non-zero with partial output: the old script parsed it anyway.
#     It must be UNKNOWN, never a negative.
# ---------------------------------------------------------------------------
if [ -r "$VMLINUX" ]; then
	CASE_PATH="$BIN/ss-partial"
	( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --vmlinux "$VMLINUX" --symbols "$FIX/7.0.0-28.symbols" --proc-root "$FIX/proc-disabled" ) > "$EVID/ss-partial.txt" 2>&1
	_rc=$?
	[ "$_rc" = 2 ] && pass "ss-partial exit 2 (UNKNOWN)" || fail "ss-partial" "exit $_rc, wanted 2"
	check_text "ss-partial" '^   VULNERABLE$'
	check_text "ss-partial" '^   SO_REUSEPORT group: UNKNOWN$'
	check_text "ss-partial" 'ss -tlnpe failed \(exit 1\).*cannot show that no SO_REUSEPORT group exists'
	check_text "ss-partial" '^   UNKNOWN -- cannot determine whether a SO_REUSEPORT group exists'
	check_absent "ss-partial" '^   NOT EXPOSED -- '

	# -----------------------------------------------------------------------
	# 14. ss exits 0 but prints no socket-table header: also UNKNOWN.
	# -----------------------------------------------------------------------
	CASE_PATH="$BIN/ss-no-header"
	( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --vmlinux "$VMLINUX" --symbols "$FIX/7.0.0-28.symbols" --proc-root "$FIX/proc-disabled" ) > "$EVID/ss-no-header.txt" 2>&1
	_rc=$?
	[ "$_rc" = 2 ] && pass "ss-no-header exit 2 (UNKNOWN)" || fail "ss-no-header" "exit $_rc, wanted 2"
	check_text "ss-no-header" '^   SO_REUSEPORT group: UNKNOWN$'
	check_text "ss-no-header" "no 'State' header line"

	# -----------------------------------------------------------------------
	# 15. bpftool fails: its failure must stay UNKNOWN, not "no program".
	# -----------------------------------------------------------------------
	CASE_PATH="$BIN/bpftool-fail"
	( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --vmlinux "$VMLINUX" --symbols "$FIX/7.0.0-28.symbols" --proc-root "$FIX/proc-disabled" ) > "$EVID/bpftool-fail.txt" 2>&1
	_rc=$?
	[ "$_rc" = 2 ] && pass "bpftool-fail exit 2 (UNKNOWN)" || fail "bpftool-fail" "exit $_rc, wanted 2"
	check_text "bpftool-fail" '^   SO_REUSEPORT group: yes$'
	check_text "bpftool-fail" 'bpftool prog show failed \(exit 1\)'
	check_text "bpftool-fail" '^   UNKNOWN -- migration is disabled by sysctl .*bpftool is unavailable'
else
	skip "ss-partial" "missing $VMLINUX"
	skip "ss-no-header" "missing $VMLINUX"
	skip "bpftool-fail" "missing $VMLINUX"
fi

# ---------------------------------------------------------------------------
# 16. A group in the container's own namespace with migration enabled is still
#     EXPOSED: the scope change must never suppress an alarm.
# ---------------------------------------------------------------------------
CASE_PATH="$BIN/exposed"
( PATH="$CASE_PATH:$PATH"; "$SCRIPT" --proc-root "$FX/proc-container-priv-mig" --boot-root "$FIX/no-such-boot" ) > "$EVID/container-privileged-exposed.txt" 2>&1
_rc=$?
[ "$_rc" = 0 ] && pass "container-privileged-exposed exit 0 (EXPOSED)" || fail "container-privileged-exposed" "exit $_rc, wanted 0"
check_text "container-privileged-exposed" '^   EXPOSED -- .*tcp_migrate_req=1'
check_text "container-privileged-exposed" 'scope: these listeners and tcp_migrate_req are this container.s network namespace'

printf '\n%d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
printf 'Outputs: %s\n' "$EVID"
[ "$FAIL" -eq 0 ]
