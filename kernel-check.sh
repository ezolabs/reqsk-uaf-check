#!/usr/bin/env bash
# =============================================================================
# kernel-check.sh
#
# Read-only, self-contained check for the request-sock timer use-after-free
# fixed by upstream commit 97c8a3c1f73d828de43a5a88e8a9a143efb2b661
# ("tcp: Fix potential UAF in reqsk_timer_handler()").
#
# It answers three questions, in this order:
#   1. Does this kernel carry the fix?  VULNERABLE / PATCHED / UNDETERMINED,
#      decided from the compiled instruction at the deciding call site inside
#      reqsk_timer_handler() -- never from the version string.
#   2. Is the vulnerable code reachable on this host?  A SO_REUSEPORT group on
#      a TCP port, a BPF_PROG_TYPE_SK_REUSEPORT program, and
#      net.ipv4.tcp_migrate_req.
#   3. One exposure line: EXPOSED / NOT EXPOSED / UNKNOWN, with the reason.
#
# It never writes to the host outside a private mktemp directory, never loads a
# module, never changes a sysctl, never uses the network, and never elevates.
#
# Run with --help for the full explanation.
# =============================================================================

set -u

LC_ALL=C
export LC_ALL

VERSION="1.0"

OPT_IMAGE=""
OPT_VMLINUX=""
OPT_SYMBOLS=""
OPT_PROC="/proc"
OPT_BOOT="/boot"
OPT_KEEP_TEMP=0
OPT_DEBUG=0
OPT_REACH=1
OPT_ASSUME_HOST_NETNS=0

# Results
KVERDICT="UNDETERMINED"
KMETHOD=""
KMETHOD_REASONS=""
EXPOSURE="UNKNOWN"
EXPOSURE_REASON=""

# Scope of the section-2 reachability inputs, relative to the node:
#   host          the invocation's own network namespace is the node's
#   ambiguous     a container read the host kernel from /proc/kcore, but ss,
#                 bpftool and tcp_migrate_req are the container's netns
#   host-asserted the caller passed --assume-host-netns
NETNS_SCOPE="host"
NETNS_SCOPE_WHY=""

R_GROUP="UNKNOWN"; R_GROUP_WHY="not checked"; R_GROUP_EVID=""
R_BPF="UNKNOWN";   R_BPF_WHY="not checked"
R_MIGRATE="UNKNOWN"; R_MIGRATE_WHY="not checked"

TMP=""
EVID=""

# ---------------------------------------------------------------------------
# output helpers
# ---------------------------------------------------------------------------
say() { printf '%s\n' "$*"; }
ev()  { printf '%s\n' "$*" >> "$EVID"; }

section() {
	say ""
	say "== $* =="
}

add_reason() {
	if [ -n "$KMETHOD_REASONS" ]; then
		KMETHOD_REASONS="$KMETHOD_REASONS; $1"
	else
		KMETHOD_REASONS="$1"
	fi
}

usage() {
	cat <<'EOF'
kernel-check.sh -- read-only check for the request-sock timer UAF
(upstream commit 97c8a3c1f73d, "tcp: Fix potential UAF in reqsk_timer_handler()")

USAGE
  ./kernel-check.sh [options]

OPTIONS
  --image FILE       compressed kernel image (vmlinuz/bzImage) to inspect
  --vmlinux FILE     already-decompressed kernel ELF to inspect
  --symbols FILE     System.map-format file for --image/--vmlinux
  --proc-root DIR    alternative /proc (testing aid; default /proc)
  --boot-root DIR    alternative /boot (default /boot)
  --assume-host-netns  the caller asserts that this invocation sees the host's
                     network namespace (e.g. --net=host, or a host process
                     inside a container).  Without it, a container that reads
                     the host kernel via /proc/kcore gets UNKNOWN instead of a
                     reachability-derived NOT EXPOSED.
  --keep-temp        keep the private decompression directory
  --debug            print extra diagnostics
  --no-reachability  skip the host reachability checks
  -h, --help         this text

WHAT IT READS
  1. Kernel fix verdict:
     - /boot/vmlinuz-$(uname -r) and /boot/System.map-$(uname -r), copied into a
       private temp dir and decompressed there (zstd, gzip, xz, lz4, bzip2,
       lzo or lzma); or an image given with --image / --vmlinux.
     - If there is no usable image, the live kernel text is read from
       /proc/kcore with symbols from /proc/kallsyms.
  2. Reachability (host-local):
     - ss -tlnpe             SO_REUSEPORT groups on listening TCP ports
     - bpftool prog show     BPF_PROG_TYPE_SK_REUSEPORT programs, found by
                             grepping the type field (the command
                             `bpftool prog show type sk_reuseport` is rejected
                             by bpftool v7.7.0)
     - /proc/sys/net/ipv4/tcp_migrate_req
  3. Exposure: EXPOSED only when the kernel is VULNERABLE and a SO_REUSEPORT
     group exists and either tcp_migrate_req=1 or a sk_reuseport program is
     attached.  Anything else is NOT EXPOSED or UNKNOWN, with the reason.

WHY THE INSTRUCTION DECIDES, NOT THE VERSION
  In reqsk_timer_handler() the failure branch of inet_ehash_insert() calls
  __inet_csk_reqsk_queue_drop(sk_listener, nreq, from_timer).  Passing true
  makes that function skip timer_delete_sync(), so the clone is freed with its
  rsk_timer still queued -- the use-after-free.  Upstream commit 97c8a3c1f73d
  changes that one argument to false.  In the compiled code the deciding call
  is preceded by `movl $0x1,%edx` (vulnerable) or `xorl %edx,%edx` /
  `movl $0x0,%edx` (patched).

  A version string cannot tell you this: a distributor can backport or omit a
  fix without changing the version.  Both vulnerable and fixed kernels also
  contain a second call to __inet_csk_reqsk_queue_drop at the `drop:` label on
  the original request, and that call passes 1 in both.  This script therefore
  finds the call to inet_ehash_insert, follows the `je` failure target, and
  only then resolves the call target to __inet_csk_reqsk_queue_drop.  The
  `drop:`-label call is printed as supporting evidence but cannot produce a
  false VULNERABLE.

PRIVILEGES (the script never elevates; it degrades and says why)
  - /boot/* and System.map: usually world-readable; no root needed.
  - /proc/kcore: mode 0400 root:root -- root or CAP_SYS_RAWIO needed.
  - /proc/kallsyms real addresses: root or CAP_SYSLOG unless kptr_restrict=0.
  - bpftool prog show: root/CAP_BPF to see all programs.
  - ss -p: root to see other users' process names; the socket list itself is
    visible without root.

CONTAINERS
  Inside a container /boot and /proc/kcore are often absent.  If neither is
  usable the script prints "run this on the node, not in a pod".  If
  /proc/kcore is readable, the container shares the host kernel, so the kernel
  verdict is the host's -- but ss, bpftool and net.ipv4.tcp_migrate_req are
  this container's network namespace, not the node's.  In that case a
  reachability-derived "no group" answer is reported as UNKNOWN (exit 2), not
  NOT EXPOSED.  Pass --assume-host-netns when the container was started with
  --net=host (or the script runs as a host process inside a container) to
  allow the confident answer.

READ-ONLY
  No module loads, no sysctl writes, no /proc or /sys writes.  The only writes
  are to a private mktemp directory, removed on exit (--keep-temp keeps it).

EXIT STATUS
  0 EXPOSED   1 NOT EXPOSED   2 UNKNOWN/UNDETERMINED   3 usage error
EOF
}

# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------
need_arg() {
	if [ "$#" -lt 2 ] || [ -z "$2" ]; then
		say "kernel-check.sh: option $1 needs an argument" >&2
		exit 3
	fi
}

is_elf() {
	[ -r "$1" ] || return 1
	_m=$(hex_at "$1" 0 4)
	[ "$_m" = "7f454c46" ]
}

# hex_at FILE OFFSET LENGTH -> lowercase hex string, no spaces
hex_at() {
	_f=$1
	_o=$2
	_l=$3
	[ "$_l" -gt 0 ] 2>/dev/null || return 0
	_blk=$((_o / 4096))
	_rem=$((_o % 4096))
	_cnt=$(( (_rem + _l + 4095) / 4096 ))
	dd if="$_f" bs=4096 skip="$_blk" count="$_cnt" 2>/dev/null \
		| dd bs=1 skip="$_rem" count="$_l" 2>/dev/null \
		| od -An -v -tx1 2>/dev/null \
		| tr -d ' \n'
}

# get_hex HEXSTRING OFFSET LENGTH -> slice of the hex string
get_hex() {
	printf '%s' "${1:$(( $2 * 2 )):$(( $3 * 2 ))}"
}

# hex byte value
hv() {
	[ -n "$1" ] && printf '%d' "0x$1" || printf '0'
}

u16le() { # file offset
	_h=$(hex_at "$1" "$2" 2)
	[ ${#_h} -eq 4 ] || { printf ''; return 1; }
	printf '%d' $((16#${_h:2:2} * 256 + 16#${_h:0:2}))
}

u32le() { # file offset
	_h=$(hex_at "$1" "$2" 4)
	[ ${#_h} -eq 8 ] || { printf ''; return 1; }
	printf '%d' $((16#${_h:6:2} * 16777216 + 16#${_h:4:2} * 65536 + 16#${_h:2:2} * 256 + 16#${_h:0:2}))
}

u64le() { # file offset; bash wraps to signed 64-bit, which is fine for comparisons
	_lo=$(u32le "$1" "$2") || return 1
	_hi=$(u32le "$1" $(( $2 + 4 ))) || return 1
	[ -n "$_lo" ] && [ -n "$_hi" ] || return 1
	printf '%d' $(( _lo + _hi * 4294967296 ))
}

# u32 at a hex-string offset
hx_u32() { # HEXSTRING BYTEOFFSET
	_h=$(get_hex "$1" "$2" 4)
	[ ${#_h} -eq 8 ] || { printf ''; return 1; }
	printf '%d' $((16#${_h:6:2} * 16777216 + 16#${_h:4:2} * 65536 + 16#${_h:2:2} * 256 + 16#${_h:0:2}))
}

hx_u64() { # HEXSTRING BYTEOFFSET
	_lo=$(hx_u32 "$1" "$2") || return 1
	_hi=$(hx_u32 "$1" $(( $2 + 4 ))) || return 1
	[ -n "$_lo" ] && [ -n "$_hi" ] || return 1
	printf '%d' $(( _lo + _hi * 4294967296 ))
}

hexaddr() { # signed/positive integer -> 0x... 64-bit hex
	if [ -z "${1:-}" ]; then
		printf '?'
		return
	fi
	printf '0x%x' "$1"
}

# mode_owner FILE -> "0600 root:root" (GNU stat, then BSD stat, else "? ?")
mode_owner() {
	_mo=""
	if _mo=$(stat -c '%a %U:%G' "$1" 2>/dev/null); then
		:
	elif _mo=$(stat -f '%Lp %Su:%Sg' "$1" 2>/dev/null); then
		:
	else
		printf '? ?'
		return 0
	fi
	# shellcheck disable=SC2086
	set -- $_mo
	_m=${1:-?}
	_o=${2:-?}
	_m=${_m#0}
	case "$_m" in
	'') _m=0000 ;;
	*[!0-7]*) ;;
	*) _m=$(printf '%04o' "$((8#$_m))" 2>/dev/null) || _m="?" ;;
	esac
	printf '%s %s' "$_m" "$_o"
}

# unreadable_file_msg FILE -> the operator-facing wording for a file that is
# there but cannot be read by this uid.  "Absent" and "present but not
# readable" are different answers and must not be confused.
unreadable_file_msg() {
	_mou=$(id -u 2>/dev/null || echo '?')
	printf '%s: present but not readable as uid %s (mode %s); re-run as root' \
		"$1" "$_mou" "$(mode_owner "$1")"
}

# ---------------------------------------------------------------------------
# ELF mapping: virtual address -> file offset
# Handles PT_LOAD program headers (real vmlinux and /proc/kcore) and
# SHT_PROGBITS section headers (small test fixtures with no phdrs).
# ---------------------------------------------------------------------------
map_vaddr() { # file vaddr
	_f=$1
	_va_raw=$2
	case "$_va_raw" in
	0x*) _va_raw=${_va_raw#0x} ;;
	0X*) _va_raw=${_va_raw#0X} ;;
	esac
	_va=$((16#$_va_raw))
	[ "$(hex_at "$_f" 0 4)" = "7f454c46" ] || return 1
	[ "$(hex_at "$_f" 4 1)" = "02" ] || return 1  # ELFCLASS64

	_phoff=$(u64le "$_f" 32) || _phoff=""
	_phentsize=$(u16le "$_f" 54) || _phentsize=""
	_phnum=$(u16le "$_f" 56) || _phnum=""

	if [ -n "$_phoff" ] && [ "$_phentsize" = "56" ] && [ -n "$_phnum" ] && [ "$_phnum" -gt 0 ] 2>/dev/null; then
		_pht_len=$(( _phnum * _phentsize ))
		# Sanity cap: a phdr table larger than 1 MiB is not a kernel image.
		[ "$_pht_len" -le 1048576 ] || return 1
		PHT=$(hex_at "$_f" "$_phoff" "$_pht_len")
		_i=0
		while [ "$_i" -lt "$_phnum" ]; do
			_base=$(( _i * _phentsize ))
			_ptype=$(hx_u32 "$PHT" "$_base") || _ptype=""
			if [ "$_ptype" = "1" ]; then
				_p_off=$(hx_u64 "$PHT" $((_base + 8))) || _p_off=""
				_p_va=$(hx_u64 "$PHT" $((_base + 16))) || _p_va=""
				_p_fsz=$(hx_u64 "$PHT" $((_base + 32))) || _p_fsz=""
				if [ -n "$_p_off" ] && [ -n "$_p_va" ] && [ -n "$_p_fsz" ]; then
					_delta=$(( _va - _p_va ))
					if [ "$_delta" -ge 0 ] && [ "$_delta" -lt "$_p_fsz" ]; then
						printf '%d' $(( _p_off + _delta ))
						return 0
					fi
				fi
			fi
			_i=$((_i + 1))
		done
	fi

	# Section headers (test fixtures built without program headers).
	_shoff=$(u64le "$_f" 40) || _shoff=""
	_shentsize=$(u16le "$_f" 58) || _shentsize=""
	_shnum=$(u16le "$_f" 60) || _shnum=""
	if [ -n "$_shoff" ] && [ "$_shentsize" = "64" ] && [ -n "$_shnum" ] && [ "$_shnum" -gt 0 ] 2>/dev/null; then
		_sht_len=$(( _shnum * _shentsize ))
		[ "$_sht_len" -le 1048576 ] || return 1
		SHT=$(hex_at "$_f" "$_shoff" "$_sht_len")
		_i=0
		while [ "$_i" -lt "$_shnum" ]; do
			_base=$(( _i * _shentsize ))
			_stype=$(hx_u32 "$SHT" $((_base + 4))) || _stype=""
			if [ "$_stype" = "1" ]; then
				_s_addr=$(hx_u64 "$SHT" $((_base + 16))) || _s_addr=""
				_s_off=$(hx_u64 "$SHT" $((_base + 24))) || _s_off=""
				_s_sz=$(hx_u64 "$SHT" $((_base + 32))) || _s_sz=""
				if [ -n "$_s_addr" ] && [ -n "$_s_off" ] && [ -n "$_s_sz" ]; then
					_delta=$(( _va - _s_addr ))
					if [ "$_delta" -ge 0 ] && [ "$_delta" -lt "$_s_sz" ]; then
						printf '%d' $(( _s_off + _delta ))
						return 0
					fi
				fi
			fi
			_i=$((_i + 1))
		done
	fi
	return 1
}

# ---------------------------------------------------------------------------
# symbol maps
# ---------------------------------------------------------------------------
sym_addr() { # name mapfile
	[ -r "$2" ] || return 1
	awk -v n="$1" '
		$3 == n {
			a = $1
			sub(/^0[xX]/, "", a)
			print a
			exit
		}
	' "$2" 2>/dev/null
}

valid_addr() {
	case "$1" in
	""|0|0000000000000000|00000000) return 1 ;;
	*[!0-9a-fA-F]*) return 1 ;;
	esac
	return 0
}

next_text_addr() { # addr mapfile (map must be sorted by address)
	awk -v a="$1" '
		{
			x = $1
			sub(/^0[xX]/, "", x)
		}
		x ~ /^[0-9a-fA-F]+$/ && $2 ~ /^[tT]$/ && x > a { print x; exit }
	' "$2" 2>/dev/null
}

# ---------------------------------------------------------------------------
# kernel image extraction
# ---------------------------------------------------------------------------
EXTRACT_WHY=""

# hex_magic_offsets FILE HEXMAGIC [max]
hex_magic_offsets() {
	_f=$1
	_m=$2
	_max=${3:-4}
	od -An -v -tx1 "$_f" 2>/dev/null \
		| tr -d ' \n' \
		| LC_ALL=C grep -bo "$_m" 2>/dev/null \
		| cut -d: -f1 \
		| awk -v m="$_max" '{ if ($1 % 2 == 0) { print $1 / 2; n++; if (n >= m) exit } }'
}

# try_format FORMAT MAGIC DECOMPRESSOR...
try_format() {
	_fmt=$1
	_magic=$2
	shift 2
	_decomp=$1

	_offs=$(hex_magic_offsets "$SRC_IMG" "$_magic" 3)
	[ -n "$_offs" ] || return 1
	if ! command -v "$_decomp" >/dev/null 2>&1; then
		ev "  $_fmt: a stream is present, but $_decomp is not installed"
		EXTRACT_WHY="$EXTRACT_WHY; $_fmt stream needs '$_decomp' (not installed)"
		return 1
	fi
	_decompressed=0
	for _o in $_offs; do
		ev "  $_fmt: trying byte offset $_o with '$_decomp'"
		tail -c +$(( _o + 1 )) "$SRC_IMG" 2>/dev/null | "$@" > "$TMP/try.vmlinux" 2>/dev/null
		if is_elf "$TMP/try.vmlinux"; then
			mv "$TMP/try.vmlinux" "$TMP/vmlinux" 2>/dev/null
			_decompressed=1
			break
		fi
	done
	[ "$_decompressed" = 1 ]
}

extract_vmlinux() { # image out
	SRC_IMG=$1
	_out=$2
	EXTRACT_WHY=""

	if is_elf "$SRC_IMG"; then
		[ "$SRC_IMG" = "$_out" ] || cp "$SRC_IMG" "$_out" 2>/dev/null
		return 0
	fi

	ev "  looking for a compressed kernel stream in $SRC_IMG"
	# Ordered by what modern distributions actually ship.  Each attempt is
	# bounded to the first three magic hits and validated by the ELF magic of
	# the decompressed output, so a false magic hit cannot produce a verdict.
	if try_format zstd  28b52ffd zstd -dc;        then return 0; fi
	if try_format gzip  1f8b08   gzip -dc;        then return 0; fi
	if try_format xz    fd377a585a00 xz -dc;      then return 0; fi
	if try_format lz4   02214c18 lz4 -dc;         then return 0; fi
	if try_format bzip2 425a68   bzip2 -dc;       then return 0; fi
	if try_format lzo   894c5a4f lzop -dc;        then return 0; fi
	if try_format lzma  5d0000   xz -dc --format=lzma; then return 0; fi

	[ -n "$EXTRACT_WHY" ] || EXTRACT_WHY="no zstd/gzip/xz/lz4/bzip2/lzo/lzma stream found"
	return 1
}

# ---------------------------------------------------------------------------
# instruction-level decision
# ---------------------------------------------------------------------------
# Globals set by decide_from_bytes:
#   KVERDICT, DECIDE_REASON, DECIDE_DESC, EDXVAL, DECIDE_SITE
DECIDE_REASON=""
DECIDE_DESC=""
EDXVAL=""
DECIDE_SITE=""

# rel32_at HEXSTRING BYTEOFFSET -> signed integer
rel32_at() {
	_h=$(get_hex "$1" "$2" 4)
	[ ${#_h} -eq 8 ] || { printf '0'; return 1; }
	_v=$((16#${_h:6:2} * 16777216 + 16#${_h:4:2} * 65536 + 16#${_h:2:2} * 256 + 16#${_h:0:2}))
	if [ "$_v" -ge 2147483648 ]; then
		printf '%d' $(( _v - 4294967296 ))
	else
		printf '%d' "$_v"
	fi
}

rel8_at() {
	_h=$(get_hex "$1" "$2" 1)
	[ ${#_h} -eq 2 ] || { printf '0'; return 1; }
	_v=$((16#$_h))
	if [ "$_v" -ge 128 ]; then printf '%d' $(( _v - 256 )); else printf '%d' "$_v"; fi
}

# find_call_sites HEX FUNC_ADDR TARGET_ADDR NFUNC -> byte offsets, one per line
# This is the hot loop: use bash string slicing directly rather than a command
# substitution per byte, so a 1-2 KiB function is scanned quickly on a busy node.
find_call_sites() {
	_hex=$1
	_fa=$2
	_tgt=$3
	_n=$4
	_i=0
	while [ "$_i" -le $(( _n - 5 )) ]; do
		if [ "${_hex:$(( _i * 2 )):2}" = "e8" ]; then
			_h4=${_hex:$(( (_i + 1) * 2 )):8}
			if [ ${#_h4} -eq 8 ]; then
				_v=$((16#${_h4:6:2} * 16777216 + 16#${_h4:4:2} * 65536 + 16#${_h4:2:2} * 256 + 16#${_h4:0:2}))
				if [ "$_v" -ge 2147483648 ]; then _rel=$(( _v - 4294967296 )); else _rel=$_v; fi
				_t=$(( _fa + _i + 5 + _rel ))
				if [ "$_t" -eq "$_tgt" ]; then
					printf '%d\n' "$_i"
				fi
			fi
		fi
		_i=$((_i + 1))
	done
}

# spaced_hex HEXSTRING OFFSET LENGTH -> "ba 01 00 00 00"
spaced_hex() {
	_h=$(get_hex "$1" "$2" "$3")
	_out=""
	while [ -n "$_h" ]; do
		_out="$_out ${_h:0:2}"
		_h=${_h:2}
	done
	printf '%s' "${_out# }"
}

regname() {
	case "$1" in
	0) printf 'rax' ;; 1) printf 'rcx' ;; 2) printf 'rdx' ;; 3) printf 'rbx' ;;
	4) printf 'rsp' ;; 5) printf 'rbp' ;; 6) printf 'rsi' ;; 7) printf 'rdi' ;;
	8) printf 'r8' ;; 9) printf 'r9' ;; 10) printf 'r10' ;; 11) printf 'r11' ;;
	12) printf 'r12' ;; 13) printf 'r13' ;; 14) printf 'r14' ;; 15) printf 'r15' ;;
	*) printf 'r?' ;;
	esac
}

# Print one decoded instruction line for the known patterns.  Unknown bytes are
# shown raw; the script never guesses at semantics it did not decode.
ev_instr() { # hexstring byteoffset maxlen comment
	_h=$1; _o=$2; _max=$3; _why=$4
	_b1=$(get_hex "$_h" "$_o" 1)
	case "$_b1" in
	ba)
		if [ "$_max" -ge 5 ]; then
			_h4=$(get_hex "$_h" $(( _o + 1 )) 4)
			_imm=$((16#${_h4:6:2} * 16777216 + 16#${_h4:4:2} * 65536 + 16#${_h4:2:2} * 256 + 16#${_h4:0:2}))
			ev "    $(spaced_hex "$_h" "$_o" 5)  movl \$0x$(printf '%x' "$_imm"),%edx  $_why"
			return 0
		fi
		;;
	31)
		if [ "$(get_hex "$_h" $(( _o + 1 )) 1)" = "d2" ] && [ "$_max" -ge 2 ]; then
			ev "    $(spaced_hex "$_h" "$_o" 2)  xorl %edx,%edx  $_why"
			return 0
		fi
		;;
	4c|48|49|4d)
		if [ "$_max" -ge 3 ] && [ "$(get_hex "$_h" $(( _o + 1 )) 1)" = "89" ]; then
			_mrm=$(get_hex "$_h" $(( _o + 2 )) 1)
			if [ -n "$_mrm" ]; then
				_m=$((16#$_mrm))
				if [ $(( _m & 0xc0 )) -eq 192 ]; then
					_dst=$(( _m & 7 ))
					_src=$(( (_m >> 3) & 7 ))
					case "$_b1" in 4c) _src=$(( _src + 8 ));; 49) _dst=$(( _dst + 8 ));; 4d) _src=$(( _src + 8 )); _dst=$(( _dst + 8 ));; esac
					ev "    $(spaced_hex "$_h" "$_o" 3)  movq %$(regname "$_src"),%$(regname "$_dst")  $_why"
					return 0
				fi
			fi
		fi
		;;
	e8)
		if [ "$_max" -ge 5 ]; then
			_rel=$(rel32_at "$_h" $(( _o + 1 )))
			_t=$(( FUNC_ADDR + _o + 5 + _rel ))
			ev "    $(spaced_hex "$_h" "$_o" 5)  call $(hexaddr "$_t")  $_why"
			return 0
		fi
		;;
	e9)
		if [ "$_max" -ge 5 ]; then
			_rel=$(rel32_at "$_h" $(( _o + 1 )))
			_t=$(( FUNC_ADDR + _o + 5 + _rel ))
			ev "    $(spaced_hex "$_h" "$_o" 5)  jmp $(hexaddr "$_t")  $_why"
			return 0
		fi
		;;
	esac
	# fall back to a short raw dump
	_l=1
	[ "$_max" -ge 3 ] && _l=3
	_bytes=$(spaced_hex "$_h" "$_o" "$_l")
	[ -n "$_bytes" ] && ev "    $_bytes  (raw)  $_why"
	return 1
}

# find_mov_before HEX FROM TO DESTREG -> source register number or empty
# Handles the two/three-byte `movq %rN,%rsi|%rdi` forms used in these kernels.
find_mov_before() {
	_h=$1; _from=$2; _to=$3; _dest=$4
	_i=$_to
	while [ "$_i" -ge "$_from" ]; do
		_b1=$(get_hex "$_h" "$_i" 1)
		case "$_b1" in
		4c|48|49|4d)
			if [ "$(get_hex "$_h" $(( _i + 1 )) 1)" = "89" ]; then
				_mrm=$(get_hex "$_h" $(( _i + 2 )) 1)
				if [ -n "$_mrm" ]; then
					_m=$((16#$_mrm))
					if [ $(( _m & 0xc0 )) -eq 192 ]; then
						_d=$(( _m & 7 ))
						_s=$(( (_m >> 3) & 7 ))
						case "$_b1" in 4c) _s=$(( _s + 8 ));; 49) _d=$(( _d + 8 ));; 4d) _s=$(( _s + 8 )); _d=$(( _d + 8 ));; esac
						if [ "$_d" -eq "$_dest" ]; then
							printf '%d' "$_s"
							return 0
						fi
					fi
				fi
			fi
			;;
		esac
		_i=$((_i - 1))
	done
	return 1
}

# decide_from_bytes HEX FUNC_ADDR DROP_ADDR EHIS_ADDR SIZE
decide_from_bytes() {
	local _hex FUNC_ADDR DROP_ADDR EHIS_ADDR _n
	_hex=$1
	FUNC_ADDR=$2
	DROP_ADDR=$3
	EHIS_ADDR=$4
	_n=$5

	# 1. the call to inet_ehash_insert inside reqsk_timer_handler
	_ehis_sites=$(find_call_sites "$_hex" "$FUNC_ADDR" "$EHIS_ADDR" "$_n")
	_ehis_count=$(printf '%s\n' "$_ehis_sites" | grep -c . 2>/dev/null || true)
	if [ "$_ehis_count" -ne 1 ]; then
		DECIDE_REASON="expected exactly one call to inet_ehash_insert inside reqsk_timer_handler, found $_ehis_count; the symbol map does not match this image"
		return 1
	fi
	_ehis_off=$_ehis_sites
	ev "    call inet_ehash_insert at $(hexaddr $(( FUNC_ADDR + _ehis_off )))"

	# 2. testb %al,%al immediately after the call (allow up to 8 bytes of slack)
	_t=$(( _ehis_off + 5 ))
	_found=""
	_k=$_t
	while [ "$_k" -le $(( _t + 8 )) ]; do
		if [ "$(get_hex "$_hex" "$_k" 2)" = "84c0" ]; then _found=$_k; break; fi
		_k=$((_k + 1))
	done
	if [ -z "$_found" ]; then
		DECIDE_REASON="no 'testb %al,%al' after the inet_ehash_insert call at $(hexaddr $(( FUNC_ADDR + _ehis_off )))"
		return 1
	fi
	_t=$_found

	# 3. the conditional jump that takes the insert-failure branch
	_j=$(( _t + 2 ))
	_jh=$(get_hex "$_hex" "$_j" 2)
	if [ "$_jh" = "0f84" ]; then
		_rel=$(rel32_at "$_hex" $(( _j + 2 )))
		_jt=$(( FUNC_ADDR + _j + 6 + _rel ))
	elif [ "${_jh:0:2}" = "74" ]; then
		_rel=$(rel8_at "$_hex" $(( _j + 1 )))
		_jt=$(( FUNC_ADDR + _j + 2 + _rel ))
	else
		DECIDE_REASON="no conditional jump after 'testb %al,%al' at $(hexaddr $(( FUNC_ADDR + _t ))); unexpected layout"
		return 1
	fi
	_boff=$(( _jt - FUNC_ADDR ))
	if [ "$_boff" -lt 0 ] || [ "$_boff" -ge "$_n" ]; then
		DECIDE_REASON="the insert-failure jump targets $(hexaddr "$_jt"), outside reqsk_timer_handler"
		return 1
	fi
	ev "    je insert-failure branch -> $(hexaddr "$_jt")"

	# 4. the value loaded into %edx at the start of that branch
	_pat=$(get_hex "$_hex" "$_boff" 5)
	_edx_off=""
	_edx_desc=""
	_edx_len=0
	if [ "${_pat:0:10}" = "ba01000000" ]; then
		_edx_off=$_boff; _edx_desc="movl \$0x1,%edx"; _edx_len=5
	elif [ "${_pat:0:4}" = "31d2" ]; then
		_edx_off=$_boff; _edx_desc="xorl %edx,%edx"; _edx_len=2
	elif [ "${_pat:0:10}" = "ba00000000" ]; then
		_edx_off=$_boff; _edx_desc="movl \$0x0,%edx"; _edx_len=5
	else
		# Some compilers put a register move or a nop before the load.  Look
		# a short way into the branch, but only accept a load of %edx.
		_k=$_boff
		while [ "$_k" -lt $(( _boff + 24 )) ] && [ "$_k" -lt "$_n" ]; do
			_p=$(get_hex "$_hex" "$_k" 5)
			if [ "${_p:0:10}" = "ba01000000" ]; then _edx_off=$_k; _edx_desc="movl \$0x1,%edx"; _edx_len=5; break; fi
			if [ "${_p:0:4}" = "31d2" ]; then _edx_off=$_k; _edx_desc="xorl %edx,%edx"; _edx_len=2; break; fi
			if [ "${_p:0:10}" = "ba00000000" ]; then _edx_off=$_k; _edx_desc="movl \$0x0,%edx"; _edx_len=5; break; fi
			_k=$((_k + 1))
		done
		if [ -z "$_edx_off" ]; then
			DECIDE_REASON="the insert-failure branch at $(hexaddr "$_jt") does not load %edx with the expected movl/xorl; raw bytes: $(spaced_hex "$_hex" "$_boff" 12)"
			return 1
		fi
		ev "    (edx load found at +$((_edx_off - _boff)) from the branch target)"
	fi
	DECIDE_DESC=$_edx_desc
	DECIDE_SITE=$(( FUNC_ADDR + _boff ))

	# 5. the call to __inet_csk_reqsk_queue_drop in that branch
	_all_drop=$(find_call_sites "$_hex" "$FUNC_ADDR" "$DROP_ADDR" "$_n")
	_call_off=$(printf '%s\n' "$_all_drop" | awk -v p="$_edx_off" '$1 >= p && $1 <= p + 48 { print; exit }')
	if [ -z "$_call_off" ]; then
		DECIDE_REASON="the insert-failure branch at $(hexaddr "$_jt") does not call __inet_csk_reqsk_queue_drop within 48 bytes"
		return 1
	fi

	# 6. print the deciding block: raw bytes first, then the instructions we
	#    actually decoded.  Nothing here is inferred beyond the matched bytes.
	ev "    deciding site $(hexaddr "$DECIDE_SITE") (start of the insert-failure branch):"
	ev "      raw: $(spaced_hex "$_hex" "$_edx_off" $(( _call_off + 5 - _edx_off )))"
	ev_instr "$_hex" "$_edx_off" 5 "# the deciding argument"
	_i=$(( _edx_off + _edx_len ))
	while [ "$_i" -lt "$_call_off" ]; do
		_b=$(get_hex "$_hex" "$_i" 1)
		case "$_b" in
		4c|48|49|4d)
			if [ "$(get_hex "$_hex" $(( _i + 1 )) 1)" = "89" ]; then
				ev_instr "$_hex" "$_i" 3 ""
				_i=$(( _i + 3 ))
			else
				_i=$(( _i + 1 ))
			fi
			;;
		*) _i=$(( _i + 1 )) ;;
		esac
	done
	ev_instr "$_hex" "$_call_off" 5 "# the deciding call"
	if [ "$(get_hex "$_hex" $(( _call_off + 5 )) 1)" = "e9" ]; then
		ev_instr "$_hex" $(( _call_off + 5 )) 5 "# post-drop jump (the no_ownership path in these kernels)"
	fi

	# 6. corroboration: the same register supplies nreq to inet_ehash_insert
	#    (as %rdi) and to the deciding drop call (as %rsi).
	_ehis_mov=$(find_mov_before "$_hex" $(( _ehis_off - 12 )) $(( _ehis_off - 1 )) 7)
	_drop_mov=$(find_mov_before "$_hex" $(( _call_off - 12 )) $(( _call_off - 1 )) 6)
	if [ -n "$_ehis_mov" ] && [ -n "$_drop_mov" ]; then
		if [ "$_ehis_mov" = "$_drop_mov" ]; then
			ev "    corroboration: %r$_ehis_mov is rdi (nreq) at inet_ehash_insert and rsi (nreq) at the drop call"
		else
			ev "    caution: rdi at inet_ehash_insert is %r$_ehis_mov but rsi at the drop call is %r$_drop_mov; the call is still the one reached from the insert-failure branch"
		fi
	fi

	# 7. the value itself
	case "$_edx_desc" in
	"movl \$0x1,%edx")
		EDXVAL=1
		KVERDICT="VULNERABLE"
		ev "    third argument (from_timer) = 1: timer_delete_sync() is skipped and the clone is freed with rsk_timer armed"
		;;
	"xorl %edx,%edx"|"movl \$0x0,%edx")
		EDXVAL=0
		KVERDICT="PATCHED"
		ev "    third argument (from_timer) = 0: timer_delete_sync() runs before the clone is freed"
		;;
	*)
		DECIDE_REASON="could not decode the %edx load at $(hexaddr $(( FUNC_ADDR + _edx_off )))"
		return 1
		;;
	esac

	# 8. show every other call to the same function, so the discriminator is
	#    explicit: the `drop:`-label call passes 1 in BOTH kernels.
	_n_other=0
	for _o in $_all_drop; do
		[ "$_o" = "$_call_off" ] && continue
		_n_other=$((_n_other + 1))
		[ "$_n_other" -gt 3 ] && break
		_pre=""
		_k=$(( _o - 12 )); [ "$_k" -lt 0 ] && _k=0
		while [ "$_k" -lt "$_o" ]; do
			if [ "${_pre}" = "" ] && [ "$(get_hex "$_hex" "$_k" 5)" = "ba01000000" ]; then _pre="edx=1 (movl \$0x1,%edx)"; fi
			if [ "${_pre}" = "" ] && [ "$(get_hex "$_hex" "$_k" 2)" = "31d2" ]; then _pre="edx=0 (xorl %edx,%edx)"; fi
			_k=$((_k + 1))
		done
		[ -n "$_pre" ] || _pre="edx load not within the preceding 12 bytes"
		ev "    other call to __inet_csk_reqsk_queue_drop at $(hexaddr $(( FUNC_ADDR + _o ))): $_pre -- this is the 'drop:'-label call on the original request, not decisive"
	done

	# 9. supporting evidence: __inet_csk_reqsk_queue_drop really gates
	#    timer_delete_sync on that argument.
	if [ -n "${KERNEL_FILE:-}" ]; then
		_gate_off=$(map_vaddr "$KERNEL_FILE" "$DROP_ADDR" 2>/dev/null) || _gate_off=""
		if [ -n "$_gate_off" ]; then
			_gate_hex=$(hex_at "$KERNEL_FILE" "$_gate_off" 128)
			case "$_gate_hex" in
			*4189d5*) _g1=1 ;;
			*) _g1=0 ;;
			esac
			case "$_gate_hex" in
			*4584ed*) _g2=1 ;;
			*) _g2=0 ;;
			esac
			if [ "$_g1" = 1 ] && [ "$_g2" = 1 ]; then
				ev "    gate confirmed in __inet_csk_reqsk_queue_drop: movl %edx,%r13d ... testb %r13b,%r13b; je <timer_delete_sync path>"
			else
				ev "    gate not visible in the first 128 bytes of __inet_csk_reqsk_queue_drop (from_timer is still the third argument by the x86-64 ABI)"
			fi
		fi
	fi

	return 0
}

# ---------------------------------------------------------------------------
# image analysis
# ---------------------------------------------------------------------------
KERNEL_FILE=""

decide_from_image() { # image description
	_img=$1
	_desc=$2
	DECIDE_REASON=""
	_map=""
	MAP_DESC=""

	if [ -n "$OPT_SYMBOLS" ]; then
		if [ -r "$OPT_SYMBOLS" ]; then
			_map=$OPT_SYMBOLS
			MAP_DESC=$OPT_SYMBOLS
		elif [ -e "$OPT_SYMBOLS" ]; then
			DECIDE_REASON="--symbols file is present but not readable: $(unreadable_file_msg "$OPT_SYMBOLS")"
			return 1
		else
			DECIDE_REASON="--symbols file does not exist: $OPT_SYMBOLS"
			return 1
		fi
	fi

	if [ -z "$_map" ] && command -v nm >/dev/null 2>&1; then
		nm -n "$_img" 2>/dev/null \
			| awk 'NF == 3 && $1 ~ /^[0-9a-fA-F]+$/ { print $1, $2, $3 }' \
			> "$TMP/nm.map"
		if [ -n "$(sym_addr reqsk_timer_handler "$TMP/nm.map")" ]; then
			_map=$TMP/nm.map
			MAP_DESC="the image's own symbol table (nm -n)"
			ev "  symbol map: the image's own symbol table (nm -n)"
		fi
	fi

	if [ -z "$_map" ]; then
		_seen_map_unreadable=""
		for _m in \
			"$OPT_BOOT/System.map-$(uname -r 2>/dev/null)" \
			"$OPT_BOOT/System.map" \
			"/lib/modules/$(uname -r 2>/dev/null)/System.map" \
			"/usr/lib/debug/boot/System.map-$(uname -r 2>/dev/null)"
		do
			if [ -n "$_m" ] && [ -r "$_m" ]; then
				_map=$_m
				MAP_DESC=$_m
				ev "  symbol map: $_m"
				break
			fi
			# Present but unreadable is not the same as absent: say which.
			if [ -n "$_m" ] && [ -e "$_m" ] && [ -z "$_seen_map_unreadable" ]; then
				_seen_map_unreadable=$_m
			fi
		done
	fi

	if [ -z "$_map" ]; then
		if [ -n "$_seen_map_unreadable" ]; then
			DECIDE_REASON="no readable symbol map for $_img: $(unreadable_file_msg "$_seen_map_unreadable")"
		else
			DECIDE_REASON="no symbol map for $_img: the image is stripped and no System.map-$(uname -r) was found; pass --symbols FILE"
		fi
		return 1
	fi

	FUNC_ADDR=$(sym_addr reqsk_timer_handler "$_map")
	DROP_ADDR=$(sym_addr __inet_csk_reqsk_queue_drop "$_map")
	EHIS_ADDR=$(sym_addr inet_ehash_insert "$_map")
	for _pair in "reqsk_timer_handler:$FUNC_ADDR" "__inet_csk_reqsk_queue_drop:$DROP_ADDR" "inet_ehash_insert:$EHIS_ADDR"; do
		_name=${_pair%%:*}
		_val=${_pair#*:}
		if ! valid_addr "$_val"; then
			DECIDE_REASON="symbol $_name is missing or zero in $_map (kernel built without CONFIG_KALLSYMS, or the map is for a different build)"
			return 1
		fi
	done

	_next=$(next_text_addr "$FUNC_ADDR" "$_map")
	if ! valid_addr "$_next"; then
		_next=$(( 16#$FUNC_ADDR + 8192 ))
	fi
	_size=$(( 16#$_next - 16#$FUNC_ADDR ))
	if [ "$_size" -le 0 ] || [ "$_size" -gt 65536 ]; then
		_size=8192
	fi

	_cls=$(hex_at "$_img" 4 1)
	_mach=$(u16le "$_img" 18)
	if [ "$_cls" != "02" ]; then
		DECIDE_REASON="$_img is not an ELFCLASS64 image (e_ident[EI_CLASS]=$_cls); only 64-bit kernels are handled"
		return 1
	fi
	if [ "$_mach" != "62" ]; then
		DECIDE_REASON="$_img is not an x86-64 image (e_machine=$_mach); the instruction decoding is x86-64 specific"
		return 1
	fi
	_off=$(map_vaddr "$_img" "$FUNC_ADDR") || {
		DECIDE_REASON="no PT_LOAD or SHT_PROGBITS region in $_img covers reqsk_timer_handler at 0x$FUNC_ADDR; the symbol map does not match this image"
		return 1
	}
	_hex=$(hex_at "$_img" "$_off" "$_size")
	if [ ${#_hex} -ne $(( _size * 2 )) ]; then
		DECIDE_REASON="short read of reqsk_timer_handler from $_img (wanted $_size bytes, got $(( ${#_hex} / 2 )))"
		return 1
	fi

	ev "  host kernel: $(uname -r 2>/dev/null || echo unknown)"
	ev "  image: $_desc"
	ev "  reqsk_timer_handler: 0x$FUNC_ADDR (size 0x$(printf '%x' "$_size"))"
	ev "  inet_ehash_insert: 0x$EHIS_ADDR"
	ev "  __inet_csk_reqsk_queue_drop: 0x$DROP_ADDR"

	KERNEL_FILE=$_img
	decide_from_bytes "$_hex" "$((16#$FUNC_ADDR))" "$((16#$DROP_ADDR))" "$((16#$EHIS_ADDR))" "$_size"
	_rc=$?
	if [ "$_rc" -eq 0 ]; then
		KMETHOD="decided from $_desc with symbol map $MAP_DESC"
		return 0
	fi
	return 1
}

decide_from_kcore() {
	DECIDE_REASON=""
	_kcore="$OPT_PROC/kcore"
	_kallsyms="$OPT_PROC/kallsyms"
	_kptr=$(cat "$OPT_PROC/sys/kernel/kptr_restrict" 2>/dev/null || echo "?")

	if [ ! -r "$_kcore" ]; then
		DECIDE_REASON="no readable $_kcore (mode 0400 root:root; needs root or CAP_SYS_RAWIO)"
		return 1
	fi
	if [ ! -r "$_kallsyms" ]; then
		DECIDE_REASON="no readable $_kallsyms"
		return 1
	fi

	FUNC_ADDR=$(sym_addr reqsk_timer_handler "$_kallsyms")
	DROP_ADDR=$(sym_addr __inet_csk_reqsk_queue_drop "$_kallsyms")
	EHIS_ADDR=$(sym_addr inet_ehash_insert "$_kallsyms")
	for _pair in "reqsk_timer_handler:$FUNC_ADDR" "__inet_csk_reqsk_queue_drop:$DROP_ADDR" "inet_ehash_insert:$EHIS_ADDR"; do
		_name=${_pair%%:*}
		_val=${_pair#*:}
		if ! valid_addr "$_val"; then
			if [ "$_kptr" = "2" ]; then
				DECIDE_REASON="$_kallsyms has no usable address for $_name (kptr_restrict=2 hides addresses from everyone; use the /boot image with System.map instead)"
			else
				DECIDE_REASON="$_kallsyms has no usable address for $_name (kptr_restrict=$_kptr; run as root or with CAP_SYSLOG)"
			fi
			return 1
		fi
	done

	_next=$(next_text_addr "$FUNC_ADDR" "$_kallsyms")
	if ! valid_addr "$_next"; then
		_next=$(( 16#$FUNC_ADDR + 8192 ))
	fi
	_size=$(( 16#$_next - 16#$FUNC_ADDR ))
	if [ "$_size" -le 0 ] || [ "$_size" -gt 65536 ]; then
		_size=8192
	fi

	_cls=$(hex_at "$_kcore" 4 1)
	_mach=$(u16le "$_kcore" 18)
	if [ "$_cls" != "02" ] || [ "$_mach" != "62" ]; then
		DECIDE_REASON="$_kcore is not an x86-64 ELF64 core (class=$_cls machine=$_mach); this check decodes x86-64 instructions only"
		return 1
	fi
	_off=$(map_vaddr "$_kcore" "$FUNC_ADDR") || {
		DECIDE_REASON="$_kcore has no PT_LOAD segment covering reqsk_timer_handler at 0x$FUNC_ADDR (KASLR mismatch or an unusual kcore layout)"
		return 1
	}
	_hex=$(hex_at "$_kcore" "$_off" "$_size")
	if [ ${#_hex} -ne $(( _size * 2 )) ]; then
		DECIDE_REASON="short read of reqsk_timer_handler from $_kcore (wanted $_size bytes, got $(( ${#_hex} / 2 )))"
		return 1
	fi

	ev "  host kernel: $(uname -r 2>/dev/null || echo unknown)"
	ev "  source: live $_kcore at runtime address 0x$FUNC_ADDR"
	ev "  reqsk_timer_handler: 0x$FUNC_ADDR (size 0x$(printf '%x' "$_size"))"
	ev "  inet_ehash_insert: 0x$EHIS_ADDR"
	ev "  __inet_csk_reqsk_queue_drop: 0x$DROP_ADDR"
	ev "  kptr_restrict=$_kptr"

	KERNEL_FILE=$_kcore
	decide_from_bytes "$_hex" "$((16#$FUNC_ADDR))" "$((16#$DROP_ADDR))" "$((16#$EHIS_ADDR))" "$_size"
	_rc=$?
	if [ "$_rc" -eq 0 ]; then
		SOURCE_WAS_KCORE=1
		KMETHOD="decided from live $_kcore (runtime text at $(hexaddr "$((16#$FUNC_ADDR))"))"
		return 0
	fi
	return 1
}

# ---------------------------------------------------------------------------
# container detection
# ---------------------------------------------------------------------------
CONTAINER="no"
CONTAINER_WHY=""
HOST_REASON=""
SOURCE_WAS_KCORE=0

detect_container() {
	CONTAINER="no"
	CONTAINER_WHY=""
	if [ -e /.dockerenv ]; then CONTAINER="yes"; CONTAINER_WHY="/.dockerenv"; return; fi
	if [ -e /run/.containerenv ]; then CONTAINER="yes"; CONTAINER_WHY="/run/.containerenv"; return; fi
	if [ -r "$OPT_PROC/1/cgroup" ] && grep -Eqi '(docker|kubepods|containerd|lxc|podman|garden|libpod)' "$OPT_PROC/1/cgroup" 2>/dev/null; then
		CONTAINER="yes"; CONTAINER_WHY="$OPT_PROC/1/cgroup"; return
	fi
	if command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt --container --quiet >/dev/null 2>&1; then
		CONTAINER="yes"; CONTAINER_WHY="systemd-detect-virt"; return
	fi
}

# ---------------------------------------------------------------------------
# network-namespace scope of the reachability inputs
# ---------------------------------------------------------------------------
# In a container the kernel verdict can come from the host's live text
# (/proc/kcore is shared with the host), while ss, bpftool and
# net.ipv4.tcp_migrate_req are all per-network-namespace -- the container's,
# not the node's.  A "no group" answer then says nothing about the node.
set_netns_scope() {
	NETNS_SCOPE="host"
	NETNS_SCOPE_WHY=""
	[ "$CONTAINER" = "yes" ] || return 0
	[ "$SOURCE_WAS_KCORE" = "1" ] || return 0
	if [ "$OPT_ASSUME_HOST_NETNS" = 1 ]; then
		NETNS_SCOPE="host-asserted"
		NETNS_SCOPE_WHY="the host network namespace, asserted by --assume-host-netns"
	else
		NETNS_SCOPE="ambiguous"
		NETNS_SCOPE_WHY="these listeners and tcp_migrate_req are this container's network namespace, not the node's (the kernel verdict came from the host's $OPT_PROC/kcore, but ss, bpftool and net.ipv4.tcp_migrate_req are per-network-namespace)"
	fi
}

# ---------------------------------------------------------------------------
# reachability
# ---------------------------------------------------------------------------
check_reachability() {
	# --- SO_REUSEPORT group ------------------------------------------------
	R_GROUP="UNKNOWN"; R_GROUP_WHY=""; R_GROUP_EVID=""
	if ! command -v ss >/dev/null 2>&1; then
		R_GROUP_WHY="ss is not installed (iproute2); cannot enumerate listening TCP sockets"
	else
		_ss_out=$(ss -tlnpe 2>"$TMP/ss.err")
		_ss_rc=$?
		# A partial or failed listing must never read as "no group".  Require a
		# clean exit AND the header line that a complete socket table starts
		# with; anything else is UNKNOWN, not a negative.
		_ss_hdr=0
		if printf '%s\n' "$_ss_out" | grep -q '^State'; then _ss_hdr=1; fi
		if [ "$_ss_rc" -ne 0 ]; then
			R_GROUP="UNKNOWN"
			R_GROUP_WHY="ss -tlnpe failed (exit $_ss_rc): $(head -n 1 "$TMP/ss.err" 2>/dev/null); the listing is partial, so it cannot show that no SO_REUSEPORT group exists"
		elif [ "$_ss_hdr" != "1" ]; then
			R_GROUP="UNKNOWN"
			R_GROUP_WHY="ss -tlnpe printed no 'State' header line; the output is not a complete socket table, so it cannot show that no SO_REUSEPORT group exists"
		else
			_marker=$(printf '%s\n' "$_ss_out" | grep -ci 'reuseport' || true)
			# Two LISTEN sockets on the same exact local address:port require
			# SO_REUSEPORT; this catches groups even when this ss build does
			# not print a literal 'reuseport' marker.  IPv4/IPv6 dual-stack
			# pairs have different local addresses and are not counted.
			_dups=$(printf '%s\n' "$_ss_out" | awk '
				NF >= 4 && $1 == "LISTEN" {
					loc = $4
					if (loc ~ /^\[/ || loc ~ /:/) { c[loc]++ }
				}
				END { for (k in c) if (c[k] > 1) printf "%d %s\n", c[k], k }
			' | sort -rn | head -n 3)
			if [ "$_marker" -gt 0 ]; then
				R_GROUP="yes"
				R_GROUP_WHY="$_marker line(s) in ss -tlnpe carry the 'reuseport' marker"
				R_GROUP_EVID=$(printf '%s\n' "$_ss_out" | grep -i 'reuseport' | head -n 3)
			elif [ -n "$_dups" ]; then
				R_GROUP="yes"
				R_GROUP_WHY="the same local address:port is bound by more than one LISTEN socket, which requires SO_REUSEPORT"
				R_GROUP_EVID=$_dups
			else
				R_GROUP="no"
				R_GROUP_WHY="no 'reuseport' marker and no duplicate exact local address:port in ss -tlnpe"
			fi
			if [ "$(id -u 2>/dev/null || echo 0)" != "0" ]; then
				R_GROUP_WHY="$R_GROUP_WHY (non-root: process names and some sockets may be hidden; the socket list itself is visible)"
			fi
		fi
	fi

	# --- BPF sk_reuseport program ------------------------------------------
	R_BPF="UNKNOWN"; R_BPF_WHY=""
	if ! command -v bpftool >/dev/null 2>&1; then
		R_BPF_WHY="bpftool is not installed; cannot determine whether a BPF_PROG_TYPE_SK_REUSEPORT program is attached"
	else
		# `bpftool prog show type sk_reuseport` is rejected by bpftool v7.7.0
		# ("expected 'id', 'tag', 'name' or 'pinned'"), so ask for the full
		# listing and grep the type field.
		_bpf_out=$(bpftool prog show 2>"$TMP/bpf.err")
		_bpf_rc=$?
		if [ "$_bpf_rc" -ne 0 ]; then
			R_BPF_WHY="bpftool prog show failed (exit $_bpf_rc): $(head -n 1 "$TMP/bpf.err" 2>/dev/null) (root/CAP_BPF needed to see all programs)"
		else
			_bpf_n=$(printf '%s\n' "$_bpf_out" | grep -cE 'type[[:space:]]+sk_reuseport' || true)
			if [ "$_bpf_n" -gt 0 ]; then
				R_BPF="yes"
				R_BPF_WHY="$_bpf_n BPF program(s) of type sk_reuseport in bpftool prog show"
			else
				R_BPF="no"
				R_BPF_WHY="no 'type sk_reuseport' program in the bpftool prog show listing"
			fi
		fi
	fi

	# --- tcp_migrate_req ---------------------------------------------------
	R_MIGRATE="UNKNOWN"; R_MIGRATE_WHY=""
	_mig="$OPT_PROC/sys/net/ipv4/tcp_migrate_req"
	if [ -r "$_mig" ]; then
		_migv=$(cat "$_mig" 2>/dev/null | tr -d ' \n')
		case "$_migv" in
		0|1)
			R_MIGRATE=$_migv
			if [ "$_migv" = 1 ]; then
				R_MIGRATE_WHY="request migration is enabled"
			else
				R_MIGRATE_WHY="request migration is disabled (the default)"
			fi
			;;
		*)
			R_MIGRATE="UNKNOWN"
			R_MIGRATE_WHY="unexpected value '$_migv' in $_mig"
			;;
		esac
	elif [ -e "$_mig" ]; then
		R_MIGRATE="UNKNOWN"
		R_MIGRATE_WHY="$_mig exists but is not readable (permission)"
	else
		R_MIGRATE="absent"
		R_MIGRATE_WHY="$_mig is not present (this kernel or network namespace does not expose request migration, which is equivalent to disabled for this path)"
	fi
}

# ---------------------------------------------------------------------------
# exposure decision
# ---------------------------------------------------------------------------
decide_exposure() {
	decide_exposure_core
	# A reachability-derived NOT EXPOSED is only about the namespace ss and
	# tcp_migrate_req described.  When that namespace is a container's rather
	# than the node's, refuse the confident negative; EXPOSED is kept, because
	# the container's own group with migration enabled is still a real path
	# through the vulnerable kernel, and suppressing an alarm is the one thing
	# that must never happen.
	[ "$KVERDICT" = "VULNERABLE" ] || return 0
	case "$NETNS_SCOPE" in
	ambiguous)
		if [ "$EXPOSURE" = "NOT EXPOSED" ]; then
			EXPOSURE="UNKNOWN"
			EXPOSURE_REASON="$EXPOSURE_REASON; but $NETNS_SCOPE_WHY, so this does not rule out exposure on the node. Re-run on the node, or pass --assume-host-netns if this container was started with --net=host"
		elif [ -n "$EXPOSURE_REASON" ]; then
			EXPOSURE_REASON="$EXPOSURE_REASON (scope: $NETNS_SCOPE_WHY)"
		fi
		;;
	host-asserted)
		EXPOSURE_REASON="$EXPOSURE_REASON (scope: $NETNS_SCOPE_WHY)"
		;;
	esac
}

decide_exposure_core() {
	if [ "$KVERDICT" = "PATCHED" ]; then
		EXPOSURE="NOT EXPOSED"
		EXPOSURE_REASON="the kernel carries the fix (from_timer=0 at the deciding call); the timer is deleted before the clone is freed"
		return
	fi
	if [ "$KVERDICT" = "UNDETERMINED" ]; then
		EXPOSURE="UNKNOWN"
		EXPOSURE_REASON="the kernel verdict is UNDETERMINED ($KMETHOD_REASONS)"
		return
	fi

	# VULNERABLE from here down.
	if [ "$R_GROUP" = "no" ]; then
		EXPOSURE="NOT EXPOSED"
		EXPOSURE_REASON="no SO_REUSEPORT group on any listening TCP port, so reqsk_timer_handler takes the non-migration path and never clones the request"
		return
	fi
	if [ "$R_GROUP" = "UNKNOWN" ]; then
		EXPOSURE="UNKNOWN"
		EXPOSURE_REASON="cannot determine whether a SO_REUSEPORT group exists: $R_GROUP_WHY"
		return
	fi

	# A group exists.
	if [ "$R_MIGRATE" = "1" ]; then
		EXPOSURE="EXPOSED"
		EXPOSURE_REASON="vulnerable kernel + a SO_REUSEPORT group + tcp_migrate_req=1"
		return
	fi
	if [ "$R_BPF" = "yes" ]; then
		EXPOSURE="EXPOSED"
		EXPOSURE_REASON="vulnerable kernel + a SO_REUSEPORT group + an attached BPF_PROG_TYPE_SK_REUSEPORT program"
		return
	fi
	if [ "$R_MIGRATE" = "0" ] || [ "$R_MIGRATE" = "absent" ]; then
		if [ "$R_BPF" = "no" ]; then
			EXPOSURE="NOT EXPOSED"
			EXPOSURE_REASON="vulnerable kernel and a SO_REUSEPORT group exist, but migration is disabled (tcp_migrate_req=$R_MIGRATE) and no sk_reuseport program is attached"
			return
		fi
		EXPOSURE="UNKNOWN"
		EXPOSURE_REASON="migration is disabled by sysctl (tcp_migrate_req=$R_MIGRATE), but bpftool is unavailable, so a sk_reuseport program cannot be ruled out"
		return
	fi
	# migrate unknown
	if [ "$R_BPF" = "no" ]; then
		EXPOSURE="UNKNOWN"
		EXPOSURE_REASON="cannot read net.ipv4.tcp_migrate_req ($R_MIGRATE_WHY) and no sk_reuseport program is attached; if the value is 1 the host is exposed"
	else
		EXPOSURE="UNKNOWN"
		EXPOSURE_REASON="cannot read net.ipv4.tcp_migrate_req ($R_MIGRATE_WHY) and cannot rule out a sk_reuseport program"
	fi
}

# ---------------------------------------------------------------------------
# main analysis
# ---------------------------------------------------------------------------
analyse_kernel() {
	KVERDICT="UNDETERMINED"
	KMETHOD=""
	KMETHOD_REASONS=""
	: > "$EVID"

	[ -n "$HOST_REASON" ] && add_reason "$HOST_REASON"

	_kind=""
	_img=""
	_desc=""

	if [ -n "$OPT_VMLINUX" ]; then
		if [ -r "$OPT_VMLINUX" ]; then
			_kind="vmlinux"; _img=$OPT_VMLINUX; _desc="$OPT_VMLINUX (already-decompressed kernel ELF)"
		else
			add_reason "--vmlinux file is not readable: $OPT_VMLINUX"
		fi
	elif [ -n "$OPT_IMAGE" ]; then
		if [ -r "$OPT_IMAGE" ]; then
			_kind="image"; _img=$OPT_IMAGE; _desc="$OPT_IMAGE"
		else
			add_reason "--image file is not readable: $OPT_IMAGE"
		fi
	else
		_rel=$(uname -r 2>/dev/null || echo "")
		_seen_unreadable=""
		for _c in \
			"$OPT_BOOT/vmlinuz-$_rel" \
			"$OPT_BOOT/vmlinuz" \
			"$OPT_BOOT/vmlinux-$_rel" \
			"/usr/lib/modules/$_rel/vmlinuz" \
			"/lib/modules/$_rel/vmlinuz" \
			"/usr/lib/debug/boot/vmlinux-$_rel"
		do
			if [ -n "$_c" ] && [ -r "$_c" ]; then
				_kind="image"; _img=$_c; _desc=$_c
				break
			fi
			# Present but unreadable is not the same as absent: say which.
			if [ -n "$_c" ] && [ -e "$_c" ] && [ -z "$_seen_unreadable" ]; then
				_seen_unreadable=$_c
			fi
		done
		if [ -z "$_kind" ]; then
			if [ -n "$_seen_unreadable" ]; then
				add_reason "no readable /boot kernel image: $(unreadable_file_msg "$_seen_unreadable")"
			else
				add_reason "no /boot kernel image (looked for $OPT_BOOT/vmlinuz-$_rel, /lib/modules/$_rel/vmlinuz, ...)"
			fi
		fi
	fi

	if [ -n "$_kind" ]; then
		if is_elf "$_img"; then
			KERNEL_FILE=$_img
		else
			ev "  extracting the compressed image into a private temp directory"
			if extract_vmlinux "$_img" "$TMP/vmlinux"; then
				KERNEL_FILE=$TMP/vmlinux
				_desc="$_desc (decompressed locally)"
			else
				add_reason "could not extract a vmlinux ELF from $_img: $EXTRACT_WHY"
				KERNEL_FILE=""
			fi
		fi
		if [ -n "$KERNEL_FILE" ]; then
			if decide_from_image "$KERNEL_FILE" "$_desc"; then
				return 0
			fi
			add_reason "$DECIDE_REASON"
		fi
		# An explicitly supplied image is never silently replaced by another
		# source: the operator asked about that image.
		if [ -n "$OPT_VMLINUX" ] || [ -n "$OPT_IMAGE" ]; then
			KMETHOD="UNDETERMINED: $KMETHOD_REASONS"
			return 1
		fi
	fi

	# Default mode only: fall back to the live kernel.
	if [ -z "$OPT_VMLINUX" ] && [ -z "$OPT_IMAGE" ]; then
		ev "  falling back to the live kernel via $OPT_PROC/kcore"
		if decide_from_kcore; then
			return 0
		fi
		add_reason "$DECIDE_REASON"
	fi

	# Every container case, not only the one where /boot was absent: a
	# readable-but-unusable /boot used to suppress this hint.
	if [ "$CONTAINER" = "yes" ]; then
		add_reason "run this on the node, not in a pod (container detected via $CONTAINER_WHY)"
	fi

	[ -n "$KMETHOD_REASONS" ] || KMETHOD_REASONS="no usable kernel image or live kernel text"
	KMETHOD="UNDETERMINED: $KMETHOD_REASONS"
	return 1
}

# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
print_report() {
	say "kernel-check.sh $VERSION -- request-sock timer UAF (upstream 97c8a3c1f73d)"
	say "date: $(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo unknown)  host: $(hostname 2>/dev/null || echo unknown)  kernel: $(uname -sr 2>/dev/null || echo unknown)"
	if [ "$CONTAINER" = "yes" ]; then
		say "container: yes ($CONTAINER_WHY)"
		if [ "$SOURCE_WAS_KCORE" = "1" ]; then
			say "  note: a container shares the host kernel; the verdict below is read from the host's live text."
		fi
		# Every container case, not only the one with no usable /boot.
		say "  note: run this on the node, not in a pod -- /boot and /proc/kcore describe the host, but ss, bpftool and tcp_migrate_req describe this container's network namespace."
	else
		say "container: no"
	fi
	say ""

	section "1) KERNEL FIX VERDICT"
	say "   $KVERDICT"
	say "   Method: $KMETHOD"
	if [ "$KVERDICT" != "UNDETERMINED" ]; then
		say "   Deciding instruction: $DECIDE_DESC at $(hexaddr "$DECIDE_SITE") (third argument from_timer=$EDXVAL) in the !inet_ehash_insert failure branch"
	fi
	say ""
	say "   Evidence:"
	if [ -s "$EVID" ]; then
		sed 's/^/   /' "$EVID"
	else
		say "     (none)"
	fi

	section "2) REACHABILITY"
	if [ "$NETNS_SCOPE" != "host" ]; then
		say "   scope: $NETNS_SCOPE_WHY"
	fi
	say "   SO_REUSEPORT group: $R_GROUP"
	say "     $R_GROUP_WHY"
	if [ -n "$R_GROUP_EVID" ]; then
		printf '%s\n' "$R_GROUP_EVID" | sed 's/^/       /' | head -n 3
	fi
	say "   BPF sk_reuseport program: $R_BPF"
	say "     $R_BPF_WHY"
	say "   net.ipv4.tcp_migrate_req: $R_MIGRATE"
	say "     $R_MIGRATE_WHY"

	section "3) EXPOSURE"
	say "   $EXPOSURE -- $EXPOSURE_REASON"

	if [ "$OPT_DEBUG" = 1 ]; then
		say ""
		say "debug: temp=$TMP kernel_file=${KERNEL_FILE:-none}"
	fi
	say ""
	say "Read-only: no module loads, no sysctl writes, no /proc or /sys writes."
	if [ "$OPT_KEEP_TEMP" = 1 ] && [ -n "$TMP" ]; then
		say "Private temp directory kept: $TMP"
	else
		say "Private temp directory removed on exit."
	fi
	say "Exit: 0 EXPOSED, 1 NOT EXPOSED, 2 UNKNOWN/UNDETERMINED, 3 usage error."
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
			-h|--help)
				usage
				exit 0
				;;
			--image)
				need_arg "$1" "${2:-}"
				OPT_IMAGE=$2
				shift 2
				;;
			--vmlinux)
				need_arg "$1" "${2:-}"
				OPT_VMLINUX=$2
				shift 2
				;;
			--symbols)
				need_arg "$1" "${2:-}"
				OPT_SYMBOLS=$2
				shift 2
				;;
			--proc-root)
				need_arg "$1" "${2:-}"
				OPT_PROC=$2
				shift 2
				;;
			--boot-root)
				need_arg "$1" "${2:-}"
				OPT_BOOT=$2
				shift 2
				;;
			--keep-temp)
				OPT_KEEP_TEMP=1
				shift
				;;
			--debug)
				OPT_DEBUG=1
				shift
				;;
			--no-reachability)
				OPT_REACH=0
				shift
				;;
			--assume-host-netns)
				OPT_ASSUME_HOST_NETNS=1
				shift
				;;
			--)
				shift
				break
				;;
			*)
				say "kernel-check.sh: unknown option '$1'" >&2
				say "Try --help." >&2
				exit 3
				;;
		esac
	done

	[ "$OPT_DEBUG" = 1 ] && OPT_KEEP_TEMP=1

	_tmpbase=${TMPDIR:-/tmp}
	_tmpbase=${_tmpbase%/}
	TMP=$(mktemp -d "$_tmpbase/kernel-check.XXXXXX" 2>/dev/null) || {
		say "kernel-check.sh: cannot create a private temp directory" >&2
		exit 2
	}
	EVID="$TMP/evidence.txt"
	: > "$EVID"

	cleanup() {
		if [ "$OPT_KEEP_TEMP" = 1 ]; then
			say "kernel-check.sh: temp directory kept at $TMP" >&2
		else
			rm -rf "$TMP" 2>/dev/null
		fi
	}
	trap cleanup EXIT INT TERM HUP

	detect_container

	if [ "$(uname -s 2>/dev/null || echo unknown)" != "Linux" ]; then
		HOST_REASON="host is $(uname -s 2>/dev/null || echo unknown), not Linux; this script inspects Linux kernels"
	fi

	if analyse_kernel; then
		:
	else
		# KMETHOD already carries the reasons.
		:
	fi

	set_netns_scope

	if [ "$OPT_REACH" = 1 ]; then
		check_reachability
	else
		R_GROUP="UNKNOWN"; R_GROUP_WHY="--no-reachability was given"
		R_BPF="UNKNOWN"; R_BPF_WHY="--no-reachability was given"
		R_MIGRATE="UNKNOWN"; R_MIGRATE_WHY="--no-reachability was given"
	fi

	decide_exposure
	print_report

	case "$EXPOSURE" in
	EXPOSED) exit 0 ;;
	"NOT EXPOSED") exit 1 ;;
	*) exit 2 ;;
	esac
}

main "$@"
