# reqsk-uaf-check

A read-only check for a Linux kernel request-socket use-after-free, fixed upstream by commit
`97c8a3c1f73d828de43a5a88e8a9a143efb2b661` ("tcp: Fix potential UAF in reqsk_timer_handler()").

It tells you whether **your** kernel carries the fix. It does not scan anything remote, install
anything, or write outside a private temporary directory.

## The defect

`reqsk_timer_handler()` clones a request socket when it migrates it to a surviving `SO_REUSEPORT`
listener, arms the clone's timer, then calls `inet_ehash_insert()`. If that insert fails — a RST
racing in on another CPU is enough — the error path frees the clone without deleting the timer, and
the timer fires about a second later on freed memory: a slab use-after-free in `request_sock_TCP`.

The upstream fix is one line in `net/ipv4/inet_connection_sock.c`:

```c
-  __inet_csk_reqsk_queue_drop(sk_listener, nreq, true);
+  __inet_csk_reqsk_queue_drop(sk_listener, nreq, false);
```

The `true` tells the drop path the caller owns the timer; the timer was never deleted, so it fires
on freed memory. `false` makes the drop path delete it.

## What the check answers

| verdict | meaning |
|---|---|
| `VULNERABLE` | the deciding call site passes `true` |
| `PATCHED` | it passes `false` |
| `UNDETERMINED` | the image needed to decide was not readable, and the check says so rather than guessing |

The verdict comes from **the compiled instruction at the deciding call site**, never from the
version string. That matters because distributors backport fixes without changing the version, and
because a version number is a claim about upstream while a backport is what is actually installed.

It also reports the three other conditions exposure needs:

- whether a TCP `SO_REUSEPORT` group exists (two or more sockets on one port)
- whether an `sk_reuseport` BPF program is attached to it
- the value of `net.ipv4.tcp_migrate_req` (defaults to `0`)

## Running it

```sh
sudo ./kernel-check.sh
```

Root is needed for a complete answer: `/proc/kcore` is mode `0400`, real `/proc/kallsyms`
addresses need root or `CAP_SYSLOG` unless `kptr_restrict=0`, and `bpftool prog show` needs
`CAP_BPF` to list all programs. Run it as an unprivileged user and those steps return
`UNDETERMINED` rather than a guess — the check will tell you which step it could not do.

It reads `/boot`, `/proc`, and `bpftool prog show`. It writes only to its own `mktemp` directory and
removes it on exit.

Options:

```
--proc-root DIR    alternative /proc (testing aid; default /proc)
--boot-root DIR    alternative /boot (default /boot)
--json             machine-readable output
--help
```

## Tests

```sh
bash test/run-tests.sh
```

48 assertions pass against fixture kernels, including a patched image, a vulnerable image, an image
whose BPF program map does not match, and one whose kcore is unreadable. The fixtures are synthetic
and small; the runner also exercises a real kernel when run on one.

## Coverage and limits

- **x86-64 only.** It decodes the x86 instruction at the call site. On arm64 it reports
  `UNDETERMINED` rather than a wrong answer.
- It answers for the kernel currently running, or for an image you point it at with `--boot-root`.
- A `VULNERABLE` verdict means the kernel carries the defect. It does **not** mean a given host is
  exploitable: that also needs a `SO_REUSEPORT` group that actually changes membership while a
  request socket is alive, which the check reports but cannot force.

## Credit

The defect and the fix are upstream work by Kuniyuki Iwashima, reported by Damiano Melotti. This
repository is only a checker; it claims no discovery.

## Licence

MIT. See `LICENSE`.
