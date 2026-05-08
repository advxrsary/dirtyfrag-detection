# dirtyfrag_probe

Non-exploitative detector for **CVE-2026-31431 (DirtyFrag)** — Linux
kernel page-cache mutation via `xfrm`/espinudp ESN and `rxrpc`/rxkad.

Single C file. Triggers both primitives against a tempfile under `/tmp`,
re-reads, reports per-primitive verdict. No setuid target, no shellcode,
no key brute force, page cache dropped on exit.

## Build / run

```
gcc -O2 -Wall -Wextra -o dirtyfrag_probe poc_no_exp.c
./dirtyfrag_probe -v
```

Flags: `--xfrm-only`, `--rxrpc-only`, `--no-cleanup`, `-v`.

## Output

```
=== DirtyFrag (CVE-2026-31431) detector ===
  XFRM/espinudp ESN seq_hi write : VULNERABLE
  rxrpc/rxkad in-place decrypt   : VULNERABLE
Result: VULNERABLE — kernel mutated probe-file page cache.
```

Verdicts: `VULNERABLE` / `NOT_VULNERABLE` / `INCONCLUSIVE`. Exit `1` if
any vulnerable, else `0`.

## Caveat

Ubuntu 24.04+ defaults to
`kernel.apparmor_restrict_unprivileged_userns=1`, blocking the
`uid_map` write — both probes return `INCONCLUSIVE`. Run via `sudo`,
or:

```
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

## Related

Upstream exploit: <https://github.com/V4bel/dirtyfrag>
