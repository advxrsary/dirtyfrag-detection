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

Per-probe verdicts:

| Verdict          | Meaning                                                                    |
|------------------|----------------------------------------------------------------------------|
| `VULNERABLE`     | Probe ran end-to-end, kernel mutated the page cache.                       |
| `NOT_VULNERABLE` | Probe ran end-to-end, page cache unchanged (kernel-side fix).              |
| `UNREACHABLE`    | Vulnerable primitive surface absent (e.g. `esp4`/`rxrpc` modules blocked). |
| `INCONCLUSIVE`   | Probe could not be run end-to-end for an unclear reason.                   |

Exit code:

| Exit | Meaning                                                                                |
|------|----------------------------------------------------------------------------------------|
| `0`  | `NOT_VULNERABLE` — including hosts where the surface is `UNREACHABLE`.                 |
| `1`  | `VULNERABLE` — at least one probe observed a mutation.                                 |
| `2`  | `ERROR` / `INCONCLUSIVE` — at least one probe couldn't run; AppArmor and similar.      |

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
