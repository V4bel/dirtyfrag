// Self-contained cache-vs-disk divergence PoC.
//
// Demonstrates that the page cache and the on-disk bytes can legitimately
// disagree, and is meant as a positive control for the multi-method file
// reader in streamlit_app.py: if that diagnostic reports DIFFER on the file
// produced by this program, the diagnostic works. (It also means the same
// approach would surface a Dirty-Frag-class write that landed in the cache
// without going to disk.)
//
// Mechanism (no exploit, no CVE):
//   1. Write 'A' bytes to a temp file, fsync.
//   2. Read once to populate the page cache with 'A'.
//   3. Write 'B' bytes to the same file via O_DIRECT — bypasses the page
//      cache, so the disk page now holds 'B' while the cached page still
//      holds 'A'.
//   4. Read via cached path -> 'A'. Read via O_DIRECT -> 'B'. Divergence.
//
// Build (Linux, inside the Custom App pod):
//   gcc -O0 -Wall -o /tmp/cache_demo cache_demo.c
//
// Requires a disk-backed filesystem at PATH; tmpfs returns EINVAL on
// O_DIRECT. /tmp on a Custom App pod is usually overlayfs and works.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PAGE 4096
#define PATH "/tmp/cache_demo.bin"

static void print_hex(const char *label, const unsigned char *b) {
    printf("%s (first 64 bytes hex):\n  ", label);
    for (int i = 0; i < 64; i++) printf("%02x", b[i]);
    putchar('\n');
}

int main(void) {
    unsigned char *A, *B, *cached, *direct;
    if (posix_memalign((void **)&A, PAGE, PAGE) ||
        posix_memalign((void **)&B, PAGE, PAGE) ||
        posix_memalign((void **)&cached, PAGE, PAGE) ||
        posix_memalign((void **)&direct, PAGE, PAGE)) {
        perror("posix_memalign");
        return 1;
    }
    memset(A, 'A', PAGE);
    memset(B, 'B', PAGE);

    int fd = open(PATH, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open create"); return 1; }
    if (write(fd, A, PAGE) != PAGE) { perror("write A"); return 1; }
    if (fsync(fd) < 0) { perror("fsync"); return 1; }
    close(fd);
    printf("[1] wrote 'A'*%d to %s and fsynced\n", PAGE, PATH);

    fd = open(PATH, O_RDONLY);
    if (read(fd, cached, PAGE) != PAGE) { perror("prime read"); return 1; }
    close(fd);
    printf("[2] primed page cache via cached read\n");

    fd = open(PATH, O_WRONLY | O_DIRECT);
    if (fd < 0) {
        fprintf(stderr,
                "[3] open O_DIRECT failed: %s\n"
                "    %s sits on a filesystem that doesn't support O_DIRECT (likely tmpfs).\n"
                "    Edit PATH to a disk-backed location and rebuild.\n",
                strerror(errno), PATH);
        return 1;
    }
    if (write(fd, B, PAGE) != PAGE) { perror("O_DIRECT write B"); return 1; }
    close(fd);
    printf("[3] wrote 'B'*%d via O_DIRECT (cache untouched, disk now 'B')\n\n", PAGE);

    fd = open(PATH, O_RDONLY);
    if (read(fd, cached, PAGE) != PAGE) { perror("cached read"); return 1; }
    close(fd);
    print_hex("[4] cached read    ", cached);

    fd = open(PATH, O_RDONLY | O_DIRECT);
    if (read(fd, direct, PAGE) != PAGE) { perror("O_DIRECT read"); return 1; }
    close(fd);
    print_hex("[5] O_DIRECT read  ", direct);

    int diverged = memcmp(cached, direct, PAGE) != 0;
    printf("\nVerdict: cache %s disk\n", diverged ? "!=" : "==");
    if (diverged) {
        printf("  Divergence achieved. Now run the Streamlit multi-method reader\n");
        printf("  on %s -- it should also report DIFFER.\n", PATH);
    } else {
        printf("  No divergence -- the kernel may have invalidated the cached\n");
        printf("  page after the O_DIRECT write (some filesystems do this on\n");
        printf("  the same inode). Try a different filesystem or path.\n");
    }

    free(A);
    free(B);
    free(cached);
    free(direct);
    return diverged ? 0 : 2;
}
