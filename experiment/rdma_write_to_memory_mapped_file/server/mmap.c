#define _GNU_SOURCE      /* for mremap */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#define FILE_NAME   "mapped_file"
#define SEG_SZ      (256 * 1024 * 1024)     /* 256 MiB initial size */
#define GROW_SZ     (128 * 1024 * 1024)     /* 128 MiB grow step */

static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int main(void)
{
    int fd = open(FILE_NAME, O_RDWR | O_CREAT, 0644);
    if (fd < 0) die("open");

    /* ------------------------------------------------- *
     * Pre-allocate first segment and map it.            *
     * ------------------------------------------------- */
    if (ftruncate(fd, SEG_SZ) == -1) die("ftruncate-init");

    uint8_t *base = mmap(NULL, SEG_SZ, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) die("mmap-init");

    printf("Mapped %d MiB at %p\n", SEG_SZ >> 20, base);

    /* ------------------------------------------------- *
     * Write something at offset 100 MiB                 *
     * ------------------------------------------------- */
    const char payload[] = "hello-world\n";
    off_t off = 100 * 1024 * 1024;          /* 100 MiB */
    memcpy(base + off, payload, sizeof payload);
    printf("Wrote payload at offset %lld\n", (long long)off);

    /* ------------------------------------------------- *
     * Need to append past current mapping → grow file   *
     * ------------------------------------------------- */
    off_t new_size = SEG_SZ + GROW_SZ;      /* 384 MiB total */
    if (ftruncate(fd, new_size) == -1) die("ftruncate-grow");

    /* On Linux we can enlarge the mapping in-place with mremap() */
    uint8_t *new_base = mremap(base, SEG_SZ, new_size, MREMAP_MAYMOVE);
    if (new_base == MAP_FAILED) die("mremap");

    printf("Remapped +%d MiB ⇒ total %lld MiB  (addr %p)\n",
           GROW_SZ >> 20, (long long)(new_size >> 20), new_base);

    base = new_base;        /* update pointer */

    /* ------------------------------------------------- *
     * Append data at offset 300 MiB (inside new region) *
     * ------------------------------------------------- */
    off = 300 * 1024 * 1024; /* 300 MiB */
    memcpy(base + off, payload, sizeof payload);
    printf("Appended payload at offset %lld\n", (long long)off);

    /* ------------------------------------------------- *
     * Flush & cleanup                                   *
     * ------------------------------------------------- */
    if (msync(base, new_size, MS_SYNC) == -1) die("msync");
    munmap(base, new_size);
    close(fd);

    puts("Done.");
    return 0;
}

