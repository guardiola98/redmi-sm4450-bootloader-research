/* Own-process observation only: no privileged IPC, driver I/O or fault stimulus.
 * Addresses are for private offline comparison; publish aggregates only.
 */
#include <asm/hwcap.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <unistd.h>

static volatile int image_marker;
int main(void) {
    volatile int stack_marker = 0;
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return 1;
    void *page = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return 2;
    unsigned long h1 = getauxval(AT_HWCAP), h2 = getauxval(AT_HWCAP2);
    printf("{\"uid\":%u,\"euid\":%u,\"page_size\":%ld,\"seccomp\":%d,"
           "\"paca\":%d,\"pacg\":%d,\"bti\":%d,\"mte\":%d,"
           "\"image\":\"%" PRIxPTR "\",\"stack\":\"%" PRIxPTR
           "\",\"mapping\":\"%" PRIxPTR "\"}\n",
           (unsigned)getuid(), (unsigned)geteuid(), page_size, prctl(PR_GET_SECCOMP),
           !!(h1 & HWCAP_PACA), !!(h1 & HWCAP_PACG),
           !!(h2 & HWCAP2_BTI), !!(h2 & HWCAP2_MTE),
           (uintptr_t)&image_marker, (uintptr_t)&stack_marker, (uintptr_t)page);
    return munmap(page, (size_t)page_size) == 0 ? 0 : 3;
}
