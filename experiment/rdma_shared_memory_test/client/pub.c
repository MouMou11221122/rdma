#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define RDMA_BUFFER_SIZE            ((1UL) << 30)

/* shared memory info */
#define SHM_NAME                    "/rdma_shm1"

int main(int argc, char* argv[])
{
    int shm_fd = shm_open(SHM_NAME, O_RDWR, 0666);
    if (shm_fd == -1) { 
        perror("shm_open"); 
        return 1; 
    }

    char *buffer = mmap(NULL, RDMA_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (buffer == MAP_FAILED) { 
        perror("mmap"); 
        return 1;
    }
    close(shm_fd);

    char cnt = 0;
    for (int i = 0; i < RDMA_BUFFER_SIZE; i++) {
        buffer[i] = cnt;
        cnt++;
    }

    munmap(buffer, RDMA_BUFFER_SIZE);
    shm_unlink(SHM_NAME);
    return 0;
}
