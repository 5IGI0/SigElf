#include <assert.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

void    *map_file_to_memory(char const *path, size_t *outlen) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;

    struct stat fdstat;
    assert(fstat(fd, &fdstat) == 0);

    void *addr = mmap(NULL, fdstat.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        return NULL;
    }

    close(fd);
    *outlen = fdstat.st_size;

    return addr;
}