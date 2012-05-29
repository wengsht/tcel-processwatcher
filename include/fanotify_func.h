#include <linux/fanotify.h>
#include <unistd.h>
#include <inttypes.h>

int mark_object(int fan_fd, const char *path, int fd, uint64_t mask, unsigned int flags);
int set_special_ignored(int fan_fd, int fd, char *path);
int set_ignored_mask(int fan_fd, int fd, uint64_t mask);
