/*  一些fanotify的接口函数,取自fanotify的例程 */
#include "fanotify_func.h"

int mark_object(int fan_fd, const char *path, int fd, uint64_t mask, unsigned int flags)
{
	return fanotify_mark(fan_fd, flags, mask, fd, path);
}
int set_special_ignored(int fan_fd, int fd, char *path)
{
	unsigned int flags = (FAN_MARK_ADD | FAN_MARK_IGNORED_MASK |
			      FAN_MARK_IGNORED_SURV_MODIFY);
	uint64_t mask = FAN_ALL_EVENTS | FAN_ALL_PERM_EVENTS;

	if (strcmp("/var/log/audit/audit.log", path) &&
	    strcmp("/var/log/messages", path) &&
	    strcmp("/var/log/wtmp", path) &&
	    strcmp("/var/run/utmp", path))
		return 0;

	return mark_object(fan_fd, NULL, fd, mask, flags);
}
int set_ignored_mask(int fan_fd, int fd, uint64_t mask)
{
	unsigned int flags = (FAN_MARK_ADD | FAN_MARK_IGNORED_MASK);

	return mark_object(fan_fd, NULL, fd, mask, flags);
}
