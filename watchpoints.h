#ifndef WATCHPOINTS_H
#define WATCHPOINTS_H

#define MAJOR_NUM 100
#define DEVICE_NAME "watchpoints"
#define DEVICE_PATH "/dev/watchpoints"

#define ADD_BREAKPOINT 1
#define REMOVE_BREAKPOINT 2

struct watchpoint_message {
	void *data_ptr;
	long data_size;
};
#endif
