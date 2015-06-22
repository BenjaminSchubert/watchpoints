#ifndef WATCHPOINTS_H
#define WATCHPOINTS_H

#define MAJOR_NUM 100
#define DEVICE_NAME "watchpoints"

#define ADD_BREAKPOINT 1
#define REMOVE_BREAKPOINT 2

struct watchpoint_message {
	pid_t pid;
	long data_ptr;
	long data_size;
};
#endif
