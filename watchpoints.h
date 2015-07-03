#ifndef WATCHPOINTS_H
#define WATCHPOINTS_H

#define MAJOR_NUM 100
#define DEVICE_NAME "watchpoints"

#define ADD_WATCHPOINT 0
#define REMOVE_WATCHPOINT 2

struct watchpoint_message {
	void *data_ptr;
	long data_size;
};
#endif
