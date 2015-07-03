#ifndef WATCHPOINTS_H
#define WATCHPOINTS_H

#define MAJOR_NUM 100
#define DEVICE_NAME "watchpoints"

#define ADD_WATCHPOINT 1600
#define REMOVE_WATCHPOINT 3200

struct watchpoint_message {
	void *data_ptr;
	long data_size;
};
#endif
