#ifndef WATCHPOINTS_H
#define WATCHPOINTS_H

#define MAJOR_NUM 100
#define DEVICE_NAME "watchpoints"

#define WATCHPOINT_ADD 1600
#define WATCHPOINT_RESIZE 2400
#define WATCHPOINT_REMOVE 3200

/* struct to which should point the pointer given to the ioctl */
struct watchpoint_message {
	/* pointer to the data that should be tracked */
	void *data_ptr;
	/* size of the data to track */
	long data_size;
	/* 
	 * pointer to the new zone in memory which should be tracked
	 * when the command is WATCHPOINT_RESIZE
	 */
	void *new_data_ptr;
};

#endif
