#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/hw_breakpoint.h>
#include <linux/slab.h>
#include <linux/list.h>
#include "watchpoints.h"


MODULE_AUTHOR("Benjamin Schubert <benjamin.schubert@epfl.ch>");
MODULE_DESCRIPTION("Set watchpoints from proc without going through ptrace");
MODULE_LICENSE("GPL");


// on x86_64 there are only 4 watchpoints
#define WATCHPOINTS_MAX 4


// Change_list object, to keep track of any changes in the tracked data
struct change_list {
	// pid of the program owning the memory
	pid_t pid;
	// userspace pointer to the memory
	__u64 ptr;
	// new value of the data
	char *data; 
	// size of the data chunk
	int data_size;
	// list to which the data belongs
	struct list_head list;
};


// place of the last byte read from the last entry read (partially)
static int last_entry_offset = 0;

// size of the data of each data currently tracked
static long watchpoint_data_size[WATCHPOINTS_MAX];

// watchpoints class
static struct class *watchpoints_class = NULL;

// table containing each watchpoint set
struct perf_event *watchpoints[WATCHPOINTS_MAX];

// list of all changes to tracked data
struct change_list changes;


static void watchpoint_handler(struct perf_event *bp, 
			       struct perf_sample_data *data, 
			       struct pt_regs *regs);
static long watchpoints_ioctl(struct file *file, unsigned int cmd, 
			      long unsigned ptr_message);
static ssize_t watchpoints_read(struct file *file,
                                char __user *user_buffer,
                                size_t length,
                                loff_t *offset);

static int __init watchpoint_init(void);
static void __exit watchpoint_exit(void);


const struct file_operations Fops = {
	.read = watchpoints_read,
	.write = NULL,
	.unlocked_ioctl = watchpoints_ioctl,
	.open = NULL,
	.release = NULL,
};

module_init(watchpoint_init);
module_exit(watchpoint_exit);


static void watchpoint_handler(struct perf_event *bp, 
			       struct perf_sample_data *data, 
			       struct pt_regs *regs)
{
	for(int i = 0; i < WATCHPOINTS_MAX; i++) {
		if(!watchpoints[i] &&
		           watchpoints[i]->attr.bp_addr == bp->attr.bp_addr) {
			continue;
		}
		
		struct change_list *new_change = 
		    kmalloc(sizeof(struct change_list), __GFP_IO | __GFP_FS);
		
		long size = watchpoint_data_size[i];
		new_change->data = kmalloc(size + 1, __GFP_IO | __GFP_FS);
		
		if(!new_change->data) {
			return;
		}
		copy_from_user(new_change->data, (void*) bp->attr.bp_addr, size);
		new_change->data[size] = '\0';
		new_change->pid = watchpoints[i]->ctx->task->pid;
		new_change->ptr = bp->attr.bp_addr;
		new_change->data_size = size + 1;

		printk(KERN_DEBUG
	           "Process %d, at position %llu, new value :%s\n",
	           new_change->pid, new_change->ptr, new_change->data);
		
		list_add_tail(&(new_change->list), &(changes.list));
		break;
	}
}


static long watchpoints_ioctl(struct file *file, unsigned int cmd, 
			      long unsigned ptr_message)
{
	struct watchpoint_message data;
	copy_from_user(&data, (void*) ptr_message, sizeof(data));
	
	if(data.pid != current->pid) {
		printk(KERN_ERR
		    "Attempting to place breakpoint on other process. Abort\n");
		return -EINVAL;
	}
	
	printk(KERN_DEBUG "Received pid %d, ptr %ld, size %ld\n",
	       data.pid, data.data_ptr, data.data_size);

	switch(cmd) {
	case ADD_BREAKPOINT:
		// Initialize breakpoint
		struct perf_event_attr attr;
		hw_breakpoint_init(&attr);
		attr.bp_addr = data.data_ptr;
		attr.bp_len = HW_BREAKPOINT_LEN_4;
		attr.bp_type = HW_BREAKPOINT_W;

		struct task_struct *tsk = pid_task(find_vpid(data.pid), PIDTYPE_PID);

		struct perf_event *perf_watchpoint = 
			register_user_hw_breakpoint(&attr, watchpoint_handler, NULL, tsk);
			
		if (IS_ERR(perf_watchpoint)) {
			printk(KERN_DEBUG "Could not set watchpoint");
			return perf_watchpoint;
		}

		for(int i = 0; i < WATCHPOINTS_MAX; i++) {
			if(watchpoints[i] && 
			   watchpoints[i]->state == PERF_EVENT_STATE_OFF) {
				printk(KERN_DEBUG 
					"Removing watchpoint at %i. Not used anymore\n", i);
				unregister_hw_breakpoint(watchpoints[i]);
				watchpoints[i] = NULL;
			}
			if(!watchpoints[i]) {
				watchpoints[i] = perf_watchpoint;
				watchpoint_data_size[i] = data.data_size;
				break;
			}
		}
		break;

	case REMOVE_BREAKPOINT:
		for(int i = 0; i < WATCHPOINTS_MAX; i++) {
			if(watchpoints[i] &&
			   watchpoints[i]->attr.bp_addr == data.data_ptr &&
			   watchpoints[i]->ctx->task->pid == data.pid) {
				unregister_hw_breakpoint(watchpoints[i]);
			}
		}

	default:
		return -EINVAL;
	}
	
	return 0;
}


static ssize_t watchpoints_read(struct file *file, char __user *user_buffer,
                		size_t length, loff_t *offset)
{
	struct change_list *new_change;
	char[] template = "pid=%d, pointer=%llu, value=%s\n";
	char *output;
	char *output_pointer;
	struct list_head *pos, *q;
	size_t bytes_read = 0;
	
	list_for_each_safe(pos, q, &changes.list) {
		new_change = list_first_entry(&(changes.list),
		                              struct change_list, list);
		output = kmalloc(snprintf(NULL, 0, template, new_change->pid,
		                          new_change->ptr, new_change->data)
		                 , __GFP_REPEAT);
		sprintf(output, template, new_change->pid, new_change->ptr,
		        new_change->data);
		output_pointer = output + last_entry_offset;
		printk(KERN_DEBUG "%s", output);
		
		while(length && *output_pointer) {
			put_user(*(output_pointer++), user_buffer++);
			length--;
			bytes_read++;
		}

		if(! *output_pointer) {
			// we finished processing this entry, let's clean !
			kfree(new_change->data);
			list_del(pos);
			last_entry_offset = 0;
		} else {
			last_entry_offset = output_pointer - output;
		}
		kfree(output);
		if(!length) {
			// we finished putting things in the buffer, let's break !
			break;
		}
	}

	return bytes_read;
}


static int __init watchpoint_init(void)
{
	watchpoints_class = class_create(THIS_MODULE, DEVICE_NAME);
	if(IS_ERR(watchpoints_class)) {
		return -EFAULT;
	}

	void *ptr_err = device_create(watchpoints_class, NULL, MKDEV(MAJOR_NUM, 0),
				      NULL, DEVICE_NAME);
	if (IS_ERR(ptr_err)) {
		class_unregister(watchpoints_class);
		class_destroy(watchpoints_class);
		return -EFAULT;
	}

	register_chrdev(MAJOR_NUM, DEVICE_NAME, &Fops);
	
	INIT_LIST_HEAD(&changes.list);

	return 0;
}


static void __exit watchpoint_exit(void)
{
	struct change_list *new_change;
	struct list_head *pos, *q;
	
	list_for_each_safe(pos, q, &changes.list) {
		new_change = list_first_entry(&(changes.list), struct change_list, list);
		kfree(new_change->data);
		list_del(pos);
	}
	
	unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
	device_destroy(watchpoints_class, MKDEV(MAJOR_NUM, 0));
	class_unregister(watchpoints_class);
	class_destroy(watchpoints_class);
}
